#!/usr/bin/env python3
"""Run the opt-in SPNEGO test with a private, temporary MIT Kerberos realm."""
import argparse
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tools-root", type=Path, required=True)
    parser.add_argument("--key-bytes", type=int, choices=(16, 32), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    tools = args.tools_root.resolve()
    output = args.output.resolve()
    for name in ("kdb5_util", "kadmin.local", "krb5kdc"):
        if not (tools / "usr/sbin" / name).is_file():
            parser.error("Missing extracted MIT Kerberos tool: " + name)
    if not Path("gradlew").is_file():
        parser.error("Run from the SMBJ feature worktree")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="smbj-krb5-") as temporary:
        directory = Path(temporary)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        enctype = "aes%d-cts-hmac-sha1-96" % (args.key_bytes * 8)
        (directory / "krb5.conf").write_text(f"""[libdefaults]
 default_realm = SMBJ.TEST
 dns_lookup_kdc = false
 dns_lookup_realm = false
 rdns = false
 udp_preference_limit = 1
 default_tkt_enctypes = {enctype}
 default_tgs_enctypes = {enctype}
 permitted_enctypes = {enctype}
[realms]
 SMBJ.TEST = {{
  kdc = 127.0.0.1:{port}
 }}
""")
        (directory / "kdc.conf").write_text(f"""[kdcdefaults]
 kdc_listen = 127.0.0.1:{port}
 kdc_tcp_listen = 127.0.0.1:{port}
[realms]
 SMBJ.TEST = {{
  database_name = {directory}/principal
  key_stash_file = {directory}/stash
  supported_enctypes = {enctype}:normal
  max_life = 1h
 }}
[dbmodules]
 db_module_dir = {tools}/usr/lib/x86_64-linux-gnu/krb5/plugins/kdb
""")
        (directory / "logback.xml").write_text('<configuration><root level="OFF"/></configuration>')
        init = directory / "test.gradle"
        init.write_text(f"""allprojects {{
    tasks.withType(Test).configureEach {{
        maxHeapSize = '192m'
        maxParallelForks = 1
        jvmArgs '-XX:ActiveProcessorCount=2'
    }}
    afterEvaluate {{
        tasks.named('integrationTest', Test).configure {{
            systemProperty 'java.security.krb5.conf', '{directory}/krb5.conf'
            systemProperty 'javax.security.auth.useSubjectCredsOnly', 'true'
            systemProperty 'logback.configurationFile', '{directory}/logback.xml'
        }}
    }}
}}
""")
        env = os.environ.copy()
        env.update(KRB5_CONFIG=str(directory / "krb5.conf"), KRB5_KDC_PROFILE=str(directory / "kdc.conf"),
                   LD_LIBRARY_PATH=str(tools / "usr/lib/x86_64-linux-gnu"))
        with (directory / "provision.log").open("wb") as log:
            password = secrets.token_urlsafe(32)
            subprocess.run([str(tools / "usr/sbin/kdb5_util"), "create", "-s", "-r", "SMBJ.TEST"],
                           input=(password + "\n" + password + "\n").encode(), env=env,
                           stdout=log, stderr=subprocess.STDOUT, check=True, timeout=30)
            for name, principal in (("client", "client@SMBJ.TEST"),
                                    ("server", "cifs/server.smbj.test@SMBJ.TEST")):
                for query in ("addprinc -randkey " + principal,
                              f"ktadd -k {directory}/{name}.keytab {principal}"):
                    subprocess.run([str(tools / "usr/sbin/kadmin.local"), "-r", "SMBJ.TEST", "-q", query],
                                   env=env, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=30)
                os.chmod(directory / (name + ".keytab"), 0o600)
        with (directory / "kdc.log").open("wb") as log:
            kdc = subprocess.Popen([str(tools / "usr/sbin/krb5kdc"), "-n", "-P", str(directory / "kdc.pid")],
                                   env=env, stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 10
                while True:
                    if kdc.poll() is not None:
                        raise RuntimeError("Private KDC exited before readiness")
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                            break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise RuntimeError("Private KDC did not become ready")
                        time.sleep(0.05)
                test_env = os.environ.copy()
                test_env.update(SMBJ_KRB5_TEST_DIR=str(directory), SMBJ_KRB5_KEY_BYTES=str(args.key_bytes))
                with (output / "build.log").open("wb") as build_log:
                    subprocess.run(["./gradlew", "--offline", "--no-daemon", "--max-workers=1",
                                    "-Dorg.gradle.jvmargs=-Xmx192m -XX:ActiveProcessorCount=2",
                                    "--init-script", str(init), "integrationTest", "--tests", "*KerberosSpnegoIT",
                                    "-x", "buildSambaImage", "licenseIntegrationTest"],
                                   env=test_env, stdout=build_log, stderr=subprocess.STDOUT, check=True)
                report = Path("build/test-results/integrationTest/TEST-com.hierynomus.smbj.connection.KerberosSpnegoIT.xml")
                shutil.copyfile(report, output / report.name)
                result = ET.parse(report).getroot()
                assert int(result.attrib["tests"]) == 3, result.attrib
                assert all(int(result.attrib[name]) == 0 for name in ("failures", "errors", "skipped")), result.attrib
                print(f"AES-{args.key_bytes * 8}: 3 passed; reports in {output}")
            finally:
                if kdc.poll() is None:
                    kdc.terminate()
                    try:
                        kdc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        kdc.kill()
                        kdc.wait()


if __name__ == "__main__":
    main()
