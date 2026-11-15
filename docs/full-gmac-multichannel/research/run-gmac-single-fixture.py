#!/usr/bin/env python3
"""Run the forced-GMAC single-session matrix on a pinned disposable Samba fixture."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--config', type=Path, default=Path('docs/full-gmac-multichannel/research/smb-gmac-gcm.conf'))
profile = parser.add_mutually_exclusive_group()
parser.add_argument('--java8-home', type=Path)
profile.add_argument('--async-cancel', action='store_true')
profile.add_argument('--public-binding', action='store_true')
profile.add_argument('--public-anchor-research', action='store_true')
profile.add_argument('--bootstrap-abort-research', action='store_true')
profile.add_argument('--unsigned-echo-research', action='store_true')
profile.add_argument('--per-request-research', action='store_true')
arguments = parser.parse_args()
if not Path('gradlew').is_file():
    parser.error('Run from the SMBJ feature worktree')
if arguments.java8_home:
    if any((arguments.public_anchor_research, arguments.bootstrap_abort_research,
            arguments.unsigned_echo_research, arguments.per_request_research)):
        parser.error('--java8-home supports the default matrix, --public-binding or --async-cancel')
    if not os.environ.get('JAVA_HOME'):
        parser.error('Select the Java 21 build JDK with JAVA_HOME when using --java8-home')
    arguments.java8_home = arguments.java8_home.resolve()
    if not (arguments.java8_home / 'bin/java').is_file():
        parser.error('--java8-home must contain bin/java')
if arguments.public_anchor_research:
    if os.environ.get('SMBJ_GMAC_AUX_RESEARCH') != 'true' or not Path('src/it/java/com/hierynomus/smbj/session/GmacPublicAnchorIT.java').is_file():
        parser.error('--public-anchor-research requires the detached research checkout and explicit opt-in')
if arguments.bootstrap_abort_research:
    if os.environ.get('SMBJ_GMAC_AUX_RESEARCH') != 'true' or not Path('src/it/java/com/hierynomus/smbj/connection/GmacBootstrapAbortIT.java').is_file():
        parser.error('--bootstrap-abort-research requires the detached research checkout and explicit opt-in')
if arguments.unsigned_echo_research:
    if os.environ.get('SMBJ_GMAC_UNSIGNED_ECHO_RESEARCH') != 'true' or not Path('src/it/java/com/hierynomus/smbj/connection/GmacUnsignedEchoIT.java').is_file():
        parser.error('--unsigned-echo-research requires the detached research checkout and explicit opt-in')
if arguments.per_request_research:
    if os.environ.get('SMBJ_GMAC_AUX_RESEARCH') != 'true' or not Path('src/it/java/com/hierynomus/smbj/connection/GmacConcurrentBootstrapIT.java').is_file():
        parser.error('--per-request-research requires the detached research checkout and explicit opt-in')
if arguments.public_binding:
    test_class, expected_count, marker, label = ('com.hierynomus.smbj.connection.PublicGmacBindingIT', 11,
                                               'PUBLIC_GMAC_COMPLETE ', 'public multichannel')
elif arguments.per_request_research:
    test_class, expected_count, marker, label = ('com.hierynomus.smbj.connection.GmacConcurrentBootstrapIT', 7,
                                               'AUXCON_COMPLETE ', 'per-request reservation research')
elif arguments.unsigned_echo_research:
    test_class, expected_count, marker, label = ('com.hierynomus.smbj.connection.GmacUnsignedEchoIT', 1,
                                               'UNSIGNED_ECHO_COMPLETE ', 'unsigned-ECHO research')
elif arguments.bootstrap_abort_research:
    test_class, expected_count, marker, label = ('com.hierynomus.smbj.connection.GmacBootstrapAbortIT', 10,
                                               'BOOTSTRAP_ABORT_COMPLETE ', 'bootstrap-abort research')
elif arguments.public_anchor_research:
    test_class, expected_count, marker, label = ('com.hierynomus.smbj.session.GmacPublicAnchorIT', 2,
                                               'PUBLIC_ANCHOR_COMPLETE ', 'public-anchor research')
elif arguments.async_cancel:
    test_class, expected_count, marker, label = ('com.hierynomus.smbj.connection.GmacAsyncCancellationIT', 8,
                                               'GMAC_ASYNC ', 'async cancellation')
else:
    test_class, expected_count, marker, label = ('com.hierynomus.smbj.SingleChannelSigningIT', 16,
                                               'SIGNING_SINGLE ', 'single-session')
os.umask(0o077)
output = arguments.output.resolve()
output.mkdir(mode=0o700, parents=True, exist_ok=False)
init = output / 'test.gradle'
init.write_text("""allprojects { tasks.withType(Test).configureEach {
    maxHeapSize = '384m'
    maxParallelForks = 1
    jvmArgs '-XX:ActiveProcessorCount=2'
    outputs.upToDateWhen { false }
} }
""")
image = 'dockurr/samba@sha256:2a0452a12b7a244a22f18d0f233101bb8d4952b5500ae263905e3b9dad3bf2ae'
config = arguments.config.resolve()
owner = 'smbj-late-response-' + str(uuid.uuid4())
password = secrets.token_urlsafe(32)
environment = os.environ.copy()
environment['SMBJ_FIXTURE_PASSWORD'] = password
cid = None
metadata = {'image': image, 'owner': owner, 'config': str(config),
            'config_sha256': hashlib.sha256(config.read_bytes()).hexdigest()}
try:
    cid = subprocess.check_output([
        'docker', 'create', '--pull=never', '--label', 'org.smbj.test-owner=' + owner,
        '--memory', '256m', '--cpus', '1', '--tmpfs', '/shared:rw,size=64m,mode=1777',
        '--publish', '127.0.0.1::445',
        '--env', 'SMBJ_FIXTURE_PASSWORD', '--entrypoint', '/bin/sh', image, '-c',
        'set -eu; id smbtest >/dev/null 2>&1 || useradd -M smbtest; '
        'printf "%s\\n%s\\n" "$SMBJ_FIXTURE_PASSWORD" "$SMBJ_FIXTURE_PASSWORD" | smbpasswd -s -a smbtest; '
        'exec /usr/sbin/smbd -F --no-process-group --configfile=/etc/samba/smb.conf'
    ], env=environment, text=True).strip()
    assert re.fullmatch('[0-9a-f]{64}', cid), cid
    metadata['container_id'] = cid
    subprocess.run(['docker', 'cp', str(config), cid + ':/etc/samba/smb.conf'], check=True)
    subprocess.run(['docker', 'start', cid], check=True, stdout=subprocess.DEVNULL)
    ports = json.loads(subprocess.check_output(['docker', 'inspect', '--format', '{{json .NetworkSettings.Ports}}', cid], text=True))
    binding = ports['445/tcp'][0]
    assert binding['HostIp'] == '127.0.0.1', binding
    port = int(binding['HostPort'])
    metadata['port'] = port
    deadline = time.monotonic() + 30
    while True:
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.25):
                break
        except OSError:
            if time.monotonic() >= deadline:
                raise RuntimeError('Task Samba fixture did not become reachable')
            time.sleep(0.25)
    metadata['version'] = subprocess.check_output(['docker', 'exec', cid, 'smbd', '--version'], text=True).strip()
    metadata['image_id'] = subprocess.check_output(['docker', 'inspect', '--format', '{{.Image}}', cid], text=True).strip()
    client_environment = os.environ.copy()
    client_environment.update(SMB_TEST_HOST='127.0.0.1', SMB_TEST_PORTS=str(port), SMB_TEST_USERNAME='smbtest',
                              SMB_TEST_PASSWORD=password, SMB_TEST_DOMAIN='WORKGROUP', SMB_TEST_SHARE='share',
                              SMB_TEST_SIGNING_ALGORITHM='AES_GMAC', SMB_TEST_DIALECT='SMB_3_1_1')
    command = ['./gradlew', '--offline', '--no-daemon', '--max-workers=1',
               '-Dorg.gradle.jvmargs=-Xmx192m -XX:ActiveProcessorCount=2', '--init-script', str(init)]
    if arguments.java8_home:
        client_environment['SMBJ_JAVA8_OUTPUT'] = str(output)
        client_environment['SMBJ_JAVA8_PUBLIC_BINDING'] = str(arguments.public_binding).lower()
        client_environment['SMBJ_JAVA8_ASYNC_CANCEL'] = str(arguments.async_cancel).lower()
        command += ['-Porg.gradle.java.installations.paths=' + str(arguments.java8_home) + ',' + os.environ['JAVA_HOME'],
                    '-Porg.gradle.java.installations.auto-detect=false', '-Porg.gradle.java.installations.auto-download=false',
                    '--init-script', 'docs/full-gmac-multichannel/research/java8-runtime-profile.gradle', 'java8RuntimeTest']
    else:
        command += ['integrationTest', '--tests', test_class]
    command += ['-x', 'buildSambaImage', 'licenseIntegrationTest']
    raw = output / 'client-raw.log'
    try:
        with raw.open('wb') as log:
            result = subprocess.run(command, env=client_environment, stdout=log, stderr=subprocess.STDOUT)
        (output / 'client.log').write_text(raw.read_text().replace(password, '<disposable-fixture-secret>'))
    finally:
        raw.unlink(missing_ok=True)
    assert result.returncode == 0, result.returncode
    reports = output / 'java8-reports' if arguments.java8_home else Path('build/test-results/integrationTest')
    report = reports / ('TEST-' + test_class + '.xml')
    root = ET.parse(report).getroot()
    assert int(root.attrib['tests']) == expected_count, root.attrib
    assert all(int(root.attrib[name]) == 0 for name in ('failures', 'errors', 'skipped')), root.attrib
    metadata['suite'] = dict(root.attrib)
    text = '\n'.join(node.text or '' for node in root.iter('system-out'))
    markers = ('AUXCON_COMPLETE ', 'AUXCON_BOOTSTRAP_ABORT ', 'AUXCON_NEGATIVE_CONTROL ',
               'AUXCON_BOOTSTRAP_NEGATIVE_CONTROL ') if arguments.per_request_research else (marker,)
    metadata['profiles'] = [line.strip() for line in text.splitlines() if line.startswith(markers)]
    expected_profiles = 8 if arguments.bootstrap_abort_research else expected_count
    assert len(metadata['profiles']) == expected_profiles, len(metadata['profiles'])
    assert len(set(metadata['profiles'])) == expected_profiles
    if arguments.bootstrap_abort_research:
        metadata['negative_controls'] = [line.strip() for line in text.splitlines() if line.startswith('BOOTSTRAP_ABORT_UNSAFE_CONTROL ')]
        assert len(metadata['negative_controls']) == 2
        assert all('result=expected_nonce_reuse_detected' in line for line in metadata['negative_controls'])
    if arguments.per_request_research:
        assert sum('result=expected_' in line and 'nonce_reuse_detected' in line for line in metadata['profiles']) == 2
    assert all('signing=AES_GMAC' in line for line in metadata['profiles'])
    assert all('cipher=AES_128_GCM' in line for line in metadata['profiles'] if 'encrypt=true' in line)
    if arguments.java8_home:
        assert all('java=1.8.' in line for line in metadata['profiles'])
        expected = {'PromiseBackedFutureTest': 5, 'RequestCancellationTest': 9,
                    'PacketSignatoryTest': 2, 'SequenceWindowExhaustionTest': 8}
        metadata['java8_local_suites'] = []
        for name, count in expected.items():
            local = list(reports.glob('TEST-*.' + name + '.xml'))
            assert len(local) == 1, local
            suite = ET.parse(local[0]).getroot()
            assert int(suite.attrib['tests']) == count, suite.attrib
            assert all(int(suite.attrib[key]) == 0 for key in ('failures', 'errors', 'skipped')), suite.attrib
            metadata['java8_local_suites'].append(dict(suite.attrib))
        metadata['java8_home'] = str(arguments.java8_home)
    (output / report.name).write_text(report.read_text().replace(password, '<disposable-fixture-secret>'))
    print(str(expected_count) + ' forced-GMAC ' + label + ' cases passed.')
finally:
    if cid:
        server_log = subprocess.run(['docker', 'logs', cid], capture_output=True, text=True)
        (output / 'server.log').write_text((server_log.stdout + server_log.stderr).replace(password, '<disposable-fixture-secret>'))
        actual_owner = subprocess.check_output(['docker', 'inspect', '--format',
            '{{index .Config.Labels "org.smbj.test-owner"}}', cid], text=True).strip()
        assert actual_owner == owner, actual_owner
        subprocess.run(['docker', 'rm', '-f', cid], check=True, stdout=subprocess.DEVNULL)
        assert not subprocess.check_output(['docker', 'ps', '-a', '-q', '--filter', 'id=' + cid], text=True).strip()
        metadata['removed'] = True
    (output / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
