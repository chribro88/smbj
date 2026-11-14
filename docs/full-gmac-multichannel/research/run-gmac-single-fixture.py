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
arguments = parser.parse_args()
if not Path('gradlew').is_file():
    parser.error('Run from the SMBJ feature worktree')
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
config = Path('docs/full-gmac-multichannel/research/smb-gmac-gcm.conf').resolve()
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
    raw = output / 'client-raw.log'
    try:
        with raw.open('wb') as log:
            result = subprocess.run([
                './gradlew', '--offline', '--no-daemon', '--max-workers=1',
                '-Dorg.gradle.jvmargs=-Xmx192m -XX:ActiveProcessorCount=2', '--init-script',
                str(init), 'integrationTest', '-x', 'buildSambaImage',
                '--tests', '*SingleChannelSigningIT', 'licenseIntegrationTest'
            ], env=client_environment, stdout=log, stderr=subprocess.STDOUT)
        (output / 'client.log').write_text(raw.read_text().replace(password, '<disposable-fixture-secret>'))
    finally:
        raw.unlink(missing_ok=True)
    assert result.returncode == 0, result.returncode
    report = Path('build/test-results/integrationTest/TEST-com.hierynomus.smbj.SingleChannelSigningIT.xml')
    root = ET.parse(report).getroot()
    assert int(root.attrib['tests']) == 16, root.attrib
    assert all(int(root.attrib[name]) == 0 for name in ('failures', 'errors', 'skipped')), root.attrib
    metadata['suite'] = dict(root.attrib)
    text = '\n'.join(node.text or '' for node in root.iter('system-out'))
    metadata['profiles'] = [line.strip() for line in text.splitlines() if line.startswith('SIGNING_SINGLE ')]
    assert len(metadata['profiles']) == 16, len(metadata['profiles'])
    assert len(set(metadata['profiles'])) == 16
    assert all('signing=AES_GMAC' in line for line in metadata['profiles'])
    assert all('cipher=AES_128_GCM' in line for line in metadata['profiles'] if 'encrypt=true' in line)
    (output / report.name).write_text(report.read_text().replace(password, '<disposable-fixture-secret>'))
    print('16 forced-GMAC/GCM single-session cases passed.')
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
