#!/usr/bin/env python3
"""Run public GMAC/Kerberos acceptance using the existing isolated Samba AD image."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, required=True)
arguments = parser.parse_args()
if not Path('gradlew').is_file():
    parser.error('Run from the SMBJ feature worktree')
output = arguments.output.resolve()
output.mkdir(mode=0o700, parents=True, exist_ok=False)
fixture = Path('docs/full-gmac-multichannel/research/kerberos-native').resolve()
image = 'smbj/kerberos-dc:e097023'
image_id = 'sha256:9501aa40203bf661632ee44df2bf2a2b1642dd62c6a77f062e9780dc8a23ade9'
actual = subprocess.check_output(['docker', 'image', 'inspect', '--format', '{{.Id}}', image], text=True).strip()
assert actual == image_id, actual
environment = os.environ.copy()
environment.update(SMBJ_AD_IMAGE=image, SMBJ_AD_IMAGE_ID=image_id, SMBJ_AD_FIXTURE=str(fixture),
                   SMBJ_AD_LOGGING=str(fixture / 'logging-off.xml'), SMBJ_AD_OUTPUT=str(output))
command = ['./gradlew', '--offline', '--no-daemon', '--max-workers=1',
           '-Dorg.gradle.jvmargs=-Xmx192m -XX:ActiveProcessorCount=2',
           '--init-script', str(fixture / 'test-limits.gradle'), 'integrationTest',
           '--tests', '*PublicGmacKerberosIT', '-x', 'buildSambaImage', 'licenseIntegrationTest']
metadata = {'image': image, 'image_id': image_id, 'command': command, 'result': 'INCOMPLETE'}
try:
    with (output / 'client.log').open('wb') as log:
        result = subprocess.run(command, env=environment, stdout=log, stderr=subprocess.STDOUT)
    metadata['returncode'] = result.returncode
    report = Path('build/test-results/integrationTest/TEST-com.hierynomus.smbj.connection.PublicGmacKerberosIT.xml')
    assert result.returncode == 0, result.returncode
    root = ET.parse(report).getroot()
    metadata['suite'] = dict(root.attrib)
    assert int(root.get('tests')) == 8, root.attrib
    assert all(int(root.get(key)) == 0 for key in ('failures', 'errors', 'skipped')), root.attrib
    lines = (root.findtext('system-out') or '').splitlines()
    metadata['profiles'] = [line for line in lines if line.startswith('PUBLIC_KRB_COMPLETE ')]
    metadata['contexts'] = [line for line in lines if line.startswith('KERBEROS_CONTEXTS ')]
    metadata['audits'] = [line for line in lines if line.startswith('AUXWIRE_COMPLETE ')]
    metadata['gcm_audits'] = [line for line in lines if line.startswith('AUXWIRE_GCM ')]
    metadata['disposal_aborts'] = [line for line in lines if line.startswith('KERBEROS_DISPOSAL_ABORT ')]
    metadata['cache_expiry'] = [line for line in lines if line.startswith('KERBEROS_CACHE_EXPIRY ')]
    metadata['peer_rejection'] = [line for line in lines if line.startswith('KERBEROS_PEER_REJECTION ')]
    assert all(len(metadata[key]) == 8 for key in ('profiles', 'contexts', 'audits', 'disposal_aborts', 'cache_expiry', 'peer_rejection'))
    assert len(metadata['gcm_audits']) == 4
    assert all('distinctMessageNonceReuses=0' in line for line in metadata['gcm_audits'])
    assert all('distinctMessageNonceReuses=0' in line for line in metadata['audits'])
    expected = {(str(size), str(borrowed).lower(), str(encrypted).lower())
                for size in (16, 32) for borrowed in (False, True) for encrypted in (False, True)}
    aborts = [dict(word.split('=', 1) for word in line.split()[1:]) for line in metadata['disposal_aborts']]
    assert {(entry['rawKeyBytes'], entry['borrowed'], entry['encrypt']) for entry in aborts} == expected
    assert all(entry['confirmedLogoffs'] == '1' and entry['timedOutLogoffs'] == '1'
               and entry['lateIgnored'] == 'true' and entry['injectedAfterDispose'] == 'true' for entry in aborts)
    expiry = [dict(word.split('=', 1) for word in line.split()[1:]) for line in metadata['cache_expiry']]
    assert {(entry['rawKeyBytes'], entry['borrowed'], entry['encrypt']) for entry in expiry} == expected
    assert all(entry['noCredential'] == 'true' and entry['setupRequests'] == '0'
               and entry['existingOpen'] == 'true' and entry['freshRetry'] == 'true' for entry in expiry)
    rejected = [dict(word.split('=', 1) for word in line.split()[1:]) for line in metadata['peer_rejection']]
    assert {(entry['rawKeyBytes'], entry['borrowed'], entry['encrypt']) for entry in rejected} == expected
    assert all(entry['status'] == 'STATUS_LOGON_FAILURE' and entry['setupRequests'] == '1'
               and entry['signed'] == 'true' and entry['oldOpenRejected'] == 'true'
               and entry['sessionRetired'] == 'true' and entry['borrowedHealthy'] == 'true'
               and entry['damagedNativeToken'] == 'true' and entry['freshSession'] == 'true'
               and entry['freshRetry'] == 'true' for entry in rejected)
    gcm = [dict(word.split('=', 1) for word in line.split()[1:]) for line in metadata['gcm_audits']]
    assert {entry['run'] for entry in gcm} == {
        'public-kerberos-' + size + '-' + borrowed + '-true'
        for size, borrowed, encrypted in expected if encrypted == 'true'}
    assert all(int(entry['verifiedTransforms']) >= 32 and int(entry['encryptedOperationalMessages']) >= 8
               and int(entry['encryptedLogoffFrames']) >= 4 for entry in gcm)
    contexts = [dict(word.split('=', 1) for word in line.split()[1:]) for line in metadata['contexts']]
    assert all(int(entry['established']) > 0 and entry['created'] == entry['disposed']
               and int(entry['created']) == int(entry['established']) + 2
               and entry['failedBeforeKey'] == '2' and entry['live'] == '0' for entry in contexts)
    seen = set()
    metadata['containers'] = []
    for line in metadata['profiles']:
        fields = dict(word.split('=', 1) for word in line.split()[1:])
        assert fields['image'] == image_id
        seen.add((fields['rawKeyBytes'], fields['borrowed'], fields['encrypt']))
        cid = fields['id']
        assert re.fullmatch('[0-9a-f]{64}', cid), cid
        assert not subprocess.check_output(['docker', 'ps', '-a', '-q', '--filter', 'id=' + cid], text=True).strip()
        metadata['containers'].append({'id': cid, 'removed': True})
    assert seen == expected, seen
    (output / report.name).write_bytes(report.read_bytes())
    metadata['result'] = 'PASS'
    print('8 public GMAC Kerberos cases passed; all eight owned domain containers removed.')
finally:
    (output / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
