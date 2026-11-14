import os, runpy, socket, sys
from pathlib import Path
args = sys.argv[1:]
secret = os.environ['SMBJ_DC_PASSWORD']
if args[:2] == ['domain', 'provision']:
    for namespace in ['uid', 'gid']:
        ranges = [list(map(int, line.split())) for line in Path('/proc/self/' + namespace + '_map').read_text().splitlines()]
        assert any(start <= 10000 and start + length >= 20000 for start, outer, length in ranges), 'Fixture ID range is outside mapped namespace'
    template = Path('/usr/share/samba/setup/idmap_init.ldif')
    data = template.read_text()
    assert data.count('lowerBound: 3000000') == 1 and data.count('upperBound: 4000000') == 1
    template.write_text(data.replace('lowerBound: 3000000', 'lowerBound: 10000').replace('upperBound: 4000000', 'upperBound: 20000'))
    import logging
    from samba.auth import system_session
    from samba.provision import provision
    provision(logging.getLogger('smbj-fixture'), system_session(), targetdir='/state',
              realm='SMBJ.TEST', domain='SMBJ', hostname='server',
              hostip=socket.gethostbyname(socket.gethostname()),
              serverrole='active directory domain controller', dns_backend='SAMBA_INTERNAL',
              adminpass=secret, backend_store='tdb',
              skip_sysvolacl=True)
    raise SystemExit(0)
elif args[:2] == ['user', 'create']:
    args += [secret]
else:
    raise SystemExit('Unsupported fixture action')
sys.argv = ['samba-tool'] + args
runpy.run_path('/usr/bin/samba-tool', run_name='__main__')
