#!/bin/sh
set -eu
python3 /fixture/samba-command.py domain provision --targetdir=/state --realm=SMBJ.TEST --domain=SMBJ --host-name=server --server-role=dc --dns-backend=SAMBA_INTERNAL --backend-store=tdb --option='acl_xattr:security_acl_name=user.NTACL' --quiet
python3 /fixture/samba-command.py user create smbtest --configfile=/state/etc/smb.conf
cat >> /state/etc/smb.conf <<'CONF'
[global]
server min protocol = SMB3_11
server max protocol = SMB3_11
server multi channel support = yes
server signing = mandatory
server smb3 signing algorithms = AES-128-GMAC
server smb3 encryption algorithms = AES-128-GCM
smb encrypt = desired
ntlm auth = disabled
acl_xattr:security_acl_name = user.NTACL
acl_xattr:ignore system acls = yes
dns forwarder =
[share]
path = /shared
read only = no
guest ok = no
smb encrypt = desired
CONF
printf 'SMBJ_DOMAIN_READY\n'
exec /usr/sbin/samba --interactive --no-process-group --configfile=/state/etc/smb.conf
