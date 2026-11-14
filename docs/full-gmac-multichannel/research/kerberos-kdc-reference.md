# Real Kerberos SPNEGO validation

`KerberosSpnegoIT` uses SMBJ's unmodified `SpnegoAuthenticator`, the JDK's real
SPNEGO initiator/acceptor and an isolated MIT Kerberos KDC. No GSS object is
mocked. The three cases pass for each of AES-128 and AES-256 Kerberos session
keys: six passing cases, with no failures or skips. Exact source/report hashes
and versions are in [validation-kerberos-kdc.json](../validation-kerberos-kdc.json).

The positive cases use implicit Subject credentials or an explicit GSS
credential. Each exchanges two fresh contexts using the same authenticated
Subject. The peer checks the client identity, `cifs/server.smbj.test` target,
mutual authentication and absence of delegation. Key export occurs after the
final peer token, matches the peer's current context key normalized to sixteen
bytes, and differs between contexts. A missing CIFS principal fails against the
real KDC. Assertions and saved reports do not print keys or tokens.

This closes the real ticket/SPN/key-export gap in the earlier controlled-GSS
check. It does **not** test an SMB server, native transport, initial/binding
SESSION_SETUP interoperability, selection of a different channel IP,
reauthentication, Windows/AD, or GMAC nonce safety. The separate
[binding regression](../validation-kerberos-binding.json) still supplies the
controlled builder/KDF/credit/publication checks. G0 and AUTH-02 remain open.

## Reproduction on Debian 12 amd64

The tested tools are MIT Kerberos `1.20.1-2+deb12u5`; native Kerberos libraries
already installed on the host have that same version. This fixture extracts
packages into `/tmp`: it installs no packages or services and changes no host
Kerberos configuration. From a new task-owned package directory:

```sh
apt-get download \
  krb5-kdc=1.20.1-2+deb12u5 krb5-admin-server=1.20.1-2+deb12u5 \
  libkdb5-10=1.20.1-2+deb12u5 libkadm5srv-mit12=1.20.1-2+deb12u5 \
  libkadm5clnt-mit12=1.20.1-2+deb12u5 libgssrpc4=1.20.1-2+deb12u5 \
  libverto1=0.3.1-1 libverto-libev1=0.3.1-1 libev4=1:4.33-1 libss2=1.47.0-2+b2
for package in ./*.deb; do dpkg-deb -x "$package" ../root; done
```

Check memory and existing build processes before each run. From the feature
worktree, with `JAVA_HOME` and `PATH` pointing to the existing JDK 21, run:

```sh
python3 docs/full-gmac-multichannel/research/run-kerberos-fixture.py \
  --tools-root /tmp/smbj-kerberos-kdc/root --key-bytes 16 \
  --output /tmp/smbj-kerberos-kdc/new-aes128
python3 docs/full-gmac-multichannel/research/run-kerberos-fixture.py \
  --tools-root /tmp/smbj-kerberos-kdc/root --key-bytes 32 \
  --output /tmp/smbj-kerberos-kdc/new-aes256
```

Each output directory must be new. Runs are sequential and use offline Gradle,
192 MiB build/test heaps, one test fork, two active processors, the existing
integration source set and `licenseIntegrationTest`. The unrelated Samba image
build is excluded. The fixture creates random-key principals and private keytabs
in a mode-0700 temporary directory, listens only on a high loopback port, disables
application logging, then terminates its KDC and removes that directory on exit.
Only the build log and XML report are retained. It never uses a host ticket cache.
The opt-in environment guard keeps this test out of ordinary fixture-free runs.

The fixture follows MIT's [KDC listener configuration](https://web.mit.edu/~kerberos/krb5-1.20/doc/admin/conf_files/kdc_conf.html)
and the JDK's [keytab login options](https://docs.oracle.com/javase/8/docs/jre/api/security/jaas/spec/com/sun/security/auth/module/Krb5LoginModule.html).
No MIT or Linux implementation source was copied into SMBJ.

The later [native SMB/Kerberos research](kerberos-native/README.md) now supplies
six passing real Samba AD DC cases with actual GMAC initial authentication,
binding, reauthentication and same-open I/O, for AES-128/AES-256 GSS contexts.
Its bounded construction and fixture limits remain explicit; this earlier
MIT-KDC-only record and its original evidence boundary are unchanged.
