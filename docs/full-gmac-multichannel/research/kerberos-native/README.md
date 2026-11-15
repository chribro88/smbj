# Native Kerberos SMB/GMAC research

**Historical detached-source record.** The current feature branch now runs this
fixture through production public APIs. Use
`python3 docs/full-gmac-multichannel/research/run-gmac-kerberos-fixture.py --output /tmp/<fresh-directory>`
from the feature worktree with the existing Java 21 build JDK selected. The four
public cases and independent wire audit are recorded in
[validation-public-kerberos.json](../../validation-public-kerberos.json).
The guard and API limitations described below belong to the older source state.

Six native cases pass on Samba AD DC 4.23.10: original channel, auxiliary-bound
channels and an original-signing-key negative control, each with actual
AES-128 or AES-256 Kerberos GSS context keys. SMB signing is **AES-128-GMAC**
in both profiles. This is a detached research extension of the bounded auxiliary
construction, not a selected production implementation. G0 stays open and the
feature worktree retains its GMAC binding guard.

The unmodified SMBJ SPNEGO authenticator uses a real JDK Subject and the domain's
real KDC. Password login disables the host ticket cache. Only SPNEGO is configured
and the server disables NTLM. Extended GSS inquiry verifies 16-byte or 32-byte
keys for every established context; the builder uses their normalized signing
material. Contexts and login credentials are explicitly released by the test.

| Per Kerberos profile | Native result |
|---|---|
| Original channel | Two successful one-round reauthentications; 161 independently checked signed messages; 393231 bytes read back through the same open. |
| Bound channels | Two reauthentications on the first operational channel; fresh binding at MID 18 after 16 auxiliary-key ECHOs; one reauthentication on the new channel; 213 independently checked signed messages across five actual key domains; 524308 readback bytes, with authenticated READ/WRITE on both operational connections. |
| Wrong original key | Bound-channel reauthentication signed with the original key gets `STATUS_ACCESS_DENIED`; channel-key ECHO still succeeds. The independent oracle rejects the incorrect client tag. |

Together the final runs complete ten reauthentications and verify 748 signed
messages in four positive traces, with no distinct-message actual-key/nonce
reuse observed. All six cases pass without failures, errors or skips. These are
one-round Kerberos exchanges; the earlier NTLM experiment supplies the separate
two-round observation. Initial authentication and actual channel binding run
through SMBJ's real builders. Research reauthentication uses real `Session.send`
with a manual fresh-GSS loop and explicit authenticated setup-credit acceptance.

The same normalized original session keys and preauthentication context are
retained across reauthentication. The live peer continues accepting the active
channel keys. A later original-key binding remains below the prior operational
MID cursor. This supports the bounded construction's key-domain separation for
this peer. It does not repair the closed-bootstrap `Session.getConnection()` API
or establish a complete lifetime/cost argument.

## Isolated domain fixture

The test-only image adds `samba-dc=4.23.10-r0` to the existing immutable Samba
base. The recorded local image is
`sha256:9501aa40203bf661632ee44df2bf2a2b1642dd62c6a77f062e9780dc8a23ade9`.
The build inputs and exact installed packages are retained beside this file.
Each test asserts the supplied image ID, provisions a fresh domain, and creates
its disposable user with private random credentials. Credentials never appear
in OS command arguments or exported reports.

The Docker daemon is rootless. The shipped ID allocation template starts at
3000000, outside the mapped IDs used here; the fixture asserts its available
UID/GID mappings and configures 10000–20000. Samba's provisioning API skips
SYSVOL Group Policy ACL setup. The synthetic share uses `user.NTACL` and ignores
system ACL mapping. These are fixture filesystem adaptations, with no signing,
GSS or protocol implementation patch. This does not qualify SYSVOL, Group Policy
or Windows ACL behavior. The API's default 2008 R2 domain functional level is used.

Each domain is limited to one CPU and 768 MiB, with 256 MiB state and 64 MiB share
tmpfs. Only SMB and Kerberos TCP ports are mapped, dynamically on loopback.
A completion marker and listener checks precede ticket login. Early diagnostic
runs exposed provisioning failures and premature port readiness; those runs are
infrastructure failures, not protocol results. Final native results use the
working source recorded in [validation-kerberos-native.json](../../validation-kerberos-native.json).
All owned domain containers and private JVM Kerberos configurations are removed.
The derived image is retained locally for reproducibility and is not published.

## Reproduce

Use a fresh detached checkout at
`e0970238331b3d53bdfcc042e6c3f9950feebc84`. Apply only the existing
`../gmac-auxiliary-experiment.patch` to its production sources. Copy the concurrent
observer from `../concurrent/GmacWireObserver.java` into
`src/it/java/com/hierynomus/smbj/connection/`. Apply the preceding
`../reauthentication/observer.patch`, then this directory's
`observer-endpoint.patch`, with Git's
`--directory=src/it/java/com/hierynomus/smbj/connection` option. Copy
`GmacKerberosNativeIT.java` beside the adapted observer. The endpoint patch keeps
the logical CIFS target `server.smbj.test` while connecting its socket to the
owned loopback port; no host DNS or Kerberos configuration is changed.

Select a fresh private output directory and the existing JDK 21. Build the
fixture image, or reuse the exact recorded local image:

```sh
export SMBJ_AD_IMAGE=smbj/kerberos-dc:e097023
DOCKER_BUILDKIT=0 docker build --rm --memory 768m --cpu-quota 100000 \
  --tag "$SMBJ_AD_IMAGE" /workspace/smbj-worktrees/full-gmac-multichannel/docs/full-gmac-multichannel/research/kerberos-native
export SMBJ_AD_IMAGE_ID=$(docker image inspect --format '{{.Id}}' "$SMBJ_AD_IMAGE")
export SMBJ_AD_FIXTURE=/workspace/smbj-worktrees/full-gmac-multichannel/docs/full-gmac-multichannel/research/kerberos-native
export SMBJ_AD_LOGGING="$SMBJ_AD_FIXTURE/logging-off.xml"
export SMBJ_GMAC_AUX_RESEARCH=true
export SMBJ_AD_OUTPUT=/tmp/smbj-native-kerberos-new-aes128
mkdir -m 700 "$SMBJ_AD_OUTPUT"
```

From the detached checkout run, with `JAVA_HOME`/`PATH` on the existing JDK 21:

```sh
SMBJ_KRB_KEY_BYTES=16 ./gradlew --offline --no-daemon --max-workers=1 \
  '-Dorg.gradle.jvmargs=-Xmx192m -XX:ActiveProcessorCount=2' \
  --init-script "$SMBJ_AD_FIXTURE/test-limits.gradle" \
  integrationTest --tests '*GmacKerberosNativeIT' -x buildSambaImage \
  licenseIntegrationTest
```

Archive the XML report before the next run. Use another fresh output directory
and `SMBJ_KRB_KEY_BYTES=32` for AES-256 Kerberos. The init script forces actual
execution, bounds the Test JVM, and disables authentication logging. Rebuilding
may resolve different transitive packages and produce a new image ID; record
that image and package bill as a new fixture qualification.

The observer reuses the pinned concurrent source and reauthentication adaptation.
It checks actual socket bytes with default-JCE GMAC and actual client key bytes,
not an independent KDF derivation. It exports only metadata and ephemeral keyed
fingerprints, with no keys, authentication tokens or SessionIds. Negative-control
audits stop at the expected incorrect tag and are not complete positive traces.

Windows/ONTAP, alternate channel IP/SPN routing, explicit native GSS credentials,
Kerberos expiry/failures/concurrency, encrypted traffic, async transport, Java 8,
sustained operation, public API ownership and complete nonce lifetimes remain
unqualified. No production source, dependency or full-suite result changed.
The [Alpine package](https://pkgs.alpinelinux.org/package/edge/main/x86_64/samba-dc)
and [Samba ACL module documentation](https://www.samba.org/samba/docs/current/man-html/vfs_acl_xattr.8.html)
identify the fixture components and ACL configuration semantics.
