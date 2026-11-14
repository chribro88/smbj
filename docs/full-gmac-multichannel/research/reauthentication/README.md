# Native reauthentication key selection — detached research

This is a bounded extension of the concurrent auxiliary-session experiment. It
is not a selected production construction and does not close G0. The feature
worktree retains its GMAC binding guard. A disposable checkout at
`54752747c8cb6885401c0351b4ea72368373f8f8` applied only the existing guard-only
research patch to production sources.

Three native cases pass against Samba 4.23.10 with SMB 3.1.1 and GMAC forced,
NTLM, Direct TCP, BC 1.86 and Java 21. The two positive cases use actual
`Session.send(request, connection)` and its connection-specific signing-key
selection. A research driver supplies fresh NTLM contexts, processes the GSS
rounds, verifies setup replies before accepting their credits, and preserves
the established Session. This is not a production reauthentication API.

| Case | Observation |
|---|---|
| Original channel | Two successful two-round reauthentications; 165 independently verified signed messages; 393231 bytes read back through the same open. |
| Auxiliary-bound channels | Two successful reauthentications on the first operational channel, a fresh binding, then one successful reauthentication on the new channel; 223 independently verified signed messages across five actual key domains; 524308 bytes read back through the same open, with authenticated READ/WRITE observed on both operational connections. |
| Original-key negative control | Reauthentication on a bound channel signed with the original session signing key receives `STATUS_ACCESS_DENIED`; a subsequent channel-key ECHO succeeds. The independent observer rejects the incorrect client tag under the expected channel-key domain. |

On the bound channels, requests, intermediate `STATUS_MORE_PROCESSING_REQUIRED`
replies and final successful replies use the existing channel signing key. The
reply tags also reject verification under the original signing key. Fresh NTLM
exports differ from the original session key; the driver deliberately retains
its original session/signing/cipher/application keys and preauthentication hash.
Live tags and subsequent I/O show continued peer acceptance of the original
active signing keys. Plaintext I/O does not qualify peer cipher-key retention.

The second binding starts at original-key MID 19 after exactly 16 real
auxiliary-key ECHOs. The first operational channel's native cursor has already
passed 19. Thus, for this observed channel-key behavior, reauthentication need
not advance the original-key reservation high-water to the operational cursor.
The two positive socket traces contain no distinct-message actual-key/nonce
reuse and consume the lowest native ranges with real credits. The negative
control stops its independent audit at the expected incorrect client tag; it is
not a complete positive nonce audit.

The observer is an adaptation of
`research/concurrent/GmacWireObserver.java` at
`7fce5f2b47df325d7a849ed09424c17ede568cb7`. The small `observer.patch` makes its
endpoint explicit, permits original-channel application traffic in that control,
and identifies non-binding setup exchanges before selecting their existing
channel keys. It still verifies socket bytes using independent default-JCE
GMAC and ephemeral keyed fingerprints. It consumes actual client key bytes;
it does not independently derive the KDF keys. No keys, authentication tokens or
SessionIds are exported in the sanitized record.

Each case owns a digest-pinned, labelled Samba container with 256 MiB memory,
one CPU, 64 MiB share tmpfs and a dynamic loopback-only port. Testcontainers
copies the config rather than binding a daemon-invisible host path. Passwords
are generated privately. Exact final source/report hashes, fixture IDs, cleanup
and sanitized observations are in [validation-reauthentication.json](../../validation-reauthentication.json).
The detached checkout is removed after archiving evidence.

## Reproduce

Create a fresh disposable checkout at the base revision above. Apply
`../gmac-auxiliary-experiment.patch` there. Copy the pinned concurrent observer
to `src/it/java/com/hierynomus/smbj/connection/GmacWireObserver.java`, then apply
`observer.patch` to that copied file (its diff paths are relative to that
directory). Copy `GmacReauthenticationIT.java` beside it. Do not copy the other
research drivers. In the checkout, select the existing Java 21 build JDK and run:

```sh
SMBJ_GMAC_AUX_RESEARCH=true \
SMBJ_REAUTH_CONFIG=/workspace/smbj-worktrees/full-gmac-multichannel/docs/full-gmac-multichannel/research/smb-gmac-gcm.conf \
JAVA_HOME=/tmp/smb-relay-java21/opt/java/openjdk \
PATH=/tmp/smb-relay-java21/opt/java/openjdk/bin:$PATH \
./gradlew --offline --no-daemon --max-workers=1 \
  '-Dorg.gradle.jvmargs=-Xmx192m -XX:ActiveProcessorCount=2' \
  --init-script /workspace/smbj-worktrees/full-gmac-multichannel/docs/full-gmac-multichannel/research/reauthentication/test-limits.gradle \
  integrationTest --tests '*GmacReauthenticationIT' -x buildSambaImage \
  licenseIntegrationTest
```

The supplied init script forces actual Test execution and limits JVMs to one fork,
384 MiB and two active processors. The final run used a byte-identical private copy.
The fixture image is
`dockurr/samba@sha256:2a0452a12b7a244a22f18d0f233101bb8d4952b5500ae263905e3b9dad3bf2ae`.
The Docker daemon, image and ordinary Gradle test dependencies must be available.
An infrastructure error or omitted research opt-in does not qualify a gate.

## Interpretation and limits

The [12 November v6 ksmbd discussion](https://lore-kernel.gnuweeb.org/linux-cifs/20261112154155.20255-1-mike.michalo@gmail.com/T/)
records a channel-key interpretation while noting conflicting specification
wording and no Windows validation. These experiments independently establish the
recorded Samba behavior; they do not resolve that wording for other peers.
The [client reauthentication rules](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/c4887c81-8340-4f0f-8264-cf90d841f838)
retain existing session key material.

The auxiliary construction still retires the public original connection, has
padding cost that grows with attempts, and lacks a complete authentication,
cleanup and actual-key lifetime proof. Kerberos, expiry-triggered recovery,
reauthentication failures/concurrency, encrypted reauthentication, async
transport, Java 8, Windows/ONTAP and sustained costs remain unqualified. The
original session's application API ownership is not repaired by this driver.
No production implementation or full-suite result changed in this milestone.
