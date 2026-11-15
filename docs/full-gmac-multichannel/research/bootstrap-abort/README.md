# Reserved-nonce bootstrap abort research

This detached native experiment tests cleanup after the peer has completed a
GMAC SMB 3.1.1 binding, while the client rejects or never receives the final
reply. It does not select or integrate a production multichannel design. The
production GMAC-binding guard remains in place.

The main session authenticates on a private bootstrap connection. The test
reserves that connection's next native MessageId for a possible original-key
LOGOFF and keeps the connection live and quiescent. On the caller's pooled
connection, an unrelated older session consumes the overlapping MessageId with
a real ECHO if needed. Thus binding requests under the original key start above
the reserved abort nonce. The observer verifies actual signatures, key domains,
native MessageIds and reuse independently. It derives the peer's provisional
bound-channel key only inside the observer to verify the final peer reply.

Two injected client-input faults cover a corrupted final signature and a
discarded final reply. In each case the peer actually completed binding; the
client does not publish the candidate channel. The test checks the original
session remains on its bootstrap connection, LOGOFF uses the reserved nonce,
the private transport closes, the older session/open and pooled connection
remain usable, and a new lease returns the same pooled connection. Fresh and
already-open caller profiles cover both one-ECHO padding and no-padding cases.

Eight positive cases pass with 360 independently verified signed inputs and no
observed distinct-message actual-key/nonce reuse. They checked 2,621,540 bytes
of file readback across the held-open and fresh-open paths. Two unsafe controls
omit the reservation and must fail specifically on original-key/nonce reuse.
The controls stop at that finding and are not counted as complete audits.

Four additional cases force the private bootstrap transport closed before
cleanup. Session close then raises `IOException`, does not allocate the reserved
abort MID or exchange LOGOFF, and still preserves the older session/open and
pooled caller connection. The observer requires zero abort requests/responses
for these cases rather than treating a missing LOGOFF as a failed audit.

This is conditional evidence for a narrow NTLM, Direct TCP, BC and Samba 4.23.10
path. A normal abort requires the bootstrap to remain live and quiescent until
LOGOFF; only the explicit pre-cleanup root-loss ordering above is covered.
LOGOFF failure, spontaneous root loss, close/authentication/publication races, arbitrary borrowed
channels, additional GSS rounds, cancellation, notifications, reauthentication,
unsigned MessageId exhaustion, resource/cost limits, and Windows/ONTAP behavior
remain open. It does not address the full actual-key lifetime or make G0 pass.

## Reproduction

The run used base `c25dcf2eacd59b1a298ca13626d307bbedb9fdf6` in a disposable
detached checkout. Apply `gmac-auxiliary-experiment.patch`, apply
`observer.patch` to the pinned concurrent observer, and copy this directory's
Java driver into `src/it/java/com/hierynomus/smbj/connection/`. The detached
main-source diff removes only the GMAC guard in `SMBSessionBuilder`; it is not
part of production. Executed source copies were byte-identical to the versioned
artifacts.

The opt-in runner profile is `--bootstrap-abort-research`; it expects the eight
positive profiles and both unsafe-control markers. Use the existing pinned
Samba fixture, Temurin 21, Gradle 8.13, the existing BC dependency and
`/tmp/smbj-full-gmac-test-limits.gradle`. Exact fixture owner, image, report,
source hashes and results are in [validation-bootstrap-abort.json](../../validation-bootstrap-abort.json).
