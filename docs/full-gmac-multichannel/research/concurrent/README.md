# Concurrent auxiliary-session construction — research only

This extends the [sequential experiment](../auxiliary-candidate.md), with a
different reservation policy. It is not selected for production and does not
close G0. The feature branch retains its GMAC binding guard. Only a disposable
detached checkout removes that guard with the previously recorded
[research patch](../gmac-auxiliary-experiment.patch).

The original sequential sources and evidence remain unchanged. This directory
contains a separate driver and an adapted copy of its independent wire observer.

## State and conditional argument

The main session is authenticated on a private bootstrap connection. Its next
native MID establishes a conservative original-key prefix that will never be
allocated to a binding. Before application traffic, a second connection acquires
an auxiliary session, binds the main session and becomes operational. The
bootstrap connection is then forcibly closed without main-session LOGOFF.

Each later private candidate authenticates its own auxiliary session. A CAS on
one shared high-water value reserves a disjoint 16-MID interval, starting no
lower than the candidate's native cursor. Real auxiliary-key ECHOs consume every
preceding native MID and receive actual credits. Nothing assigns, skips or
rewinds the native sequence window. The cursor is read only before publication.

Every interval stays burned, even after success. The driver does not reclaim a
tail from a cursor that application traffic could already advance. The observer
instead checks the MID of each binding input against that candidate's recorded
interval. The native builder's 16-exchange bound supplies the reservation size
for this bounded experiment. All observed requests must consume the lowest
native sequence range and obey observed credit grants.

After binding, ordinary traffic uses the actual operational key. The experiment
checks that auxiliary and operational keys differ from the original key and
independently authenticates messages under their actual key bytes. Under these
tested conditions, original-key binding inputs occupy disjoint ranges, including
failed and partially transmitted attempts. The coordinator keeps one high-water
value; diagnostic counters and the bounded observer are separate research state.

This remains a conditional NTLM argument, not a complete actual-key lifetime
proof. In particular, it does not qualify all GSS rounds, cancellation,
notifications, reauthentication, independent-session key reintroduction,
bootstrap interruption at every boundary, or unsigned-space exhaustion.

## Concurrent application traffic and faults

Three independent candidates authenticate and bind concurrently. Their first
original-key writes are gated after socket submission. The gate waits outside
the observer monitor. A 128 KiB file, opened before those bindings, must complete
a full write/readback while the candidate writers are held. Eight more
write/readbacks and 256 ECHOs run after releasing the gates. The same open is
checked again after all binds, including a fresh retry after an injected loss.

One fault closes a candidate after its complete first binding request is written.
Another submits only a 76-byte prefix of that request and closes the socket. For
the latter, the observer retains the complete signed *write input* for independent
tag and nonce checking, but labels it `input=write-attempt`, not a complete wire
frame. `preparedOnly` and partial socket byte counts remain separate in reports.
No claim is made that a full request reached the peer in that case.

The observer still checks the entire signed application stream and compares
actual-key/nonce domains with ephemeral keyed input fingerprints. Raw keys,
authentication tokens and raw SessionIds are not exported. An ordinary unsafe
binding control must fail specifically on distinct-message actual-key/nonce reuse.
These controlled gates establish functional overlap; elapsed times include them
and are not throughput measurements.

## Bootstrap abort is a separate original-key use

If the first operational binding fails, the bootstrap connection is still the
main session's only usable channel. Its native cursor can overlap the failed
candidate's original-key reservation. A normal `Session.close()` sends LOGOFF
under that original key and can therefore reuse a nonce already consumed by the
binding. The experiment includes a negative control for this cleanup path.

The safe-abort cases invalidate the unpublished session and forcibly close its
transports without LOGOFF. The original-key interval remains burned, and no
candidate becomes eligible. This is an obligation of a future bootstrap
implementation, not a change to ordinary published-session LOGOFF behavior.

## Cost and remaining selection obligations

For the tested two-request NTLM exchanges, each auxiliary session leaves its
private connection at MID 3. With full 16-slot reservations, `N` attempts require
`8 * N * (N - 1)` padding ECHOs, including failed reserved attempts. Four successful
bindings require 96 padding ECHOs, versus 12 in the sequential tail-releasing
experiment. A failed attempt followed by a fresh retry requires five reservations
and 160 ECHOs. This deliberately trades padding cost for simple concurrent state;
it is not a constant-cost wire construction.

The driver limits padding to 256 per candidate and exercises at most five
reservations. It is not a production unsigned-MID allocator. Auxiliary GSS key
availability/freshness, public API ownership (`Session.getConnection()` still
returns the closed bootstrap connection), all cleanup and key-retention
boundaries, Kerberos, reauthentication and Windows/target ONTAP compatibility
remain unresolved. Authentication-driven resource limits and sustained costs
also need qualification before selecting this mechanism.

## Recorded results

The final seven-case run on 14 November 2026 (Sydney) passed with zero failures,
errors or skips. Its XML timestamp is `2026-11-13T23:55:02.620Z`; test execution
took 17.72 seconds. The separate `licenseIntegrationTest` task succeeded with
state `UP-TO-DATE`. Exact source hashes, commands, fixture ownership and cleanup
are recorded in [validation-auxiliary-concurrent.json](../../validation-auxiliary-concurrent.json).
The [sanitized observation](observation.json) retains only protocol metadata and
ephemeral keyed equality fingerprints.

| Case | Reservations | Padding ECHOs | Verified signed inputs | Prepared only | Actual key domains | Operational signed messages |
|---|---:|---:|---:|---:|---:|---:|
| Concurrent, no loss | 4 | 96 | 809 | 0 | 9 | 592 |
| Concurrent, complete request lost, fresh retry | 5 | 160 | 939 | 0 | 10 | 592 |
| Concurrent, partial request lost, fresh retry | 5 | 160 | 939 | 1 | 10 | 592 |
| Bootstrap abort after complete request | 1 | 0 | 4 | 0 | 2 | 0 |
| Bootstrap abort after partial request | 1 | 0 | 3 | 1 | 2 | 0 |

All five positive cases reported zero distinct-message actual-key/nonce reuses.
Each concurrent application case finished with four operational channels and
1,441,792 bytes of checked file readback, including 131,072 bytes while all three
candidate writers were gated. The two remaining cases are negative controls:
ordinary unsafe binding and native bootstrap LOGOFF after a partial binding
both failed specifically on distinct-message actual-key/nonce reuse, as expected.
Their exported traces stop at that finding and are not complete positive audits.

The observer defers the original-connection application-traffic policy assertion
until after its nonce checks. This preserves the nonce finding if a loopback
LOGOFF response is recorded before its client write. The inherited report field
`replacements=3` labels the three post-anchor bindings; it does not establish
three operational channel-loss replacements in this experiment.

The production source tree and GMAC binding guard are unchanged. These results
do not qualify the remaining lifetime, API, authentication or performance gates.

## Reproduce

Use base `9e11a7aaf9f1e8d3edeeaa19a5fcee2e8249c35b` in a disposable detached checkout.
Apply only `../gmac-auxiliary-experiment.patch` there. Copy the two Java files from
this directory to `src/it/java/com/hierynomus/smbj/connection/` in that checkout.
Do not copy the sequential observer alongside this variant.

The task-owned Samba 4.23.10 fixture uses the image digest and bounded resources
recorded in [validation-auxiliary-concurrent.json](../../validation-auxiliary-concurrent.json),
loopback port 36535 and the existing [GMAC/GCM profile](../smb-gmac-gcm.conf).
The sources contain only the disposable fixture identity. Use the existing
Temurin 21 installation, Gradle 8.13 and the recorded test-limit init script:

```sh
SMBJ_GMAC_AUX_RESEARCH=true ./gradlew --offline --no-daemon --max-workers=1 \
  '-Dorg.gradle.jvmargs=-Xmx192m -XX:ActiveProcessorCount=2' \
  --init-script /tmp/smbj-full-gmac-test-limits.gradle \
  integrationTest -x buildSambaImage --tests '*GmacConcurrentBootstrapIT' \
  licenseIntegrationTest
```

Skipping the explicit research opt-in or failing to provide the pinned fixture
does not complete any acceptance gate. Remove only the exact task-owned fixture
and detached checkout after archiving their source/report evidence.
