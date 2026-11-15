# Concurrent auxiliary-session construction — research only

This extends the [sequential experiment](../auxiliary-candidate.md) with
per-request original-key MID reservations. It does not close G0. The feature
branch retains its GMAC binding guard. The native run used a disposable detached
checkout with only that guard removed; production reservation code remained the
same.

## State and conditional argument

The main session is authenticated on a private bootstrap connection. Initial
authentication initializes a monotonic original-key high-water value from the
connection's next native MID. Each candidate authenticates an independent
auxiliary session before binding the main session.

For every original-key request, the connection allocates its lowest available
native MID under the existing allocation lock. A session-wide CAS accepts that
MID only when it is not below the high-water value, then advances the value past
the reserved MID. A collision consumes the native MID with a real unsigned,
session-0 ECHO outside the allocation lock, waits for its response and retries.
The collision probe consumes exactly one credit even when the deferred original
request needs a multi-credit range. No sequence value is assigned, rewound or
skipped. Reservations are never released, including after failure or partial
transmission.

The auxiliary session makes ECHO valid on an otherwise fresh candidate without
relying on portable sessionless ECHO behavior. The original channel uses the same
reservation path for signed application traffic and LOGOFF, so later bindings
cannot rewind the original-key nonce domain. After binding, ordinary candidate
traffic uses its derived channel key.

The observer independently authenticates messages with their actual key bytes
and compares actual-key/nonce domains using ephemeral keyed input fingerprints.
Raw keys, authentication tokens and raw SessionIds are not exported. It counts
binding requests and collision ECHOs and checks native MID/credit behavior.

This remains a conditional NTLM/direct-TCP/BC argument, not a complete key
lifetime proof. Per-request reservation removes fixed-slot overallocation but
does not bound the number of collision ECHOs when a fresh connection is far
behind the session high-water value. Kerberos/variable GSS rounds,
reauthentication, cancellation, notifications, independent-session key
reintroduction, bootstrap interruption, native exhaustion, resource limits and
independent Windows/target ONTAP behavior remain unqualified. Local tests cover
terminal-MID rejection, collision timeout/late reply and abort cleanup.

## Concurrent application traffic and faults

Three independent candidates authenticate and bind concurrently. Their first
original-key writes are gated after socket submission; the gate waits outside
the observer monitor. A 128 KiB file opened before those bindings completes a
full write/readback while the candidate writers are held. Eight more
write/readbacks and 256 ECHOs follow. The same open is checked after all binds,
including a fresh retry after an injected loss. Two original-channel ECHOs after
the first binding explicitly exercise application traffic under the original
key.

One fault closes a candidate after its complete first binding request is written.
Another submits only a 76-byte prefix and closes the socket. The observer retains
the complete signed write input for tag/nonce checking but labels it
`input=write-attempt`, not a complete wire frame. `preparedOnly` and partial
socket byte counts remain separate. No claim is made that a complete partial-fault
request reached the peer.

## Bootstrap abort

If the first operational binding fails, the bootstrap remains the main session's
only usable channel. Its native cursor can overlap the failed candidate's
original-key reservation. A normal original-channel LOGOFF would then reuse a
nonce already consumed by binding. The safe-abort cases invalidate the
unpublished session and forcibly close its transports without LOGOFF. The failed
reservation remains burned and no candidate becomes eligible. A separate control
confirms that omitting this rule produces the expected collision.

## Recorded results

The seven-case run passed on Samba 4.23.10 with zero failures, errors or skips.
Its XML timestamp is `2026-11-14T18:19:30.046Z`; test execution took 3.514
seconds. The separate `licenseIntegrationTest` task succeeded. Exact source
hashes, commands, fixture identity and cleanup are recorded in
[validation-per-request.json](validation-per-request.json).

| Case | Binding requests | Collision ECHOs | Verified signed inputs | Prepared only | Actual key domains | Operational signed messages |
|---|---:|---:|---:|---:|---:|---:|
| Concurrent, no loss | 8 | 23 | 621 | 0 | 9 | 592 |
| Concurrent, complete request lost, fresh retry | 9 | 28 | 623 | 0 | 10 | 592 |
| Concurrent, partial request lost, fresh retry | 9 | 30 | 623 | 1 | 10 | 592 |
| Bootstrap abort after complete request | 1 | 0 | 4 | 0 | 2 | 0 |
| Bootstrap abort after partial request | 1 | 0 | 3 | 1 | 2 | 0 |

All five positive cases reported zero distinct-message actual-key/nonce reuses,
for 1,874 independently verified signed inputs. Each application case finished
with four operational channels and 1,441,792 bytes of checked file readback.
Both unsafe controls failed specifically on distinct-message actual-key/nonce
reuse. Their traces stop at that expected finding and are not positive audits.

The preceding fixed-slot experiment consumed 96 ECHOs without a fault and 160 in
each fault case. Per-request reservation consumed 23, 28 and 30 respectively.
These controlled runs include gates and are not throughput measurements. The
inherited `replacements=3` report field labels post-anchor bindings, not three
operational channel-loss replacements.

The production guard remains intact. Public construction, auxiliary-session
lifecycle, bounded late-binding cost and the remaining matrix requirements are
still unresolved; these results do not complete G0 or any release gate.

## Reproduce

Use base `ec92a0b9b8f5e386afb80d1a6539ead84209aa04` in a disposable detached
checkout. Apply the recorded production reservation changes, remove only the
GMAC binding guard as shown by the archived executed `SMBSessionBuilder.java`,
and copy the two Java files from this directory to
`src/it/java/com/hierynomus/smbj/connection/`. Do not copy the sequential
observer alongside this variant.

The exact executed source, reports and checksums were archived under
`/tmp/smbj-gmac-per-request-results-5/`. Only the detached `SMBSessionBuilder`
guard differs from the feature worktree; the documentary and executed drivers
match byte for byte.

Use the task-owned Samba fixture and existing [GMAC/GCM profile](../smb-gmac-gcm.conf)
through the single-fixture runner:

```sh
SMBJ_GMAC_AUX_RESEARCH=true \
JAVA_HOME=/tmp/smb-relay-java21/opt/java/openjdk \
PATH=/tmp/smb-relay-java21/opt/java/openjdk/bin:$PATH \
python3 docs/full-gmac-multichannel/research/run-gmac-single-fixture.py \
  --per-request-research --output /tmp/smbj-gmac-per-request-results
```

The runner uses the existing Temurin 21 installation, Gradle 8.13 and recorded
test limits. Skipping the explicit research opt-in or failing to provide the
pinned fixture does not complete an acceptance gate.
