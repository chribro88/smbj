# Full GMAC multichannel implementation status

The requested full feature is **incomplete**. The completion contract in
[plan.md](plan.md) remains unchanged. G0 is open: this branch does not yet have a
protocol-compliant, independently verified binding key/nonce uniqueness mechanism.
The inherited GMAC-binding rejection remains containment and does not satisfy G0.
An independent live Go/Samba trace now confirms the ordinary legitimate-binding
collision in both directions; see [research evidence](research/README.md).

A bounded auxiliary-session candidate now passes four independently observed
bootstrap/replacement cases and an unsafe-flow negative control. It is isolated
research, not a selected production construction; see
[validation-auxiliary.json](validation-auxiliary.json) and
[its design limits](research/auxiliary-candidate.md).

The separate concurrent extension passes seven research cases: three
application/fault cases, two bootstrap-abort cases and two unsafe-flow controls.
It uses one atomic high-water reservation value without holding a global lock
across network I/O. Complete and partial first-binding losses retain their full
reservations; an open file survives concurrent binding and a fresh retry. A
negative control also demonstrates why an unpublished bootstrap abort must
force-close without original-key LOGOFF. This remains an unselected bounded
NTLM/direct-TCP/BC construction with quadratic padding cost; see
[validation-auxiliary-concurrent.json](validation-auxiliary-concurrent.json) and
[the concurrent record](research/concurrent/README.md).

## Inputs and history

- Branch: `feature/full-gmac-multichannel`.
- Worktree: `/workspace/smbj-worktrees/full-gmac-multichannel`.
- Existing feature base: `3ac158f017e416b9ae2b679d9a604b473b9956f2`.
- Upstream baseline: `1c5b9345df2898b8d57cf34d50ae599cab07b2b8`.
- Original feature implementation: `c2c8994` (ancestor of the selected base).
- Production compilation target: Java 8 (`compileJava.options.release = 8`).
- Ordinary build/test runtime: the existing Temurin 21 installation at
  `/tmp/smb-relay-java21/opt/java/openjdk`; Gradle 8.13; Bouncy Castle 1.86.
- The optional compatibility profile also executes on Temurin 8u512; its Gradle
  process/compiler remain on Java 21 and compile the isolated tests with release 8.
- Input checksums: [input-sha256.txt](input-sha256.txt).
- Resolved production graph: [runtime-dependencies.txt](runtime-dependencies.txt).

Neither upstream PR head `0de6366ac201701be5e4a0aa74a5750dcff36281` (#907) nor
`3352e2b530bbc6c000781c708d499170c94d16a9` (#910) was an ancestor of the selected
feature base. The reviewed adaptations were reused, with cherry-pick provenance:

| Existing reviewed commit | Commit on this feature | Change |
|---|---|---|
| `074983f` | `03e5655` | Failed promise futures report done (#907) |
| `da1367d` | `b4fc651` | Terminal connection/request/credit/socket lifecycle (#910) |
| `e387115` | `c934aa4` | Combined-feature race regressions and cancellation publication checks |

The later `f74ba4c` change was already covered by the selected feature's
`isClosed()` checks. Its transport liveness check was kept outside the session
scheduler lock. The admission-test merge retained the selected feature's richer
signer-observation fixture.

## Implemented foundations

- Ordinary plaintext responses use the matching request's SessionId for signing
  policy and channel-key selection. A changed response SessionId cannot bypass
  required signing or substitute another session's key. Unknown nonzero request
  sessions are discarded before granting credits or completing requests. Signed
  error replies follow the same request ownership; initial/binding authentication,
  notifications and permitted unsigned interim replies retain their phase handling.
- Initial authentication verifies the final wire response with the newly derived
  signing key before establishing or publishing the session. Session keys follow
  the protocol's 16-byte truncation/right-padding rule. Missing keys, invalid or
  missing required signatures, wrong roles and tampered padding fail the attempt.
  The configured provider remains in use; ordinary optional signing or required
  data encryption does not bypass the final authentication check.
- SESSION_SETUP credits are deferred to the authentication builder. Initial
  bootstrap challenges retain their permitted unsigned behavior; binding
  continuations, finals and signed errors accept credits only after verification
  with their phase's key. An unsigned binding error does not replenish credits.
  A response with a mismatched command cannot complete an outstanding request or
  bypass the deferred-credit path. SMB1-to-SMB2 negotiation remains supported.
- Signing authenticates stable serialized packet segments, including compound
  member padding, with header-relative offsets at nonzero buffer positions.
  Receive verification enforces the server role, signed flag and message extent,
  preserves received bytes, and compares tags in constant time. GMAC retains the
  configured SMBJ AEAD provider and validates its 128-bit signing key input.
- Per-connection sequence allocation rejects unsigned MessageId exhaustion before
  wrap or the reserved notification MID, while allowing the signed-long boundary.
  Credit charges are bounded before range allocation. Signing/serialization
  failures settle registered requests and retire only the failed channel.
- Request cancellation completes its local future and wakes existing waiters.
  Cancellation/completion races leave one consistent terminal result.
- Request cancellation atomically captures synchronous/asynchronous identity and
  claims one attempt, including AsyncId zero. Failed cancellation cannot re-sign
  changed bytes under the same CANCEL nonce. Cancellation callbacks execute
  outside the future's internal lock.
- Signed lease notifications authenticate before dispatch. Lease notifications
  with random MIDs cannot complete numerically matching requests or grant credits.
  Permitted unsigned lease notifications remain supported. Compound traversal
  follows validated member boundaries even when a member is discarded.
- Reviewed lifecycle prerequisites now fail outstanding requests and credit
  waiters, abort a real blocked socket write, and reject late-created sockets.
- Additional lifecycle work makes concurrent Connection closes share physical
  cleanup completion/failure, handles reentrant shutdown without waiting on
  itself, configures direct-transport candidates before publication, and closes
  candidates on configuration failure.
- Async transport shutdown rejects late connect publication, clears queued frames
  after failure and avoids retrying ambiguous failed writes. Async reader failures
  reach the Connection owner once; intentional shutdown suppresses spurious read
  failures. Failed async connection attempts close their candidate channel.

The fixed SMB LOGOFF vector comes from smb-rs revision
`f4524d032c8951cc288e1c8231ad68588583abda`. See
[vector notices](../gmac-test-vector-notices.md) for retained notices. The existing
SMBJ implementations and supplied skeleton informed the integration; no new
cryptographic dependency or hand-written AES/GHASH implementation was added.

## Bounded asynchronous write ownership

`SMB2Writer` reads the caller's provider on the calling thread, with backpressure.
No provider reads occur after `writeAsync` returns; callers can reuse their input
buffers. A worker retains each chunk until its acknowledgement permits advancing
or submitting only the remaining tail. Counts are checked against the actual
credit-limited submitted extent, not the larger retained snapshot. Status errors,
zero/negative/oversized counts and offset overflow fail truthfully.

Each session admits four active write workers and 64 queued operations. A queued
producer waits for its worker before copying input. Each active operation retains
at most 4 MiB of chunk data and at most 64 in-flight requests. This bounds the
owned chunk cache to 16 MiB per session; it is not a bound on caller-owned data,
transport buffers or all protocol request state. Cancellation churn and sustained
transport-queue memory remain operational acceptance work.

Normal File close drains its accepted async writes before sending CLOSE. No-wait
close cancels them, preventing later tail submissions. Failures still release the
remote handle. Session shutdown stops admission, interrupts active workers and
settles queued futures. Losing one channel leaves the surviving session worker
pool available; losing the last channel stops it.

## Executed validation

| Run | Actual result | Scope |
|---|---|---|
| Signing/cancellation/notifications | PASS: 31 tests | Both providers; fixed vector; malformed extents; compound padding; concurrent provider state; cancellation snapshot/failure; actual Connection notification chain |
| Integrated prerequisites | PASS: 99 tests | Lifecycle, real blocked socket write, late SocketFactory, Connection publication, admission (read/write/transact), ownership and signing foundations |
| Initial additional lifecycle run | PASS: 37 tests | Both transports, async read/write failure, concurrent close, direct candidate configuration |
| Exhaustion/provider-failure follow-up | PASS: 55 focused tests | Unsigned boundary/wrap; concurrent exhaustion; bounded credit charge; invalid provider tags; request cleanup and healthy-channel continuation |
| `clean check` milestone | PASS: 716 tests, zero failures/skips | Full unit suite, Java 8 release compilation, license checks and JaCoCo report; integration tests remain separate |
| Combined async `check` milestone | PASS: 753 tests, zero failures/skips | Full unit suite, including 21 async writer cases, worker limits, source ownership, actual submitted extents, File close ordering and cancellation races |
| Native async compatibility matrix | PASS: 8 tests, zero failures/skips | Both transports; lightweight BC and explicitly configured JCE/BC; encryption on/off; full live readback beyond the pipeline window |
| Authentication `check` milestone | PASS: 778 tests, zero failures/skips | Full unit suite, license checks and JaCoCo; includes 22 initial-authentication and 28 binding-response cases, phase-specific credit acceptance and mismatched-command rejection |
| Authentication live compatibility repeat | PASS: 8 tests, zero failures/skips | Actual SMB 3.1.1 initial authentication and full 8 MiB + 10 byte readback; both transports and BC/JCE-with-BC; CMAC and optional/required CCM encryption |
| Modern forced-GMAC single-session matrix | PASS: 16 tests, zero failures/skips | Samba 4.23.10; NTLM; both transports; BC/default JCE; GMAC with GCM encryption off/on; write-through off/on; exact readback and unsafe-binding containment |
| Receive-policy `check` milestone | PASS: 798 tests, zero failures/skips | Full unit suite, license checks and JaCoCo; 19 request-session response regressions; includes the concurrent local bound-channel SESSION_SETUP key-selection patch and its one test |
| Encrypted receive follow-up | PASS: 39 focused cases and 16 live single-session cases; full check 817/818 | All new receive cases pass; the existing above-2-GiB async writer test repeatedly exceeded its unchanged 30-second deadline; diagnostic logging/chunk experiments did not resolve it and were restored |
| Shared encryption nonce ownership | PASS: 20 new cases; 63 connected cases | Five supported cipher/provider profiles; native Session.send with mocked Connections; concurrent sends, replacement, retained-key reinstallation, provider failure and atomic exhaustion; independent transform tag/plaintext checks |
| SPNEGO binding key ownership | PASS: 22 new cases; 112 connected cases | Actual SPNEGO adapter with controlled GSS contexts; BC and JCE/BC; fresh final-token key export, 7/16/32-byte normalization, rejection of retained session/previous-binding KDF inputs and missing/failed key export; established keys preserved; native SMB Kerberos and GMAC binding remain unqualified |
| Real Kerberos SPNEGO | PASS: 6 integration cases, zero failures/skips | Isolated MIT KDC and actual JDK GSS; AES-128/AES-256 keys; implicit Subject/explicit GSS credentials; CIFS target and client identity; mutual authentication; fresh context exports; missing-SPN rejection; no SMB-server binding or GMAC qualification |
| Ready WRITE response scheduling | PASS: 28 connected tests; clean check 861/861; 8 native async cases | Latch regression fails before the five-line fix and passes after it; completed responses drain before an empty-input wait; unfinished-response pipelining and memory bounds retained; above-2-GiB case passes its unchanged deadline; live CMAC/CCM full readback on both transports/providers |
| Late WRITE response wakeup | PASS: 15 new cases; 51 connected; clean check 876/876; 8 legacy async + 16 GMAC async single-session cases | Request completion wakes the input monitor after publication; late success/error/cancel handled without native polling; opaque Future fallback retained; real GMAC/GCM async overwrite and changed-byte readback on both transports/providers; full multichannel remains unqualified |
| Java 8 runtime compatibility | PASS: 40 cases on 8u512; 16 default Java 21 native regression cases | 24 unchanged local cases plus 16 forced-GMAC/GCM async profiles with an odd-length payload; actual test JVM recorded; same production JAR in both runs; all 511 production classes have Java 8 bytecode; isolated test tooling only; full feature remains incomplete |
| Bounded auxiliary-session research | PASS: 5 tests, zero failures/skips | Detached checkout only; direct TCP, BC, NTLM, Samba 4.23.10; 0/3/7 replacements, lost-binding reservation, independent GMAC/MID verification and unsafe-flow negative control; G0 remains open |
| Concurrent auxiliary-session research | PASS: 7 tests, zero failures/skips | Detached checkout only; direct TCP, BC, NTLM, Samba 4.23.10; four operational channels, concurrent held-open I/O, complete/partial binding loss and fresh retry, safe bootstrap abort and two nonce-reuse controls; G0 remains open |
| Independent legitimate-binding observation | NONCE REUSE CONFIRMED | Pinned Go donor + Samba 4.23.10: two successful bindings; 17 independently verified signed messages across three actual key domains; two distinct-message original-key/nonce reuses |

The modern native source is `0be7f6f`; its production and unit-test trees remain
identical to the 778-test authentication milestone. The independent observer and
sanitized trace were committed in `5fe1c32`. See
[validation-modern-gmac.json](validation-modern-gmac.json) for exact revisions,
profiles, resource limits, commands and checksums. The observer is outside SMBJ's
guarded production path and does not qualify unsafe bindings as supported.

The preceding authentication unit source revision is `0357c30bf743ee311d18aa32530bc08fd14bb0e3`;
the live source revision is `97841a15d169476ce310c04ab22dbfcebb169790`. Their
production, unit-test and build configuration trees are identical. The latter
adds the negotiated dialect to sanitized live metadata. Exact reports, checksums,
profiles and remaining gates are in [validation-authentication.json](validation-authentication.json).
The initial full run exposed obsolete unsigned/missing-command synthetic fixtures;
those fixtures were corrected and the complete check rerun successfully.

The preceding async milestone's unit source revision is `df8c1accd0670a5deb75f21cb70727c8a788ea39`; its
live source revision is `c0bec22d4c1ac86c5493c52961fefda54fbb71cf`. Their production source trees are
identical; the latter adds complete 8 MiB + 10 byte live readback assertions.
Exact per-suite results and sanitized fixture metadata are in
[validation-async.json](validation-async.json).

The clean-check source revision is `cec9f6f2bd43a4e1174656bf08b247616ff1b825`.

The exhaustion/failure follow-up source revision is `863d3ae66072a4581aa38fbaacc846497156b15d`; its exact
filters and results are in [validation-exhaustion.json](validation-exhaustion.json).

These counts describe distinct executions at their respective source states, not
an additive acceptance total. The full scenario/variant assertions in
[test-matrix.csv](test-matrix.csv) remain unproven unless recorded there.

The receive-policy run used the combined local source state, including concurrent
Session changes. Exact changed-file hashes and separate baseline/focused/full
results are recorded in
[validation-response-authentication.json](validation-response-authentication.json).
The first full run exposed an admission fixture that omitted primary-session
registration and a large-write timeout. The fixture was corrected; both affected
suites then passed with the original deadlines, followed by the successful full
run. The supplied Session key-selection test is a narrow unit check, not a
reauthentication lifecycle or interoperability qualification.

The encrypted-response follow-up extends that actual receive-chain regression
to independently generated AES-GCM frames with distinct session keys. It checks
request ownership after decryption, requires every uncompressed compound member
to match the transform session, and validates compound header extents before
dispatching any member. Decrypted traversal now shares the native checked
NextCommand cursor logic, including when the first reply is discarded. The
header pass retains no member list and copies no payload. See
[validation-encrypted-response.json](validation-encrypted-response.json) for the
baseline, focused checks and validation results. These changes follow the
[MS-SMB2 decryption rules](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d3c03e33-7dc7-4d58-8428-0a1484c5c874);
compression, complete body validation and reauthentication remain outside this
regression scope. G0 is still open.

The preceding 818-case full run was not passing: its sole failure is the existing
large async streaming test's 30-second deadline, also reproduced in isolation.
The bounded JFR recorded only 0.53 seconds of GC pauses. Neither suppressing
writer debug output nor using a larger bounded test chunk resolved the deadline;
both experiments were restored. Production writer, timeout and logging behavior
were unchanged by those diagnostic experiments. The later ready-response
milestone below passes a clean full check without changing the deadline; this
does not turn the diagnostic timings into qualified throughput results.
The three license checks pass; target JDT.LS diagnostics remain
unavailable through this connector, and the user authorized the available checks.

The W7 transmit follow-up verifies the existing retained encryptor through
`Session.send`, including four concurrent callers, retirement of the original
channel, a replacement channel, provider failure after nonce allocation and the
counter's last usable value. Tracking uses key values, so reinstalling equal key
bytes through a fresh key object cannot hide reuse. Standard JCE independently
authenticates the transforms and checks plaintext, size, session and nonce
padding across BC CCM/GCM, explicit JCE/BC CCM/GCM and default-JCE GCM.
The five profiles produce 20 new passing cases; all 63 connected cases and
`licenseTest` succeeds (UP-TO-DATE). Exact source/report hashes and limits are in
[validation-encryption-ownership.json](validation-encryption-ownership.json).

These are isolated fixed-key unit scenarios with mocked Connection boundaries;
they do not form a combined production key-lifetime trace. Channels are installed
directly without a binding exchange. Authentication-driven replacement, server
nonce behavior, recovery key freshness and identical key reintroduction through
independent sessions remain unqualified. Production and build sources are
unchanged by that test-only follow-up. Its full suite was not rerun until the
later ready-response milestone below. G0 and the full ENC-02 matrix
remain open.

Reproduce the clean check with the existing JDK 21 and Gradle wrapper:

```sh
JAVA_HOME=/tmp/smb-relay-java21/opt/java/openjdk \
PATH=/tmp/smb-relay-java21/opt/java/openjdk/bin:$PATH \
./gradlew --offline --no-daemon --max-workers=1 \
  '-Dorg.gradle.jvmargs=-Xmx256m -XX:ActiveProcessorCount=2' \
  --init-script /tmp/smbj-full-gmac-test-limits.gradle clean check
```

The temporary init script limits test heaps to 384 MiB, test forks to one, and
active processors to two. Log: `/tmp/smbj-full-gmac-check.log`. Integration tests
are a separate Gradle task and have not been counted as part of `check`. The
latest filtered live matrix runs `integrationTest -x buildSambaImage --tests
'*SMB2FileIntegrationTest.shouldWriteAsyncFile'`, with
`TESTCONTAINERS_HOST_OVERRIDE=localhost` and
`TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/run/user/1000/docker-codex.sock`.
Its legacy Samba 4.7.6 fixture validates CMAC/CCM compatibility, with BC and the
JCE adapter explicitly configured with BC. Default JCE failed the four legacy
CMAC/CCM variants due to unavailable algorithms; the diagnostic log is preserved.
That legacy result does not establish GMAC interoperability. The later 16-case
modern run establishes default-JCE live GMAC/GCM single-session compatibility;
safe GMAC binding and the full multichannel contract remain unproven.

The local Sonar CLI reported no secrets in the changed scope, with an
`Authentication was not successful` warning. This is not a clean authenticated
SonarQube analysis claim. JDT.LS subsequently reached READY and returned no
per-file diagnostics for SMB2Writer, SMBSessionBuilder and the outstanding-response
handler. A complete Gradle project diagnostic pass was
not established; Java 8 release compilation and actual tests remain the semantic
validation evidence.

The [SPNEGO binding follow-up](validation-kerberos-binding.json) exercises the
Linux Kerberos fix's key-ownership scenario through SMBJ's actual
`SpnegoAuthenticator`, extended-GSS key inquiry and binding builder. Each attempt
creates a fresh authenticator/GSS context. Its exported key becomes available
only after the final peer token; binding requests still use the original signing
key. Independent KDF and wire-tag checks accept the new channel key and reject
finals derived from the original raw session key or the previous binding's export.
Missing keys and GSS inquiry failures reject the candidate before publication or
credit acceptance. The established session, signing, cipher and application keys
and initial preauthentication transcript remain unchanged.

These 22 new cases pass with both configured provider adapters; all 112 connected
binding, initial-authentication, channel-key-selection and response-authentication
cases also pass. That check mocks the GSS contexts, Session and Connection
boundaries. The separate [real-KDC follow-up](research/kerberos-kdc-reference.md)
now verifies actual ticket processing, CIFS SPN creation, final-token processing
and fresh key export through the unmodified SPNEGO adapter: six passing cases
across AES-128/AES-256 Kerberos keys and both credential modes. It does not send
SMB packets. Native SMB binding, alternate-IP selection, concurrent GMAC binding
and reauthentication remain unqualified. Production sources and the GMAC guard are
unchanged by that test-only follow-up. The full suite was not repeated until
the later ready-response milestone below.

The [ready-response follow-up](validation-ready-ack.json) fixes a concrete
asynchronous WRITE scheduling defect: when the producer has no queued input,
the worker waits for more source data even if its oldest submitted response is
already complete. A latch-based source that prepares its second chunk only
after consumption of that ready acknowledgement reproduces the stall. Five
lines in the existing consumer loop drain the completed head response before
waiting for input. An unfinished response still permits filling the pipeline;
the existing 64-request/4-MiB backpressure and cancellation checks pass.

All 28 connected writer/session cases pass. A subsequent `clean check` passes
861 tests across 100 suites with zero failures, errors or skips, Java 8 release
compilation, coverage reporting and all three license checks. The above-2-GiB
case takes 6.664 seconds in that full run under its unchanged 30-second deadline.
Eight native async cases also pass against the cached Samba 4.7.6 fixture,
including complete 8 MiB + 10 byte readback with both transports and BC/JCE-BC,
with encryption off or CCM. Both task containers were removed by Testcontainers
and their exact IDs confirmed absent. Sources, report hashes and a compact
100-suite manifest are recorded with the follow-up.

The unchanged pre-fix standard case also passed at 29.006 seconds in this
investigation. The scheduling regression establishes its specific defect; the
recorded diagnostic timings do not prove the sole cause of every earlier
deadline failure or qualify sustained throughput. A response completing only
after the worker has already entered its empty-input wait was outside that
five-line change; the later wakeup follow-up below handles it. Native GMAC
multichannel and
the full G0/G5 requirements remain open. No API, dependency, build configuration,
chunk/window limit, logging setting or test deadline changed.

The [late-response follow-up](validation-late-response.json) supplies a private
completion signal owned by each Request. Its Promise publishes the value/error
before signalling outside its delivery lock. Cancellation signals its claimed
local outcome before invoking the potentially blocked send callback. The future
helper only registers monitor notification. The writer checks both its input
queue and the oldest response's terminal state under that monitor, so completion
between checking and waiting cannot be lost. An end-of-input decision also checks
that the producer finished and the queue is still empty.

Native request futures and CompletableFuture use completion notifications with
no polling or new threads. Opaque custom Future implementations use a 10 ms
bounded wait fallback. Legacy Promise/CancellableFuture constructors remain
available; their value/error and cancellation behavior is retained. The optional
one-shot Promise signal requires publication without an externally held Promise
lock, as in the Request path. Source I/O remains owned by the calling thread.

Two synchronized late-response cases fail on the preceding production source.
The final nine writer cases cover success, failure and cancellation with native,
CompletableFuture and opaque futures; four Request cases cover publication and
failed cancellation; two Promise cases check publication-before-signal and lock
release. A blocked-cancellation-send test also verifies that the completion
monitor wakes before that callback is released. All 51 connected cases and a
clean 876-test full check pass without failures or skips. Coverage reporting and
all three license checks pass.

Eight legacy native async cases retain complete 8 MiB + 10 byte readback with
CMAC and optional CCM. The existing forced-GMAC matrix now asynchronously
overwrites each open file with different bytes before its complete readback:
all 16 single-session profiles pass with both transports, BC/default JCE,
GCM encryption off/on and write-through off/on. Its rejected binding candidate
still leaves the existing session/file usable. Task-owned Samba/reaper containers
were removed and their exact IDs checked. This is single-session GMAC coverage,
not a safe binding construction or a full multichannel pass.

The [reusable GMAC fixture runner](research/run-gmac-single-fixture.py) copies the
existing profile into the pinned container before startup, avoiding daemon/client
filesystem assumptions. It generates private test credentials, forces actual
test execution, retains sanitized evidence and removes only its verified owner
container. With the existing JDK 21 selected, run it from this worktree using
`python3 docs/full-gmac-multichannel/research/run-gmac-single-fixture.py --output <new-private-directory>`.
G0, the full peer/authentication matrix and sustained
operational/performance qualification remain open. This follow-up does not
interrupt a caller-owned blocking source read or qualify a response that never
completes while that source is blocked.

The [Java 8 runtime follow-up](validation-java8-runtime.json) executes the actual
client on Temurin 8u512, not merely Java 8 bytecode on a newer JVM. Six existing
test/support sources compile with release 8 into a private directory using Java
21. A separate opt-in Test task uses a Java 8 launcher and the unchanged complete
production JAR/runtime dependencies. Its 24 local cases cover Request/Promise
publication and cancellation, CMAC response/padding verification and MessageId
exhaustion/concurrency. All 16 native profiles force GMAC and exercise actual
async overwrite/readback with both transports, BC/default JCE, GCM off/on and
write-through off/on. The payload now has a five-byte tail to exercise unaligned
GMAC/GCM data and credit rounding. All 40 cases pass without failures or skips.

The native output records Java 8 in every case. The launcher metadata records
Java 21 for the build/compiler and Java 8 for execution; all isolated test
classes and all 511 production classes have major version 52. The ordinary
Java 21 runner also passes its 16 current native cases. Its production JAR is
byte-for-byte identical to the one exercised on Java 8. Task-owned fixtures and
the never-started runtime extraction container were removed.

The profile reuses existing JUnit artifacts while omitting incompatible or
unused test-only infrastructure. In particular, the current Logback test backend
has Java 11 bytecode; Java 8 uses SLF4J API NOP logging. No production dependency,
default classpath, implementation/unit source, or build file was changed. This
is not the full 876-test suite on Java 8, and its timings are not a logging-matched
performance comparison. The preceding full-suite milestone remains the current
876-test result; it was not repeated for this harness-only change.

To reproduce, extract `/opt/java/openjdk` from the exact Temurin image digest in
the validation record into a fresh local runtime directory, then use the existing
JDK 21 for the build:

```sh
JAVA_HOME=/tmp/smb-relay-java21/opt/java/openjdk \
PATH=/tmp/smb-relay-java21/opt/java/openjdk/bin:$PATH \
python3 docs/full-gmac-multichannel/research/run-gmac-single-fixture.py \
  --java8-home /tmp/smbj-java8-runtime/openjdk \
  --output /tmp/smbj-java8-runtime/new-validation
```

The output directory must be new. The [profile](research/java8-runtime-profile.gradle)
keeps test outputs separate and disables toolchain downloads/discovery beyond
the supplied installations. Normal invocation without `--java8-home` retains the
ordinary test path. G0 and the complete Java 8 multichannel/authentication,
failure/load and peer matrix remain unqualified.

## Remaining contract and release gates

| Gate | Result | Missing authoritative evidence |
|---|---|---|
| G0 | BLOCKED | Supported binding nonce mechanism, full safe actual-key lifetime proof, authoritative interpretation and independent validation of that construction; ordinary-flow collision now confirmed live |
| G1 | BLOCKED | All four reproductions resolved together; nonce collision remains unsolved |
| G2 | NOT_RUN | Complete local matrix across providers/transports/runtimes; the 40-case Java 8 profile passes, but the complete Java 8 multichannel/authentication/failure matrix remains unqualified |
| G3 | BLOCKED | Complete NTLM/Kerberos authentication lifecycle and reauthentication variants, all applicable notifications, replay/fencing and GMAC binding cases |
| G4 | BLOCKED | Forced-GMAC multi-channel runs on capable independent Samba/Windows peers and target ONTAP release/configuration |
| G5 | NOT_RUN | Sustained concurrent I/O and cancellation-churn memory (including transport queues), replacement/recovery and comparative measurements |
| G6 | NOT_RUN | Complete source/provenance mapping, validated peer traces and complete reproducible review package |

Specific remaining implementation work includes the approved G0 mechanism,
remaining authentication lifecycle and reauthentication handling, complete notification coverage,
replay/fencing and recovery semantics, sustained cancellation/transport-queue
memory validation, and the remaining matrix assertions. Local sync/async short-write checks and live legacy-server compatibility do not
establish the GMAC binding, native fault-peer or sustained operational requirements.

The supplied [protocol-resolution.md](protocol-resolution.md) contains the precise
questions and required evidence. No external message has been sent. The current
Microsoft signing/sequence rules and the referenced ksmbd discussion were checked
again during implementation; the independent live trace confirms the ordinary
flow's collision, and no validated general construction was established.
A missing construction is a design blocker, not evidence of a JDK/provider/kernel
bug or a reason to report the full feature complete.
