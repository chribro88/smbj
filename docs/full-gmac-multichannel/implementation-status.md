# Full GMAC multichannel implementation status

The requested full feature is **incomplete**. The completion contract in
[plan.md](plan.md) remains unchanged. G0 is open: this branch does not yet have a
protocol-compliant, independently verified binding key/nonce uniqueness mechanism.
The inherited GMAC-binding rejection remains containment and does not satisfy G0.

## Inputs and history

- Branch: `feature/full-gmac-multichannel`.
- Worktree: `/workspace/smbj-worktrees/full-gmac-multichannel`.
- Existing feature base: `3ac158f017e416b9ae2b679d9a604b473b9956f2`.
- Upstream baseline: `1c5b9345df2898b8d57cf34d50ae599cab07b2b8`.
- Original feature implementation: `c2c8994` (ancestor of the selected base).
- Production compilation target: Java 8 (`compileJava.options.release = 8`).
- Build/test runtime used here: the existing Temurin 21 installation at
  `/tmp/smb-relay-java21/opt/java/openjdk`; Gradle 8.13; Bouncy Castle 1.86.
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

The latest unit source revision is `0357c30bf743ee311d18aa32530bc08fd14bb0e3`;
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
This result does not establish GMAC multichannel or default-JCE live GMAC/GCM
interoperability.

The local Sonar CLI reported no secrets in the changed scope, with an
`Authentication was not successful` warning. This is not a clean authenticated
SonarQube analysis claim. JDT.LS subsequently reached READY and returned no
per-file diagnostics for SMB2Writer, SMBSessionBuilder and the outstanding-response
handler. A complete Gradle project diagnostic pass was
not established; Java 8 release compilation and actual tests remain the semantic
validation evidence.

## Remaining contract and release gates

| Gate | Result | Missing authoritative evidence |
|---|---|---|
| G0 | BLOCKED | Supported binding nonce mechanism, full actual-key lifetime proof, authoritative protocol interpretation and independent peer trace |
| G1 | BLOCKED | All four reproductions resolved together; nonce collision remains unsolved |
| G2 | NOT_RUN | Complete local matrix across providers/transports/runtimes; Java 8 runtime execution |
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
again during implementation; no validated general construction was established.
A missing construction is a design blocker, not evidence of a JDK/provider/kernel
bug or a reason to report the full feature complete.
