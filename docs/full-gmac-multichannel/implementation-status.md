# Full GMAC multichannel implementation status

GMAC signing and the public multichannel APIs are implemented and work in the
tested Samba configurations: concurrent binding, replacement channels and
existing-open file I/O pass with independent wire/tag checks on the audited
profiles. The requested full feature is **incomplete**. G0 remains open against
the complete lifetime and interoperability requirements in [plan.md](plan.md);
this does not mean that GMAC or multichannel is disabled. Windows testing is
explicitly deferred by the user; implementation and acceptance continue on Linux.

Earlier diagnostic and prototype records are historical evidence. The live
Go/Samba collision trace and the auxiliary/concurrent experiments explain the
implemented construction; their earlier “unselected” labels describe those
source states. See [research history](research/README.md),
[the auxiliary record](validation-auxiliary.json) and
[the concurrent record](validation-auxiliary-concurrent.json).

## Current production integration

Client-managed GMAC authentication establishes the target session on a private
root, reserves its next MID for abort LOGOFF, and binds back onto the caller
before returning. The caller's verified channel key carries application I/O;
file traffic does not advance the original-key reservation cursor. Initial
binding MIDs on a busy caller are retained as at most 16 sparse exclusions.

`SMBClient.openChannel` and `Connection.bind` authenticate an independent
auxiliary session before GMAC binding. Its actual key bytes must differ from
the target's original key. Every binding round reserves its actual native MID;
unsigned connection ECHOs consume collisions through native credit allocation.
Reservations remain burned after uncertain outcomes. No arbitrary sequence jump
or alternate GMAC nonce is used. The auxiliary session is closed before the
verified target channel is published.

`openChannel` owns its candidate; direct `bind` borrows the caller's transport.
Private bootstrap and cleanup candidates inherit the caller's configuration,
event bus, authentication hostname and endpoint, including callers whose
settings differ from the client's defaults. They are registered before connect
and explicitly released. Client closure and session state gate publication.
A failed attempt preserves unrelated sessions and their open files on borrowed
connections.

Validation records below identify their exact source states and scope. The
latest lifecycle record is
[validation-bootstrap-lifecycle.json](validation-bootstrap-lifecycle.json).
Remaining engineering work includes public reauthentication and Kerberos failure/expiry paths,
complete failure/key-lifetime coverage, sustained binding-history/resource cost
and target-server qualification. These are tracked implementation and test tasks;
no further cryptographic-library change or paper search is required to proceed.

### Authentication attempt ownership

Authentication now keeps its provisional Session in the attempt context rather
than looking it up again by a peer-controlled continuation SessionId. A failed
continuation, rejected final or exceeded 16-exchange limit removes only that
attempt's provisional entry and disposes its unpublished Session without LOGOFF
or transport closure. Changed continuation SessionIds and collisions with
provisional/active sessions are rejected. Conditional table registration/removal
also protects channel binding against publication and replacement races.

Both discarded authentication attempts and normally closed sessions release
their event subscription. A native Samba test injects an NTLM authenticator
failure after the auxiliary challenge while an older session has an open file.
It checks empty provisional state, unchanged live subscription count, continued
older-open I/O, and a successful bind retry on the same borrowed connection.
The public native suite now has three cases; the two wire-audited concurrent/
replacement cases still verify 116 signed inputs without observed reuse.
The combined `check` passes **903 tests in 102 suites**, zero failures/errors/skips,
with license and JaCoCo checks. The three public cases and sixteen native
provider/transport/encryption profiles pass on the changed production source.
See [validation-authentication-ownership.json](validation-authentication-ownership.json).

### Automatic GMAC bootstrap and caller handoff

Client-managed GMAC authentication now establishes the logical session on a
private connection, binds it back onto the caller's existing connection, and
retires the private transport without LOGOFF before returning. The returned
`Session.getConnection()` is the caller, retains the real SMBClient and pooled
identity, and sends ordinary I/O under its verified channel key. Original-key
reservations are therefore driven by binding rounds rather than file traffic.
Signing-disabled and non-multichannel paths retain direct authentication.

The private bootstrap's next MID is reserved for possible abort LOGOFF. The
initial caller's at-most-16 original-key binding MIDs are kept as sparse outliers
instead of raising the fresh-candidate reservation cursor to a busy caller's
counter. Later per-request claims exclude the initial prefix, abort nonce and
sparse outliers. The existing per-connection allocation and unsigned ECHO path
still consume all native MIDs legally; there is no fabricated counter jump.

The private connection inherits the caller's exact configuration, event bus,
authentication hostname and actual endpoint, including borrowed callers whose
settings differ from the SMBClient defaults. The client tracks private candidates
explicitly through connect/authentication and releases them even when the caller
uses a different event bus. Client closure is checked at handoff publication. On failure, session cleanup preserves the
borrowed caller; on success the closed bootstrap is removed from channel
membership. The original signing context remains available for later binding.

Native coverage includes a busy pooled session with 1,024 prior requests and
1,024 application requests before fresh concurrent binds and replacement. The
fresh-channel catch-up assertion is at most 32 ECHOs across the tested attempts,
independent of those 2,048 application requests. A final-reply client-input fault
verifies genuine peer MAC acceptance, rejection after corruption, original-key
LOGOFF at reserved MID 3, private-root disposal, older-open continuity and retry.
The combined `check` passes **905 tests in 102 suites**, zero failures/errors/skips,
with license and JaCoCo checks. All 20 Java 21 native cases pass; the actual Java 8
profile passes 40 cases (16 native, 24 selected local) using the identical production
JAR. The two independently audited public profiles verify 4,243 signed inputs
without observed distinct-message actual-key/nonce reuse.
See [validation-bootstrap-production.json](validation-bootstrap-production.json).

This removes application-traffic-driven catch-up in the integrated public path;
it does not prove constant cost for an unbounded binding/retry history. Complete
lost-final/root-loss variants, all publication/close races, public Kerberos/runtime
variants, the complete actual-key lifetime and independent server acceptance
remain open. Earlier cost/status statements below retain their historical scope.

### Lost bootstrap final and private-root cleanup

Failed automatic bootstrap now makes one owned cleanup-channel attempt when its
private root is already closed and the borrowed caller remains connected. It
reuses the caller's configuration, endpoint, event bus and existing auxiliary
authentication/binding flow. Only a verified new channel key is used to LOGOFF
the failed session. Both owned transports are disposed, and the original
authentication failure is preserved with any cleanup failures suppressed.
An open root continues to use its reserved original-key LOGOFF nonce.

The native public suite now has seven cases. New cases drop the peer's successful
final binding reply, preserve older-session file I/O during the pending wait,
and optionally close the private root. Successful cleanup receives a successful
LOGOFF response; original-key binding request MIDs remain distinct. A failed
cleanup connect causes one attempt, closes its owned candidate, preserves the
original failure and older open, and permits fresh authentication. In that case
remote session cleanup is unconfirmed. The root-loss regression fails on the
preceding production implementation and passes with this change.

This is bounded Samba 4.23.10/NTLM/Direct-TCP/BC/Java-21 coverage. Root loss during
LOGOFF, cleanup authentication/binding faults, all close/publication races and
the full lifetime/provider/server matrix remain open. No new cryptographic
implementation or research is introduced. See
[validation-bootstrap-loss.json](validation-bootstrap-loss.json).

This milestone passes **905 local tests in 102 suites**, with license and JaCoCo
checks; **23 Java 21 native cases** (seven public, 16 matrix); and the actual
Java 8 profile's **40 cases** (16 native, 24 selected local). There are no
failures/errors/skips. The identical production JAR is used before and after
Java 8 validation, with all 511 production classes targeting Java 8. These totals
do not close the outstanding G0 scenarios above.

### Candidate disposal and client-close publication

Private roots and owned cleanup candidates now explicitly remove the exact
attempt's session-table entry during disposal. A root that has unsubscribed from
the event bus cannot otherwise receive later LOGOFF events. Removal uses the
existing identity check, so it cannot erase a replacement entry.

If binding has already verified the borrowed caller but client closure rejects
canonical handoff, cleanup uses that verified channel. It does not create a
second candidate. Native barriers exercise closure before final verification and
immediately before handoff publication, while older-session file I/O proceeds.
The client rejects late handoff, target/provisional entries are removed and the
borrowed connection remains usable. Additional native cases fail cleanup NTLM
continuation and corrupt its final binding input; neither retries cleanup or
claims that the remote failed session was successfully logged off.

The existing Java 8 profile can now select this same public acceptance suite.
The default transport/provider matrix remains selectable. Runtime markers and
the selected Java launcher record the actual test JVM; the production JAR is
shared with Java 21 acceptance. See
[validation-bootstrap-lifecycle.json](validation-bootstrap-lifecycle.json).

This milestone passes **85 focused local tests in nine suites** plus license
checks; **27 Java 21 native cases** (11 public, 16 matrix); and both actual Java 8
profiles: **35 cases** (11 public, 24 focused local) and **40 cases** (16 matrix,
24 focused local). All have zero failures/errors/skips. The production JAR is
identical across the runtime runs and all 511 classes target Java 8. The prior
905-test full-check result remains recorded at its earlier source state.

### Public Kerberos multichannel

The existing Samba AD fixture now tests the production public APIs directly.
Four native cases pass on Linux/Samba AD 4.23.10, Direct TCP, BC and Java 21:
16-byte and 32-byte real Kerberos context keys, each with/without an older session
on the caller. SMB signing remains AES-128-GMAC in every case; the peer disables
NTLM. Two public binds pause before first socket write while the existing open
continues I/O. Replacement and same-open readback then succeed across channels.

The reused independent JCE observer verifies **256 signed inputs** across all
four traces with zero observed distinct-message actual-key/nonce reuse. Extended
GSS inquiry checks **42 established contexts**. All four owned domain containers
are confirmed removed; Subject login, contexts and private Kerberos configuration
are released. The production JAR remains identical to the preceding lifecycle
milestone. The shared observer passes all 11 NTLM public cases on Java 21 and the
35-case Java 8 profile (11 native, 24 focused local).

Run the existing pinned local fixture from this worktree with the Java 21 build
JDK selected:

```sh
python3 docs/full-gmac-multichannel/research/run-gmac-kerberos-fixture.py \
  --output /tmp/<fresh-private-directory>
```

See
[validation-public-kerberos.json](validation-public-kerberos.json) for source,
image, runtime and audit scope. Public reauthentication, failure/expiry variants,
remaining transports/providers and sustained churn remain engineering tasks.

### Public reauthentication and channel-close safety

`Session.reauthenticate()` now validates the existing credentials on one live
SMB 3.x channel, using that channel's current signing key for the entire exchange.
It retains session/channel keys, preauthentication and MID/nonce state. Fresh
Closeable authentication contexts are disposed on success and failure. Invalid
MACs, changed SessionIds, guest/null results, missing exported keys, signed
authentication errors and the 16-exchange bound do not publish replacement state.
Close can complete while authentication waits; a late final cannot return success
after close. Shared SESSION_SETUP wait handling retires timed-out/interrupted
lookups without discarding unrelated requests or borrowed transports.

A deterministic send/close regression exposed a separate wrong-key race: channel
removal could clear D between send validation and signing-key selection, causing
fallback to original K. Both operations now use the existing channel monitor;
serialization and network I/O remain outside it. The regression fails before the
fix and passes afterward.

Full `check` passes **927 tests in 104 suites**, with license and JaCoCo checks.
The **31 Java 21 native cases** comprise 11 public NTLM, four public Kerberos and
16 provider/transport/encryption profiles. The same production JAR passes actual
Java 8's **35-case public profile** and **40-case matrix profile**. All these
results have zero failures/errors/skips. There are 14 NTLM and 24 Kerberos public
reauthentications, plus 32 in each default matrix run. Same-open I/O and later
replacement binding remain usable. The independent observer verifies **4,299
NTLM** and **304 Kerberos** signed inputs on Java 21 with zero observed
distinct-message actual-key/nonce reuse; Java 8 repeats the 4,299-input NTLM audit.
The production JAR contains 511 Java-8-targeted classes.

An additional global `smb encrypt = required` fixture **fails**, before reaching
reauthentication: eight encryption-disabled profiles are denied during initial
authentication, and eight encryption-enabled profiles are rejected on the first
bootstrap bind. The pinned Samba implementation rejects plaintext session traffic
at its encryption-required check before binding/signature dispatch. This is an
explicit unqualified interoperability policy, not a passing encryption test.
The successful default profiles use optional session encryption and exercise GCM
I/O. No binding-encryption workaround has been introduced.

See [validation-public-reauthentication.json](validation-public-reauthentication.json)
and [g0-implementation-invariants.md](g0-implementation-invariants.md). Remaining
Linux work includes current-public cancellation/notification lifetime coverage,
sustained replacement/resource/catch-up measurements and the outstanding failure
matrix. Windows testing remains deferred; further paper or private-service access
is not required to continue this work.

### Public multichannel cancellation and CHANGE_NOTIFY

The existing four-profile native cancellation fixture now uses the current
managed GMAC bootstrap and two bound channels. It captures notification/CANCEL
inputs with their physical owners and independently verifies each with that
owner's actual bound key, rather than using original K. Each profile carries
notifications on both original channels and their replacement. Ordinary ECHO
traffic moves round robin away from each pending watch before cancellation;
the CANCEL and final response remain on that watch's owner. The other channel
is closed and replaced while a pending reply is held before publication.

Across two fresh watched directories, every profile checks eight unsigned
interim replies, two synchronous and four asynchronous one-shot CANCELs,
six cancelled finals, two successful finals and retirement of the outstanding
request. Eight callers compete to cancel in each concurrent-cancel round.
Every ordinary serialized request consumes its connection's lowest native MID
range; CANCEL consumes no range. Independent default-JCE checks verify **22
GMAC tags per profile**, merge nonce state by actual key, and reject the ordinary
request nonce for each CANCEL tag.

All **four Java 21 native profiles** pass (Direct/Async transport × BC/default
JCE), as does the actual Java 8 profile's **28 cases** (four native and 24 selected
local). There are zero failures/errors/skips, **88 independently verified GMAC
tags per runtime**, and no observed key/nonce reuse among those inputs. License
checks pass and the production JAR is unchanged. The preceding 927-test full
check remains at its recorded production state; no new full local run is claimed.

The first expanded run exposed a fixture mistake: reusing a watched directory
after creating/deleting its event file legitimately completes the next watch
immediately, rather than producing another STATUS_PENDING. Fresh directories
isolate each four-watch group. Directory leases are disabled in this fixture so
unrelated background lease ACKs cannot move the scheduler. This is CHANGE_NOTIFY
acceptance, not evidence for unsolicited lease/oplock-break notifications.
Timeout/owner-loss, encryption, Kerberos cancellation and sustained churn remain
separate acceptance work. See
[validation-public-cancellation.json](validation-public-cancellation.json).

Reproduce from this worktree with the Java 21 build JDK selected:

```sh
python3 docs/full-gmac-multichannel/research/run-gmac-single-fixture.py \
  --async-cancel --output /tmp/<fresh-java21-directory>
python3 docs/full-gmac-multichannel/research/run-gmac-single-fixture.py \
  --async-cancel --java8-home /tmp/smbj-java8-runtime/openjdk \
  --output /tmp/<fresh-java8-directory>
```

### Pending-owner loss and encrypted cancellation

The same public cancellation suite now has eight native profiles: both
transports × both providers × signing-only/GCM operation. Every profile closes
the physical owner of a pending watch. The failed future reports the transport
failure, both request/cancel lookup entries are removed, and later cancellation
returns false without emitting another CANCEL on a survivor. Ordinary listing
still succeeds using the existing directory handle. A second replacement binds
successfully, and an explicitly reopened directory subscription delivers a fresh
event on that replacement. All four bound physical connections carry watches
over the profile's lifetime.

Independent default-JCE code now verifies encrypted transforms before the normal
receiver processes them. It uses the owning connection's actual session keys,
including auxiliary sessions, and authenticates raw header AAD, ciphertext and
tag. It checks outer/inner SessionId agreement and tracks actual-key/nonce
identity across connections and sessions. A ciphertext-tampering control fails
tag verification. The signing-only profiles retain their independent GMAC and
CANCEL-discriminator checks. Ordinary native MID consumption is checked for both
plaintext and independently decrypted requests.

All **eight Java 21 native profiles** pass, as does actual Java 8's **32-case
profile** (eight native, 24 selected local). Each runtime independently verifies
**100 GMAC tags** and **844 GCM transforms**, with zero observed key/nonce reuse
among those inputs. Each encrypted profile includes all 35 notification/CANCEL
frames, including ten interim replies, in its transform checks. License checks
pass; the production JAR remains identical. The prior full local result remains
927 tests at its recorded production source state.

Two exploratory same-handle watch-resubscription runs **fail in all four
signing-only profiles**: after owner loss, a new watch on the same handle reaches
STATUS_PENDING but its first create event does not complete within five seconds.
Completing the mutation's file close does not resolve this. These failures are
preserved in the evidence archive and are not counted as successful recovery.
The passing recovery explicitly closes the failed subscription's handle and
opens a new one. This demonstrates one recovery path, not safe transparent
watch replay or complete event continuity. Same-handle watch resubscription
remains unqualified on the tested Samba 4.23.10 fixture.

See [validation-encrypted-owner-loss.json](validation-encrypted-owner-loss.json).
The existing `--async-cancel` reproduction commands now run all eight profiles;
adding `--java8-home` runs the 32-case compatibility profile. Remaining work
includes timeout/publication-fault cancellation, Kerberos cancellation,
unsolicited notifications and sustained churn/resource measurements. Mandatory
global-encryption binding retains its separately recorded failure. Windows
testing remains deferred.

### Churn and cached transport-error cleanup

A prepared binding-send fault exposed a production error-preservation defect.
The send aborted the candidate with a cached transport exception; auxiliary
LOGOFF then raised that same object. The automatic resource-suppression code
threw `IllegalArgumentException: Self-suppression not permitted`, hiding the
original failure. All eight initial native profiles reproduced it. Focused
regressions fail for identical IOException, RuntimeException and Error objects;
a distinct cleanup exception already behaves correctly.

Connection binding now closes the auxiliary explicitly on failure, retains the
primary failure and suppresses only a distinct cleanup failure. Successful
binding still closes the auxiliary before channel publication in the existing
builder. The borrowed transport contract and authentication exception conversion
are preserved. The owning SMBClient also closes failed candidates after Error
and guards against self-suppression from a cached close failure. Three added
ownership cases reproduce the missing Error disposal and cached-close masking
before that fix. Regression checkpoint: `95a5806`.

The opt-in churn phase reuses the existing performance fixture and four-worker
range workload. It keeps two channels live, holds each new candidate's first
reserved binding request while the existing open completes generation-specific
writes/readback, publishes and exercises the candidate, then retires it. Every
eighth cycle fails an already prepared original-key request before transport
publication. Retry must burn that MID. Application I/O cannot advance the
original-key cursor. The probe explicitly asserts negotiated GMAC and the actual
GCM/key context on every channel. It checks original-key identity, fresh bound
key bytes, unchanged encryption ownership, stable active/pending/client tables,
subscriptions, descriptors, live threads and weak-reference collectability.

The 64-cycle matrix covers both transports, BC/default JCE and signing-only/GCM
on Java 21 and actual Java 8. Per profile: **64 successful replacements**, **eight
prepared failures**, **73 retired connections collected**, and **66 fresh bound
keys**. Descriptor counts return to each profile's baseline; thread counts stay
within the declared eight-thread allowance. Each runtime exercises 512 successful
replacements and 64 prepared failures. The full local `check` passes **934 tests
in 105 suites**. Actual Java 8's profile passes **32 cases** (eight native and
24 selected local). Current-production NTLM/Kerberos public acceptance also passes
11/four cases, independently verifying 4,299/304 signed inputs without observed
distinct-message key/nonce reuse. See
[validation-churn-cleanup.json](validation-churn-cleanup.json).

These are bounded operational measurements. Collision ECHOs grow from **five to
139 per successful candidate** over the tested history, with **5,216 total** per
profile including the failed attempts and initial companion. Catch-up therefore
still grows with binding history; this is a measured cost, not a constant-time
claim. The heap gauges include the probe's retained weak references, fingerprints
and samples. Collectability/ownership checks do not substitute for complete
allocation or transport-buffer profiling. No thousand-cycle-per-session soak,
comparative 1/2/4-channel throughput or deployment performance gate is claimed.
The existing transfer meter now excludes disconnected bootstrap/candidate
transports from its live registry; its separate throughput workload was not run
as part of this churn result.

Run from this worktree with the Java 21 build JDK selected:

```sh
python3 docs/full-gmac-multichannel/research/run-gmac-single-fixture.py \
  --churn --churn-cycles 64 --output /tmp/<fresh-java21-directory>
python3 docs/full-gmac-multichannel/research/run-gmac-single-fixture.py \
  --churn --churn-cycles 64 --java8-home /tmp/smbj-java8-runtime/openjdk \
  --output /tmp/<fresh-java8-directory>
```

Remaining work includes longer-history cost/resource qualification, sustained
cancellation/stall variants, complete allocation/buffering measurements and the
remaining authentication/notification policy cases. Windows remains deferred.

### Bounded collision-probe pipelining

Binding catch-up now sends up to 32 native unsigned ECHOs before waiting for
their replies, subject to available credits. With probes pending and only one
credit remaining, it waits before allocating another MID. Native allocation,
one-credit probes and original-key reservations are unchanged. An accepted target
MID/range is allocated with its reservation before waiting, then published only
after every probe completes. Timeout, interruption or a reservation failure
retires the call's pending probes and leaves unrelated requests intact. A target
allocated before a failed wait remains burned. No network wait holds the
allocation lock.

Seven added regression cases cover bounded/out-of-order replies with another
sender, low credits, an unpublished accepted reservation, interruption, callback
RuntimeException/Error and exhaustion with a pending probe. The full `check`
passes **941 tests in 105 suites**, zero failures/errors/skips, plus license and
JaCoCo. The same 64-cycle native churn matrix passes on Java 21 and actual Java 8:
**1,024 replacements and 128 injected prepared failures** in total, with every
retired connection collected and descriptors returning to baseline. Java 8 also
passes the existing 24 selected local runtime cases; the Mockito reservation
tests run on Java 21.

The changed JAR also passes 11 public NTLM binding cases, four public Kerberos
cases and eight cancellation/owner-loss cases, making **31 native Java 21 cases**
including churn. Separate wire audits independently verify **4,703 GMAC tags and
844 GCM transforms** without observed distinct-message actual-key/nonce reuse
in those inputs. All task-owned Samba/AD fixtures are removed after validation.
All 511 production classes retain Java 8 bytecode compatibility.

Compared with the preceding committed workload, median binding latency across
the eight Java 21 profiles falls from **62–101 ms to 21–37 ms**; Java 8 falls from
**60–102 ms to 23–34 ms**. The key/MID, payload, prepared-failure and collection
counters match the baseline. These are sequential bounded runs on this host,
not a general throughput benchmark. Packet count still grows from five to 139
ECHOs per candidate, with 5,216 total per profile. Longer histories, transport
buffer allocations and the remaining G0 lifetime variants stay open. See
[validation-batched-probes.json](validation-batched-probes.json).

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
| Reserved-nonce bootstrap-abort research | PASS: 10 native cases, zero failures/skips | Detached checkout only; Samba 4.23.10, NTLM, Direct TCP, BC; eight bad/lost-final cases include four forced root-loss cleanups with no LOGOFF or abort-MID allocation; all preserve the older session/open and pooled connection; two controls detect nonce reuse without reservation; 360 independent tag checks, zero reuse in positives; other lifecycle paths remain open |
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

The [native async cancellation follow-up](validation-async-cancellation.json)
passes four forced-GMAC Samba 4.23.10 profiles across both TCP transports and
BC/default JCE. Each profile gates an actual unsigned `STATUS_PENDING` before
Request publication, cancels that watch with its synchronous identity, cancels a
second after AsyncId publication, and races eight cancellation callers on a third.
Exactly one synchronous and two asynchronous CANCEL inputs are emitted. A fourth
watch completes after a real file creation, using the same connection.

A bounded observer captures serializer inputs and incoming frames, separately
from SMBJ's signing and verification code. It independently checks all eleven
signed tags per profile, prescribed MID/direction/CANCEL nonces, no repeated
nonce under that profile's actual channel key, matching AsyncIds/final statuses,
consecutive native request ranges despite CANCEL, and removal from the owning
connection's outstanding-request table after every final response. Each CANCEL tag rejects
the ordinary-request nonce. Peer responses corroborate successful transmission;
this is transport-boundary observation, not a packet capture. The observer
exports only phase metadata, with no keys, authentication tokens or SessionIds.

The existing CHANGE_NOTIFY cancellation test now expects `CancellationException`
from the cancelled Future. Its two default-fixture cases and 73 connected local
crypto, cancellation and response/notification-authentication cases pass. The
ordinary 16-case GMAC/GCM single-session runner is checked separately. Main/unit
sources, dependencies and production JAR remain unchanged. This follow-up covers
NTLM/plaintext/single-channel behavior on Java 21; encrypted cancellation,
Kerberos, bound-channel routing, timeout/disconnect races and the full lifetime
argument remain unqualified. G0 stays open.

Reproduce the new native profile with the existing build JDK selected:

```sh
JAVA_HOME=/tmp/smb-relay-java21/opt/java/openjdk \
PATH=/tmp/smb-relay-java21/opt/java/openjdk/bin:$PATH \
python3 docs/full-gmac-multichannel/research/run-gmac-single-fixture.py \
  --async-cancel --output /tmp/smbj-gmac-async-cancel/new-validation
```

`--async-cancel` and `--java8-home` select separate opt-in profiles. The output
directory must be new; the runner removes its exact owner-labelled Samba fixture.

The [native reauthentication research](validation-reauthentication.json) now
passes three detached cases on Samba 4.23.10/NTLM/Direct TCP/BC/Java 21. Original
and bound channels complete five reauthentications in total. On the bound
channels, outgoing setup requests and both intermediate/final peer replies use
the existing channel key; those reply tags reject the original signing key.
An original-key request on a bound channel receives `STATUS_ACCESS_DENIED`,
after which a channel-key ECHO succeeds. The positive cases independently verify
388 signed messages with no distinct-message actual-key/nonce reuse observed.

After reauthentication advances an operational cursor, a fresh binding still
starts at original-key MID 19 with 16 actual auxiliary-key ECHOs. The same open
survives reauthentication and the additional channel. This supports keeping
original-key reservation state separate from operational MIDs under this peer's
channel-key interpretation. The research driver uses actual `Session.send` but
supplies its own GSS loop and setup-response acceptance; it is not a production
reauthentication API. Its [source, reproduction and limits](research/reauthentication/README.md)
retain the unqualified public-connection ownership, padding cost, Kerberos,
expiry/failure/concurrency, encryption, other transport/runtime and Windows/ONTAP
boundaries. The production tree and GMAC guard are unchanged; G0 stays open.

The [native Kerberos follow-up](validation-kerberos-native.json) passes six
research cases on a real Samba AD DC 4.23.10/KDC, NTLM disabled, Direct TCP,
BC and Java 21. The original/bound/wrong-original-key cases run with both AES-128
and AES-256 Kerberos context keys, verified through extended GSS inquiry; SMB
signing remains AES-128-GMAC. Actual initial/binding builders process the final
peer token and derive channel keys from the current context's normalized key.

Ten reauthentications succeed. A later binding at MID 18 uses 16 real auxiliary
ECHOs; the same open carries authenticated I/O on both operational channels.
Four positive traces independently verify 748 signed messages without observed
distinct-message actual-key/nonce reuse. Both wrong-original-key controls get
`STATUS_ACCESS_DENIED`, followed by a successful channel-key ECHO. This closes
the earlier real-KDC-only observation's native SMB gap for this bounded profile.
It does not qualify a production bootstrap/reauthentication API or close G0.

The [fixture/source/reproduction record](research/kerberos-native/README.md)
explains the rootless UID range, omitted SYSVOL ACL setup, user-xattr share and
strict separation of initial infrastructure failures from final protocol results.
Windows/ONTAP, alternate IP/SPN routing, explicit native GSS credentials,
expiry/failure/concurrency, encryption, async transport, Java 8, sustained costs
and complete lifetime/API ownership remain unqualified. Production source and
the GMAC binding guard remain unchanged.

The [shared caller-connection follow-up](research/public-anchor/README.md) passes
both native NTLM/Direct TCP/BC cases on Samba 4.23.10. An unpublished main session
moves from a private bootstrap onto the caller's existing connection; its public
connection, real SMBClient and pooled identity remain live. An older session/open
performs I/O between the two binding authentication rounds and remains usable
after bootstrap retirement and new-session close. The main open reads and writes
on both operational channels.

The busy caller signs original-key binding inputs at MIDs 1037 and 1044, while a
later fresh candidate binds at MID 3 with zero padding. Recording the bounded
initial anchor's sparse original-key inputs avoids raising the fresh-candidate
cursor to the caller's high operational cursor. The two traces independently
verify 2,332 signed inputs without observed distinct-message actual-key/nonce
reuse; [the evidence record](validation-public-anchor.json) pins all sources.

This qualifies a bounded happy-path handoff, not production public authentication
or failure cleanup. Client-close during bootstrap, borrowed-connection cleanup
after a bad/lost final response, arbitrary shared additional channels, full
allocator/cost proof and remaining peer/auth/transport variants stay open. The
production source and GMAC guard are unchanged; G0 remains open.

The [authentication-timeout lifecycle follow-up](validation-authentication-timeout.json)
fixes a production prerequisite for lost-final binding cleanup. A failed synchronous
SESSION_SETUP wait now removes both request lookups and settles the abandoned
promise without cancelling an unrelated session or fabricating response credits.
Late replies, including retirement during response parsing, cannot complete that
request again. Ordinary operation timeout tracking is retained. Promise waits now
restore the interrupt flag before wrapping interruption.

Six new regressions and 70 connected cases pass. The clean milestone passes
**882 tests in 101 suites, zero failures/errors/skips**, with license and JaCoCo
checks. Native compatibility then passes 16 forced-GMAC cases on Temurin 21 and
40 cases on actual Temurin 8u512 (16 native and 24 selected local), using the changed
production JAR. These native runs cover successful authentication/I/O and do not
inject final binding loss. The six timeout regressions use Mockito on Java 21;
they are not a full Java 8 authentication-failure matrix.

The [reserved-nonce bootstrap-abort follow-up](research/bootstrap-abort/README.md)
passes ten native research cases: eight bad/lost-final positive cases and two
unsafe controls. The positive cases keep the private bootstrap live and quiescent,
reserve its next native MID for possible original-key LOGOFF, and keep caller
binding inputs above that nonce. The older pooled session/open and pooled
connection remain usable after the private transport closes. The observer
independently verifies 360 signed inputs with no distinct-message actual-key/nonce
reuse; omitting the reservation reproduces reuse. Four cases force root loss
before cleanup: close raises `IOException`, neither allocates the reserved abort
MID nor exchanges LOGOFF, and the caller/older session remain usable.

This bounds two abort paths after the peer completes binding but the client cannot
accept its final reply. LOGOFF failure, spontaneous/racing root loss, close/authentication/publication
races, production bootstrap integration and the complete actual-key lifetime
argument remain required. G0 and the production GMAC binding guard remain open.

The [per-request reservation follow-up](research/concurrent/README.md) replaces
fixed 16-MID research intervals with a monotonic original-key high-water value.
Each binding request reserves its actual native MID. A collision is consumed by
an unsigned session-0 ECHO after auxiliary authentication, outside the allocation
lock, and the request retries. Original-channel signed application traffic and
LOGOFF share the same cursor. The first focused run passed 76 tests. Follow-up
hardening narrows the public callback to a session-specific operation, retires
timed-out collision ECHOs, prevents terminal-MID wraparound and limits each
collision probe to one credit before a deferred multi-credit request. Local
regressions also cover late timeout replies, abort cleanup and terminal-MID
exhaustion. The resulting five focused suites pass 81 tests, and full `check`
passes 889 tests in 102 suites with zero failures/errors/skips plus license and
JaCoCo tasks.

Seven detached Samba 4.23.10/Direct-TCP/BC/NTLM cases pass with the production
guard removed only in that checkout. Three application cases and two abort cases
independently verify 1,874 signed inputs with zero distinct-message nonce reuse.
The application cases use 23, 28 and 30 collision ECHOs rather than the previous
fixed-slot 96, 160 and 160, and each verifies 1,441,792 readback bytes plus
original-channel signed traffic after binding. Both unsafe controls still detect
the expected nonce reuse. Exact source hashes and results are in
[validation-per-request.json](research/concurrent/validation-per-request.json).

This does not close G0. A fresh candidate can require an unbounded number of
collision ECHOs after substantial earlier original-key traffic. Automatic public
auxiliary-session construction and cleanup, native cancellation/exhaustion and
the complete key lifetime, Kerberos/variable GSS rounds, reauthentication, both
providers/transports, independent Windows/target ONTAP behavior and production
guard removal remain unqualified.

## Remaining contract and release gates

Results below cover each complete gate. `NOT_RUN` includes gates with partial
passing evidence but an incomplete required matrix; it does not erase the scoped
results above. Windows testing is deferred for the current Linux work.

| Gate | Result | Missing authoritative evidence |
|---|---|---|
| G0 | NOT_RUN | Implemented construction and key/MID argument; finish current-public cancellation/notification lifetime variants, sustained churn/cost and remaining Linux failure/policy coverage |
| G1 | NOT_RUN | Existing regressions and full local check pass; remaining combined operational qualification is recorded per scenario |
| G2 | NOT_RUN | Complete local matrix across providers/transports/runtimes; the 40-case Java 8 profile passes, but the complete Java 8 multichannel/authentication/failure matrix remains unqualified |
| G3 | NOT_RUN | Public NTLM/Kerberos reauthentication passes; complete expiry/failure variants, notifications and replay/fencing/recovery cases |
| G4 | NOT_RUN | Native Linux/Samba acceptance passes in recorded configurations; mandatory-global-encryption binding remains unqualified; Windows deferred and ONTAP-specific behavior untested |
| G5 | NOT_RUN | Sustained concurrent I/O and cancellation-churn memory (including transport queues), replacement/recovery and comparative measurements |
| G6 | NOT_RUN | Complete source/provenance mapping, validated peer traces and complete reproducible review package |

Specific remaining implementation work includes authentication expiry/failure
variants, complete notification coverage, replay/fencing and recovery semantics,
sustained cancellation/transport-queue memory validation, and remaining matrix
assertions. The implemented public construction and its written invariants are
at the top of this document; earlier missing-construction statements describe
historical source states. Native bounded success does not establish every failure
or sustained operational requirement. Continue with the available Linux fixtures;
no external research access or Windows fixture is needed for that work.
