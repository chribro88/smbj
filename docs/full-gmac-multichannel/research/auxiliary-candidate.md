# Auxiliary-session candidate — research only

This candidate is not selected for production and does not close G0. The feature
worktree retains its GMAC binding rejection. The experiment runs in a detached
checkout at `/tmp/smbj-gmac-aux-prototype`, based on `cce87dd`, with a narrowly
recorded containment-guard patch and two additional integration-test sources.
No nonce layout, signing algorithm, cryptographic primitive, dependency or
native MID allocator is changed.

## Construction exercised

1. Negotiate the caller's physical connection and a separate connection that
   establishes the main logical session. The latter holds the original signing
   key. Before application traffic, record the MID of its signed final response.
2. Authenticate an auxiliary logical session on the caller's connection with a
   fresh authenticator. Its derived signing key must differ from the main
   session's original key. Native session tables retain both logical sessions.
3. Inspect the connection's next native MID without consuming or assigning it.
   Find a 16-MID interval with no original-key reservation. Consume preceding
   slots with actual ECHO requests under the auxiliary key, receiving their real
   credit grants. Reserve the interval before starting the main binding.
4. Use the existing binding builder with the original signing key. Verify every
   reply and derive the operational channel key through the existing machinery.
   On success, release only the unused reservation tail, then LOGOFF the
   auxiliary session without closing its physical connection.
5. Close the connection holding the original key, without LOGOFF of the main
   session, before application traffic. Subsequent ordinary operations use
   operational channel keys. Further bindings repeat steps 2–4 with independent
   physical credit windows, while retaining the original-key reservation state.
6. If binding fails after signing or transmission could have occurred, retain
   its entire reservation. A retry must consume those occupied MIDs under its
   auxiliary key before signing with the original key.

The supplied native builder bounds binding to 16 GSS requests. This experiment
reserves that many slots conservatively. A successful sequential attempt records
the actual native cursor after binding and releases its unissued tail. The
prototype bounds padding to 256 ECHOs and tests at most eight successful binds;
these bounds are research limits, not a proposed production support policy.

## What the independent observer checks

`GmacWireObserver` observes complete TCP frames outside SMBJ serialization,
signing and receive verification. It independently checks the prescribed GMAC
nonce and tags using standard JCE AES-GCM with empty plaintext. Actual key bytes
are copied in memory from established session/channel contexts. Key IDs and
normalized-message fingerprints use an ephemeral unexported HMAC key.

The observer checks every signed frame, including application traffic. It rejects
unknown signed sessions, incorrect sender roles and different authenticated bytes
under the same actual key/nonce. It also checks that native requests consume the
lowest connection-local MID range and do not exceed observed credits. Grants
read before the writer records its completed write are deferred until the
corresponding request is accounted for.

Only pseudonymous handshake/auxiliary metadata and aggregate verification counts
are exported. Raw keys, authentication tokens, SessionIds and packet bytes are
not exported. An injected connection failure can leave an incomplete frame;
its byte count is reported and no tag-verification claim is made for that frame.
The negative control uses two ordinary legitimate bindings without auxiliary
padding. It must fail specifically on distinct-message actual-key/nonce reuse,
so a successful candidate run cannot be explained by a disabled observer.

## Conditional safety argument

For the synchronous NTLM flows tested here, the original key signs the initial
final response and subsequent binding requests/non-final responses. The initial
response MID is excluded. Every binding's original-key MIDs occupy a disjoint
reservation, and a failed reservation remains consumed. Direction and CANCEL
retain their specified nonce discriminators. Ordinary application traffic uses
distinct operational keys after the original-key connection is retired.

This argument depends on enforcing the complete lifetime of the original key.
It is not sufficient to introduce padding only when a later binding is requested:
an already-used original primary channel can have a large occupied MID prefix.
The proposed bootstrap must occur before application traffic, and all later
original-key uses must pass through the same ownership policy.

The current proof is not complete for notifications, signed/interim responses,
GSS key availability or equality before export, reauthentication, concurrent
bindings, cancellation, every failure boundary, or key/sequence exhaustion. The
independent observer remains necessary when those paths are added.

## Cost and compatibility obligations

With the tested two-request NTLM exchange and successful reservation-tail
release, binding number `i` needs `2 * (i - 1)` ECHOs on a fresh connection.
Across `N` successful binds, that is `N * (N - 1)` ECHOs. A fully consumed failed
16-slot reservation increases subsequent padding accordingly. The original
operational connection carries 256 ECHOs before replacement in each scenario;
its application MID growth does not extend the original-key occupied prefix.
This is not a latency-independent or constant-cost construction.

The bootstrap needs three GSS exchanges in total: main-session establishment,
auxiliary establishment and binding. Each later bind needs auxiliary
authentication in addition to binding. The server must allow another logical
session for the identity. Those additional authentication and connection costs
are explicit compatibility dependencies; they are not established requirements
of the original plan.

Before selecting this design, resolve at least:

- The existing session's `getConnection()` still returns the retired original
  connection. The prototype records this consequence; it does not present it as
  preserved public API behavior.
- Cursor-based successful-tail release is valid only while no other caller
  consumes candidate MIDs. Production publication and concurrent sessions need
  request-specific accounting and a proven synchronization policy without I/O
  under a global lock.
- The prototype's TreeSet is bounded by the experiment. A production allocator
  needs bounded state, unsigned MID handling and measured lifetime cost.
- Auxiliary authentication failure, partial writes, final-response loss,
  cancellation and shutdown need complete reservation/cleanup evidence.
- The connection can return its identical cached terminal exception from an
  operation and subsequent auxiliary close. The research driver composes these
  failures explicitly to avoid Java try-with-resources self-suppression; general
  resource-composition behavior still needs a dedicated production decision.
- Key availability/equality through NTLM and Kerberos, hostname/SPN preservation,
  and the protocol's reauthentication wording remain unresolved.
- Windows and the target ONTAP release/configuration need independent traces.
  This Samba experiment cannot establish their auxiliary-session behavior.

The passing bounded cases are evidence that this wire construction is possible
for the recorded peer. They are not evidence that the full requested feature is
implemented or that this is an acceptable general production construction.

## Recorded execution

The final run passed five tests, with no failures, errors or skips. Four positive
cases independently verified 544, 613, 761 and 719 signed messages respectively,
with no observed distinct-message actual-key/nonce reuse. The separate negative
control completed two legitimate ordinary bindings and detected the expected
reuse. The injected fault left zero partial-frame bytes in either direction.

| Replacements | Lost binding | Successful binds | Padding ECHOs | Verified file bytes |
|---:|---|---:|---:|---:|
| 0 | No | 1 | 0 | 131072 |
| 3 | No | 4 | 12 | 524288 |
| 7 | No | 8 | 56 | 1048576 |
| 3 | Yes | 4 | 62 | 655360 |

The byte counts are cumulative exact readbacks across stages of a single
128 KiB file held open through each scenario. They are not throughput results.
The failed attempt adds two padding ECHOs and occupies 16 reserved MIDs, adding
16 ECHOs to each subsequent candidate. Source/report checksums and diagnostic
harness failures preceding the final run are in
[validation-auxiliary.json](../validation-auxiliary.json). Sanitized observations
are in [auxiliary-observation.json](auxiliary-observation.json).

The two Java files here are research artifacts and are not in the feature's
production or test source sets. To reproduce, create a disposable detached
checkout at `cce87dd2d8149e66b1f918137af78b3ec8cc0058`, apply only
`gmac-auxiliary-experiment.patch` there, and copy both Java files into its
`src/it/java/com/hierynomus/smbj/connection/` directory. Never apply the containment
guard patch to a production branch.

Use the owner-labelled, resource-limited pinned fixture from the adjacent
[README](README.md), substituting the unique name/owner
`smbj-gmac-aux-research` and loopback port **36532** for the older Go observer's
name and port. Keep the signing-only configuration and disposable credentials.
The Java observer accepts only this loopback endpoint. Verify effective GMAC
and multichannel settings before running. With the existing Java 21 toolchain,
Gradle caches and the test-memory init script recorded in the validation JSON:

```sh
SMBJ_GMAC_AUX_RESEARCH=true ./gradlew --offline --no-daemon --max-workers=1 \
  '-Dorg.gradle.jvmargs=-Xmx256m -XX:ActiveProcessorCount=2' \
  --init-script /tmp/smbj-full-gmac-test-limits.gradle \
  integrationTest -x buildSambaImage --tests '*GmacAuxiliaryBootstrapIT'
```

The environment opt-in is mandatory; an unopted run skips the experiment and
does not count as validation. The focused `licenseIntegrationTest` check also
succeeded. Only the task-owned fixture and detached checkout may be removed
after their identity and archived sources are verified.
