# SMBJ: full GMAC and multichannel implementation plan

**Date:** 13 November 2026, Australia/Sydney  
**Deliverable:** implementation plan, integration skeleton, requirement/test matrix and protocol decision record.  
**Target:** complete protocol-correct SMB 3.1.1 AES-GMAC support throughout SMBJ TCP multichannel operation.  
**Design status:** **G0 OPEN — the general binding signing-key/nonce uniqueness design is not established.**  
**Production status:** no production implementation or interoperability qualification is claimed by this document.

## 1. Completion contract

Full GMAC support is mandatory. The work is complete only when GMAC functions throughout negotiation, authentication, channel binding, ordinary and compound operations, cancellation, asynchronous responses, applicable notifications, channel replacement and shutdown, with the correct encryption interactions.

A guard that disables GMAC binding, a CMAC-only multichannel release, a first-channel-only implementation, a skipped GMAC integration suite, or an unspecified nonce-allocation function does not meet this contract. Necessary changes to existing SMBJ behavior belong in the implementation. The four reported defects must all be resolved in the resulting supported configuration.

This document supersedes the restricted feature policy in the earlier corrective plan. In particular, the earlier GMAC-binding guard is containment, not the requested implementation, and inherited SMBJ lifecycle defects cannot remain in a production-ready multichannel configuration. Separate prerequisite commits are appropriate; they do not remove those requirements.

The requested output is planning and skeleton code. No production worktree has been changed. The included Java examples establish concrete reusable portions of the design and diagnostics. They do not contain a fabricated solution to G0 or masquerade as a complete SMB client.

### What is established, and what remains open

| Item | Present evidence | Required outcome |
|---|---|---|
| Java GMAC capability | Existing SMBJ AEAD interfaces support the required AES-GCM operation with empty plaintext and SMB bytes as authenticated data. | Reuse the configured SMBJ provider and verify both built-in provider paths. |
| Shared session and file semantics | Existing SMBJ objects and donor multichannel tests establish the necessary integration model. | One logical session/tree/open state shared by independently credited connections. |
| Findings #2 and #3 | Supplied reproductions and inspected upstream lifecycle code identify SMBJ locking/publication defects. PR #910 contains directly relevant changes. | Prove real blocked-write abort and complete-Connection publication invariants on the combined branch. |
| Finding #4 | The supplied reproduction demonstrates comparison against the wrong configuration owner. | Every admitted channel supports the established session's effective operation limits. |
| Finding #1 | The ordinary binding flow combines the original signing key with repeated connection-local MessageIds. Existing donors do not establish a safe general solution. | Close G0 with a concrete protocol-compliant design, proof and interoperability evidence. |
| JDK/provider/kernel changes | None of the four findings establishes a defect in those dependencies. | Reassess a separately reproduced external defect if one is found; do not prescribe unrelated upgrades. |

## 2. Pin the inputs and retain existing code

The full feature worktree was not available in this session. The class map below is grounded in the complete public SMBJ source at the pinned upstream revision, the inspected prerequisite PR source, the supplied transport code and the reported feature behavior. It is not a claim to have inspected every line of the user's current feature branch.

| Input | Revision / evidence |
|---|---|
| Public SMBJ baseline | **1c5b9345df2898b8d57cf34d50ae599cab07b2b8**, inspected complete source archive |
| Feature reference supplied by user | **c2c8994**; replace this short label with the full current feature SHA before implementation |
| PR #907 | **0de6366ac201701be5e4a0aa74a5750dcff36281**; open/unmerged when checked |
| PR #910 | **3352e2b530bbc6c000781c708d499170c94d16a9**; open/unmerged when checked; includes the #907 prerequisite |
| Production Java baseline | Upstream sets compileJava.options.release to **8** |
| Test style | Existing JUnit Jupiter and Groovy/Spock tests; extend their families |
| Crypto baseline | Upstream Bouncy Castle **1.86**, plus the selectable JCE provider path |
| Integration fixture | Existing Gradle integrationTest suite, Samba image and external-server smoke-test conventions |

Before implementation, record the full feature SHA, its ancestry relative to both prerequisite PRs, the resolved dependency graph and the selected transport/provider configuration. Reuse feature code that already satisfies this plan. Inspect changes from the supplied review revision rather than assuming every finding remains unchanged.

Do not apply #907 twice through a second cherry-pick of #910. Keep prerequisite lifecycle changes distinguishable in history so they can be reviewed and merged independently.

Historical counts such as the supplied 623 unit tests and earlier Samba results are prior evidence, not validation of the final combined revision. Upstream's **check task does not itself execute integrationTest**. Record those results separately.

## 3. G0: resolve original-key GMAC binding before approving the design

### 3.1 The concrete problem

An established session has signing key K. Two new connections each negotiate with MessageId 0 and then normally begin binding with MessageId 1. Binding uses the original session signing key until the new channel key is available.

For a signed server response with MessageId 1, the prescribed nonce is:

    01 00 00 00 00 00 00 00 01 00 00 00

Two different NTLM challenge responses can therefore authenticate different bytes with the same K and nonce. Later NTLM authentication requests or first-round Kerberos authenticators can also differ at overlapping MessageIds. This example follows the published ordinary flow and is consistent with the user's reproduction; it is not a new live-server experiment performed for this plan.

The original channel also matters: its signing key initially equals the session signing key. Tracking only secondary bindings is insufficient. The argument must cover the actual key's entire lifetime, including initial authentication responses, primary traffic, all binding rounds, reauthentication, failures and retries.

### 3.2 Protocol constraints

| Constraint | Primary reference | Design consequence |
|---|---|---|
| GMAC nonce layout is prescribed. | MS-SMB2 §3.1.4.1 [S1] | Do not introduce a random signing nonce or channel-ID suffix. |
| Binding requests are signed and checked with the original session signing key. | §§3.2.4.1.1, 3.3.5.2.4 and 3.3.5.5 [S2, S3, S4] | A client cannot substitute a newly derived channel key unilaterally. |
| Signed non-success session-setup responses use the session signing key. | §3.3.4.1.1 [S5] | Intermediate authentication responses belong in the proof. |
| A new connection starts with sequence window {0}; credits extend it and allocation uses the lowest available sequence/range. | §3.2.4.1.6 [S6] | A global counter cannot simply choose an arbitrary high MessageId on a new connection. |
| Binding SESSION_SETUP requests must not be encrypted. | §3.2.4.1.8 [S7] | Encrypting binding is not an accepted workaround. |
| Initial channel/session signing keys coincide; binding does not rotate the original session key. | §§3.2.5.3.1 and 3.3.5.5.3 [S8, S9] | Later channel keys do not repair signatures already made under K. |

Serializing binds does not change the repeated values. Generating a unique channel key after authentication is necessary but does not solve the preceding exchange. A provider's acceptance or rejection of a repeated initialization is not a protocol-wide uniqueness guarantee.

An auxiliary authenticated session might consume low MessageIds under another key before binding. That remains an unvalidated research alternative: it introduces extra authentication/session state, must coordinate original-channel future values, and can require catch-up traffic proportional to the primary connection's MessageId. It is not the selected design, a donor-backed fix or a hidden requirement in the skeleton.

### 3.3 New corroborating evidence

The November 2026 ksmbd discussion independently reports repeated original-key GMAC response nonces during binding. Its demonstrated server defect permits responses to an unverified binding request. The proposed verification fix addresses that unauthenticated signing oracle; it does not itself establish uniqueness for legitimate bindings [S15].

The discussion explicitly raises legitimate-binding reuse, and the later cover letter separates the GMAC addition from the verification fixes. The inspected Samba client/server paths also contain connection-local MessageIds and original-key binding; the inspected Go donor documents its uniqueness limitation [D2, D7].

This does not prove that every possible client-only construction is impossible. It does mean that copying those donors cannot honestly be presented as the solved design. The ksmbd finding is not evidence that SMBJ requires a Linux kernel patch.

### 3.4 Exact work to close G0

1. Obtain an authoritative interpretation or documented interoperable construction for the constraint combination above. Use the prepared questions and evidence in **protocol-resolution.md**; no question has been sent externally.
2. Trace both directions of real GMAC binding, with controlled test credentials, across one-round and multi-round authentication. Record original-key versus channel-key identity, MessageId, derived nonce, signed-byte digest, credits and authentication status.
3. Account for primary-channel traffic, two concurrent binds, two sequential binds, failed-then-successful binds, repeated replacement channels and reauthentication.
4. Specify the algorithm's allocation/state transitions, synchronization, rollback/burn rules, key lifetimes, cleanup and cost. The algorithm must preserve valid credit/sequence behavior and existing handle semantics.
5. Produce a written uniqueness argument for every signing-key domain. Independently test it with an observer outside the signer, so a shared mistake in the implementation and its tests cannot manufacture agreement.
6. Resolve the two related specification interpretation issues: the reauthentication signing key on an existing bound channel, and the SMB 3.1.1 binding KDF/transcript wording described in protocol-resolution.md.
7. Demonstrate the resulting wire behavior against appropriate independent servers. Record the exact protocol revision/product behavior relied upon.

**G0 closes only when these items produce an actual supported mechanism.** A diagnostic assertion, rejection of GMAC, a placeholder allocator or a successful sign/verify round trip does not close it. If clarification requires a protocol amendment or a server change, add the explicit dependency and return it for the requested reassessment. The full-support target remains unchanged.

## 4. State ownership and request flow

Keep the existing SMBJ object model and extend the smallest useful seams.

| Owner | State it owns | State it must not duplicate or reset |
|---|---|---|
| Session / SessionContext | Logical SessionId, authentication identity, original signing context, shared tree/open state, encryption keys and their nonce domain, effective operation limits, channel membership | Independent per-connection credits or request maps |
| SessionChannel | Exact Connection identity, negotiated policy and signing algorithm, derived channel signing context, lifecycle and scheduling eligibility | A divergent copy of logical session/tree/open state |
| Connection | Transport, negotiated context, SequenceWindow, OutstandingRequests, terminal state and connection generation | A session-wide MessageId sequence |
| Binding attempt | Candidate connection, fresh authenticator/GSS context, exact preauthentication transcript, authentication phase and provisional key | Mutable original-session transcript or another binding's authenticator |
| Request | Owning connection, MessageId/range, credits, response completion, async identity and cancellation state | A second chance to choose a different connection after signing |

A regular send has a single ownership order:

1. Validate the session, operation and required transfer size.
2. Select an eligible active channel without holding a global lock during I/O or credit waits.
3. Reserve that connection's credits and MessageId/range.
4. Finalize the header, operation extent and compound boundaries.
5. Select the correct signing context for that exact connection and message phase.
6. Serialize and sign, or encrypt according to the protocol's message policy.
7. Register and transmit through the same connection.
8. Verify incoming data against that receiving connection and the appropriate provisional/active key before accepting authenticated effects.
9. Complete or fail the request once; release only resources whose ownership is established.

Once a request has consumed signing state or reached a transport with an ambiguous outcome, do not recycle its nonce or move its serialized bytes to another channel. A protocol-authorized replay is a new, explicitly constructed operation using the destination connection's identifiers, keys and replay rules.

## 5. Implementation work packages

All packages contribute to one full-support target. Work on foundations can proceed while G0 is resolved, but feature completion and production approval depend on every applicable gate.

| Package | Work | Prerequisites | Completion evidence |
|---|---|---|---|
| W0 | Resolve binding/reauthentication/KDF protocol decisions | Pinned source/spec evidence | G0 decision record and cross-key-lifetime proof |
| W1 | Integrate and verify lifecycle prerequisites | Exact feature/PR ancestry | Original #2/#3 reproductions and full-path race tests |
| W2 | Negotiation and GMAC packet signing | Existing provider interfaces | Provider/vector/negative/codec tests |
| W3 | Authentication, transcripts and channel key ownership | W2; W0 for disputed behavior | NTLM/Kerberos/multiround staged-verification tests |
| W4 | Safe binding and channel publication | W0, W1, W3 | Repeated/concurrent binding and nonce-lifetime tests |
| W5 | Receive dispatch, CANCEL, async and notifications | W2–W4 | Per-path authenticated dispatch and race tests |
| W6 | Admission, partial writes and channel recovery | W1, W4 | #4 regression, handle/credit/write/fencing tests |
| W7 | Shared-session encryption interactions | W3, W4 | Transform nonce/key ownership and policy tests |
| W8 | Independent-server integration and performance | W0–W7 | Forced-GMAC live matrix, integrity and fault results |
| W9 | Upstream review package | All acceptance evidence | Focused commits, provenance and reproducible report |

### W1. Lifecycle prerequisites: findings #2 and #3

**Files:** Connection, DirectTcpTransport, PacketReader, SequenceWindow, OutstandingRequests, Request, SMBClient connection-pool handling; also AsyncDirectTcpTransport and AsyncPacketReader.

Reuse the relevant behavior in #907/#910. Source inspection shows #910 closes the raw socket outside the writer lock and rejects late-created sockets using a disconnect generation. Recheck the combined feature branch and retain any equivalent fixes already present.

The required invariants are:

- A terminal transition prevents subsequent socket/channel publication.
- Shutdown can reach raw socket closure while another thread is blocked writing to it. It must not first acquire the writer's lock, obtain a read lock behind that writer, or flush/close BufferedOutputStream.
- A socket factory completing after shutdown has its returned socket closed and cannot start a new usable reader or transmit NEGOTIATE.
- The complete Connection path rechecks/coordinates state after transport connection and before negotiation. A transport-only check does not cover every Connection race.
- Concurrent closes share a completion result; one caller must not report completed closure while another still owns an unclosed socket.
- Credit waiters, existing requests and requests racing with registration fail once with a meaningful terminal cause.
- No user completion callback runs while an internal lifecycle lock is held. Reader-triggered shutdown must not join or wait for itself.
- Pool eviction checks connection identity so closure of an old object cannot evict its replacement.

Treat connection establishment as a generation-owned operation. Create/configure the candidate outside long-held lifecycle locks; publish it only if the generation and lifecycle state remain valid. Shutdown marks the generation terminal and detaches resources before performing closure. Starting the reader, entering negotiation and registering requests must participate in that ownership scheme.

Use monotonic Connection states such as NEW, CONNECTING, NEGOTIATING, ACTIVE, CLOSING and CLOSED, or equivalent existing state with the same invariants. Avoid adding a parallel state machine that disagrees with the existing abort cause.

**Tests:** a real loopback TCP peer that accepts but stops reading, a sufficiently large ongoing write, a blocked SocketFactory, a pause after transport completion but before Connection negotiation, concurrent close callers, request-registration races, and close of every active/candidate channel. Verify both selectable TCP transports. Synchronize test preconditions with latches/observable state and bounded deadlines rather than sleeps.

Java Socket.close already defines interruption of blocked socket I/O [S16]. If a minimal standard-JDK reproduction fails that contract, isolate it separately. The reproduced SMBJ lock ordering is not evidence of such a JDK defect.

### W2. Negotiation and packet signing

**Files:** SmbConfig, SMBProtocolNegotiator, NegotiationContext, ConnectionContext, SMB2NegotiateRequest/Response, SMB2NegotiateContextType/factory, PacketSignatory, Signatory and NoSignatory.

Add or retain the feature branch's signing-capabilities codec and configured algorithm list. Validate structure lengths/counts, selected algorithm membership, unsupported selections, duplicate/conflicting contexts and dialect applicability. Implement the protocol's context-absence behavior without treating it as successful forced-GMAC coverage. An explicit GMAC-only configuration must never silently operate under another algorithm.

Store the negotiated algorithm separately from raw key material and select the correct immutable signing context per channel. Preserve HMAC-SHA256 and AES-CMAC behavior for existing dialect/configuration combinations.

Reuse SecurityProvider.getAEADBlockCipher with AES/GCM/NoPadding. It already accepts GCMParameterSpec, segmented authenticated data and finalization. GMAC requires no plaintext encryption and a 128-bit tag; implement no AES/GHASH arithmetic and add no cryptographic dependency merely for GMAC.

The operation authenticates the message extent as:

    bytes before Signature
    sixteen zero bytes
    bytes after Signature through this compound member's padding

The direct-TCP framing prefix is outside that extent. Header-relative offsets must remain correct when the SMB header begins at a nonzero buffer position. Validate bounds before reading or hashing. The packet bytes must be stable from final header construction through serialization/signing/transmission.

Use independently initialized operation state per message and separate transmit/receive state. Preserve the configured provider rather than silently substituting one. Validate the expected sender role independently of caller-controlled header flags. ASYNC is not an extra nonce discriminator; CANCEL has its prescribed discriminator.

Verification must authenticate the exact received bytes with the signature field logically zeroed, preserve the bytes required by preauthentication hashing, and use provider authentication or constant-time tag comparison. Include malformed/unsigned-policy cases, corrupted header/body/padding/signature, wrong key, wrong role, compound boundaries and reused cipher-state errors.

**Donors:** SMBJ's AEAD abstractions first; Go's known-answer/nonce/segmentation tests; Rust's fixed SMB packet vector; Python's forced-algorithm interoperability scenario. The included concrete signing skeleton uses these existing SMBJ interfaces.

### W3. Authentication, transcripts and signing contexts

**Files:** SMBSessionBuilder and its BuilderContext pattern; Authenticator/NtlmAuthenticator/SpnegoAuthenticator; Session/SessionContext; SessionTable/preauthSessionTable; SMB2SignatureVerificationPacketHandler.

Each binding attempt gets a fresh authenticator and its own transcript initialized from the candidate connection's negotiate exchange. Hash exact wire messages in the specified order. Parallel bindings must not overwrite the original session's transcript, cryptographic keys or authentication state.

Preserve the original logical server authentication identity when a secondary TCP connection uses another address. In particular, a different IP must not silently change the intended Kerberos service principal. Include hostname-to-address and multiple eligible endpoint cases in the authentication tests.

Keep distinct phases for initial authentication, binding with the original signing key, final binding verification with a provisional channel key, and authenticated operation. Establish when the GSS context/key becomes available and which final-response bytes are included in the KDF transcript; encode that order in tests rather than mutating a shared hash opportunistically.

The public baseline's signature handler explicitly bypasses SESSION_SETUP verification. Replace that blanket bypass with phase-aware verification. Initial unsigned exchanges and protocol exceptions remain valid; required signed binding/final responses must be verified before the candidate becomes usable.

For SMB 3.1.1, use the signing-key label and binding preauthentication context established by the protocol decision and independent vectors. The current client binding page's legacy SMB2AESCMAC/SmbSign wording must not be copied blindly where the SMB 3.1.1 server rules use SMBSigningKey and the binding transcript [S9, S10]. Preserve existing deriveKey/KDF machinery and the specified GSS key input.

Reauthentication on an already bound channel has conflicting client/server key wording in the inspected sources. Resolve and document the selected interpretation in W0, with a real peer trace and both signing directions. Do not apply the original-key binding rule indiscriminately to every SESSION_SETUP.

Tests must include NTLM and Kerberos, multi-round authentication, malformed/intermediate/final signature failures, bad credentials, session expiry, reauthentication, cancellation and closure during authentication. A failed candidate must not become eligible or accidentally discard healthy session channels.

### W4. Binding and atomic channel publication

**Files:** SMBSessionBuilder binding path; Session channel collection; per-attempt state; Connection session registration.

This package consumes the **approved W0 algorithm**. Its implementation cannot be completed by adding a generic nonce allocator interface whose semantics remain undecided.

Before publishing, validate the server/session identity and protocol policy, complete authentication, verify required responses, derive the correct channel signing context, and confirm that both session and candidate connection remain live. Publication must atomically transition one candidate from BINDING to ACTIVE while registering exactly that connection's channel state.

A session shutdown, candidate abort or authentication failure wins over publication. Cleanup removes candidate-only state and closes that transport without corrupting shared keys or existing channels. A losing publication attempt cannot start application I/O.

The candidate must preserve the established session's identity, relevant capabilities, signing/encryption policy, dialect, preauthentication algorithm and effective operation limits. Distinguish protocol-mandated equality from a deliberate compatibility restriction; support legal combinations required by the final coverage contract and test rejection statuses/cleanup for illegal ones.

Validate every selected endpoint against the authenticated server/session policy. Multiple DNS addresses alone do not establish that they are eligible channels for the same session. Retain the existing explicit endpoint API and apply the same admission rules wherever advertised interface information is used for automatic selection.

Maintain independent connection credits and request maps. Select the channel before MessageId assignment/signing. Ordinary channel data uses its channel signing key; the original binding key and the encryption key domain remain explicit owners.

Required success tests include adding two or more channels, concurrent bindings, repeated sequential bindings, failed-then-successful attempts, retiring the original connection, late replacement after substantial traffic and operations through an already-open handle. The independent nonce observer must cover the full actual-key lifetime, not only one connection or a single bind.

### W5. Receive dispatch, cancellation, asynchronous traffic and notifications

**Files:** Connection.init handler chain; SMB2CompoundedPacketHandler, SMB2IsOutstandingPacketHandler, SMB2SignatureVerificationPacketHandler, SMB2CreditGrantingPacketHandler, SMB2AsyncResponsePacketHandler, SMB2LeaseBreakPacketHandler and SMB2ProcessResponsePacketHandler; Connection.CancelRequest and Request.

Classify frame/compound members before using an outstanding-request lookup as the only admission rule. A legitimate server notification can carry a MessageId that does not identify an outstanding client request; GMAC-related notifications can use random MessageIds [S11]. Authenticate the applicable notification with the correct connection/session context, then route it to the relevant handle/session callback. Preserve documented unsigned exceptions; neither unconditional acceptance nor unconditional rejection is correct.

Carry exact receiving-connection identity through decryption, signature verification, credit processing and response completion. A response arriving on another connection must not accidentally complete a request merely because its numeric MessageId matches. Validate compound member offsets, lengths, padding and policy individually.

Remove any path that accepts unauthenticated credit or response effects just because a session object exists. Where the protocol permits an unsigned interim response, encode that explicit phase/status exception and verify the final authenticated completion. Do not count interim progress as operation success.

Cancellation belongs to the original request:

1. Retain the request's owning connection and MessageId.
2. Atomically snapshot the current synchronous/asynchronous identity while claiming the single cancellation attempt.
3. Construct CANCEL for that owner without consuming another credit or MessageId and without session channel selection.
4. Sign once using the correct context and prescribed CANCEL discriminator.
5. A transport failure after possible signing/publication does not authorize a newly serialized CANCEL with the same nonce and altered AsyncId/flags.
6. A completion racing with cancellation must produce one terminal user-visible result and no duplicate resource release.

The included RequestCancellation skeleton illustrates ownership and atomic decision-making. Fold that behavior into existing Request/Connection code rather than introducing a second future/cancellation framework.

### W6. Admission, partial writes, scheduling and recovery

**Files:** Session, Share, SMBSessionBuilder admission, SMB2Writer, SMB2WriteRequest, ByteChunkProvider implementations, File/FileOutputStream and request/channel scheduling.

#### Finding #4: original effective limits

Capture immutable requirements from the original authenticated session using the same calculations that existing Share objects use. For read, write and transaction operations, combine the original configured limit with the original negotiated maximum and any applicable credit/capability restriction.

A candidate must support those requirements. Its configuration must not redefine what existing Shares can issue. A session that issues 1 MiB writes must reject a channel whose usable write limit is 32 KiB, even if that candidate is itself configured for 32 KiB.

Also check local transport/decoder constraints and relevant capabilities. Compare effective behavior, not SmbConfig object identity. Test all three limits and exact-boundary equality. If a later design chooses per-channel segmentation instead of rejecting a smaller channel, it must prove the same public semantics for every operation and preserve full compatibility; it is not an incidental admission shortcut.

#### Partial writes and acknowledged progress

Retain each in-flight write's submitted extent until its response determines acknowledged progress. For a valid short write, advance the file offset by the returned count and submit the unsent tail using a newly allocated request. Retain only bounded in-flight data; do not retain or recopy an entire file merely to handle a short response.

Reject zero progress where it would otherwise cause an infinite retry loop, counts beyond the submitted length, invalid negative/overflowed interpretations and offset arithmetic overflow. Apply the same rules to synchronous and asynchronous APIs. Test multiple successive partial responses, a final one-byte tail, cancellation and a failure after some bytes have been acknowledged.

An explicit short-write response and a lost response have different evidence. After an ambiguous transport failure, do not report unacknowledged bytes as written and do not invent transparent exactly-once replay. Apply the protocol's command/open-specific recovery and replay rules; where they cannot establish success, propagate the defined failure/uncertainty outcome.

#### Channel choice, failure and existing handles

Keep independent credits and request maps. Avoid holding a session-wide lock while waiting for credits or a blocked socket. Preserve fairness and use available healthy channels; a stalled connection must not stall unrelated eligible work. Once credit/MID/signing ownership is assigned, channel choice is fixed for that transmission.

Test shared file/tree identities across channels, simultaneous disjoint range writes and correct total content. Include channel sequence/fencing behavior and applicable replay flags during channel change. Pike's stale-write/fresh-write scenario is a useful behavioral donor [D4]; Microsoft's alternate-channel replay example provides an independent protocol reference [S12].

When another channel remains, retire the failed channel, settle its outstanding work according to the protocol and continue eligible session operations. When all channels are lost, apply the negotiated open/session recovery rules and expose a truthful outcome. Recovery must not silently reset a nonce allocator under retained key material or reuse stale tree/file identities.

### W7. Encryption interactions

**Files:** PacketEncryptor, SMB3DecryptingPacketHandler, Session.shouldEncryptData/send and shared session security state.

GMAC signing nonces and SMB transform-encryption nonces are separate mechanisms. A shared encryption nonce allocator does not fix binding signing nonces.

For encryption keys shared by channels, nonce allocation must be owned by the actual session encryption-key domain. All channels using that key must obtain values from the same non-resetting state. Handle counter exhaustion explicitly, retain state while any user of that key remains, and require fresh keys or correctly retained allocator state on recovery. Do not use System.nanoTime as a uniqueness proof.

Keep the specified GCM/CCM transform nonce lengths and padding, correct authenticated transform fields and session identity checks. Preserve the configured encryption algorithms and provider. An encrypted message is processed under the protocol's encryption/signing rules; forcing an extra GMAC signature everywhere is not the definition of full support.

Test signing-only, session-required encryption, share-required encryption, encrypted responses/notifications, wrong session identity, authentication-tag failure and traffic across multiple channels using the same encryption key. Binding remains subject to the explicit no-encryption rule in G0.

### W8. Independent-server integration and performance

Extend the existing IntegrationTest/SambaContainer and external-server smoke patterns. Reuse existing SMBJ_IT_HOST and related fixture conventions where they fit; inspect and document the actual supported credentials/share settings instead of creating a competing configuration system.

| Axis | Required coverage |
|---|---|
| Signing | Force AES-GMAC and assert the negotiated value; separately retain CMAC/HMAC and context-absence regression coverage |
| Providers | Default Bouncy Castle and selectable JCE path |
| Transports | DirectTcpTransport and AsyncDirectTcpTransport |
| Authentication | NTLM and Kerberos, relevant authentication rounds and reauthentication |
| Channels | One, two and more than two; concurrent binds; sequential/retried/replacement binds; original-channel retirement |
| Operations | Existing-handle reads/writes, compound operations, metadata, directory operations, CHANGE_NOTIFY, cancellation and applicable notifications |
| Security policy | Signing-required, encryption-required and compatible mixed operation policies |
| Peers | Suitable pinned Samba and Windows profiles; the target ONTAP version/configuration for deployment qualification |
| Failure | Malformed signatures, incompatible negotiation, connection loss, stalls, pending/cancel races, late socket completion and shutdown under load |

A GMAC-incapable server cannot provide GMAC interoperability evidence. Record that capability result and test correct explicit-GMAC rejection/negotiation behavior separately. Do not count a CMAC fallback or skipped case as a GMAC pass. Qualify each target against the feature profile it actually supports and obtain GMAC evidence from capable independent peers.

A Samba container is an optional way to supply a test server. It is not a production dependency or the answer to G0. The planner and primitive checks do not require Docker. For container-based integration, verify Docker API connectivity, fixture image startup, mapped-port reachability and the Testcontainers resource reaper before recording protocol results. An infrastructure failure before the first SMB exchange is **INFRASTRUCTURE_FAILURE**, not a protocol pass, protocol failure or skip that completes a gate.

Use the project's separate tasks:

    ./gradlew clean check
    ./gradlew integrationTest

Focused commands for the proposed new JUnit classes will use the existing test filtering mechanism, for example:

    ./gradlew test --tests '*GmacBindingNonceTest'
    ./gradlew integrationTest --tests '*GmacMultichannelIntegrationTest'

These class names are proposed additions. The commands become executable once their tests and appropriate fixtures are implemented. Keep the exact feature SHA, fixture version, selected algorithms and test counts with every result.

Compare multichannel against an already-pipelined single-channel baseline with the same integrity/durability settings. Measure throughput, CPU, allocation/GC, latency percentiles, credit occupancy, memory bounds, fairness and recovery time. Include a stalled channel and sustained replacement/retry activity. Record host/network/storage limits so additional channels are not credited with, or blamed for, a different bottleneck.

GMAC operation state must be safe under concurrent transmit/receive. Optimize only after correctness measurements identify an actual cost. Use segmented authenticated data and existing packet buffers to avoid full-message copies where ownership makes that safe.

### W9. Make the upstream contribution reviewable

Prepare a sequence of focused commits or dependent PRs:

1. Existing future/lifecycle prerequisites and their exact race regressions.
2. Negotiation/signing provider integration and crypto/codec tests.
3. Session/channel ownership, authentication verification and the approved G0 mechanism.
4. Dispatch, CANCEL, notification and encryption interactions.
5. Admission, write progress, scheduling and recovery.
6. Independent-server integration, performance evidence and documentation.

The feature branch is complete only when the full set is integrated and the acceptance matrix passes. Splitting review work does not redefine the deliverable as a partial GMAC implementation.

PR descriptions must state the user-visible behavior, required protocol interpretation, compatibility effects, provenance and exact validation. Include a compact key/nonce-lifetime argument and relevant captures in the security review evidence. Keep test credentials and sensitive authentication material out of public reports.

Maintainers control PR acceptance. A complete, reproducible contribution can be prepared; acceptance or timing cannot be guaranteed. Any request to remove required GMAC paths must be assessed as a scope change, not described as satisfying this plan.

## 6. Requirements, test ownership and release gates

The accompanying **test-matrix.csv** contains 63 scenarios with fixture, variant, source and assertion columns. Every acceptance scenario is currently marked **planned**. The skeleton checks are a separate, explicitly limited execution record.

| Requirement family | Main code owner | Required evidence |
|---|---|---|
| Protocol-correct key/nonce lifetime | Binding/authentication/channel ownership | G0 resolution; original-key and channel-key observer traces; no cross-binding or primary-traffic collision |
| Negotiation and compatibility | Protocol negotiator/context codecs | Positive/negative context tests, dialect regression and forced algorithm assertion |
| GMAC primitive/message extent | PacketSignatory/provider adapter | Independent known vectors; offset/compound/padding/role/tamper tests on both providers |
| Initial/binding/reauth verification | SMBSessionBuilder and signature handler | Phase/key/transcript tests and independent-server responses |
| Credit and connection ownership | Connection/SequenceWindow/Request | Correct ranges, owner-local responses/CANCEL and no post-sign rerouting |
| Notifications and asynchronous work | Receiver handlers | Correct authentication and dispatch even without an outstanding MID; final response and CANCEL races |
| Effective channel limits | Session/Share/admission | The exact 1 MiB-versus-32 KiB reproduction for write plus read/transact cases |
| Write progress and recovery | SMB2Writer/channel lifecycle | Short-write tails, content integrity, uncertainty/replay/fencing outcomes |
| Shutdown/publication | Transport/Connection/channel collection | Real blocked socket write; late-created socket; no post-close NEGOTIATE; waiters completed |
| Encryption interaction | Session key domain/PacketEncryptor | Shared-key nonce uniqueness and transform policy/authentication tests |
| Interoperability and performance | integrationTest and external fixtures | Actual GMAC on capable independent servers, all required variants, measured behavior |

### Acceptance gates

- **G0 — design:** resolved key/nonce and related signing interpretation, explicit algorithm and proof, no unsupported allocator assumptions.
- **G1 — baseline integration:** exact feature and prerequisite revisions recorded; all four original reproductions exercised on the resulting branch.
- **G2 — local correctness:** codec, crypto, auth, ownership, cancellation, admission, lifecycle and encryption tests pass on the supported provider/transport/runtime combinations.
- **G3 — protocol behavior:** negative/tampering/compound/async/notification/replay/fencing tests pass; all required authentication phases verify correctly.
- **G4 — live interoperability:** forced-GMAC multichannel succeeds against capable independent peers and the deployment profile is qualified; no required test silently skips.
- **G5 — operational behavior:** sustained concurrency, bounded memory, partial writes, channel replacement, shutdown and integrity checks pass; measured performance is acceptable against the agreed baseline.
- **G6 — review package:** protocol mapping, donor provenance, source pins, licenses, logs and reproducible commands are complete.

Use explicit result states: PASS, FAIL, NOT_RUN, BLOCKED and INFRASTRUCTURE_FAILURE. A test may be inapplicable only when the documented protocol condition truly does not hold; the corresponding feature capability still needs evidence in an applicable fixture. A large aggregate unit-test count cannot substitute for a missing required scenario.

## 7. Concrete skeleton and its evidence boundary

The **skeleton/** directory contains actual Java source and an executable verification harness, not production changes to SMBJ.

| File | Implemented planning component | Integration destination |
|---|---|---|
| GmacSigning.java | Existing SMBJ AEAD provider; prescribed nonce; sender-role validation; signature zeroing; bounds/compound extent; provider tag verification | PacketSignatory and exact channel/phase signing-context selection |
| SessionRequirements.java | Immutable original effective limits and candidate admission | Session/Share requirements and SMBSessionBuilder admission |
| RequestCancellation.java | Exact original connection ownership, atomic async snapshot, single cancellation attempt | Existing Request and Connection.CancelRequest |
| GmacSkeletonChecks.java | Known vectors, corruption/offset/padding/nonce checks, admission and cancellation checks; separate collision diagnostic | Existing JUnit test families |
| verify_skeleton.py | Compiles against supplied upstream source and executes the actual configured providers | Reproducible planning verification |

There is **no safe binding orchestration in the skeleton**, because G0 remains unresolved. No hidden allocator, placeholder method or GMAC-disabled binding path is supplied as the purported solution. The full architecture and required integration work remain in this plan. This is the material limit preventing the package from being described as an implementation-ready, complete GMAC multichannel design.

### Checks actually executed

- Compiled against the pinned SMBJ security interfaces with OpenJDK **21.0.13**, using Java 8 source/target syntax and bytecode.
- Ran **11 distinct focused scenarios with each actual SMBJ provider**: JCE and default Bouncy Castle 1.86. That is **22 provider/check executions**.
- Verified the Go empty-GMAC expected tag and the Rust fixed SMB LOGOFF packet/tag, plus message extent, tampering, role, nonce, admission and cancellation cases.
- Separately reproduced distinct messages using the same key/nonce and both verifying. This is a diagnostic of the unresolved allocation problem, not a passing security-conformance result.
- The installed trimmed compiler runtime could not supply Java 8 release symbols. A full --release 8 build and a Java 8 runtime execution remain acceptance checks; the harness records the weaker source/target check accurately.
- No complete SMBJ build, live SMB binding, container integration, ONTAP test or production throughput test was run for this package.

The exact command, dependency hash and output are in skeleton/README.md and skeleton/validation.log. The standalone verification harness does not download dependencies or require server credentials.

## 8. Donor provenance and reuse policy

Reuse SMBJ's own abstractions and family style first. Favor permissively licensed test vectors and patterns where they supply equivalent behavior. Port only the behavior verified at the pinned revision; a project's feature name is not evidence that its binding nonce problem is solved.

| ID / project | Pinned revision | Useful donor | Treatment |
|---|---|---|---|
| D1 — SMBJ | 1c5b9345df2898b8d57cf34d50ae599cab07b2b8 | SecurityProvider/AEADBlockCipher, builder, signatory, request, transport and test families | Apache-2.0; first-choice existing code |
| D2 — Go go-smb2 | 7f69f65878329522ceb556435bdeb3cde6552656 | GMAC vectors, segmentation, CANCEL/failure tests, binding authentication/retry tests | BSD-2-Clause; adapt with notices; documented binding nonce limitation remains |
| D3 — Python smbprotocol | 3acc9843483716a1d0c033e3368675ea8419fb1f | GMAC AAD/empty-plaintext implementation and forced-GMAC server test | MIT; adapt applicable patterns; no multichannel donor claim |
| D4 — Dell Pike | bcbb343c5bfb7dd3198d2d79d7381dfdad0f0873 | Existing-handle binding and stale-write/fresh-write scenarios | Core BSD; scenario donor; inspected signing is CMAC |
| D5 — Rust smb-rs | f4524d032c8951cc288e1c8231ad68588583abda | Fixed SMB LOGOFF GMAC vector | MIT; vector adapted with notice in skeleton |
| D6 — Microsoft protocol suite | 29ddb4238a5443b7499e82934c90cc898861c5e7 | Forced GMAC positive and bad-signature rejection scenarios | MIT; scenario donor |
| D7 — Samba | a167c65ab6f7c0f95ef69f7f16c3426114cb8393 | GMAC operation/CANCEL and incompatible-binding scenarios; client/server behavior inspection | GPL source; reference implementation and test peer, no verbatim implementation transplant in this bundle |
| D8 — codelibs/jcifs | 992699c5192859494017778b7cca06bf5d940adf | Java nonce/signing and forced-GMAC file-I/O tests | Inspected tests LGPL-2.1-or-later; behavioral reference, no verbatim transplant in this bundle |

These are provenance facts, not a blanket legal conclusion about every possible form of reuse. Preserve applicable notices and identify the origin of each adapted unit. The included code uses newly written Java integration/control flow and the named permissive test vectors; it does not copy Samba or jcifs implementation code.

For each eventual production change, record donor commit/path/symbol, copied/adapted/specification-derived status, changed assumptions and matching test IDs. Do not replace another project's license header with an SMBJ header or treat a copied test as independent evidence when it shares the same assumptions.

## 9. Questions already answered and inputs needed at execution

**No container is required to read this plan or execute the primitive skeleton checks.** A container can supply a Samba test peer later. It cannot settle a contradictory or incomplete binding design merely by existing.

**No additional cryptographic library is identified as necessary.** Existing SMBJ AEAD provider interfaces are sufficient for the GMAC primitive. Findings #2/#3 belong to SMBJ lifecycle code; #4 belongs to admission policy. G0 concerns protocol/state coordination and any clarified peer requirements, rather than an established JDK/provider/kernel defect.

Before producing the actual patch, use the complete current feature branch so the integrations fit its existing code and avoid duplicate fixes. Before production qualification, record the target ONTAP release/security configuration and provide an appropriate way to run the external-server tests. Those are execution inputs; they did not prevent preparation of this plan or its concrete skeleton.

The outstanding protocol decision is recorded explicitly in protocol-resolution.md. It includes ready-to-use questions and an evidence schema. It has not been posted to maintainers or vendors. Obtain authorization before sending an external message.

## 10. Primary references

### Protocol and runtime

- **S1:** [MS-SMB2 §3.1.4.1 — signing an outgoing message](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/a3e9ea1e-53c8-4cff-94bd-d98fb20417c0).
- **S2:** [MS-SMB2 §3.2.4.1.1 — client signing-key selection](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/973630a8-8aa1-4398-89a8-13cf830f194d).
- **S3:** [MS-SMB2 §3.3.5.2.4 — server signature verification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/85df1680-2ee7-4d25-a916-a982371ddc75).
- **S4:** [MS-SMB2 §3.3.5.5 — receiving session setup](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e545352b-9f2b-4c5e-9350-db46e4f6755e).
- **S5:** [MS-SMB2 §3.3.4.1.1 — server signing-key selection](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d594481c-f6d5-4de5-8842-9099063d41e7).
- **S6:** [MS-SMB2 §3.2.4.1.6 — connection sequence allocation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/bed7a84e-33a7-4289-9de9-6042cf8aa7cc).
- **S7:** [MS-SMB2 §3.2.4.1.8 — message encryption, including binding exclusion](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/6234c8b8-e36b-4d4c-973f-9733d97d2428).
- **S8:** [MS-SMB2 §3.2.5.3.1 — session setup handling](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/7fd079ca-17e6-4f02-8449-46b606ea289c).
- **S9:** [MS-SMB2 §3.3.5.5.3 — GSS authentication and key derivation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5ed93f06-a1d2-4837-8954-fa8b833c2654).
- **S10:** [MS-SMB2 §3.2.5.3.3 — binding handling](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/9a697646-6085-4597-808c-765bb2280c6e).
- **S11:** [MS-SMB2 §4.11.1 — multichannel notifications, signing and encryption](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/a83e375c-e771-4395-9849-4d73b58928dd).
- **S12:** [MS-SMB2 §4.9 — alternate-channel replay example](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/c84b3098-082f-45cf-961c-1b69fe9f6b13).
- **S13:** [MS-SMB2 §3.1.5.1 — incoming signature verification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5b570c0b-0854-4324-8fb5-d410692dde3e).
- **S14:** [NIST SP 800-38D — GCM and GMAC, including IV uniqueness](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf).
- **S15:** [Linux CIFS mailing-list discussion, November 2026](https://lore-kernel.gnuweeb.org/linux-cifs/20261106190622.20990-4-mike.michalo@gmail.com/T/); [binding signature-verification patch](https://lkml.iu.edu/2611.1/09010.html).
- **S16:** [Java Socket.close contract](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/Socket.html#close()).

### Pinned code and tests

- **D1:** [SMBJ pinned source](https://github.com/hierynomus/smbj/tree/1c5b9345df2898b8d57cf34d50ae599cab07b2b8); [PR #907](https://github.com/hierynomus/smbj/pull/907); [PR #910](https://github.com/hierynomus/smbj/pull/910).
- **D2:** [Go signer tests](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/x/protocol/signer_test.go); [binding tests](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/x/protocol/channel_test.go); [documented binding limitation](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/session.go).
- **D3:** [Python GMAC signing implementation](https://github.com/jborean93/smbprotocol/blob/3acc9843483716a1d0c033e3368675ea8419fb1f/src/smbprotocol/connection.py); [forced-algorithm test](https://github.com/jborean93/smbprotocol/blob/3acc9843483716a1d0c033e3368675ea8419fb1f/tests/test_tree.py).
- **D4:** [Pike multichannel tests](https://github.com/dell/pike/blob/bcbb343c5bfb7dd3198d2d79d7381dfdad0f0873/src/pike/test/multichannel.py).
- **D5:** [Rust fixed SMB GMAC vector](https://github.com/afiffon/smb-rs/blob/f4524d032c8951cc288e1c8231ad68588583abda/crates/smb/src/session/signer.rs).
- **D6:** [Microsoft signing suite](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/Signing/Signing.cs).
- **D7:** [Samba session tests](https://github.com/samba-team/samba/blob/a167c65ab6f7c0f95ef69f7f16c3426114cb8393/source4/torture/smb2/session.c); [client binding/key selection](https://github.com/samba-team/samba/blob/a167c65ab6f7c0f95ef69f7f16c3426114cb8393/libcli/smb/smbXcli_base.c); [GMAC nonce implementation](https://github.com/samba-team/samba/blob/a167c65ab6f7c0f95ef69f7f16c3426114cb8393/libcli/smb/smb2_signing.c).
- **D8:** [Java jcifs nonce tests](https://github.com/codelibs/jcifs/blob/992699c5192859494017778b7cca06bf5d940adf/src/test/java/org/codelibs/jcifs/smb/internal/smb2/Smb2GmacNonceTest.java); [signing tests](https://github.com/codelibs/jcifs/blob/992699c5192859494017778b7cca06bf5d940adf/src/test/java/org/codelibs/jcifs/smb/internal/smb2/Smb2GmacSigningTest.java); [forced-GMAC file-I/O integration](https://github.com/codelibs/jcifs/blob/992699c5192859494017778b7cca06bf5d940adf/src/test/java/org/codelibs/jcifs/smb/it/SigningIT.java).
