# G0 Linux/Samba acceptance

**Status: PASS for the agreed Linux/Samba G0 scope.**

This is the active G0 finish line agreed with the user: the implemented GMAC
construction using the available Linux/Samba fixtures. Windows and ONTAP are
deferred. No external research access is required for this scope. This record
does not close the broader feature's G1–G6 release matrices.

The production/new-test checkpoint is
`422453273fd48e7960c5c794e165bc3a0dd8a2eb`, rebased onto development
`7109ef0`; the native fixture follow-up is `f99b7664`. Historical records below retain their own source revisions and
artifact hashes; their successful runs are not automatically attributed to the
rebased artifact.

## Mechanism and safety argument

The [implementation invariants](g0-implementation-invariants.md) specify the
state ownership, allocation proof, failure handling, key lifetimes and measured
cost. The construction uses existing SMB authentication, signing and credit
rules; it introduces no cryptographic primitive or nonce layout.

Initial authentication uses a private bootstrap connection. Before handing the
Session to the caller, SMBJ reserves a bootstrap-abort MID and binds the caller
under its verified channel signing key. The private original-key connection is
then retired. Application traffic uses the channel key rather than advancing the
original-key binding domain.

The original-key domain retains a burned initial prefix, a one-use abort MID,
at most 16 sparse initial-caller exclusions, and an unsigned monotonic Session
cursor. Every later binding round claims its MID before signing. Failure never
returns a claim. An independently authenticated auxiliary session lets the new
physical connection consume conflicting MIDs through ordinary unsigned ECHOs,
using real credits and the lowest native sequence range. Auxiliary cleanup must
complete before the target channel is published. Terminal original-key exhaustion
must fail before credits, probes or signing, while preserving the already reserved
one-use bootstrap abort.

Successful reauthentication verifies with the selected existing channel key and
retains established keys, preauthentication and nonce owners. Newly exported GSS
material is not installed as replacement keys. A verified peer rejection retires
the logical Session; recovery authenticates a fresh Session/open. Local credential
failure before transmission preserves the established Session.

The [revision pin](research/ms-smb2-revision-pin.md) records MS-SMB2 v20260928
and the Samba behavior used for the binding KDF/transcript and bound-channel
reauthentication interpretation. This is a documented interoperable construction,
not a claim of Microsoft clarification or universal server conformance.

## Requirement-to-evidence map

All nine rows are **PASS for this scope**, using the composed allocation/lifetime argument, focused boundary tests and native interoperability evidence below.
[Final qualification](validation-development-7109ef0.json) records the exact revisions and renewed profiles. Historical records keep their own narrower boundaries.

| Requirement | Existing evidence and final-check boundary |
|---|---|
| G0-01 — repeated fresh connection MIDs | The pinned Go/Samba baseline demonstrates ordinary-flow reuse. [Public binding](validation-public-binding.json), [public Kerberos](validation-public-kerberos.json) and [concurrent bindings](validation-concurrent-binding-matrix.json) independently verify positive GMAC inputs grouped by actual key bytes. Current NTLM/Kerberos profiles pass. |
| G0-02 — complete original-key domain | [Automatic bootstrap](validation-bootstrap-production.json) covers initial final authentication, private-root retirement, busy caller/application traffic and later binding. The prefix/abort/exclusion/cursor proof is in the invariants. [Bootstrap loss](validation-bootstrap-loss.json) and [lifecycle](validation-bootstrap-lifecycle.json) cover unpublished cleanup and publication barriers. |
| G0-03 — concurrent reservations | [Concurrent matrix](validation-concurrent-binding-matrix.json): 2/4/8 binds on Direct/Async, Java 21 and actual Java 8, with exact scenario/audit-set checks and independent credit/tag validation. Current Java 8 public profile passes. |
| G0-04 — failures burn used nonces | [Authentication ownership](validation-authentication-ownership.json), [bootstrap loss](validation-bootstrap-loss.json), [bootstrap lifecycle](validation-bootstrap-lifecycle.json), [authentication disposal](validation-authentication-disposal.json) and [disposal LOGOFF](validation-disposal-logoff.json) cover recorded preparation, response, disposal and cleanup boundaries. Current reservation tests cover accepted-but-unpublished timeout, interruption and reservation failure. New `PublicGmacBindingIT.partialBindingWriteBurnsItsNonceAndFreshRetryPreservesTheOpen` adds a 76-byte partial target write, burned MID, fresh retry and same-open I/O; it passes on actual Java 8, including the strict signed-input audit. |
| G0-05 — retained key across replacement | [Public binding](validation-public-binding.json), [encrypted owner loss](validation-encrypted-owner-loss.json) and [1,000-cycle churn](validation-churn-1000.json) cover replacement, surviving opens and retained original-key reservations. The churn record contains 8,000 successful replacements and 1,000 prepared failures. Current public replacement paths pass. |
| G0-06 — intermediate authentication rounds | Native NTLM/Kerberos records cover their actual exchanges. New `SMBBindingResponseTest.authenticatesSeveralRoundsWithTheKeyExportedOnlyAtCompletion` includes GMAC three-round success, corrupt continuation/final and authenticated denial, with independent request/response tags and a reservation call per exchange. This controlled-peer test and its current run are distinct from native Samba interoperability. |
| G0-07 — reauthentication key/state lifetime | [Public reauthentication](validation-public-reauthentication.json), [cache expiry](validation-kerberos-cache-expiry.json) and [verified peer denial](validation-peer-reauthentication-denial.json) cover retained keys, local credential failure, signed peer rejection and fresh-session recovery. `SMBReauthenticationTest.verifiesEveryRoundWithTheBoundChannelKeyAndRetainsSessionState` checks retained owners; `onlyVerifiedPeerDenialRetiresThePublicSession` distinguishes authenticated rejection from local/unauthenticated failures. All eight renewed native Kerberos profiles pass. |
| G0-08 — legal sequence/credit behavior | Independent native observers validate lowest MID consumption and actual credits. [Public cancellation](validation-public-cancellation.json) and [encrypted owner loss](validation-encrypted-owner-loss.json) cover owner-bound CANCEL discriminators and replacement. `ConnectionMessageIdReservationTest.collisionEchoConsumesOneCreditBeforeAMultiCreditRequest` and `oneCreditConnectionWaitsForEachProbeAndResumesWhenCreditsReturn` cover probe/multi-credit ordering without synthetic grants. |
| G0-09 — exhaustion without reuse | Existing [exhaustion evidence](validation-exhaustion.json) covers physical sequence windows. New `ConnectionMessageIdReservationTest` cases `exhaustedOriginalKeyFailsBeforeAllocatingCreditsOrWritingOnABorrowedConnection`, `exhaustedOriginalKeyStillAllowsItsReservedBootstrapAbortExactlyOnce` and `concurrentLastOriginalKeyClaimExhaustsWithoutWrapping` extend this to the Session cursor, including 2/4/8 simultaneous last-slot claimants. All 20 reservation cases pass, including the new terminal-state cases. |

## Final qualification

[The final record](validation-development-7109ef0.json) preserves reports, exact source and artifact identities, fixture metadata and the verified evidence archive.

- Local `check -x integrationTest`: **1,405 tests in 128 suites**, zero failures/errors/skips.
- Actual Java 8: **17 native public cases plus 34 selected runtime cases**, all passing. Eight complete independent audit records include the partial-write attempt with exactly one `preparedOnly` input.
- Java 21 native Kerberos: **8/8**, covering peer-denial retirement, local-cache failure/retry, both raw key sizes, signing/GCM and owned/borrowed caller modes. All **236** authentication contexts are disposed; none remain live.
- Java 21 native lease isolation: **4/4**, renewing affected cache/session/tree behavior.
- Independent renewed checks: **6,081 GMAC inputs and 654 GCM transforms**, zero observed distinct-message nonce reuse across the audited inputs.
- Production JAR SHA-256: `354d6a39b5317d20dffffd8e85691e590acc6ef4f026268244d07c75ac80bf4d`; **515 classes**, all Java 8 bytecode.
- All **11** owned containers, including the failed audit-fixture attempt, are confirmed removed. **449** retained files were verified byte-for-byte in the compact archive before removing loose task artifacts.

## Assumptions and limits

- Existing authentication/KDF security assumptions and server behavior apply.
  Auxiliary actual signing-key bytes must differ from the target original key.
  The observers group actual key bytes and independently compute GMAC/GCM;
  they do not independently derive every KDF input or prove unobserved traffic.
- Three-round GMAC testing uses a controlled peer. Native Samba authentication
  exercises its actual round count; no native three-round result is claimed.
- The partial-write observer verifies the complete signed write attempt. Only
  its 76-byte prefix reaches the server. It records that distinction explicitly
  rather than treating the incomplete wire packet as a complete received frame.
- Per-candidate catch-up grows linearly with binding history; aggregate catch-up
  grows quadratically. The 1,000-cycle measurements document this operating cost,
  not a constant latency bound or transfer-throughput qualification.
- Mandatory global-encryption binding remains unqualified on the tested Samba
  configuration. Successful optional GCM operation does not qualify that policy.
- Native root loss during abort LOGOFF and binding-phase authenticator disposal
  failure are not separately qualified. Existing burn rules and local failure
  tests support the nonce argument without asserting those native outcomes.
- Server-originated unsolicited/asynchronous nonce behavior, complete notification
  and authentication-policy matrices, transfer scaling and broader resource
  pressure remain under the later release gates. Windows and ONTAP stay deferred.

G0 is complete for this scoped Linux/Samba construction under these assumptions and limits. Broader release qualification remains separate.
