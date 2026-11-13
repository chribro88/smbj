# G0 — Resolve GMAC signing nonce ownership during channel binding

**Status:** OPEN — prerequisite to accepting the GMAC multichannel design.  
**Scope:** Full SMB 3.1.1 GMAC support throughout SMBJ TCP multichannel.  
**Evidence reviewed:** 13 November 2026.  
**Deliverable:** A concrete protocol-compliant construction, implementation mapping and independently checked evidence. This document is a design decision record within the implementation plan; it is not an implemented solution.

Full GMAC remains mandatory. A CMAC-only release, disabled GMAC binding, or an unspecified nonce allocator does not close G0. Independent work on signing, lifecycle and admission can proceed, but the overall feature cannot be accepted as complete while G0 is open.

## 1. Decision to establish

Determine how SMBJ can authenticate every binding exchange without reusing a GMAC signing key and nonce, while obeying SMB's key-selection, MessageId and credit rules. The construction must include failed attempts, concurrent bindings, authentication rounds, channel replacement and relevant reauthentication.

The ordinary sequence below exposes the reported collision. Research has not established a validated, efficient general solution. This is **not proof that every possible client-only solution is impossible**, and it does not establish a JDK, cryptographic-provider or kernel dependency defect.

## 2. Normative constraints

The linked Microsoft sections are the primary references inspected on the evidence date. Record the precise specification revision and applicable product-behavior notes when closing G0; section URLs alone are not immutable revision pins.

| Reference | Requirement, paraphrased | Design consequence |
|---|---|---|
| [MS-SMB2 §3.1.4.1 — outgoing signing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/a3e9ea1e-53c8-4cff-94bd-d98fb20417c0) | GMAC uses the MessageId and prescribed direction/CANCEL bits in a 12-byte nonce; remaining bits are zero. | An arbitrary IV or channel suffix is not interchangeable with the wire-defined nonce. |
| [§3.2.4.1.1 — client signing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/973630a8-8aa1-4398-89a8-13cf830f194d) | Session-setup requests use the session signing key; ordinary requests use their channel's signing key. | Later channel-key derivation cannot repair an earlier binding signature. |
| [§3.3.5.5 — session setup](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e545352b-9f2b-4c5e-9350-db46e4f6755e), [§3.3.5.2.4 — verification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/85df1680-2ee7-4d25-a916-a982371ddc75) | Binding is signed and verified with the globally identified session's signing key. | A client cannot silently substitute a new binding key. |
| [§3.3.4.1.1 — server signing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d594481c-f6d5-4de5-8842-9099063d41e7) | Signed non-success SESSION_SETUP responses use the session signing key. | Intermediate authentication responses must be included. |
| [§3.2.4.1.6 — client sequence allocation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/bed7a84e-33a7-4289-9de9-6042cf8aa7cc), [§3.3.1.1 — server window](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/dec8e905-9477-4c3f-bc64-b18d97c9f905) | Each connection begins with sequence window `{0}`. Credits extend it; client allocation consumes the lowest available value or range. | A global counter cannot simply select a high MID on a new connection. Out-of-order arrival permission does not waive client allocation rules. |
| [§3.2.4.1.8 — client encryption](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/6234c8b8-e36b-4d4c-973f-9733d97d2428) | Binding SESSION_SETUP requests must not be encrypted. | Encryption is not a conformant substitute for binding signing. |
| [§3.3.5.5.3 — authentication completion](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5ed93f06-a1d2-4837-8954-fa8b833c2654), [§3.2.5.3.1 — new authentication](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/7fd079ca-17e6-4f02-8449-46b606ea289c) | The initial channel uses the session signing key. Binding derives a subsequent channel key; session signing-key creation excludes binding and reauthentication. | Ownership must span the actual key's lifetime, including primary-channel traffic. |

The cryptographic uniqueness requirement is addressed by [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf), particularly its IV requirements. Successfully verifying two generated signatures does not establish safe nonce usage.

## 3. Ordinary-flow counterexample

Consider authenticated session S with GMAC signing key K. Connections A and B are fresh secondary connections. Both negotiate at MID 0 and then immediately bind with valid credentials and valid signatures. Assume the server signs its intermediate NTLM responses, consistent with the signing rules.

| Event | Connection | MID | Signing key | Relevant effect |
|---|---|---:|---|---|
| First binding request | A | 1 | K | Begins NTLM exchange. |
| Intermediate response | A | 1 | K | Contains challenge A; server-direction nonce is `010000000000000001000000`. |
| First binding request | B | 1 | K | Begins another valid NTLM exchange. |
| Intermediate response | B | 1 | K | Contains challenge B; nonce is identical to A's response. |

Different challenge responses are authenticated with the same key and nonce. Subsequent client authenticate messages at MID 2 can produce another collision. Kerberos can vary the authenticator in the first binding request, so restricting analysis to identical initial NTLM tokens is insufficient.

This is an **inference from the ordinary flow and published rules**, consistent with the user's reproducer. It is not a newly executed live-server experiment or a claim that every server follows this exact response policy. Two secondary connections suffice; concurrency is unnecessary.

The initial channel also uses K. Consequently, uniqueness cannot be scoped only to secondary bindings. Relevant original-channel messages, intermediate setup responses, abandoned attempts and future replacement channels belong to the same analysis. A fresh Java signer object does not create a fresh cryptographic key.

## 4. Alternatives and decisions

| Approach | Decision |
|---|---|
| Preserve protocol nonce format, immutable key context and separate channel state | Accepted foundations; they do not alone resolve G0. |
| Serialize binding calls | Rejected as a solution: sequential connections can repeat the same MIDs. |
| Derive distinct post-binding channel keys | Required, but insufficient for the preceding exchange. |
| Random IV, channel suffix or unilateral binding-key substitution | Rejected without a normative mechanism and interoperable peer support. |
| Global MID allocation that skips connection sequence values | Rejected: credit and lowest-available constraints remain. |
| Encrypt binding | Rejected by the explicit binding encryption prohibition. |
| Reauthenticate to rotate the original key | Rejected as an assumed mechanism; [§3.3.5.5.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5ecc02fb-0e60-4cba-afeb-f13100a6e65e) retains the existing session key. |
| Advance MIDs with unauthenticated ECHO | Not portable: [§3.3.5.17](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fa23e613-2768-49e5-aa68-97c4bba72379) says the server should disconnect when no session exists. |
| Reuse an identical first signed request | Rejected as a general solution: later authentication bytes and server challenges still vary. |
| Authenticate auxiliary sessions and consume MIDs under unrelated keys | Unvalidated research candidate. Requires full lifecycle proof, server acceptance and performance analysis; catching up to primary traffic may require O(primary MID) extra requests. |
| Reject GMAC binding or force CMAC | Containment only; does not meet the agreed completion criterion. |

## 5. Related upstream evidence and wording issues

The [3 November 2026 ksmbd report](https://lkml.iu.edu/2611.0/07825.html) describes repeated challenge responses under the same GMAC key and nonce. Its tested cause was **missing verification of binding requests**, permitting an unauthenticated signing oracle. That published experiment is distinct from the legitimate-binding inference above.

The [primary mailing-list thread](https://lore-kernel.gnuweeb.org/linux-cifs/20261106190622.20990-4-mike.michalo@gmail.com/T/) records the author's intention to investigate legitimate binding too. The v2 cover letter removes the GMAC addition for separate posting. The [10 November v4 verification patch](https://lkml.iu.edu/2611.1/09010.html) authenticates requests before producing responses; that change alone does not allocate unique nonces for multiple valid bindings. These dated messages identify a **ksmbd server issue**, not a required SMBJ kernel patch.

Two specification interpretations also require explicit treatment:

1. **Reauthentication:** client §3.2.4.1.1 names the session key for session setup, while server §3.3.5.2.4 names the channel key for non-binding requests. The upstream discussion explicitly identifies this ambiguity and follows Samba's bound-channel-key behavior. Obtain and document the applicable interpretation rather than extending one rule silently.
2. **Binding KDF:** [client §3.2.5.3.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/9a697646-6085-4597-808c-765bb2280c6e) displays legacy `SMB2AESCMAC`/`SmbSign` inputs, whereas server §3.3.5.5.3 expressly uses `SMBSigningKey` and the binding preauthentication hash for SMB 3.1.1. Resolve this using the pinned specification interpretation and independent interoperability evidence.

## 6. Questions requiring a concrete answer

No question has been sent externally. A protocol-implementer inquiry should include the clause references and minimal trace, then ask:

1. What normative mechanism or documented Windows behavior prevents repeated session-key/nonces when separate valid bindings use the same connection-local MIDs?
2. How does it cover NTLM intermediate responses, Kerberos, retries, failed authentication and existing primary-channel traffic?
3. Is an amendment, erratum or applicable product-behavior exception missing from the cited sequence/signing rules?
4. Which key and KDF context apply to reauthentication on an existing secondary channel and to its responses?

## 7. Evidence required to close G0

G0 closes only when all of the following are reviewable:

- **Construction:** explicit states, actual key ownership, MID/credit transitions and send/verify rules for every authentication round. Explain uniqueness across the entire key lifetime and why every wire operation is permitted.
- **Independent check:** a pinned established implementation, authoritative clarification, or equivalent evidence validates the relevant protocol interpretation. A mock sharing SMBJ's assumptions is insufficient.
- **Regression evidence:** the reported collision fails on the current behavior and passes with the proposed construction. Cover multiple binds, retries after each failure boundary, both authentication mechanisms, primary traffic, replacement, reauthentication and signing/write failures.
- **Interoperability:** force GMAC, assert selection and exercise several real channels against suitable independent servers. Record server/version/configuration and failures; skipped or CMAC-negotiated tests are not GMAC evidence.
- **Operational fit:** show bounded resource ownership and measure additional authentication, network round trips and throughput costs. Account for cancellation, shutdown and permanently consumed signing inputs.

### Safe observational trace

Instrument test runs with ordered event IDs, connection/generation IDs, pseudonymous session/channel IDs, direction, command/status, binding/signed/encrypted flags, MID, CreditCharge and grants, allocation-window transitions, authentication round, key role, opaque actual-key identity and normalized-message fingerprint. Record preauthentication stage and final-signature verification outcome.

Key identities must preserve equality of actual key material across object copies without exporting that material. Fingerprints must distinguish authenticated byte sequences while avoiding token disclosure. Correlate client and server events with sanitized packet metadata where available.

**Never include raw keys, passwords, authentication tokens or unredacted production captures in the plan or its evidence artifacts.** The review needs equality relationships and protocol transitions, not secrets. No exploit construction is needed to establish the regression.
