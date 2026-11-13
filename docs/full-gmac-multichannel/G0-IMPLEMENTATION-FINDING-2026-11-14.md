# G0 design decision — 14 November 2026

**Status: NOT RESOLVED; full AES-GMAC multichannel binding must remain fail-closed.**

## Evidence from checked-in source and traces

- `SMBSessionBuilder.bind` explicitly rejects GMAC before signing or sending a binding request.
- MS-SMB2 §3.1.4.1 defines the 12-byte GMAC nonce: 8-byte MessageId followed by sender/CANCEL bits. This is not application-configurable.
- MS-SMB2 §§3.2.4.1.1 and 3.3.5.2.4 select the original session signing key for binding.
- MS-SMB2 §3.2.4.1.6 initializes the independent new-connection MessageId sequence and requires lowest-available allocation.
- `research/gmac-binding-observation.json` documents two successful ordinary binds against Samba 4.23.10 using the pinned Go SMB2 donor. A transcript observed outside the implementation's signer independently validated 17 signed events.
- The reproducible sanitized metadata audit reports **two different-message repetitions of the same key/nonce** at events 12/20 (server NTLM challenge responses, MID 1) and 13/21 (client authentication requests, MID 2). It additionally detects identical-input reuse at events 11/19; the latter is not a different-message collision.
- `research/auxiliary-observation.json` supports four positive bounded experimental cases. Its *unsafe-control* records end prematurely because the observer detects the intended collision; these 6 partial events are excluded from positive counts and no fifth positive case is implied.

## Why the current auxiliary strategy cannot be promoted unchanged

The research driver authenticates an auxiliary session, advances native MIDs under that different key, reserves a **fixed 16-slot range**, binds the main session, then retires the original physical connection. This can prevent collisions for the recorded bounded NTLM flows, but is not a lifetime-wide proof.

To select it for production, demonstrate all of the following:

1. **Original key ownership:** initial authentication, primary-channel application messages, every binding request/response and any permitted original-key notifications are accounted for, including concurrent events.
2. **Per-request accounting:** no unobserved connection operation can take one of the reserved MIDs. The driver cannot rely on reflective reads of the sequence cursor and subsequently assume exclusive access.
3. **Variable-length authentication:** a fixed 16-request budget must be replaced with per-exchange reservation/burn rules that cover NTLM, Kerberos, signed errors, retries, reauthentication and cancellation.
4. **Session lifecycle:** retiring the original connection must preserve the session and any open files without leaving public APIs or lease ownership tied to the dead connection. Closing the auxiliary session must not terminate the bound main session.
5. **Cost and exhaustion:** the current approach needs additional authentication and progressively more ECHOs as bind attempts accumulate. Quantify upper bounds, connection exhaustion and server rate limiting.
6. **Independent interoperability:** reproduce successful, safe GMAC binding on at least Samba and a second suitable independent server. Test both transports and both providers, with live nonces and key-domain evidence.

A crypto library update cannot supply the missing SMB allocation semantics. Replacing the protocol nonce with a random or channel-specific value would break verification on unchanged servers.

## Completed in this local source patch

- Correct `Session.getSigningKey` to select an already-bound **channel** signing key for SESSION_SETUP/reauthentication on that channel, while preserving the original session signing key on not-yet-bound candidates (including binding continuations). This aligns with the Samba/ksmbd interpretation for existing bound channels; the corresponding client/server normative wording remains a documented ambiguity.
- Add a regression test for initial/binding versus bound-channel SESSION_SETUP key selection across request, continuation, final and error states.
- Add an independent sanitized-trace auditor. It reconstructs the protocol nonce from direction, command and MID and flags repeated `(key identity, nonce)` pairs. It never handles raw keys or raw SMB authentication tokens.
- Keep GMAC binding disabled in production. No completion or live interoperability claim is made.

## Validation limits

- Standalone Python auditor tests: **4/4 pass** on the supplied archive's sanitized traces.
- The original standalone review environment could not run Gradle. Subsequent validation in the feature worktree passed **798 unit tests** with no failures or skips, license checks and JaCoCo, including the new channel-key test and 19 request-session response regressions. Exact combined-source hashes are recorded in [validation-response-authentication.json](validation-response-authentication.json).
- Native single-session GMAC compatibility also passed **16 cases** on Samba 4.23.10 with both transports/providers and encryption/write-through toggles. Those cases retain binding rejection and do not exercise reauthentication.
- The channel-key test checks selection for request/continuation/final/error states. It does not qualify the reauthentication exchange, retained-key nonce lifetime, active-handle behavior or the unresolved normative wording.
- No Windows/ONTAP live peer is accessible here.
- No source branch was pushed or modified remotely.

## Required decision for full completion

The full requested feature still requires a documented construction that meets the six obligations above and independent interoperability validation, or an applicable protocol clarification/extension. GMAC binding remains explicitly unsupported until that work is complete. Existing CMAC compatibility does not satisfy or narrow the requested full-GMAC completion contract.

## Protocol and review references

- [MS-SMB2 §3.1.4.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/a3e9ea1e-53c8-4cff-94bd-d98fb20417c0) — GMAC nonce layout
- [MS-SMB2 §3.2.4.1.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/973630a8-8aa1-4398-89a8-13cf830f194d) — client signing-key selection
- [MS-SMB2 §3.3.5.2.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/85df1680-2ee7-4d25-a916-a982371ddc75) — server signature verification
- [MS-SMB2 §3.2.4.1.6](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/bed7a84e-33a7-4289-9de9-6042cf8aa7cc) — MID allocation
- [ksmbd reauthentication signing-key discussion, 12 Nov 2026](https://lkml.iu.edu/2611.1/16582.html)
- [ksmbd binding request verification](https://lkml.iu.edu/2611.1/04580.html) — distinct from legitimate-binding nonce reuse
