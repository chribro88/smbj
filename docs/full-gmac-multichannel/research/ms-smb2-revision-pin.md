# MS-SMB2 revision used for G0

The supplied [MS-SMB2 PDF](/workspace/plans/reference/SMBJ-GMAC-Multichannel-Reference-Pack-2026-11-13/spec/MS-SMB2-v20260928.pdf)
identifies itself as **v20260928**, released **28 September 2026**, revision
**88.0**. Its size is **11,674,269 bytes** and its SHA-256 is
`fef3a06507679130a8cfdcaeaed581482d7f235435dd904f6c794f113ff04bd1`.
The release header, revision history and sections below were read from that
file on 15 November 2026 using the already cached PDFBox text extractor.
No dependency was added to SMBJ. Online retrieval was unavailable during this
check; this pin identifies the supplied revision, not the latest online version.

## Interpretation and failure boundaries

| Section | Printed page | Relevant behavior and implementation consequence |
| --- | --- | --- |
| 3.2.5.3.2 | 236–237 | Reauthentication returns authentication errors to its caller and retains established key material. It does not promise that remote opens survive server authentication failure. |
| 3.2.5.3.3 | 237–239 | The client binding section still lists the legacy CMAC KDF label/context. The recorded SMB 3.1.1 Samba exchanges instead validate the dialect-specific `SMBSigningKey` construction described in the server section. |
| 3.3.4.1.1 | 277–278 | The text selects the session signing key for non-success SESSION_SETUP replies, and the channel key for other signed replies. The established-channel reauthentication interpretation therefore needs explicit peer evidence. |
| 3.2.5.1.3 | 226–227 | The receive-side wording has the corresponding non-success SESSION_SETUP key distinction. It does not independently resolve the established-channel reauthentication ambiguity. |
| 3.3.5.5.2–3.3.5.5.3 | 312–315 | A GSS failure on the server removes the session and closes its opens and tree connections. A successful retry may require a fresh session and fresh handles. |

The implementation follows the independently recorded Samba 4.23.10
established-channel key behavior for reauthentication, and its SMB 3.1.1 binding
KDF/transcript behavior. See [protocol resolution](../protocol-resolution.md),
[native reauthentication](../validation-reauthentication.json),
[native Kerberos](../validation-public-kerberos.json), and
[public reauthentication](../validation-public-reauthentication.json).
This is a documented interoperability interpretation; it is not a correction
issued by Microsoft or evidence for Windows or ONTAP.

The [client cached-ticket expiry check](../validation-kerberos-cache-expiry.json)
fails before any SESSION_SETUP reaches the peer, so its same-open recovery
assertion is appropriate. A damaged GSS token sent to the peer crosses a
different boundary. Tests of that boundary must observe the authenticated
failure and account for remote session retirement, rather than requiring the
old remote opens to survive. Neither the absence of local key replacement nor
a locally retained Session object establishes that the remote session survived.
