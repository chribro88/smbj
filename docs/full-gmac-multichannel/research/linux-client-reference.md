# Linux mount.cifs and multichannel reference

Reviewed 14 November 2026 (Sydney). Linux source snapshot:
`97d73c8251226cf27cc6656b4c542869bb8c69fa`, resolved from the upstream master ref
and fetched directly from `torvalds/linux`. This is a source inspection, not a
Linux mount or interoperability test. Distribution and out-of-tree patches must
be checked separately.

## Finding relevant to G0

`mount.cifs` is the userspace mount helper supplied by cifs-utils. The kernel SMB
client implements channel establishment, MID/credit handling and signing. The
[kernel usage guide](https://docs.kernel.org/admin-guide/cifs/usage.html) describes
that division and the mount configuration.

At the pinned revision, `build_signing_ctxt()` advertises only AES-CMAC and leaves
AES-GMAC as a TODO. `smb3_calc_signature()` computes CMAC. Thus this kernel client
does not provide an implemented GMAC binding nonce-uniqueness construction that
SMBJ can adopt. Its working signed multichannel path does not qualify G0.
AES-GCM support for encryption is a separate capability from AES-GMAC signing.

## Implementation map

| Behavior | Pinned source | What it establishes |
|---|---|---|
| Signing negotiation | [smb2pdu.c:697](https://github.com/torvalds/linux/blob/97d73c8251226cf27cc6656b4c542869bb8c69fa/fs/smb/client/smb2pdu.c#L697) | `build_signing_ctxt()` offers AES-CMAC; GMAC remains TODO. |
| Channel creation | [sess.c:502](https://github.com/torvalds/linux/blob/97d73c8251226cf27cc6656b4c542869bb8c69fa/fs/smb/client/sess.c#L502) | `cifs_ses_add_channel()` creates a fresh transport, preserves logical server/authentication configuration, then negotiates and establishes the session while holding `session_mutex`. |
| Per-connection MID allocation | [smb2ops.c:389](https://github.com/torvalds/linux/blob/97d73c8251226cf27cc6656b4c542869bb8c69fa/fs/smb/client/smb2ops.c#L389) | `smb2_get_next_mid()` increments `server->current_mid` under that connection's `mid_counter_lock`; negotiation resets this value to zero. It is not a session-wide counter. |
| Multi-credit allocation | [smb2transport.c:602](https://github.com/torvalds/linux/blob/97d73c8251226cf27cc6656b4c542869bb8c69fa/fs/smb/client/smb2transport.c#L602) | `smb2_seq_num_into_buf()` assigns the first MID and consumes the remaining CreditCharge range; callers hold the transport's send mutex. |
| Binding versus ordinary signing key | [smb2transport.c:33](https://github.com/torvalds/linux/blob/97d73c8251226cf27cc6656b4c542869bb8c69fa/fs/smb/client/smb2transport.c#L33) | `smb3_get_sign_key()` chooses `ses->smb3signingkey` during binding and the matching channel's `signkey` otherwise. |
| Key derivation ownership | [smb2transport.c:302](https://github.com/torvalds/linux/blob/97d73c8251226cf27cc6656b4c542869bb8c69fa/fs/smb/client/smb2transport.c#L302) | `generate_smb3signingkey()` installs only the new channel signing key during binding and preserves the existing session signing key. |
| Actual SMB3 signer | [smb2transport.c:463](https://github.com/torvalds/linux/blob/97d73c8251226cf27cc6656b4c542869bb8c69fa/fs/smb/client/smb2transport.c#L463) | `smb3_calc_signature()` uses AES-CMAC. It contains no GMAC signing nonce allocator. |
| Kerberos binding input key | [smb2pdu.c:1748](https://github.com/torvalds/linux/blob/97d73c8251226cf27cc6656b4c542869bb8c69fa/fs/smb/client/smb2pdu.c#L1748) | `SMB2_auth_kerberos()` takes the current authentication's exported key before establishing/deriving the channel. This raw KDF input is distinct from the original derived signing key. |

The native request setup also rolls MIDs back after some local setup/signing
failures. That behavior belongs to this CMAC implementation and needs separate
analysis before any GMAC adaptation. It does not establish the requested
permanently consumed signing-input invariant.

## Particularly useful Kerberos regression

Commit [d9d1e319b39ea685ede59319002d567c159d23c3](https://github.com/torvalds/linux/commit/d9d1e319b39ea685ede59319002d567c159d23c3),
`smb: client: fix broken multichannel with krb5+signing`, explains an actual
secondary-channel signature failure. Kerberos binding had reused the previous
authentication's raw session key as KDF input. The fix supplies the new
authentication result when deriving that channel's signing key. The original
derived session signing key used to authenticate binding remains separately
owned.

This supplies a concrete correctness scenario for SMBJ Kerberos channel-key
validation. It does not address GMAC nonce reuse during the preceding binding
exchange, or establish that reauthentication rotates existing signing keys.
No Linux implementation code has been copied into SMBJ.

## Useful guides and patch history

- [Linux kernel CIFS/SMB usage guide](https://docs.kernel.org/admin-guide/cifs/usage.html):
  mount-helper/kernel separation, configuration and diagnostics.
- [Demystifying Linux SMB mount options — SNIA SDC 2024](https://www.snia.org/sites/default/files/2025-05/SNIA-SDC2024-Prasad-Demystyfiying-Linux-Mount-Options.pdf):
  client contributors explain mount options; slide 13 covers `multichannel` and
  `max_channels`, while slide 19 covers connection credit limits. This is an
  operational guide, not GMAC binding qualification.
- [Enzo Matsumiya's 2022 GMAC patch discussion](https://marc.info/?l=linux-cifs&m=166446070616314&w=2):
  useful primitive/nonce implementation discussion, explicitly a proposed patch.
  The pinned mainline implementation above still has CMAC-only signing.
- [November 2026 ksmbd verification series](https://lore-kernel.gnuweeb.org/linux-cifs/20261106190622.20990-4-mike.michalo%40gmail.com/T/):
  server-side binding/reauthentication request verification. `ksmbd` is a separate
  kernel server, not the client behind `mount.cifs`; verification fixes alone
  do not prove nonce uniqueness across valid bindings.

## Consequence for the SMBJ feature

Linux is a useful reference for channel lifecycle, per-connection sequencing and
correct Kerberos KDF input ownership. It supplies no replacement for the
client-only auxiliary-session construction or its outstanding G0 proof. The
[seven-case auxiliary validation](../validation-auxiliary-concurrent.json) remains
bounded NTLM/direct-TCP/BC/Samba evidence. Kerberos, Windows/ONTAP, complete key
lifetime, API ownership and sustained costs still need validation. The full
feature and G0 remain incomplete.
