# G0 implementation invariants

This records the implemented Linux/Samba construction and the state transitions
behind the independent wire checks. It covers the client's original-key binding
domain and how that domain is separated from application and reauthentication
traffic. It does not assert that an arbitrary server generates safe nonces for
its own unsolicited or asynchronous messages.

## State and ownership

| State | Owner | Rule |
| --- | --- | --- |
| Native MID/credit window | Physical Connection | Allocate the lowest available MID/range; never assign, skip or rewind the window. |
| Original signing key K | Logical Session | Retain it for binding; successful reauthentication does not replace it. |
| Original-key cursor H | Logical Session | Unsigned monotonic CAS reservation; every successful reservation remains burned. |
| Abort MID R | Unpublished Session/private root | Burn R before binding; only the original root's LOGOFF can claim it, once. |
| Initial caller exclusions A | Unpublished Session, then immutable | At most 16 actual initial-caller binding MIDs; retain sparse outliers without raising H. |
| Bound signing key D | Session + physical channel | Publish only after final verification; ordinary I/O and reauthentication use this channel's key. |
| Auxiliary key KA | Attempt-owned auxiliary Session | Actual key bytes must differ from K; close auxiliary authentication before target publication. |

## Original-key allocation argument

1. Initial authentication runs on a private connection before the target Session
   is exposed. Its consumed native MID prefix is burned for K in both directions.
2. Preparation reserves the next private MID R for abort LOGOFF and advances H
   past it. Caller binding cannot use a MID below H, including R.
3. Initial caller requests add their actual allocated MIDs to A. The per-physical
   allocation lock serializes those allocations. A duplicate entry is rejected.
4. The initial caller exchange completes or unwinds before recovery binding or
   public use can begin. After successful handoff the anchor is removed and A is
   no longer extended. This phase ordering matters: a concurrent set alone would
   not make an A insertion atomic with a reservation against H.
5. Later binding/recovery rounds exclude A and claim M only when M is at least H,
   atomically changing H to M+1. Two successful claims cannot share M, and a
   subsequent claim cannot return to an earlier value.
6. Unsigned connection ECHOs consume rejected native MIDs through real credits.
   They do not create MAC inputs under K. The connection first has an independent
   authenticated auxiliary session; its own signed traffic uses KA.
7. A failed or uncertain exchange never releases its reservation. A fresh retry
   starts from its own native sequence and consumes collisions rather than
   reusing a burned original-key input.

Collision probes are pipelined in batches of at most 32 per send call, bounded
also by real available credits. When probes are pending and only one credit
remains, the call flushes its batch before another allocation. A one-credit
connection can still send one probe and wait for its response. Neither writes
nor response waits hold the connection allocation lock. An accepted original-key MID/range is
allocated atomically with its reservation before waiting; the target is registered
and written only after every earlier probe has completed. Failure burns an
allocated but unpublished target MID as well. Timeout, interruption and callback
failure retire only that call's retained probes without granting synthetic
credits or aborting unrelated requests. Transport failure/exhaustion retains the
existing connection-wide failure behavior.

Thus the initial prefix, R, A and later monotonic reservations are disjoint for
K. A server binding continuation uses the request's unique MID and the prescribed
server-direction bit; the final binding response uses the verified new channel
key. Direction and CANCEL discriminators remain the existing wire-defined GMAC
nonce fields. The implementation does not introduce another nonce layout.

## Application traffic and reauthentication

Key separation retains the existing authenticated key-exchange and KDF security
assumptions. Independent authentication supplies fresh auxiliary key material;
the byte check enforces its distinction from K before binding. The observer
groups MAC inputs by actual key bytes, including across symbolic roles, rather
than treating different key labels as evidence of independence.

The caller receives the target only after its bound key D is verified. The
private root is retired without LOGOFF on successful handoff. Application traffic
therefore advances the caller's native window under D without raising H.

Reauthentication selects one live channel for the whole exchange and serializes
reauthentications within that Session. Requests are signed, unencrypted
SESSION_SETUP messages. Requests and every accepted response use the existing
selected-channel key; a binding request is distinguished by its binding flag,
not merely by its command code.

Fresh authentication validates the credentials and processes the final GSS token.
Its exported material is not installed as replacement session/channel keys. The
five established keys, preauthentication value, original-key reservations and
encryption-counter owner remain unchanged. Later binding still uses K. Closeable
authentication attempts are disposed on success and failure.

Selected Closeable authenticators also belong to the initial-authentication or
binding attempt, starting before initialization. Their GSS contexts are released
after the final token/key/signature checks and before local session/channel
publication. Cleanup clears its owned reference before closing, preserves an
identical cached primary failure and suppresses only distinct cleanup failures.
Failure removes provisional/attempt-local table state. Authentication identities
and caller credentials remain available for later independent exchanges. The
live Kerberos fixture checks zero retained contexts before its fallback cleanup;
native disposal-error/peer-LOGOFF behavior remains unqualified. See
[validation-authentication-disposal.json](validation-authentication-disposal.json).

On a live channel, native allocation does not repeat an ordinary request MID.
CANCEL retains its request's owner/MID and uses the existing one-shot cancellation
claim and CANCEL discriminator. Exhaustion is rejected rather than wrapping.
The server remains responsible for safe nonce selection for its own messages;
the independent observer compares actual bytes and actual keys for every signed
frame included in a trace, including server responses.

## Failure and shutdown

An unmanaged direct Session can retain its original connection. Its original-key
sends, including reauthentication, use the same monotonic reservation callback
as binding. This preserves uniqueness while allowing original traffic to raise H;
the managed private-bootstrap path avoids that application-driven catch-up cost.

An unpublished abort uses R if its original root remains usable. If that root is
already closed and the caller has no verified target entry, cleanup attempts one
owned channel using the same auxiliary/binding path. Successful cleanup uses a
verified D for target LOGOFF. Cleanup failure preserves the original exception
and leaves remote disposal unconfirmed; it does not replay data or revive the
failed Session.

If binding verified the caller but client closure rejects handoff, that verified
channel performs cleanup. No further candidate is needed. Disposal removes only
the target attempt's identity from private tables, including roots already
unsubscribed from LOGOFF events. Borrowed transports and other sessions survive.

Sending snapshots channel membership and its signing key under the same short
monitor used to remove keys. Serialization and network I/O occur after releasing
it. Closing cannot remove D between validation and selection and make an admitted
send fall back to K. Reauthentication checks closing state before starting and
after completing; a completed close cannot produce a late successful API return.

## Cost and validation boundaries

Reservation memory is one cursor, one abort slot and at most 16 initial-caller
exclusions, plus existing per-active-channel state. Network catch-up depends on
burned binding history. The current construction does not have constant catch-up
cost for an unbounded number of replacements. File traffic no longer drives that
cost. The current 64-cycle operational probe checks 512 replacements and 64
prepared failures per runtime across eight profiles, stable live ownership and
collectability of all 73 retired connections per profile. Catch-up grows from
five to 139 ECHOs per successful candidate. Bounded pipelining improves measured
64-cycle binding latency on Java 21 and Java 8 while preserving those counts;
it does not bound total catch-up packets for a longer history. Longer-history
limits, allocation/buffering profiles and comparative transfer throughput remain
unqualified; see [validation-churn-cleanup.json](validation-churn-cleanup.json)
and [validation-batched-probes.json](validation-batched-probes.json).

The current native evidence uses Samba 4.23.10, NTLM and Kerberos with real
16/32-byte GSS keys. Existing JCE wire checks independently verify tags and
actual-key/nonce identities; they do not independently reimplement the KDF.
Provider/transport/runtime, encrypted operation and negative cases are recorded
at their exact source states in the linked validation files. Remaining lifetime
variants retain explicit open coverage. Windows testing is deferred by user
instruction; it does not block further Linux implementation.

The optional-GCM profiles pass. A separate Samba 4.23.10 fixture with global
`smb encrypt = required` rejects the first bootstrap binding request even with
client encryption enabled. The existing pinned
[Samba dispatcher](https://github.com/samba-team/samba/blob/a167c65ab6f7c0f95ef69f7f16c3426114cb8393/source3/smbd/smb2_server.c#L3155)
has an encryption-required rejection before signing and binding dispatch. Source
inspection and the live rejection are consistent; the container's binary was not
rebuilt from that reference commit. Mandatory-global-encryption binding and
reauthentication are therefore unqualified, and are not counted among the passing
profiles. Binding remains signed and unencrypted.

- [Public binding](validation-public-binding.json)
- [Automatic bootstrap](validation-bootstrap-production.json)
- [Root-loss cleanup](validation-bootstrap-loss.json)
- [Client-close and candidate lifecycle](validation-bootstrap-lifecycle.json)
- [Public Kerberos](validation-public-kerberos.json)
- [Public reauthentication](validation-public-reauthentication.json)
- [Public multichannel CANCEL and CHANGE_NOTIFY](validation-public-cancellation.json)
- [Pending-owner loss and encrypted cancellation](validation-encrypted-owner-loss.json)
- [Churn resources and cached-error cleanup](validation-churn-cleanup.json)
- [Bounded collision-probe pipelining](validation-batched-probes.json)
- [Authentication context disposal](validation-authentication-disposal.json)
