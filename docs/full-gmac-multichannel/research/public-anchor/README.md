# Shared caller connection — bounded GMAC bootstrap research

Two native Samba 4.23.10 cases preserve the caller's live connection, its SMBClient
and pooled identity, and an older session/open on that connection through bootstrap
and new-session close. This extends the earlier [concurrent experiment](../concurrent/README.md).
It is not selected for production, does not implement public authentication
orchestration, and does not close G0. The feature branch's production GMAC binding
guard remains unchanged.

## Construction tested

The caller connects through an actual SMBClient pool and authenticates an older
session P on connection U. P opens a 131,077-byte file. One case sends no extra
ECHOs; the other sends 1,024 P ECHOs before bootstrap.

The new main session S authenticates on a private connection R, created with the
same config, client, event bus and ServerList. R's next native MID is 3. That whole
original-key prefix remains burned. U authenticates an independent auxiliary
session Q and binds S. The actual NTLM authenticator pauses before its second
round, after the first authenticated binding response has returned. P writes and
reads its existing open during this pause. No transport or global network lock
is held by the pause. The actual original-key binding MIDs on U are therefore
noncontiguous, and both are at or above the burned original prefix.

After the final binding signature is verified and the channel is published, a
research-only package-private method promotes U to S's canonical connection.
That method checks expected bootstrap identity, verified membership/key, live
transport and session lifecycle under the existing channel monitor. R is then
forcibly closed without LOGOFF, and Q is logged off. Only after this sequence does
the driver use S for application work. The test checks:

- `S.getConnection() == U`, with U still live and owned by the actual SMBClient.
- A new pooled lease returns the same U after private R closes.
- P's existing open remains usable after R closes and after S closes.
- S's same open reads and writes on both U and a fresh additional channel.
- Closing S closes its additional private channel while preserving U and P.

The ordinary production `Connection.authenticate` method is not redirected by
these patches. The detached driver performs this orchestration explicitly. The
handoff patch alone does not establish safe public publication or shutdown.

## Sparse original-key use and fresh-candidate padding

Before publication, the driver records at most 16 actual original-key binding
MIDs from U; the native builder bounds authentication exchanges to 16. It does
not reserve a contiguous range on a busy U or advance the low fresh-candidate
cursor to U's high cursor. For one later private candidate, it reserves a
16-MID interval above the burned R prefix that excludes every observed U binding
MID. An independent auxiliary session consumes any preceding native MIDs with
real signed ECHOs and actual credit grants. No sequence value is skipped,
rewound or assigned.

| Case | Original prefix end | U's original-key binding MIDs | Fresh interval | Padding ECHOs |
|---|---:|---|---|---:|
| No extra P ECHOs | 3 | 13, 20 | [21, 37) | 18 |
| 1,024 extra P ECHOs | 3 | 1037, 1044 | [3, 19) | 0 |

This shows that a high caller cursor need not force padding fresh connections up
to that cursor. It does not eliminate the earlier construction's accumulating
reservation/padding cost, implement a full unsigned allocator, or qualify
arbitrary concurrent binding onto existing busy connections.

## Independent checks and results

The copied [concurrent wire observer](../concurrent/GmacWireObserver.java) receives
only the changes in [observer.patch](observer.patch): package relocation, dynamic
owned loopback port, bounded binding-MID observation and read/write connection
checks. Its independent JCE tag calculation, actual-key/nonce collision check,
lowest-native-range check and observed-credit accounting are retained. It checks
the older and auxiliary sessions too, and forbids main-session application
traffic on R. Keys, tokens and raw SessionIds are not exported.

The final run has two tests, zero failures/errors/skips. The traces independently
verify 160 and 2,172 signed inputs, respectively, across six actual key domains
per case, with zero observed distinct-message actual-key/nonce reuse. Each case
checks 1,179,693 main-open readback bytes and 655,385 older-open readback bytes;
131,077 of the latter are checked while the authentication round is held.
Both traces contain READ and WRITE requests on both main operational connections.
The observer's inherited `replacements=1` field denotes one additional binding,
not an operational failure/replacement event.

An initial harness version paused inside U's socket write, retaining the shared
transport write lock. Older-session I/O then correctly could not progress and the
gate expired. The gate was moved to the NTLM round boundary. A preliminary
corrected test run passed, but its runner expected the unrelated single-session
marker and rejected report collection. The final runner accepts and checks the
specific ownership marker. These attempts are not included in the final pass
count. [validation-public-anchor.json](../../validation-public-anchor.json)
records exact source pins, final reports and fixture cleanup.

## Reproduce

Use a disposable detached checkout of
`29cfb137b8d6cdb20ff7c6055a9e3a0079ba0099`. Apply, in order:

1. [The existing guard-only research patch](../gmac-auxiliary-experiment.patch).
2. [ownership.patch](ownership.patch) to Session.java.
3. Copy the pinned concurrent GmacWireObserver.java to a temporary directory,
   apply observer.patch there, and place the result in
   `src/it/java/com/hierynomus/smbj/session/` in the checkout.
4. Copy GmacPublicAnchorIT.java from this directory into that same package.
5. Copy the updated [fixture runner](../run-gmac-single-fixture.py) into the
   checkout at its existing path.

The patches have been reapplied independently and compared byte-for-byte with
all executed Java sources. With the existing Temurin 21 installation selected:

```sh
SMBJ_GMAC_AUX_RESEARCH=true \
  JAVA_HOME=/tmp/smb-relay-java21/opt/java/openjdk \
  PATH=/tmp/smb-relay-java21/opt/java/openjdk/bin:$PATH \
  python3 docs/full-gmac-multichannel/research/run-gmac-single-fixture.py \
    --public-anchor-research --output /tmp/smbj-public-anchor-new-run
```

The runner uses the already pinned Samba image, random disposable credentials,
dynamic loopback-only port, 256 MiB memory, one CPU and 64 MiB tmpfs share. It
forces test execution, archives sanitized reports and checks exact owner identity
before removing its fixture. It neither mounts a host directory nor installs a
host package. The build uses Gradle 8.13 and Java 8 production bytecode, BC 1.86,
Direct TCP, NTLM, mandatory AES-128-GMAC signing and plaintext application SMB.
LicenseIntegrationTest succeeds. All four fixtures from this investigation were
confirmed absent; the detached checkout was removed after evidence capture.

## Remaining obligations

The happy-path canonical handoff is qualified only for this bounded profile.
Public authenticate/openChannel integration, client-close during private bootstrap,
session-close races, failed or lost final authentication after possible peer
binding, cleanup that preserves an unrelated session on borrowed U, arbitrary
shared additional channels and private bootstrap tracking still need design and
tests. In particular, force-closing borrowed U on every bootstrap failure would
destroy P; a bad/lost final can leave no verified operational key for safe cleanup.

No production selection follows from this result. The complete actual-key
lifetime/unsigned exhaustion argument, sustained padding/resource cost, full
failure/retry/concurrency matrix, Kerberos handoff, async transport, encryption,
Java 8 native multichannel and independent Windows/ONTAP qualification remain.
The earlier native Kerberos and reauthentication results remain separate
profile evidence. JDT.LS was unavailable through this connector; available Gradle
compilation and native checks were used. Secrets scans reported no findings but
warned that scanner authentication was unsuccessful; no authenticated SonarQube
analysis is claimed.
