# Explicit SMB3 channels

One Session owns one tree/open-file namespace. Additional TCP connections bind to
that same session and get their own signing keys, credits, MessageIds and response
matching. Existing Shares and Files use the channels automatically. No interface
discovery or additional IP address is required; callers choose each endpoint,
which must negotiate the same server identity and compatible session policy.

Select CMAC before the original connection negotiates. Binding requires signing
to be enabled, but ordinary signing need not be globally required. CMAC signing
and AES-GCM data encryption are separate choices and can be used together.

```java
SmbConfig config = SmbConfig.builder()
    .withDialects(SMB2Dialect.SMB_3_1_1)
    .withSigningAlgorithms(SMB3SigningAlgorithm.AES_CMAC)
    .withSigningRequired(true)
    .withEncryptData(true)
    .build();
try (SMBClient client = new SMBClient(config);
     Connection primary = client.connect("files.example", 445);
     Session session = primary.authenticate(credentials)) {
    client.openChannel(session, "files.example", 445);
    // session.connectShare(...) and its Files now use both physical connections.
}
```

`SMBClient.openChannel` creates and owns its candidate, preserving the original
logical authentication hostname even when the physical address differs. It closes
a rejected candidate. Alternatively, `Connection.bind(session)` binds an already
negotiated, caller-owned candidate. Validation failure leaves that candidate open
for its caller to close or retry. Different local buffer configurations are
permitted when the candidate's negotiated maxima carry the established session's
requests. Matching client GUIDs are still required.

The read, write and transact ceilings are each the minimum of the original session
configuration and original negotiated maximum. They remain stable for existing
and future Shares. A candidate below any ceiling is rejected before binding
registration or authentication. A larger channel does not enlarge those ceilings.

SMB 3.0, 3.0.2 and 3.1.1 binding use CMAC signing. AES-GMAC remains available for
single-channel SMB 3.1.1 sessions. **GMAC binding is unsupported pending a nonce
uniqueness design**: binding uses the original signing key across independent
connection MessageId spaces. Rejection occurs before any binding SESSION_SETUP is
signed, sent or registered; candidate negotiation may already have occurred.
There is no silent fallback from an explicit GMAC preference. The established
single-channel session remains usable after rejection.

Requests are distributed across live channels. A blocked response or exhausted
credit window belongs to its connection; no session lock spans network writes,
credit waits or response waits. CANCEL stays on the originating connection. A
failed binding does not LOGOFF the shared session. Binding verifies the final
response with the new channel key before publication, and retains established
session encryption keys and their shared nonce allocator. Closing or cancelling a
candidate prevents its publication; retired channels leave the scheduler.

A failed transport fails its outstanding requests without transparent replay.
Other live channels can continue, but a lost WRITE response leaves that write's
outcome uncertain. The caller must decide how to recover the file or generation.
An acknowledgement of a partial write only retries the unacknowledged suffix;
this is different from replaying a write with an unknown result.

## Deferred upstream lifecycle defects

Pinned upstream: `hierynomus/smbj@1c5b9345df2898b8d57cf34d50ae599cab07b2b8`.
The implementation deliberately retains these generic limitations:

- `DirectTcpTransport.disconnect` can wait behind a blocked socket write because
  stream/socket closure is behind the transport locks.
- A blocked SocketFactory can return after disconnect and publish a live socket.
  Connection may then send a late NEGOTIATE. The feature's closed flag and null
  cleanup guard do not establish a terminal connect/disconnect lifecycle.

No bounded forced shutdown, cancellation of a blocked SocketFactory, or absence
of late NEGOTIATE is promised. `isConnected()` continues to report the actual
transport, including the problematic closed-but-connected state. These are Java
implementation limitations, not evidence of a JDK defect. Reassess when an
upstream fix merges, a maintainer requires it, or a required feature guarantee
needs it. SMBJ PR 910 and its dependency are not included by this change.

## Reproducible integration and transfer measurements

Run from the repository root with Docker and the repository's JDK 21 build. Main
production classes retain `options.release = 8`. The script uses pinned Samba
4.23.10 and 4.12.2 images, 256 MiB/one CPU per container, loopback ports 36529/36530,
and 64 MiB temporary shares. It only modifies containers carrying its owner label.
The credentials below are disposable test credentials.

For native Testcontainers tasks on rootless Docker, set
`TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE` to the actual socket path on the Docker
host and `TESTCONTAINERS_HOST_OVERRIDE` to its reachable published-port address.
The native Samba fixture uses a dynamic host port and routes its loopback DFS
referrals to that port, keeping port 445 inside the container. Its existing DFS
assertions expect the native Testcontainers host name `localhost`. No privileged
host-port permission is required.

```bash
src/it/samba-multichannel.sh up SMB3_11 required
export SMB_TEST_HOST=127.0.0.1 SMB_TEST_PORTS=36529,36530
export SMB_TEST_USERNAME=smbtest SMB_TEST_PASSWORD='TestOnly123!' SMB_TEST_DOMAIN=WORKGROUP SMB_TEST_SHARE=share
export SMB_TEST_SIGNING_ALGORITHM=AES_CMAC SMB_TEST_DIALECT=SMB_3_1_1 SMB_TEST_ENCRYPTION_REQUIRED=true
./gradlew integrationTest -x buildSambaImage --tests '*BoundChannelsIT' --tests '*MultichannelProtocolIT' --tests '*SingleChannelSigningIT' --rerun-tasks
```

Repeat for `SMB3_02`/`SMB_3_0_2` and `SMB3_00`/`SMB_3_0`. For both plaintext and
encrypted I/O, use `up <dialect> desired` and unset
`SMB_TEST_ENCRYPTION_REQUIRED`. Every case also checks write-through on/off. The
script verifies multichannel is enabled; successful binding and negotiated
dialect checks provide the wire evidence. A missing fixture causes a skip, not a
successful integration result.

Global `smb encrypt = required` on these Samba versions rejects signed plaintext
binding SESSION_SETUP with ACCESS_DENIED. Positive fixtures use global `desired`
and share `required` for encrypted tests. Do not encrypt binding SESSION_SETUP or
weaken signature verification to work around that server behavior. Existing
fixtures with global encryption required may be exercised separately using
`SMB_TEST_REJECT_BINDING_PORTS`.

For GMAC single-channel/rejection evidence, use only the modern server, set
`SMB_TEST_SIGNING_ALGORITHM=AES_GMAC`, and run `*SingleChannelSigningIT`. The older
fixture does not provide GMAC interoperability evidence.

For end-to-end transfer measurements, use the modern fixture with the chosen
share policy and dialect, CMAC, and:

```bash
export SMB_TEST_PORT=36529 SMB_TEST_PERFORMANCE=true SMB_TEST_PERF_ENCRYPTION=true
./gradlew integrationTest -x buildSambaImage --tests '*MultichannelPerformanceIT' --rerun-tasks
```

The harness uses four workers, 1 MiB requests and the same 32 MiB file workload for
1, 2 and 4 channels, after equal warmup. It reports all three samples per count:
elapsed time, client process CPU, throughput, fully checked bytes, and per-physical
connection WRITE bytes/request counts. The active-channel peak measures overlapping
calls to distinct transports, including time queued inside each transport; it is
not a measurement of server-side parallel execution. Each channel must carry
data, and multichannel calls must overlap. There is no universal speedup threshold.
These bounded loopback/tmpfs runs do not establish disk, WAN, ONTAP or sustained
production throughput. Record host load and server CPU/resource limits with results.

Delete test files on each test's exit, and finish with:

```bash
src/it/samba-multichannel.sh down
```

Windows and NetApp/ONTAP multichannel interoperability remain unverified until
independent runs record server versions and settings. Do not infer broad server
compatibility from Samba results.

## Donor provenance

These scenarios were adapted to SMBJ's native test framework; the donor suites
were source-reviewed, not executed here. No Linux or Samba implementation code
was copied. Existing Apache notices and copied donor notices are retained.

| Donor | Exact revision | Source and behavior |
|---|---|---|
| hirochachacha/go-smb2 | `7f69f65878329522ceb556435bdeb3cde6552656` | `x/protocol/channel.go`, `session.go`, `x/protocol/channel_test.go`: original-session admission invariant, explicit binding, independent flow control and original-key GMAC limitation. SMBJ admission uses effective configured limits rather than raw maxima. |
| dell/pike | `bcbb343c5bfb7dd3198d2d79d7381dfdad0f0873` | `src/pike/model.py`, `src/pike/test/multichannel.py`: `test_open_bind_close`, shared SessionId/TreeId/FileId, disjoint range I/O and stale-sequence fencing. |
| microsoft/WindowsProtocolTestSuites | `29ddb4238a5443b7499e82934c90cc898861c5e7` | `ProtoSDK/MS-SMB2/Client/Smb2Client.cs`, `TestSuites/FileServer/src/SMB2/TestSuite/MultipleChannel/MultipleChannelBasic.cs`, `MultipleChannelWithEncryption.cs`: failed bind/fresh retry with existing open, channel-key verification, cross-channel lock/unlock and established encryption-key preservation. |

The mixed-configuration matrix is a new SMBJ regression. The CMAC-only guard
contains the unsafe combination; it does not solve GMAC binding nonce uniqueness.
