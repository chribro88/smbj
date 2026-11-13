# GMAC binding observation, 13 November 2026

G0 remains **OPEN**. This is a reproduction of nonce reuse, not a supported
construction or a full-feature acceptance pass. SMBJ's production binding guard
was retained throughout this experiment.

The pinned independent Go client completed two legitimate NTLM bindings against
Samba 4.23.10. A socket observer outside its signer independently derived the
SMB 3.1.1 signing keys from exported GSS keys and captured preauthentication
transcripts, then checked all 17 signed messages using standard AES-GCM with
empty plaintext. The 26-event trace includes initial authentication, primary
ECHO traffic, binding exchanges, channel-key traffic and LOGOFF.

| Events | Direction | MID | Verified result |
|---|---|---:|---|
| 12 and 20 | Server | 1 | Different challenge responses share the original signing key and nonce `010000000000000001000000` |
| 13 and 21 | Client | 2 | Different authentication requests share the original signing key and nonce `020000000000000000000000` |

The final binding responses verify under distinct derived channel keys. Those
keys do not repair the preceding original-key collisions. All three negotiated
connections selected GMAC. The trace does not establish Kerberos, failed binds,
concurrent binds, replacement, reauthentication, Windows or ONTAP behavior.

The observer exports HMAC fingerprints under an ephemeral, unexported random
key. Key IDs preserve equality of actual key material across object copies;
message fingerprints cover exact wire bytes with only the signature zeroed.
Raw keys, tokens, passwords, SessionIds and packets are not exported. The source
uses only disposable credentials for the dedicated loopback fixture. It does
not bypass authentication, recover GHASH keys or forge network messages.

## Pinned inputs

- Go donor: `hirochachacha/go-smb2`,
  `7f69f65878329522ceb556435bdeb3cde6552656` (BSD-2-Clause).
  Its source was archived into `/tmp/smbj-gmac-go-donor`; the original checkout
  was not modified. The diagnostic uses its public authentication/transport APIs.
- Official Go 1.27.0, Linux amd64 archive SHA-256:
  `675c26c449cbb18fc24b74650de1eabbae6e16f64326fd85a283fb3b58280685`.
  The archive was verified and extracted under `/tmp/smbj-gmac-go-toolchain`.
  Production Java and dependency configuration were unchanged.
- Samba fixture image:
  `dockurr/samba@sha256:2a0452a12b7a244a22f18d0f233101bb8d4952b5500ae263905e3b9dad3bf2ae`.
  `smbd --version` reported `Version 4.23.10`. Dedicated container
  `smbj-gmac-g0-research`, owner label `org.smbj.test-owner=smbj-gmac-g0-research`,
  256 MiB/one CPU, 64 MiB tmpfs share, no host mounts, loopback port 36531.

The accompanying `smb-gmac-gcm.conf` profile passed 16 native SMBJ single-session
cases: both TCP transports, BC/default JCE, encryption off/on and write-through
off/on. These asserted GMAC negotiation and exact file readback before and after
rejection of an unsafe binding. They do **not** test successful SMBJ GMAC binding.

The observer uses `smb-signing-only.conf`, which retains required GMAC signing
and GCM availability but does not enable session encryption globally. The first
observer attempt with global encryption `desired` correctly rejected encrypted
traffic as outside its plaintext-signing scope; the signing-only run below is
the recorded result. Binding requests remain plaintext as the protocol requires.

## Reproduction

Run from the SMBJ worktree. The isolated server must use the specified image,
owner label, tmpfs share, disposable account `smbtest` / `TestOnly123!`, and
`smb-signing-only.conf`; verify effective settings with `testparm` before testing.
The diagnostic deliberately connects only to `127.0.0.1:36531`.

For a new fixture, these commands fail if its name is already taken. They do not
reuse or overwrite an existing container:

```sh
docker create --name smbj-gmac-g0-research \
  --label org.smbj.test-owner=smbj-gmac-g0-research --memory 256m --cpus 1 \
  --tmpfs /shared:rw,size=64m,mode=1777 -p 127.0.0.1:36531:445 \
  -e NAME=share -e USER=smbtest -e 'PASS=TestOnly123!' \
  dockurr/samba@sha256:2a0452a12b7a244a22f18d0f233101bb8d4952b5500ae263905e3b9dad3bf2ae &&
docker cp docs/full-gmac-multichannel/research/smb-signing-only.conf \
  smbj-gmac-g0-research:/etc/samba/smb.conf &&
docker start smbj-gmac-g0-research
for attempt in {1..30}; do
  docker exec smbj-gmac-g0-research pidof smbd >/dev/null 2>&1 && break
  sleep 1
done
docker exec smbj-gmac-g0-research pidof smbd
docker exec smbj-gmac-g0-research smbd --version
docker exec smbj-gmac-g0-research testparm -s --parameter-name='server smb3 signing algorithms'
docker exec smbj-gmac-g0-research testparm -s --parameter-name='server multi channel support'
```

Archive the exact donor revision and overlay the observer; use an existing Go
1.27-compatible toolchain or the verified isolated one above:

```sh
mkdir -p /tmp/smbj-gmac-go-donor
git -C /workspace/go-smb2 archive 7f69f65878329522ceb556435bdeb3cde6552656 |
  tar -xf - -C /tmp/smbj-gmac-go-donor
mkdir -p /tmp/smbj-gmac-go-donor/cmd/smbj-gmac-observer
cp docs/full-gmac-multichannel/research/gmac-bind-observer.go \
  /tmp/smbj-gmac-go-donor/cmd/smbj-gmac-observer/main.go
cd /tmp/smbj-gmac-go-donor
export GOTOOLCHAIN=local GOMAXPROCS=2 GOPATH=/tmp/smbj-gmac-go-path
export GOCACHE=/tmp/smbj-gmac-go-cache GOMODCACHE=/tmp/smbj-gmac-go-mod
/tmp/smbj-gmac-go-toolchain/go/bin/go build -mod=readonly -p=1 \
  -o /tmp/smbj-gmac-bind-observer ./cmd/smbj-gmac-observer
/tmp/smbj-gmac-go-toolchain/go/bin/go vet -mod=readonly -p=1 ./cmd/smbj-gmac-observer
/tmp/smbj-gmac-bind-observer > /tmp/smbj-gmac-binding-observation.json
```

Expected diagnostic result: `NONCE_REUSE_CONFIRMED`, two successful bindings and
at least one independently verified reuse with different message fingerprints.
Opaque fingerprints vary between executions. Exit zero means the unsafe flow
was observed; it does not qualify GMAC multichannel as safe. An observer error
or absent collision is not a uniqueness proof.

The checked-in trace is `gmac-binding-observation.json`. Exact native source,
profiles and checksums are recorded in `../validation-modern-gmac.json`.
Only this task's owner-labelled container may be changed or removed during
cleanup. Do not modify the existing shared Samba test containers.

## Consequence for the design

Copying the donor's successful binding flow cannot close G0. A proposed
construction must change the key/MID lifetime relationship in a protocol-allowed
way and pass this independent observation, together with the complete lifetime
and interoperability requirements in `../protocol-resolution.md`. A separate [auxiliary-session experiment](auxiliary-candidate.md) now exercises
a bounded sequential NTLM construction on the same Samba version, including
replacement and one lost-binding boundary. Its independent verifier and negative
control pass. That research does not select a production design or close G0.
