# badsharing

[![CI](https://github.com/ihatemyfcklife/badsharing/actions/workflows/release.yml/badge.svg)](https://github.com/ihatemyfcklife/badsharing/actions/workflows/release.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/ihatemyfcklife/badsharing.svg)](https://pkg.go.dev/github.com/ihatemyfcklife/badsharing)
[![Go Report Card](https://goreportcard.com/badge/github.com/ihatemyfcklife/badsharing)](https://goreportcard.com/report/github.com/ihatemyfcklife/badsharing)
[![Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

**badsharing** is a Go toolkit for encrypted, loss-tolerant peer-to-peer file transfer. It combines [badrlnc](https://github.com/ihatemyfcklife/badrlnc) (random linear network coding over GF(2)) with [badcrypt](https://github.com/ihatemyfcklife/badcrypt) (ChaCha20-Poly1305 authenticated frames).

It includes a **resumable, multi-source swarm engine**, authenticated generation manifests, peer discovery, and an optional **Pion WebRTC transport with ICE/STUN/TURN support**. The original standalone UDP CLI remains available. No central server stores the file, although the WebRTC mode currently relies on a signaling rendezvous server.

> **Scope:** This is a library and command-line toolkit, not a fully autonomous public BitTorrent/DHT network or a finished browser file-sharing application. Real-world NAT/TURN deployments and large public swarms require additional testing and operational safeguards.

## Features

- **Encrypted transfers:** 32-byte shared key and authenticated 1,380-byte badcrypt frames; randomized sender session IDs.
- **RLNC recovery:** 1,280-byte source chunks, generations of up to 64 chunks, and configurable parity for lost packets.
- **Multi-peer download:** concurrent generation requests, rarest-available scheduling, redundancy adaptation, stalled-request retries, and source selection.
- **Verified resume:** per-generation SHA-256 digests in an HMAC-authenticated manifest; re-hash existing `.part` generations on restart.
- **WebRTC:** ICE with configurable STUN/TURN, an ordered reliable control DataChannel, and an unordered lossy data DataChannel.
- **Signaling:** room-scoped HTTPS rendezvous, bearer authentication, bounded queues, and allowlisted browser origins.
- **Optional browser bridge:** [WebRTC JavaScript adapter](transport/webrtc/browser/peer.js) for integrating a Go/WASM engine.
- **Legacy UDP mode:** a simple direct-send CLI, plus optional authenticated UDP `PeerMesh` discovery.

## How it works

```text
Sender / seeder                       Receiver / downloader
Source file
  │
  ├─ Generation manifest ───────────► Authenticate manifest (HMAC)
  │  (file hash + per-generation hashes)       │
  │                                             ▼
  └─ 1,280-byte chunks                  Request rare/missing generations
        │                                       ▲
        ▼                                       │
     badrlnc ── coded fragments ──► P2P links from one or more seeders
        │                                       │
        ▼                                       ▼
     badcrypt AEAD ── WebRTC/UDP ──► Verify and decrypt each frame
                                                │
                                                ▼
                                      Decode RLNC generations
                                                │
                                                ▼
                                   Verify each generation SHA-256
                                                │
                                                ▼
                                     Write / resume .part file
                                                │
                                                ▼
                                      Verify full file SHA-256
```

The swarm layer schedules **independent generations**, so several seeders can contribute to one file. Each generation is checked before being committed to disk. The receiving application can keep partially verified data across restarts.

`badsharing` does **not** yet provide a DHT, global trackerless discovery, live inventory gossip, guaranteed NAT connectivity, or automatic promotion of every downloader into a fully managed seeder. Shared swarm keys authenticate a *group*; they do not uniquely identify or isolate individual participants.

## Requirements and installation

- **Go 1.24+** for the core module; your Go toolchain may download a newer version when building the optional WebRTC module.
- A network-accessible **signaling endpoint** for WebRTC, and optionally your own **STUN/TURN infrastructure**.
- Strong, independently exchanged secrets. **Do not publish keys or bearer tokens.**

```bash
go get github.com/ihatemyfcklife/badsharing@latest
```

The core module imports as `github.com/ihatemyfcklife/badsharing`. Go-compatible module versions are in the **v1.x** series; the historical GitHub `v2.0.0` tag is not a valid v2 module path without `/v2`.

The Pion-based transport is an **optional nested module** at `transport/webrtc/`. Its current `go.mod` includes a local `replace` pointing at the parent checkout. Build it **from a clone of this repository**, not as a standalone published SDK.

## Quickstart: encrypted WebRTC transfer

The following local example uses three terminals on the **same machine**. To connect across machines, use a reachable HTTPS signaling URL and specify appropriate ICE servers.

### 1. Set secrets for all three terminals

Generate the secrets **once** and securely transfer the exact same values to all participants:

```bash
export BADSHARING_SIGNAL_TOKEN="$(openssl rand -hex 32)"
export BADSHARING_KEY_HEX="$(openssl rand -hex 32)"
```

`BADSHARING_SIGNAL_TOKEN` authorizes access to the rendezvous service. `BADSHARING_KEY_HEX` is the 64-character hex representation of the 32-byte transfer key. Keep them separate and confidential.

### 2. Start the signaling server

From the repository root:

```bash
go run ./cmd/badsharing-signaling -listen 127.0.0.1:8088
```

This server exchanges SDP offers/answers and peer lists; it **does not store files**. It refuses to listen on a public interface without TLS certificate settings. For an Internet deployment:

```bash
go run ./cmd/badsharing-signaling \
  -listen :8443 \
  -tls-cert /path/to/fullchain.pem \
  -tls-key /path/to/privkey.pem
```

Use a public hostname with a valid certificate and pass `-signal https://your-domain.example:8443` to clients. Provision server-side authentication, rate limiting, monitoring and temporary TURN credentials for public use.

### 3. Sender (terminal A)

From the repository root:

```bash
cd transport/webrtc
go mod tidy
go run ./cmd/badsharing-swarm \
  -mode send \
  -room private-demo \
  -file /path/to/archive.zip
```

### 4. Receiver (terminal B)

With **the same secrets**, from `transport/webrtc/`:

```bash
go run ./cmd/badsharing-swarm \
  -mode recv \
  -room private-demo \
  -out archive-received.zip
```

The receiver authenticates the generation manifest, downloads and verifies the data, keeps the partial download in `archive-received.zip.part` and renames it after successful verification.

For **multiple seeders**, run `-mode send` on additional machines with an identical file, matching file name and same transfer key/room. Then use:

```bash
go run ./cmd/badsharing-swarm \
  -mode recv \
  -room private-demo \
  -sources 2 \
  -gather 8s \
  -out archive-received.zip
```

`-sources 2` asks the receiver to gather up to two sources before beginning; it does not guarantee that two sources exist. The current CLI's source set is selected at startup. Rerunning a failed receive with the same `-out` verifies and reuses intact generations in its `.part` file; completed output filenames are not overwritten.

### STUN/TURN and NAT traversal

On both sender and receiver, pass ICE server addresses as needed:

```bash
export BADSHARING_TURN_USER="short-lived-user"
export BADSHARING_TURN_PASSWORD="short-lived-password"

go run ./cmd/badsharing-swarm \
  -mode recv \
  -room private-demo \
  -signal https://your-domain.example:8443 \
  -stun stun:stun.example.net:3478 \
  -turn turn:turn.example.net:3478 \
  -out archive-received.zip
```

ICE tries usable direct routes first; TURN is an **optional relay**, not a file storage service. To test a relay-only path, append `-relay-only`. You must operate or provision a reachable TURN service with valid credentials. A TURN relay may carry significant bandwidth, even though file frames remain encrypted by badcrypt.

### Browser clients

The [browser adapter](transport/webrtc/browser/peer.js) handles signaling and WebRTC DataChannels, and forwards byte packets to your application. It **does not** provide a complete UI, WASM file-transfer glue, storage implementation or key-management interface.

For a browser app hosted on another origin (for example GitHub Pages), configure the signaling service before startup:

```bash
export BADSHARING_SIGNAL_ORIGINS="https://ihatemyfcklife.github.io"
```

A browser requires JavaScript for WebRTC integration. The **legacy Go/UDP transfer** does not require browser JavaScript.

## Legacy UDP CLI

For simple direct transfers that do not use WebRTC or a swarm:

```bash
go build -o badsharing ./cmd/badsharing
```

Generate a long passphrase once and set the **same** value on both machines:

```bash
export BADSHARING_PASSPHRASE="$(openssl rand -hex 32)"
```

Receiver:

```bash
./badsharing recv -listen :9099 -out received.bin
```

Sender:

```bash
./badsharing send \
  -file input.bin \
  -addr 127.0.0.1:9099 \
  -redundancy 0.40
```

The UDP CLI derives a transfer key with **Argon2id and a fresh random salt**; the salt accompanies authenticated encrypted metadata. No default passphrase is used. Older UDP CLI protocol versions are not compatible with this handshake.

For lossy-network simulation, add `-loss 0.25` to the sender. The receiver's UDP port must be reachable; this legacy CLI has no ICE/TURN negotiation.

## Go packages and APIs

| Package | Purpose |
| --- | --- |
| `badsharing` | `FileMetadata`, `Sender`, `Receiver`, `SessionConfig`, `PeerMesh`, `GenerationManifest`, `NewGenerationSender`, `NewGenerationReceiver` |
| `badsharing/swarm` | `Source`, `Download`, `Scheduler`, `Peer`, `Link`, `SendManifest` and `ReceiveManifest` |
| `badsharing/signaling` | `Server` and `Client` for authenticated WebRTC rendezvous |
| `transport/webrtc` (nested module) | Pion `Link`, ICE/STUN/TURN configuration, automatic `Coordinator` and the `badsharing-swarm` CLI |

For custom integrations:

1. Generate a random key with `GenerateRandomKey()` (recommended).
2. Compute `FileMetadata` and `BuildGenerationManifest(...)` from a seekable source.
3. Share the authenticated manifest and key through an appropriate trusted channel.
4. Connect authenticated peers over an implementation of `swarm.Link`.
5. Call `swarm.Source.Serve(...)` on seeders and `swarm.Download(...)` on the receiving side, using an `io.WriterAt` destination and an `io.ReaderAt` for verified resume.

`NewGenerationSender(...)` uses a fresh random badcrypt session ID per generation request. Never reuse a key/session ID combination with a reset encryption counter.

For passphrase-derived library keys, use `GeneratePassphraseSalt()` plus `DeriveKeyFromPassphraseWithSalt(...)`. The legacy fixed-salt `DeriveKeyFromPassphrase(...)` is **deprecated**.

### WebAssembly

The Go core and optional Pion module are built for `GOOS=js GOARCH=wasm` in CI:

```bash
GOOS=js GOARCH=wasm go build ./...

cd transport/webrtc
go mod tidy
GOOS=js GOARCH=wasm go build ./...
```

A successful WASM build does **not** mean there is a ready-to-deploy standalone browser file-sharing app.

## Security and production limitations

- AEAD authentication rejects unauthenticated frames; HMAC manifests and generation hashes detect invalid output before disk commit. **Anyone holding the shared group key may still actively disrupt a swarm**; group keys are not a per-peer identity model.
- Signaling participants and TURN operators can observe **network metadata**. Signaling is a rendezvous dependency; it is not a decentralized DHT.
- The scheduler makes decisions using source availability and configured telemetry; live dynamic peer inventory, large-scale congestion control, malicious-peer quarantine and global discovery are not yet implemented.
- The HTTP signaling broker has bounded queues and restricted CORS, but **needs reverse-proxy rate limiting, monitoring and abuse controls** before public exposure.
- Real NAT-restricted paths, TURN failover, mobile browsers, WAN loss behavior and large swarms still need production-environment tests. Avoid treating a green CI run as a comprehensive security audit.
- The WebRTC `swarm.Link` implementation uses two DataChannels; control messages are reliable and ordered while RLNC shard messages are unordered with no retransmits.

## Testing

At the repository root:

```bash
go mod verify
go vet ./...
go test -race ./...
GOOS=js GOARCH=wasm go build ./...
```

Optional WebRTC module (including local ICE/DataChannel integration tests):

```bash
cd transport/webrtc
go mod tidy
go test -race ./...
GOOS=js GOARCH=wasm go build ./...
```

CI runs these checks on pull requests and pushes to `main`. The tests verify local behavior; they do not prove universal NAT reachability or production readiness.

## License

Apache License 2.0. See [LICENSE](LICENSE).
