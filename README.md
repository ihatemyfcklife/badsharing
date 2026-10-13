# badsharing

[![CI](https://github.com/ihatemyfcklife/badsharing/actions/workflows/release.yml/badge.svg)](https://github.com/ihatemyfcklife/badsharing/actions/workflows/release.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/ihatemyfcklife/badsharing.svg)](https://pkg.go.dev/github.com/ihatemyfcklife/badsharing)
[![Go Report Card](https://goreportcard.com/badge/github.com/ihatemyfcklife/badsharing)](https://goreportcard.com/report/github.com/ihatemyfcklife/badsharing)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**badsharing** is a decentralized, high-throughput peer-to-peer file distribution engine combining **badrlnc** (Sliding-Window Random Linear Network Coding over $\text{GF}(2)$) and **badcrypt** (ChaCha20-Poly1305 AEAD with anti-replay protection and SessionID multiplexing).

Designed for direct peer-to-peer data transfer with optional bootstrap peers, and compilable to **WebAssembly** (`GOOS=js GOARCH=wasm`), `badsharing` streams files over lossy datagram transports (UDP, WebRTC DataChannels) with erasure recovery and authentication of frames before they reach the decoder.

---

## Table of Contents

- [Why badsharing?](#why-badsharing)
- [Architecture Overview](#architecture-overview)
- [P2P Swarm Dynamics](#p2p-swarm-dynamics)
- [Installation](#installation)
- [Quickstart Guide](#quickstart-guide)
  - [1. Sender Pipeline](#1-sender-pipeline)
  - [2. Receiver Pipeline](#2-receiver-pipeline)
- [Component Reference](#component-reference)
  - [FileMetadata](#filemetadata)
  - [Sender](#sender)
  - [Receiver](#receiver)
  - [SessionConfig](#sessionconfig)
- [CLI Tool](#cli-tool)
- [WebAssembly Browser Integration](#webassembly-browser-integration)
- [Testing & Validation](#testing--validation)
- [License](#license)

---

## Why badsharing?

Traditional P2P file sharing protocols (such as BitTorrent) divide files into static blocks. This approach suffers from two fundamental limitations:
1. **The Coupon Collector Problem**: Peers struggle to locate the rarest final pieces, causing swarms to stall near completion.
2. **Coordination Overhead**: Peers must constantly exchange piece availability bitfields and coordinate transfers with $O(N^2)$ control message traffic.

Furthermore, running raw Random Linear Network Coding (RLNC) over untrusted decentralized networks introduces the vulnerability of **pollution attacks**: if an attacker tampers with even a single bit in a linear combination, Gaussian elimination propagates that corruption into every decoded packet across the sliding window.

`badsharing` solves both problems:
- **Zero-Coordination Swarms**: Powered by `badrlnc`, shards represent random linear combinations over $\text{GF}(2)$. Every incoming innovative shard provides useful mathematical entropy ($+1$ degree of freedom).
- **Cryptographic Pollution Immunity**: Powered by `badcrypt`, every shard is encapsulated within an authenticated 1380-byte wire frame (`SealFrame` / `OpenFrame`). Frames without a valid MAC are rejected before decoding. Peers who possess the shared group key are trusted and can still introduce malicious coded shards; group authentication is not peer-by-peer authorization.
- **Microsecond In-Memory Recovery**: Lost packets are reconstructed on-the-fly in under $1\ \mu\text{s}$ without retransmission delays (0 RTT).

---

## Architecture Overview

```
                     BADSHARING SENDER
+---------------------------------------------------------+
| Source File / Stream (io.Reader)                        |
|   │ (Streamed in chunks of 1280 bytes)                  |
|   ▼                                                     |
| [ badrlnc.SlidingWindowEncoder ] (GF(2) Parity Shards)  |
|   │ (Shards serialized to 1344-byte plaintext buffers)  |
|   ▼                                                     |
| [ badcrypt.ShardAEAD.SealFrame ] (1380-byte wire frame) |
+----------------------------┬----------------------------+
                             │
                             │ Lossy Network (UDP / WebRTC DataChannel)
                             ▼
                    BADSHARING RECEIVER
+---------------------------------------------------------+
| Encrypted 1380-byte Frames                              |
|   │                                                     |
|   ▼ (ChaCha20-Poly1305 Auth + RFC 6479 Anti-Replay)     |
| [ badcrypt.ShardAEAD.OpenFrame ] (Discards Tampered)    |
|   │                                                     |
|   ▼ (Clean Shards)                                      |
| [ badrlnc.IncrementalDecoder ] (Gauss-Jordan Solver)    |
|   │                                                     |
|   ▼ (Recovered Packets)                                 |
| [ badrlnc.InOrderResequencer ] (Strict Monotonicity)    |
|   │                                                     |
|   ▼                                                     |
| Destination File / Stream (io.Writer)                   |
+---------------------------------------------------------+
```

---

## P2P Swarm Dynamics

When multiple peers download the same file simultaneously:
1. **On-the-Fly Recoding**: A peer that has received only 15% of the file can recombine its existing shards using SIMD XOR ($>10\text{ GB/s}$) to emit brand-new valid linear parity shards to other peers.
2. **Bandwidth Multiplication**: The original seeder only uploads approximately $1.05\times$ the file size into the mesh. The peer swarm handles the remaining propagation, allowing overall swarm speed to increase as more peers join.
3. **Bounded Memory Footprint**: Circular sliding windows require less than $20\text{ MB}$ of RAM per node, enabling multi-gigabyte transfers on low-resource hardware and mobile browser tabs.

---

## Installation

```bash
go get github.com/ihatemyfcklife/badsharing
```

Package documentation and API reference are available on [pkg.go.dev/github.com/ihatemyfcklife/badsharing](https://pkg.go.dev/github.com/ihatemyfcklife/badsharing).

Requirements: **Go 1.24+**.

---

## Quickstart Guide

The library supports raw 32-byte random session keys (recommended); distribute
them over an authenticated, out-of-band channel. In both examples below, set
`BADSHARING_KEY_HEX` to the **same** 64-character hex key on both machines.
Do not commit the key to source control.

### 1. Sender Pipeline

```go
package main

import (
	"os"
	"encoding/hex"

	"github.com/ihatemyfcklife/badsharing"
)

func main() {
	file, err := os.Open("document.pdf")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	meta, err := badsharing.NewFileMetadata("document.pdf", file)
	if err != nil {
		panic(err)
	}

	keyBytes, err := hex.DecodeString(os.Getenv("BADSHARING_KEY_HEX"))
	if err != nil || len(keyBytes) != 32 {
		panic("BADSHARING_KEY_HEX must contain exactly 32 random key bytes in hex")
	}
	var key [32]byte
	copy(key[:], keyBytes)
	cfg := badsharing.SessionConfig{
		SessionID:       meta.SessionID,
		SharedKey:       key,
		WindowSize:      32,
		RedundancyRatio: 0.30, // 30% parity redundancy
	}

	sender, err := badsharing.NewSender(meta, file, cfg)
	if err != nil {
		panic(err)
	}

	for {
		frame, eof, err := sender.NextFrame()
		if err != nil {
			panic(err)
		}
		if eof {
			break
		}

		// Transmit 1380-byte encrypted frame via UDP socket or WebRTC DataChannel
		_ = frame
	}
}
```

### 2. Receiver Pipeline

```go
package main

import (
	"encoding/hex"
	"os"

	"github.com/ihatemyfcklife/badsharing"
)

func main() {
	// 1. Receive metadata bytes over network and unmarshal
	var meta badsharing.FileMetadata
	// _ = meta.UnmarshalBinary(metadataBytes)

	outFile, err := os.Create("downloaded_document.pdf")
	if err != nil {
		panic(err)
	}
	defer outFile.Close()

	keyBytes, err := hex.DecodeString(os.Getenv("BADSHARING_KEY_HEX"))
	if err != nil || len(keyBytes) != 32 {
		panic("BADSHARING_KEY_HEX must contain exactly 32 random key bytes in hex")
	}
	var key [32]byte
	copy(key[:], keyBytes)
	cfg := badsharing.SessionConfig{
		SessionID:  meta.SessionID,
		SharedKey:  key,
		WindowSize: 32,
	}

	receiver, err := badsharing.NewReceiver(&meta, outFile, cfg)
	if err != nil {
		panic(err)
	}

	// 2. Ingest incoming 1380-byte frames as they arrive from network
	// completed, err := receiver.IngestFrame(wireFrame)

	// 3. Finalize transfer and verify end-to-end SHA-256 integrity
	if err := receiver.Close(); err != nil {
		panic("checksum verification failed")
	}
}
```

---

## Component Reference

### `FileMetadata`
Encapsulates file characteristics and cryptographic integrity anchors:
- `Name`: String representation of the file name ($\le 255$ bytes).
- `Size`: Total file size in bytes (`uint64`).
- `Checksum`: SHA-256 digest of original uncompressed content (`[32]byte`).
- `ChunkSize`: Default raw chunk payload size (`1280` bytes).
- `TotalChunks`: Computed chunk count (`(Size + ChunkSize - 1) / ChunkSize`).

### `Sender`
Handles source reading, sliding-window RLNC convolution, and AEAD frame sealing:
- `NewSender(meta *FileMetadata, r io.Reader, cfg SessionConfig) (*Sender, error)`
- `NextFrame() ([]byte, bool, error)`: Emits the next 1380-byte sealed wire frame.
- `Stats() (dataPackets, parityPackets uint64)`: Returns operational telemetry.

### `Receiver`
Authenticates frames, solves missing linear equations on-the-fly, and streams in-order data directly to disk:
- `NewReceiver(meta *FileMetadata, w io.Writer, cfg SessionConfig) (*Receiver, error)`
- `IngestFrame(wireFrame []byte) (completed bool, err error)`: Authenticates and ingests an incoming frame.
- `Close() error`: Flushes remaining resequencer buffers and confirms SHA-256 integrity.
- `Progress() (bytesReceived, totalBytes uint64, percent float64)`: Returns real-time completion status.
- `Stats() (framesReceived, framesDropped uint64)`: Returns security and reception telemetry.

### `SessionConfig`
- `SessionID`: 64-bit identifier authenticated within AEAD Additional Authenticated Data (AAD).
- `SharedKey`: 32-byte secret key used to derive directional AEAD ciphers.
- `WindowSize`: Sliding window convolution depth in `badrlnc` (default `32`).
- `RedundancyRatio`: Frequency of generated parity shards (e.g. `0.25` = 25% parity).

---

## CLI Tool

A complete command-line utility is provided under `cmd/badsharing` to test transfers across UDP sockets:

### Build

```bash
go build -o badsharing ./cmd/badsharing
```

### Start Receiver

The CLI requires a secret; there is **no default passphrase**. Set the same
strong, random passphrase in the environment of both processes. Avoid `-key`
when possible because shell history and process listings can expose arguments.
Each transfer derives an encryption key using **Argon2id with a fresh 16-byte
salt**, carried with authenticated encrypted metadata. Receivers reject old
plaintext metadata. The new CLI wire handshake is not compatible with older
CLI builds (the library's legacy derivation remains deprecated for migration).

```bash
export BADSHARING_PASSPHRASE="replace-with-a-long-random-secret"
./badsharing recv -listen :9099 -out /tmp/received_file.bin
```

### Start Sender with 25% Simulated Packet Loss

```bash
./badsharing send -file my_file.bin -addr 127.0.0.1:9099 -loss 0.25 -redundancy 0.40
```

The receiver will output:
```text
File successfully received and 100% verified against SHA-256!
```

---

## Optional UDP Peer Discovery & Mesh

`PeerMesh` offers authenticated, best-effort UDP peer introductions and frame
fan-out. A reachable peer can act as a bootstrap for others (no central file
storage or mandatory tracker). Each participant uses the **same strong shared
secret** for HMAC discovery messages. Only observed, authenticated peers are
listed by `Peers()`. The mesh does **not** automatically distribute files,
schedule RLNC generations, manage congestion, or guarantee NAT traversal.

```go
conn, err := net.ListenPacket("udp4", ":9000")
if err != nil { panic(err) }
defer conn.Close()

mesh, err := badsharing.NewPeerMesh(conn, sharedKey) // [32]byte
if err != nil { panic(err) }

ctx, cancel := context.WithCancel(context.Background())
defer cancel()

go mesh.Maintain(ctx, []string{"203.0.113.10:9000"}) // reachable bootstrap example
err = mesh.Serve(ctx, func(frame []byte, from net.Addr) {
    // Pass frames to Receiver.IngestFrame for the corresponding file session.
})
// Call mesh.BroadcastFrame(senderFrame) to fan out an already sealed frame.
```

`Serve` owns reads from its UDP socket; use a dedicated UDP socket or route all
mesh traffic through it. When peers meet through a reachable bootstrap, it
exchanges candidate endpoints and triggers **reciprocal UDP probes**. This works
for some NAT configurations; restrictive/symmetric NATs may require ICE/STUN
and a TURN relay, which are **not included**.

## Key Derivation

For library clients, prefer `GenerateRandomKey()`. If a human passphrase is
needed, use `GeneratePassphraseSalt()` for **every new transfer** and then
`DeriveKeyFromPassphraseWithSalt(passphrase, salt)` on both sides. Include the
public salt in an authenticated transfer handshake; never reuse a fixed salt.
`DeriveKeyFromPassphrase(passphrase)` is deprecated and retained only for
legacy integrations (fixed-salt PBKDF2), **not** for new transfers.

---

## WebAssembly Browser Integration

`badsharing` contains zero CGO dependencies and compiles natively to WebAssembly for browser-to-browser execution over WebRTC DataChannels:

```bash
GOOS=js GOARCH=wasm go build ./...
```

### WebRTC Configuration Example

```javascript
const channel = peerConnection.createDataChannel("badsharing-stream", {
  ordered: false,       // Eliminate Head-of-Line Blocking
  maxRetransmits: 0     // Pure datagram mode; badrlnc corrects all packet loss
});

channel.onmessage = (event) => {
  // Pass 1380-byte ArrayBuffer directly to WebAssembly receiver
  wasmReceiver.ingestFrame(new Uint8Array(event.data));
};
```


---

## Automatic multi-peer swarms (new)

The `swarm` package adds **authenticated per-generation manifests**, out-of-order
GF(2) RLNC decoding from multiple independently encrypted senders, rarity-based
scheduling, bounded retries, per-generation SHA-256 verification before disk
writes, and crash-safe resume using re-hashing of previously downloaded
generations. The library remains usable without WebRTC and without a server.

`signaling` provides a bounded HTTP rendezvous service for ICE SDP exchange.
Signaling nodes do not receive encrypted file shards; however, they can observe
network metadata. Clients must use HTTPS away from localhost and authenticate
with a strong bearer token. This broker is a bootstrap service, **not a trackerless
DHT**. It is suitable for small private swarms, not an internet-wide directory.

The optional **Pion WebRTC** transport lives in a separate Go module under
`transport/webrtc/`, keeping the core Go module lean. It supports ICE,
STUN and TURN, with a reliable ordered control DataChannel (manifest and requests)
and an unordered, retransmission-disabled DataChannel for RLNC frames.
Use TURN credentials from a trusted deployment. A TURN relay may carry encrypted
traffic when direct peer connectivity fails; this is still encrypted end-to-end
at the badcrypt layer.

### Quickstart: two terminals over WebRTC

You need Go 1.24+ (a newer toolchain may be downloaded for Pion),
a reachable signaling server and a strong *independently shared* pair
of secrets. Generate both once, and set the same values on sender and receiver:

```bash
export BADSHARING_SIGNAL_TOKEN="$(openssl rand -hex 32)"
export BADSHARING_KEY_HEX="$(openssl rand -hex 32)"
```

Use the **same** environment values in the receiver terminal; don't rerun
the generator there. Distribute secrets via a secure channel, not through
the signaling service. The token limits rendezvous access; the random
`BADSHARING_KEY_HEX` authenticates manifest and encrypted data.

Start a rendezvous server on the same machine:

```bash
go run ./cmd/badsharing-signaling -listen 127.0.0.1:8088
```

For a public rendezvous, configure TLS and a public hostname; the server refuses
to listen on a public address without `-tls-cert` and `-tls-key`.
On an actual internet deployment, `-signal` must use HTTPS.

Then start the sender (from inside the optional module):

```bash
cd transport/webrtc
go mod tidy
go run ./cmd/badsharing-swarm -mode send -room my-private-room -file /path/to/file.zip
```

In the receiver terminal, run from that same `transport/webrtc` directory:

```bash
go run ./cmd/badsharing-swarm -mode recv -room my-private-room -out received.zip
```

For **multi-source** download, run multiple `-mode send` peers hosting
identical content and sharing the exact same authenticated manifest, then
start `-mode recv -sources 2`. All participants need the same transfer
key and room. The receiver writes to `received.zip.part`, verifies
each generation, and atomically renames the finished file. Running again
with the same filename re-verifies partial generations and resumes missing ones.

For NAT traversal, add STUN and, when necessary, TURN to **both** clients:

```bash
export BADSHARING_TURN_USER="temporary-turn-user"
export BADSHARING_TURN_PASSWORD="temporary-turn-password"
go run ./cmd/badsharing-swarm -mode recv -room my-private-room \
  -stun stun:stun.l.google.com:19302 \
  -turn turn:turn.example.net:3478 -relay-only
```

Use your **own TURN endpoint**, valid short-lived credentials and a TLS
signaling endpoint for deployment. ICE chooses direct connections when
possible; `-relay-only` forces the TURN path for testing and restricted
networks. ICE does not guarantee a working path without suitable servers.

### Go API

`BuildGenerationManifest`, `NewGenerationSender`,
`NewGenerationReceiver`, `swarm.Source.Serve`, and `swarm.Download`
are composable independent of WebRTC. The `swarm.Link` interface only needs
`Send(ctx, payload)`, `Recv(ctx)` and `Close()`. The transport layer
must authenticate peers; a shared swarm key is a group secret, not a
per-peer identity.

Each generation sender uses a **fresh random badcrypt SessionID** to avoid
reusing ChaCha20-Poly1305 nonces. Metadata uses an HMAC plus per-generation
digests to prevent silently committing polluted data to disk. File-level
SHA-256 is checked before completion.

### Browser integration

A JavaScript transport/room adapter is available at
[`transport/webrtc/browser/peer.js`](transport/webrtc/browser/peer.js).
It connects a browser to Go/native Pion peers using compatible WebRTC
DataChannels and forwards binary messages to an application-supplied
`onPacket(peerID, bytes)` callback. Use a separate Go/WASM instance to
process those bytes through badcrypt/badrlnc. The browser adapter **is not
a full graphical upload/download application**; an application must still
wire its WASM engine, session key management and UI. Pion itself also offers
a `GOOS=js GOARCH=wasm` build, verified in CI.

### Operational limits and threats

- Only 64 source chunks per generation; verification prevents writing bad
  generations, but a malicious peer possessing the shared group key can
  disrupt a generation or cause retransmission.
- Resume re-hashes existing generation bytes; it never trusts a progress
  counter alone.
- Multi-peer scheduling uses static availability lists supplied at connection
  time (nil means full seed). Dynamic gossip inventories, a global DHT,
  bandwidth throttling, and congestion-aware fair queues across swarms
  remain future improvements.
- Large swarms require TURN bandwidth budgeting and active DoS defenses for
  the rendezvous server. Do not expose the broker publicly without TLS,
  rate limits, monitoring, and rotating private bearer tokens.
- The independent WebRTC module uses a local `replace` to compile against the
  checkout of this repository. For a published standalone transport SDK,
  migrate to a released Go module version and remove that replace.

---

## Testing & Validation

Run unit tests and verification suites:

```bash
# Run unit & integration tests
go test -v ./...

# Run tests with Go race detector
go test -v -race ./...

# Run benchmarks
go test -bench=. -benchmem -run=^$ ./...
```

---

## License

This project is licensed under the **Apache License 2.0**. See the [LICENSE](LICENSE) file for details.
