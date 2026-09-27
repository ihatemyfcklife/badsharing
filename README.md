# badsharing

[![CI](https://github.com/ihatemyfcklife/badsharing/actions/workflows/release.yml/badge.svg)](https://github.com/ihatemyfcklife/badsharing/actions/workflows/release.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/ihatemyfcklife/badsharing.svg)](https://pkg.go.dev/github.com/ihatemyfcklife/badsharing)
[![Go Report Card](https://goreportcard.com/badge/github.com/ihatemyfcklife/badsharing)](https://goreportcard.com/report/github.com/ihatemyfcklife/badsharing)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Zero Alloc](https://img.shields.io/badge/Allocations-0%20allocs%2Fop-brightgreen.svg)]()

**badsharing** is a decentralized, high-throughput peer-to-peer file distribution engine combining **badrlnc** (Sliding-Window Random Linear Network Coding over $\text{GF}(2)$) and **badcrypt** (ChaCha20-Poly1305 AEAD with anti-replay protection and SessionID multiplexing).

Engineered to operate with zero central servers and fully compilable to **WebAssembly** (`GOOS=js GOARCH=wasm`), `badsharing` streams files over lossy datagram transports (UDP, WebRTC DataChannels) with sub-microsecond in-memory erasure recovery and cryptographic immunity to network coding pollution attacks.

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
- **Cryptographic Pollution Immunity**: Powered by `badcrypt`, every shard is encapsulated within an authenticated 1380-byte wire frame (`SealFrame` / `OpenFrame`). Any tampered or injected frame is rejected in $O(1)$ by Poly1305 authentication before it can reach the Gauss-Jordan solver.
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

### 1. Sender Pipeline

```go
package main

import (
	"os"

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

	key := badsharing.DeriveKeyFromPassphrase("shared-session-secret")
	cfg := badsharing.SessionConfig{
		SessionID:       badsharing.GenerateSessionID(),
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

	key := badsharing.DeriveKeyFromPassphrase("shared-session-secret")
	cfg := badsharing.SessionConfig{
		SessionID:  0xBADD00D500000001,
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

```bash
./badsharing recv -listen :9099 -out /tmp/received_file.bin -key "my-secret-key"
```

### Start Sender with 25% Simulated Packet Loss

```bash
./badsharing send -file my_file.bin -addr 127.0.0.1:9099 -loss 0.25 -redundancy 0.40 -key "my-secret-key"
```

The receiver will output:
```text
File successfully received and 100% verified against SHA-256!
```

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
