# badsharing

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go)](go.mod)

**badsharing** is a decentralized, high-throughput peer-to-peer file sharing engine combining **badrlnc** (Sliding-Window Random Linear Network Coding over $\text{GF}(2)$) and **badcrypt** (ChaCha20-Poly1305 AEAD with anti-replay protection and SessionID multiplexing).

Designed to operate with zero central servers and fully compilable to **WebAssembly** (`GOOS=js GOARCH=wasm`), `badsharing` streams files over lossy datagram transports (UDP, WebRTC DataChannels) with sub-microsecond in-memory erasure recovery and cryptographic immunity to network coding pollution attacks.

---

## Key Capabilities

- **Loss Immunity Without Retransmission Delays**:
  Powered by `badrlnc`, sliding-window convolutional parity shards allow the receiver to reconstruct lost packets in under $1\ \mu\text{s}$ using incremental Gauss-Jordan elimination, maintaining continuous line-rate throughput even under 20% to 40% packet drop.

- **Cryptographic Pollution Attack Defense**:
  In random linear network coding, forged bits corrupt entire decoding matrices. `badsharing` embeds every shard into calibrated 1380-byte `badcrypt` authenticated frames (`SealFrame` / `OpenFrame`). Any tampered or corrupted frame is rejected in $O(1)$ by Poly1305 and dropped before reaching the linear solver.

- **Monotonic Streaming to Disk**:
  Incoming packets are reordered via `badrlnc.InOrderResequencer` and streamed directly to an `io.Writer`, preventing memory blowup when transferring large files.

- **100% WebAssembly Compatible**:
  Zero CGO dependencies. Compiles directly to Wasm for serverless browser-to-browser transfers over WebRTC DataChannels (`ordered: false, maxRetransmits: 0`).

---

## Architecture

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

## Installation

```bash
go get github.com/ihatemyfcklife/badsharing
```

Requirements: **Go 1.24+**.

---

## Quickstart

### Sender Pipeline

```go
package main

import (
	"bytes"
	"os"

	"github.com/ihatemyfcklife/badsharing"
)

func main() {
	file, _ := os.Open("archive.tar.gz")
	defer file.Close()

	meta, _ := badsharing.NewFileMetadata("archive.tar.gz", file)

	key := badsharing.DeriveKeyFromPassphrase("shared-secret-passphrase")
	cfg := badsharing.SessionConfig{
		SessionID:       badsharing.GenerateSessionID(),
		SharedKey:       key,
		WindowSize:      32,
		RedundancyRatio: 0.30, // 30% parity redundancy
	}

	sender, _ := badsharing.NewSender(meta, file, cfg)

	for {
		frame, eof, err := sender.NextFrame()
		if err != nil || eof {
			break
		}
		// Send 1380-byte encrypted frame over UDP or WebRTC DataChannel
		_ = frame
	}
}
```

### Receiver Pipeline

```go
package main

import (
	"os"

	"github.com/ihatemyfcklife/badsharing"
)

func main() {
	var meta badsharing.FileMetadata
	// (Receive metadata packet and unmarshal via meta.UnmarshalBinary)

	outFile, _ := os.Create("downloaded_" + meta.Name)
	defer outFile.Close()

	key := badsharing.DeriveKeyFromPassphrase("shared-secret-passphrase")
	cfg := badsharing.SessionConfig{
		SessionID:  0xBADD00D500000001,
		SharedKey:  key,
		WindowSize: 32,
	}

	receiver, _ := badsharing.NewReceiver(&meta, outFile, cfg)

	// Ingest incoming 1380-byte frames as they arrive
	// completed, err := receiver.IngestFrame(wireFrame)

	// Finalize and verify end-to-end SHA-256 integrity
	if err := receiver.Close(); err != nil {
		panic("integrity check failed")
	}
}
```

---

## CLI Usage

A lightweight CLI tool is provided under `cmd/badsharing` to test transfers over UDP:

### Build CLI

```bash
go build -o badsharing ./cmd/badsharing
```

### 1. Start Receiver

```bash
./badsharing recv -listen :9099 -out /tmp/received_file.bin -key "my-secret-key"
```

### 2. Start Sender (With 25% Simulated Packet Loss)

```bash
./badsharing send -file my_file.bin -addr 127.0.0.1:9099 -loss 0.25 -redundancy 0.50 -key "my-secret-key"
```

The receiver will output:
```text
File successfully received and 100% verified against SHA-256!
```

---

## WebAssembly Build

To compile `badsharing` for in-browser WebRTC execution:

```bash
GOOS=js GOARCH=wasm go build ./...
```

---

## License

This project is licensed under the **Apache License 2.0**. See the [LICENSE](LICENSE) file for details.
