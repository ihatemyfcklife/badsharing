// Package badsharing provides authenticated, loss-tolerant peer-to-peer file
// transfer primitives with generation-based Random Linear Network Coding
// (RLNC) and ChaCha20-Poly1305 encryption.
//
// It builds on [badrlnc] and [badcrypt] and supports both direct UDP streaming
// and multi-source swarms using transport-independent packet links. A separate,
// optional Go module provides Pion WebRTC transport, with ICE, STUN, and TURN.
//
// # Core transfer
//
// A FileMetadata describes a source file and its SHA-256 digest. NewSender
// reads the file, encodes systematic and parity shards, and emits fixed-size
// encrypted frames through NextFrame. NewReceiver authenticates frames,
// incrementally decodes RLNC shards and writes recovered bytes to an io.Writer.
// Call Receiver.Close to verify the complete file against its SHA-256 digest.
//
// Each transfer needs a strong 32-byte SharedKey and a matching SessionID.
// Prefer GenerateRandomKey over passwords. If a passphrase is unavoidable,
// use GeneratePassphraseSalt and DeriveKeyFromPassphraseWithSalt; the older
// fixed-salt DeriveKeyFromPassphrase is deprecated.
//
// The standalone UDP CLI is in cmd/badsharing. For direct transfers, sender
// and receiver must share a passphrase via BADSHARING_PASSPHRASE. The CLI's
// Argon2id-based handshake uses a fresh random salt per transfer.
//
// # Authenticated generations and resumable swarms
//
// BuildGenerationManifest hashes each RLNC generation and authenticates those
// digests and file metadata with an HMAC. NewGenerationSender produces frames
// for a requested generation using a fresh random encryption session ID.
// NewGenerationReceiver authenticates frames from multiple source sessions,
// recovers a generation out of order, checks its SHA-256 digest and only then
// commits the generation using io.WriterAt.
//
// The [github.com/ihatemyfcklife/badsharing/swarm] package contains the
// transport-independent multi-peer protocol and orchestration:
//
//   - swarm.Source serves generation requests from a verified source.
//   - swarm.Download requests generations from multiple peers, retries stalled
//     work, and resumes already-verified generations when ReaderAt is supplied.
//   - swarm.Scheduler selects rare generations and ranks available sources.
//   - swarm.Link is the Send, Recv and Close interface for custom transports.
//
// Peer inventories used by the scheduler are currently supplied by callers;
// the implementation is not a trackerless DHT or a complete public swarm
// discovery network.
//
// # WebRTC, signaling and browsers
//
// [github.com/ihatemyfcklife/badsharing/signaling] provides a bounded HTTP
// rendezvous server and client. It exchanges peer identities and SDP offers
// and answers, not stored file content. Production signaling must use HTTPS,
// authentication, rate limiting and appropriate operational controls.
//
// Native Pion WebRTC DataChannels are implemented in the optional nested
// transport/webrtc module. The WebRTC command is at
// transport/webrtc/cmd/badsharing-swarm. It supports ICE candidate gathering,
// configurable STUN/TURN servers and multi-source downloading. A separate
// JavaScript adapter in transport/webrtc/browser/peer.js exposes a browser
// DataChannel packet bridge; this is not a complete browser file-sharing UI.
//
// The optional WebRTC module currently contains a local replace directive
// for the parent module, so build it from a repository checkout. The core
// module remains independent of the optional Pion dependencies.
//
// # Security and limitations
//
// Encrypted frames are authenticated before decoding. Per-generation SHA-256
// hashes detect corrupted reconstructed data before it is written to disk.
// The shared swarm key is a group credential: peers that know it can still
// deliberately disrupt transfers and are not uniquely identified by it.
//
// ICE/STUN/TURN improves the chance of connecting across NATs but does not
// guarantee every network path. TURN relays may forward encrypted file frames
// and consume bandwidth, but do not need to store file content. Signaling
// servers and TURN relays can observe network metadata.
//
// This toolkit is not yet a fully autonomous DHT-based file-sharing network
// or a production-hardened large public swarm. In particular, wide-area NAT,
// TURN failover, malicious peers, and scale-out behavior require further
// operational testing.
//
// # Documentation and examples
//
// The repository [README] contains runnable instructions for:
//
//   - The simple UDP sender/receiver with Argon2id-derived session keys.
//   - The private WebRTC swarm CLI with signaling, STUN and TURN configuration.
//   - Multi-source downloads and verified .part file resumes.
//   - Optional browser integration and supported build targets.
//
// CI tests the core package, swarm, signaling, Go race detection, WebRTC
// DataChannels and WebAssembly builds.
//
// [badrlnc]: https://github.com/ihatemyfcklife/badrlnc
// [badcrypt]: https://github.com/ihatemyfcklife/badcrypt
// [README]: https://github.com/ihatemyfcklife/badsharing#readme
package badsharing
