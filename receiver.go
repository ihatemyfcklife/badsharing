package badsharing

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"sync"
	"time"

	"github.com/ihatemyfcklife/badcrypt"
	"github.com/ihatemyfcklife/badrlnc"
)

var (
	ErrChecksumVerificationFailed = errors.New("badsharing: file checksum verification failed (data corruption)")
	ErrFileAlreadyCompleted       = errors.New("badsharing: file transfer already completed")
	ErrInvalidFrameSize           = errors.New("badsharing: received frame size does not match wire frame size")
)

// Receiver decrypts incoming 1380-byte frames with badcrypt AEAD, feeds validated shards
// to badrlnc Gauss-Jordan incremental solver, resequences in-order, and writes to an io.Writer.
type Receiver struct {
	meta        *FileMetadata
	aead        *badcrypt.ShardAEAD
	decoder     *badrlnc.IncrementalDecoder
	resequencer *badrlnc.InOrderResequencer

	ingestMu sync.Mutex
	plainBuf []byte

	solverMu sync.Mutex

	writeMu       sync.Mutex
	writer        io.Writer
	hasher        hash.Hash
	bytesWritten  uint64
	chunksDecoded uint64
	completed     bool

	statsMu        sync.Mutex
	framesReceived uint64
	framesDropped  uint64
	framesRecoded  uint64

	recoderMu sync.Mutex
	recoder   *badrlnc.SwarmRecoder
}

// NewReceiver creates a new file receiving pipeline.
func NewReceiver(meta *FileMetadata, w io.Writer, cfg SessionConfig) (*Receiver, error) {
	if meta == nil {
		return nil, errors.New("badsharing: metadata cannot be nil")
	}
	if w == nil {
		return nil, errors.New("badsharing: writer cannot be nil")
	}

	aead, err := CreateSessionAEAD(cfg.SharedKey, cfg.SessionID)
	if err != nil {
		return nil, fmt.Errorf("badsharing: failed to initialize AEAD: %w", err)
	}

	r := &Receiver{
		meta:      meta,
		writer:    w,
		aead:      aead,
		hasher:    sha256.New(),
		plainBuf:  make([]byte, badcrypt.DefaultPlaintextFrameSize),
		completed: meta.Size == 0,
		recoder: badrlnc.NewSwarmRecoder(badrlnc.RecoderConfig{
			Capacity:   128,
			SymbolSize: int(meta.ChunkSize),
			Checksum:   true,
		}),
	}

	// 1. Resequencer delivers packets strictly monotonically (0, 1, 2, ...) to writer
	initSeq := uint64(0)
	r.resequencer = badrlnc.NewInOrderResequencerWithConfig(badrlnc.ResequencerConfig{
		MaxWait:    5 * time.Second,
		MaxPending: 4096,
		InitialSeq: &initSeq,
		OnEmit: func(seq uint64, packet []byte) {
			r.onPacketInOrder(seq, packet)
		},
	})

	// 2. Incremental Decoder reconstructs missing packets on-the-fly and pushes to Resequencer
	r.decoder = badrlnc.NewIncrementalDecoder(badrlnc.DecoderConfig{
		Capacity:   4096,
		SymbolSize: int(meta.ChunkSize),
		ZeroCopy:   false,
		OnDecoded: func(seq uint64, packet []byte) {
			r.resequencer.Push(seq, packet)
		},
	})

	return r, nil
}

// onPacketInOrder writes monotonically ordered packets to the destination stream and tracks integrity.
func (r *Receiver) onPacketInOrder(seq uint64, packet []byte) {
	r.writeMu.Lock()
	defer r.writeMu.Unlock()

	if r.completed {
		return
	}

	// Calculate how much remaining data needs to be written to avoid trailing padding
	remaining := r.meta.Size - r.bytesWritten
	toWrite := len(packet)
	if uint64(toWrite) > remaining {
		toWrite = int(remaining)
	}

	if toWrite > 0 {
		n, _ := r.writer.Write(packet[:toWrite])
		r.hasher.Write(packet[:toWrite])
		r.bytesWritten += uint64(n)
		r.chunksDecoded++
	}

	if r.bytesWritten >= r.meta.Size {
		r.completed = true
	}
}

// IngestFrame processes an incoming 1380-byte encrypted frame:
//  1. Validates AEAD authentication and anti-replay via badcrypt.
//  2. Decodes RLNC shard and feeds into Gauss-Jordan incremental solver.
//  3. Emits recovered packets to in-order stream.
//
// Returns (completed, err). If frame is forged or corrupted, err is non-nil and frame is discarded.
func (r *Receiver) IngestFrame(wireFrame []byte) (bool, error) {
	r.statsMu.Lock()
	r.framesReceived++
	r.statsMu.Unlock()

	if len(wireFrame) != badcrypt.ConstantWireFrameSize {
		r.statsMu.Lock()
		r.framesDropped++
		r.statsMu.Unlock()
		return false, fmt.Errorf("%w: expected %d, got %d",
			ErrInvalidFrameSize, badcrypt.ConstantWireFrameSize, len(wireFrame))
	}

	// 1. Authenticated Decryption with badcrypt (drops forged or replayed packets)
	r.ingestMu.Lock()
	plain, err := r.aead.OpenFrame(r.plainBuf, wireFrame)
	if err != nil {
		r.ingestMu.Unlock()
		r.statsMu.Lock()
		r.framesDropped++
		r.statsMu.Unlock()
		return false, fmt.Errorf("badsharing: frame authentication failed: %w", err)
	}

	// 2. Decode RLNC shard
	shard, err := badrlnc.DecodeShard(plain)
	if err != nil {
		r.ingestMu.Unlock()
		r.statsMu.Lock()
		r.framesDropped++
		r.statsMu.Unlock()
		return false, fmt.Errorf("badsharing: shard decoding failed: %w", err)
	}
	shard = shard.Clone()
	r.ingestMu.Unlock()

	// Buffer innovative shard into recoder pool for distributed swarm P2P recoding
	r.recoderMu.Lock()
	r.recoder.AddShard(shard)
	r.recoderMu.Unlock()

	// 3. Feed shard into incremental solver (solverMu synchronizes decoder and resequencer emissions)
	r.solverMu.Lock()
	_, pushErr := r.decoder.PushShard(shard)
	r.solverMu.Unlock()

	if pushErr != nil {
		// Harmless if linearly dependent (no new innovation)
		if !errors.Is(pushErr, badrlnc.ErrLinearlyDependent) {
			r.statsMu.Lock()
			r.framesDropped++
			r.statsMu.Unlock()
			return false, fmt.Errorf("badsharing: solver error: %w", pushErr)
		}
	}

	r.writeMu.Lock()
	done := r.completed
	r.writeMu.Unlock()

	return done, nil
}

// RecodeFrame produces a new innovative random linear combination over GF(2)
// from the currently received shards and seals it into an authenticated wire frame.
// This allows intermediate peers to act as active swarm seeders even with partial file data.
func (r *Receiver) RecodeFrame() ([]byte, error) {
	r.recoderMu.Lock()
	shard, err := r.recoder.Recode()
	r.recoderMu.Unlock()
	if err != nil {
		return nil, err
	}

	r.statsMu.Lock()
	r.framesRecoded++
	r.statsMu.Unlock()

	plainBuf := make([]byte, badcrypt.DefaultPlaintextFrameSize)
	wireBuf := make([]byte, badcrypt.ConstantWireFrameSize)

	n, err := shard.EncodeTo(plainBuf)
	if err != nil {
		return nil, fmt.Errorf("badsharing: failed to encode recoded shard: %w", err)
	}
	clear(plainBuf[n:])

	sealed, err := r.aead.SealFrame(wireBuf, plainBuf)
	if err != nil {
		return nil, fmt.Errorf("badsharing: failed to seal recoded frame: %w", err)
	}

	out := make([]byte, len(sealed))
	copy(out, sealed)
	return out, nil
}

// Close flushes the resequencer and verifies end-to-end file integrity against meta.Checksum.
func (r *Receiver) Close() error {
	r.solverMu.Lock()
	defer r.solverMu.Unlock()

	if r.resequencer != nil {
		r.resequencer.Close()
	}

	r.writeMu.Lock()
	defer r.writeMu.Unlock()

	if r.bytesWritten < r.meta.Size {
		return fmt.Errorf("badsharing: incomplete transfer: received %d of %d bytes",
			r.bytesWritten, r.meta.Size)
	}

	computed := r.hasher.Sum(nil)
	if !bytes.Equal(computed, r.meta.Checksum[:]) {
		return fmt.Errorf("%w: expected %x, got %x",
			ErrChecksumVerificationFailed, r.meta.Checksum, computed)
	}

	return nil
}

// IsComplete returns true if all file bytes have been successfully received and reconstructed.
func (r *Receiver) IsComplete() bool {
	r.writeMu.Lock()
	defer r.writeMu.Unlock()
	return r.completed
}

// Progress returns current transfer metrics.
func (r *Receiver) Progress() (bytesReceived, totalBytes uint64, percent float64) {
	r.writeMu.Lock()
	defer r.writeMu.Unlock()

	pct := 0.0
	if r.meta.Size > 0 {
		pct = (float64(r.bytesWritten) / float64(r.meta.Size)) * 100.0
		if pct > 100.0 {
			pct = 100.0
		}
	} else if r.completed {
		pct = 100.0
	}
	return r.bytesWritten, r.meta.Size, pct
}

// CurrentGeneration returns the active generation index being processed.
func (r *Receiver) CurrentGeneration() uint64 {
	r.writeMu.Lock()
	defer r.writeMu.Unlock()
	genSize := uint64(r.meta.GenerationSize)
	if genSize == 0 {
		genSize = DefaultGenerationSize
	}
	return r.chunksDecoded / genSize
}

// Stats returns frame reception metrics: framesReceived and framesDropped.
func (r *Receiver) Stats() (framesReceived, framesDropped uint64) {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	return r.framesReceived, r.framesDropped
}

// FramesRecoded returns the total number of recoded parity frames produced for the swarm.
func (r *Receiver) FramesRecoded() uint64 {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	return r.framesRecoded
}
