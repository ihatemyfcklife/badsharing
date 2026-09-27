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
	mu           sync.Mutex
	meta         *FileMetadata
	writer       io.Writer
	aead         *badcrypt.ShardAEAD
	decoder      *badrlnc.IncrementalDecoder
	resequencer  *badrlnc.InOrderResequencer
	hasher       hash.Hash

	bytesWritten     uint64
	chunksDecoded    uint64
	framesReceived   uint64
	framesDropped    uint64
	completed        bool

	plainBuf []byte
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
		meta:     meta,
		writer:   w,
		aead:     aead,
		hasher:   sha256.New(),
		plainBuf: make([]byte, badcrypt.DefaultPlaintextFrameSize),
	}

	// 1. Resequencer delivers packets strictly monotonically (0, 1, 2, ...) to writer
	initSeq := uint64(0)
	r.resequencer = badrlnc.NewInOrderResequencerWithConfig(badrlnc.ResequencerConfig{
		MaxWait:    500 * time.Millisecond,
		MaxPending: 2048,
		InitialSeq: &initSeq,
		OnEmit: func(seq uint64, packet []byte) {
			r.onPacketInOrder(seq, packet)
		},
	})

	// 2. Incremental Decoder reconstructs missing packets on-the-fly and pushes to Resequencer
	r.decoder = badrlnc.NewIncrementalDecoder(badrlnc.DecoderConfig{
		Capacity:   2048,
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
	r.mu.Lock()
	defer r.mu.Unlock()

	r.framesReceived++

	if len(wireFrame) != badcrypt.ConstantWireFrameSize {
		r.framesDropped++
		return false, fmt.Errorf("%w: expected %d, got %d",
			ErrInvalidFrameSize, badcrypt.ConstantWireFrameSize, len(wireFrame))
	}

	// 1. Authenticated Decryption with badcrypt (drops forged or replayed packets)
	plain, err := r.aead.OpenFrame(r.plainBuf, wireFrame)
	if err != nil {
		r.framesDropped++
		return false, fmt.Errorf("badsharing: frame authentication failed: %w", err)
	}

	// 2. Decode RLNC shard
	shard, err := badrlnc.DecodeShard(plain)
	if err != nil {
		r.framesDropped++
		return false, fmt.Errorf("badsharing: shard decoding failed: %w", err)
	}

	// 3. Feed shard into incremental solver
	if _, err := r.decoder.PushShard(shard); err != nil {
		// Harmless if linearly dependent (no new innovation)
		if !errors.Is(err, badrlnc.ErrLinearlyDependent) {
			r.framesDropped++
			return false, fmt.Errorf("badsharing: solver error: %w", err)
		}
	}

	return r.completed, nil
}

// Close flushes the resequencer and verifies end-to-end file integrity against meta.Checksum.
func (r *Receiver) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.resequencer != nil {
		r.resequencer.Close()
	}

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
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.completed
}

// Progress returns current transfer metrics.
func (r *Receiver) Progress() (bytesReceived, totalBytes uint64, percent float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	pct := 0.0
	if r.meta.Size > 0 {
		pct = (float64(r.bytesWritten) / float64(r.meta.Size)) * 100.0
		if pct > 100.0 {
			pct = 100.0
		}
	}
	return r.bytesWritten, r.meta.Size, pct
}

// Stats returns frame reception metrics.
func (r *Receiver) Stats() (framesReceived, framesDropped uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.framesReceived, r.framesDropped
}
