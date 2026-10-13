package badsharing

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/ihatemyfcklife/badcrypt"
	"github.com/ihatemyfcklife/badrlnc"
)

// NewGenerationSender creates a sender for one generation of an authenticated
// manifest. Each invocation MUST use a fresh, random SessionID. Reusing the
// same key + SessionID with a new sender resets the nonce counter and is unsafe.
func NewGenerationSender(manifest *GenerationManifest, source io.ReaderAt, key [32]byte, generation uint64, redundancy float64) (*Sender, error) {
	if manifest == nil || source == nil {
		return nil, errors.New("badsharing: nil source or manifest")
	}
	if err := manifest.Verify(key); err != nil {
		return nil, err
	}
	offset, size, err := GenerationRange(manifest.Metadata, generation)
	if err != nil {
		return nil, err
	}
	local := manifest.Metadata
	local.Size = uint64(size)
	local.TotalChunks = (local.Size + uint64(local.ChunkSize) - 1) / uint64(local.ChunkSize)
	sid := GenerateSessionID()
	if sid == 0 {
		return nil, errors.New("badsharing: random session ID cannot be zero")
	}
	cfg := SessionConfig{
		SessionID: sid,
		SharedKey: key,
		SequenceStart: generation * uint64(max(1, manifest.Metadata.GenerationSize)),
		GenerationSize: int(max(1, manifest.Metadata.GenerationSize)),
		RedundancyRatio: redundancy,
	}
	if manifest.Metadata.GenerationSize == 0 {
		cfg.SequenceStart = generation * DefaultGenerationSize
		cfg.GenerationSize = DefaultGenerationSize
	}
	return NewSender(&local, io.NewSectionReader(source, offset, size), cfg)
}

// GenerationReceiver incrementally solves one independent RLNC generation.
// Different authenticated sender sessions can contribute to the same solver.
// A whole generation is committed only after its SHA-256 matches the manifest.
// At most 16 simultaneous sender session windows are retained per generation.
type GenerationReceiver struct {
	mu          sync.Mutex
	manifest    *GenerationManifest
	key         [32]byte
	generation  uint64
	offset      int64
	size        int64
	startSeq    uint64
	need        int
	decoder     *badrlnc.IncrementalDecoder
	ciphers     map[uint64]*badcrypt.ShardAEAD
	packets     [][]byte
	collected   int
	destination io.WriterAt
	completed   bool
	writeErr    error
}

func NewGenerationReceiver(manifest *GenerationManifest, destination io.WriterAt, key [32]byte, generation uint64) (*GenerationReceiver, error) {
	if destination == nil || manifest == nil {
		return nil, errors.New("badsharing: nil destination or manifest")
	}
	if err := manifest.Verify(key); err != nil {
		return nil, err
	}
	offset, size, err := GenerationRange(manifest.Metadata, generation)
	if err != nil {
		return nil, err
	}
	g := uint64(manifest.Metadata.GenerationSize)
	if g == 0 {
		g = DefaultGenerationSize
	}
	count := int((uint64(size) + uint64(manifest.Metadata.ChunkSize) - 1) / uint64(manifest.Metadata.ChunkSize))
	r := &GenerationReceiver{
		manifest: manifest, key: key, generation: generation,
		offset: offset, size: size, startSeq: generation*g, need: count,
		ciphers: make(map[uint64]*badcrypt.ShardAEAD),
		packets: make([][]byte, count), destination: destination,
	}
	r.decoder = badrlnc.NewIncrementalDecoder(badrlnc.DecoderConfig{
		Capacity: int(g), SymbolSize: int(manifest.Metadata.ChunkSize),
		OnDecoded: r.onDecoded,
	})
	return r, nil
}

// Called by decoder while GenerationReceiver.mu is held.
func (r *GenerationReceiver) onDecoded(seq uint64, packet []byte) {
	if seq < r.startSeq || seq >= r.startSeq+uint64(r.need) || r.writeErr != nil || r.completed {
		return
	}
	pos := int(seq-r.startSeq)
	if r.packets[pos] != nil {
		return
	}
	expected := int(r.manifest.Metadata.ChunkSize)
	remaining := r.size-int64(pos)*int64(expected)
	if remaining < int64(expected) {
		expected = int(remaining)
	}
	if expected <= 0 || len(packet) != expected {
		r.writeErr = errors.New("badsharing: decoded packet has invalid length")
		return
	}
	r.packets[pos] = bytes.Clone(packet)
	r.collected++
	if r.collected < r.need {
		return
	}
	// Compute digest before writing anything to disk.
	h := sha256.New()
	for _, part := range r.packets {
		_, _ = h.Write(part)
	}
	if !bytes.Equal(h.Sum(nil), r.manifest.Hashes[r.generation][:]) {
		r.writeErr = errors.New("badsharing: generation SHA-256 mismatch")
		return
	}
	at := r.offset
	for _, part := range r.packets {
		n, err := r.destination.WriteAt(part, at)
		if n < 0 || n > len(part) {
			r.writeErr = errors.New("badsharing: invalid WriteAt result")
			return
		}
		if err != nil {
			r.writeErr = fmt.Errorf("badsharing: persisting generation: %w", err)
			return
		}
		if n != len(part) {
			r.writeErr = fmt.Errorf("badsharing: persisting generation: %w", io.ErrShortWrite)
			return
		}
		at += int64(n)
	}
	r.completed = true
	// No longer retain plaintext after a successful, verified write.
	r.packets = nil
}

// IngestFrame authenticates a sender's uniquely randomized session ID, then
// validates that all coded source indices belong to this generation.
// A compromised holder of the shared encryption key can still pollute packets;
// the independently authenticated manifest detects this at generation commit.
func (r *GenerationReceiver) IngestFrame(frame []byte) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.writeErr != nil {
		return false, r.writeErr
	}
	if r.completed {
		return true, nil
	}
	if len(frame) != badcrypt.ConstantWireFrameSize {
		return false, ErrInvalidFrameSize
	}
	session := binary.BigEndian.Uint64(frame[:8])
	if session == 0 {
		return false, errors.New("badsharing: zero sender session")
	}
	cipher := r.ciphers[session]
	fresh := cipher == nil
	if fresh {
		if len(r.ciphers) >= 16 {
			return false, errors.New("badsharing: generation sender session limit reached")
		}
		var err error
		cipher, err = CreateSessionAEAD(r.key, session)
		if err != nil {
			return false, err
		}
	}
	plain, err := cipher.OpenFrame(nil, frame)
	if err != nil {
		return false, fmt.Errorf("badsharing: unauthenticated generation frame: %w", err)
	}
	if fresh {
		r.ciphers[session] = cipher
	}
	shard, err := badrlnc.DecodeShard(plain)
	if err != nil {
		return false, err
	}
	if shard.BaseSeq < r.startSeq || shard.BaseSeq >= r.startSeq+uint64(r.need) || shard.Mask.Weight() == 0 {
		return false, errors.New("badsharing: shard references another generation")
	}
	// Check ALL selected sequence positions, not just the base index.
	for word, mask := range shard.Mask {
		for bit := 0; bit < 64; bit++ {
			if mask&(uint64(1)<<uint(bit)) != 0 {
				seq := shard.BaseSeq + uint64(word*64+bit)
				if seq < shard.BaseSeq || seq >= r.startSeq+uint64(r.need) {
					return false, errors.New("badsharing: shard mask crosses generation boundary")
				}
			}
		}
	}
	_, err = r.decoder.PushShard(shard)
	if err != nil && !errors.Is(err, badrlnc.ErrLinearlyDependent) {
		return false, err
	}
	return r.completed, r.writeErr
}

// Progress provides the recovered symbol count and innovation rank.
func (r *GenerationReceiver) Progress() (decoded, required int, innovative uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, innovative, _, _ = r.decoder.Stats()
	return r.collected, r.need, innovative
}

func (r *GenerationReceiver) Complete() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.completed
}
