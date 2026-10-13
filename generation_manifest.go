package badsharing

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

// GenerationManifest authenticates both the file identity and each independent
// RLNC generation. Distribute it using a trusted transfer key or trusted channel.
// A shared swarm key cannot protect against malicious holders of that same key.
type GenerationManifest struct {
	Metadata    FileMetadata
	Hashes      [][32]byte
	Signature   [32]byte // HMAC-SHA256 over the canonical metadata and generation hashes
}

const MaxManifestGenerations = 1 << 20

// GenerationRange returns the byte offset and byte length of a generation.
// The last generation can contain fewer than GenerationSize chunks.
func GenerationRange(meta FileMetadata, generation uint64) (offset int64, length int64, err error) {
	g := uint64(meta.GenerationSize)
	if g == 0 {
		g = DefaultGenerationSize
	}
	chunk := uint64(meta.ChunkSize)
	if chunk == 0 || chunk > DefaultChunkSize || g == 0 || g > 64 {
		return 0, 0, errors.New("badsharing: generation requires 1..64 chunks of up to 1280 bytes")
	}
	if meta.Size > uint64(^uint64(0)>>1) {
		return 0, 0, errors.New("badsharing: file exceeds supported address space")
	}
	startChunks := generation * g
	if generation > 0 && startChunks/g != generation {
		return 0, 0, errors.New("badsharing: generation number overflow")
	}
	if startChunks >= meta.TotalChunks || meta.TotalChunks != (meta.Size+chunk-1)/chunk {
		return 0, 0, errors.New("badsharing: invalid generation or metadata chunk count")
	}
	start := startChunks * chunk
	if chunk > 0 && startChunks > 0 && start/chunk != startChunks {
		return 0, 0, errors.New("badsharing: generation offset overflow")
	}
	end := start + g*chunk
	if end < start || end > meta.Size {
		end = meta.Size
	}
	return int64(start), int64(end-start), nil
}

func validateGenerationMetadata(meta FileMetadata) error {
	g := uint64(meta.GenerationSize)
	if g == 0 {
		g = DefaultGenerationSize
	}
	c := uint64(meta.ChunkSize)
	if c == 0 || c > DefaultChunkSize || g == 0 || g > 64 {
		return errors.New("badsharing: unsupported manifest chunk or generation size")
	}
	if meta.Size > uint64(^uint64(0)>>1) {
		return errors.New("badsharing: file too large")
	}
	expected := meta.Size/c
	if meta.Size%c != 0 {
		expected++
	}
	if meta.TotalChunks != expected {
		return errors.New("badsharing: manifest chunk count mismatch")
	}
	gens := expected/g
	if expected%g != 0 {
		gens++
	}
	if gens > MaxManifestGenerations {
		return errors.New("badsharing: too many generations")
	}
	return nil
}

func (m *GenerationManifest) canonicalMAC(key [32]byte) ([32]byte, error) {
	var result [32]byte
	if m == nil {
		return result, errors.New("badsharing: nil manifest")
	}
	if err := validateGenerationMetadata(m.Metadata); err != nil {
		return result, err
	}
	n := m.Metadata.TotalGenerations()
	if m.Metadata.Size == 0 {
		n = 0
	}
	if uint64(len(m.Hashes)) != n {
		return result, fmt.Errorf("badsharing: expected %d generation hashes, got %d", n, len(m.Hashes))
	}
	metaBytes, err := m.Metadata.MarshalBinary()
	if err != nil {
		return result, err
	}
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("badsharing-generation-manifest-v1\x00"))
	_, _ = mac.Write(metaBytes)
	for _, digest := range m.Hashes {
		_, _ = mac.Write(digest[:])
	}
	copy(result[:], mac.Sum(nil))
	return result, nil
}

// Verify authenticates the manifest and validates its shape before allocation.
func (m *GenerationManifest) Verify(key [32]byte) error {
	calculated, err := m.canonicalMAC(key)
	if err != nil {
		return err
	}
	if !hmac.Equal(calculated[:], m.Signature[:]) {
		return errors.New("badsharing: manifest authentication failed")
	}
	return nil
}

// BuildGenerationManifest hashes the source file and every generation without
// loading the complete file in memory. The same manifest and key are used by all
// receivers; the metadata must describe the source exactly.
func BuildGenerationManifest(meta FileMetadata, src io.ReaderAt, key [32]byte) (*GenerationManifest, error) {
	if src == nil {
		return nil, errors.New("badsharing: nil manifest reader")
	}
	if err := validateGenerationMetadata(meta); err != nil {
		return nil, err
	}
	total := meta.TotalGenerations()
	if meta.Size == 0 {
		total = 0
	}
	m := &GenerationManifest{Metadata: meta, Hashes: make([][32]byte, total)}
	whole := sha256.New()
	buffer := make([]byte, int(meta.ChunkSize)*int(max(1, meta.GenerationSize)))
	for gen := uint64(0); gen < total; gen++ {
		offset, size, err := GenerationRange(meta, gen)
		if err != nil {
			return nil, err
		}
		data := buffer[:int(size)]
		if _, err := src.ReadAt(data, offset); err != nil {
			return nil, fmt.Errorf("badsharing: reading generation %d: %w", gen, err)
		}
		m.Hashes[gen] = sha256.Sum256(data)
		_, _ = whole.Write(data)
	}
	if got := whole.Sum(nil); !hmac.Equal(got, meta.Checksum[:]) {
		return nil, errors.New("badsharing: source does not match metadata SHA-256")
	}
	m.Signature, _ = m.canonicalMAC(key)
	return m, nil
}
