package badsharing

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"path/filepath"
)

var (
	// MagicHeader identifies a Badsharing metadata packet.
	MagicHeader = [4]byte{'B', 'S', 'H', 'R'}
)

const (

	// ProtocolVersion is the current wire version of Badsharing.
	ProtocolVersion = 0x01

	// DefaultChunkSize is the size in bytes of raw file chunks fed into the RLNC encoder.
	// 1280 bytes guarantees that with extended headers (48B) and length prefixes (2B),
	// the total shard wire size is <= 1344 bytes (calibrated badcrypt AEAD frame).
	DefaultChunkSize = 1280

	// MaxChunkSize is the maximum permitted chunk size to guarantee fit within badcrypt frame plaintext.
	MaxChunkSize = 1300

	// MaxFileNameLength is the maximum allowed length of file names in bytes.
	MaxFileNameLength = 255
)

var (
	ErrInvalidMagic       = errors.New("badsharing: invalid metadata magic header")
	ErrUnsupportedVersion = errors.New("badsharing: unsupported protocol version")
	ErrCorruptMetadata    = errors.New("badsharing: metadata payload is corrupted or truncated")
	ErrFileNameTooLong    = errors.New("badsharing: filename exceeds maximum allowed length")
	ErrInvalidChunkSize   = errors.New("badsharing: invalid chunk size in metadata")
)

// FileMetadata encapsulates essential file characteristics and cryptographic integrity anchors.
type FileMetadata struct {
	Name        string   `json:"name"`
	Size        uint64   `json:"size"`
	Checksum    [32]byte `json:"checksum"` // SHA-256 hash of original file
	ChunkSize   uint16   `json:"chunk_size"`
	TotalChunks uint64   `json:"total_chunks"`
}

// NewFileMetadata computes metadata from an io.ReadSeeker by hashing the content with SHA-256.
func NewFileMetadata(name string, r io.ReadSeeker) (*FileMetadata, error) {
	if len(name) > MaxFileNameLength {
		return nil, ErrFileNameTooLong
	}

	hasher := sha256.New()
	size, err := io.Copy(hasher, r)
	if err != nil {
		return nil, fmt.Errorf("badsharing: failed to hash file: %w", err)
	}

	// Rewind reader back to start
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("badsharing: failed to rewind reader: %w", err)
	}

	var sum [32]byte
	copy(sum[:], hasher.Sum(nil))

	chunkSize := uint16(DefaultChunkSize)
	totalChunks := uint64(0)
	if size > 0 {
		totalChunks = (uint64(size) + uint64(chunkSize) - 1) / uint64(chunkSize)
	}

	return &FileMetadata{
		Name:        name,
		Size:        uint64(size),
		Checksum:    sum,
		ChunkSize:   chunkSize,
		TotalChunks: totalChunks,
	}, nil
}

// MarshalBinary encodes FileMetadata into binary format:
// [4B Magic] [1B Version] [8B Size] [32B SHA-256] [2B ChunkSize] [8B TotalChunks] [1B NameLen] [NameBytes]
func (m *FileMetadata) MarshalBinary() ([]byte, error) {
	nameBytes := []byte(m.Name)
	if len(nameBytes) > MaxFileNameLength {
		return nil, ErrFileNameTooLong
	}

	buf := make([]byte, 4+1+8+32+2+8+1+len(nameBytes))
	copy(buf[0:4], MagicHeader[:])
	buf[4] = ProtocolVersion
	binary.BigEndian.PutUint64(buf[5:13], m.Size)
	copy(buf[13:45], m.Checksum[:])
	binary.BigEndian.PutUint16(buf[45:47], m.ChunkSize)
	binary.BigEndian.PutUint64(buf[47:55], m.TotalChunks)
	buf[55] = uint8(len(nameBytes))
	copy(buf[56:], nameBytes)

	return buf, nil
}

// UnmarshalBinary parses binary-encoded FileMetadata.
func (m *FileMetadata) UnmarshalBinary(data []byte) error {
	if len(data) < 56 {
		return ErrCorruptMetadata
	}
	if data[0] != MagicHeader[0] || data[1] != MagicHeader[1] || data[2] != MagicHeader[2] || data[3] != MagicHeader[3] {
		return ErrInvalidMagic
	}
	if data[4] != ProtocolVersion {
		return ErrUnsupportedVersion
	}

	m.Size = binary.BigEndian.Uint64(data[5:13])
	copy(m.Checksum[:], data[13:45])
	m.ChunkSize = binary.BigEndian.Uint16(data[45:47])
	if m.ChunkSize == 0 || m.ChunkSize > MaxChunkSize {
		return ErrInvalidChunkSize
	}
	m.TotalChunks = binary.BigEndian.Uint64(data[47:55])

	nameLen := int(data[55])
	if len(data) < 56+nameLen {
		return ErrCorruptMetadata
	}
	rawName := string(data[56 : 56+nameLen])
	cleanName := filepath.Base(filepath.Clean(rawName))
	if cleanName == "." || cleanName == "/" || cleanName == "" {
		cleanName = "unnamed.bin"
	}
	m.Name = cleanName

	return nil
}
