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
	// MagicHeader identifies a Badsharing unencrypted metadata packet.
	MagicHeader = [4]byte{'B', 'S', 'H', 'R'}

	// MagicEncryptedHeader identifies an encrypted, AEAD-authenticated Badsharing metadata packet.
	MagicEncryptedHeader = [4]byte{'B', 'S', 'H', 'E'}
)

const (
	// ProtocolVersion1 is the legacy wire version (without dynamic SessionID in metadata).
	ProtocolVersion1 = 0x01

	// ProtocolVersion2 includes a dynamic 64-bit SessionID in metadata to eliminate nonce reuse.
	ProtocolVersion2 = 0x02

	// ProtocolVersion is the default wire version for newly generated metadata.
	ProtocolVersion = ProtocolVersion2

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
	SessionID   uint64   `json:"session_id"`
	Name        string   `json:"name"`
	Size        uint64   `json:"size"`
	Checksum    [32]byte `json:"checksum"` // SHA-256 hash of original file
	ChunkSize   uint16   `json:"chunk_size"`
	TotalChunks uint64   `json:"total_chunks"`
}

// NewFileMetadata computes metadata from an io.ReadSeeker by hashing the content with SHA-256.
// The filename is automatically sanitized with filepath.Base to prevent local directory path leakage.
func NewFileMetadata(name string, r io.ReadSeeker) (*FileMetadata, error) {
	cleanName := filepath.Base(filepath.Clean(name))
	if cleanName == "." || cleanName == "/" || cleanName == "" {
		cleanName = "unnamed.bin"
	}
	if len(cleanName) > MaxFileNameLength {
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
		SessionID:   GenerateSessionID(),
		Name:        cleanName,
		Size:        uint64(size),
		Checksum:    sum,
		ChunkSize:   chunkSize,
		TotalChunks: totalChunks,
	}, nil
}

// MarshalBinary encodes FileMetadata into binary format:
// [4B Magic] [1B Version] [8B SessionID] [8B Size] [32B SHA-256] [2B ChunkSize] [8B TotalChunks] [1B NameLen] [NameBytes]
func (m *FileMetadata) MarshalBinary() ([]byte, error) {
	nameBytes := []byte(m.Name)
	if len(nameBytes) > MaxFileNameLength {
		return nil, ErrFileNameTooLong
	}

	buf := make([]byte, 4+1+8+8+32+2+8+1+len(nameBytes))
	copy(buf[0:4], MagicHeader[:])
	buf[4] = ProtocolVersion2
	binary.BigEndian.PutUint64(buf[5:13], m.SessionID)
	binary.BigEndian.PutUint64(buf[13:21], m.Size)
	copy(buf[21:53], m.Checksum[:])
	binary.BigEndian.PutUint16(buf[53:55], m.ChunkSize)
	binary.BigEndian.PutUint64(buf[55:63], m.TotalChunks)
	buf[63] = uint8(len(nameBytes))
	copy(buf[64:], nameBytes)

	return buf, nil
}

// UnmarshalBinary parses binary-encoded FileMetadata, supporting ProtocolVersion1 and ProtocolVersion2.
func (m *FileMetadata) UnmarshalBinary(data []byte) error {
	if len(data) < 56 {
		return ErrCorruptMetadata
	}
	if data[0] != MagicHeader[0] || data[1] != MagicHeader[1] || data[2] != MagicHeader[2] || data[3] != MagicHeader[3] {
		return ErrInvalidMagic
	}

	switch data[4] {
	case ProtocolVersion1:
		m.SessionID = 0
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

	case ProtocolVersion2:
		if len(data) < 64 {
			return ErrCorruptMetadata
		}
		m.SessionID = binary.BigEndian.Uint64(data[5:13])
		m.Size = binary.BigEndian.Uint64(data[13:21])
		copy(m.Checksum[:], data[21:53])
		m.ChunkSize = binary.BigEndian.Uint16(data[53:55])
		if m.ChunkSize == 0 || m.ChunkSize > MaxChunkSize {
			return ErrInvalidChunkSize
		}
		m.TotalChunks = binary.BigEndian.Uint64(data[55:63])

		nameLen := int(data[63])
		if len(data) < 64+nameLen {
			return ErrCorruptMetadata
		}
		rawName := string(data[64 : 64+nameLen])
		cleanName := filepath.Base(filepath.Clean(rawName))
		if cleanName == "." || cleanName == "/" || cleanName == "" {
			cleanName = "unnamed.bin"
		}
		m.Name = cleanName
		return nil

	default:
		return ErrUnsupportedVersion
	}
}

// MarshalEncrypted serializes FileMetadata and seals it with ChaCha20-Poly1305 AEAD.
// Wire Format: [4B MagicEncrypted "BSHE"] [Sealed AEAD payload]
func (m *FileMetadata) MarshalEncrypted(key [32]byte) ([]byte, error) {
	plain, err := m.MarshalBinary()
	if err != nil {
		return nil, err
	}

	aead, err := CreateSessionAEAD(key, m.SessionID)
	if err != nil {
		return nil, err
	}

	sealed, err := aead.Seal(nil, plain, MagicEncryptedHeader[:])
	if err != nil {
		return nil, fmt.Errorf("badsharing: failed to seal metadata: %w", err)
	}

	out := make([]byte, 4+len(sealed))
	copy(out[0:4], MagicEncryptedHeader[:])
	copy(out[4:], sealed)
	return out, nil
}

// UnmarshalEncrypted decrypts and verifies an authenticated metadata payload.
func (m *FileMetadata) UnmarshalEncrypted(data []byte, key [32]byte) error {
	if len(data) < 4+20+16 { // 4B magic + 20B wire header + 16B poly1305 tag
		return ErrCorruptMetadata
	}
	if data[0] != MagicEncryptedHeader[0] || data[1] != MagicEncryptedHeader[1] ||
		data[2] != MagicEncryptedHeader[2] || data[3] != MagicEncryptedHeader[3] {
		return ErrInvalidMagic
	}

	sealed := data[4:]
	// Extract session ID from the first 8 bytes of sealed wire frame
	sessionID := binary.BigEndian.Uint64(sealed[:8])

	aead, err := CreateSessionAEAD(key, sessionID)
	if err != nil {
		return err
	}

	plain, err := aead.Open(nil, sealed, MagicEncryptedHeader[:])
	if err != nil {
		return fmt.Errorf("badsharing: metadata authentication failed: %w", err)
	}

	return m.UnmarshalBinary(plain)
}
