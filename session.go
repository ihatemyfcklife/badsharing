package badsharing

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/ihatemyfcklife/badcrypt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

// legacyKDFSalt is retained only to decode sessions created by older applications.
// Deprecated: never use the legacy fixed-salt derivation for new sessions.
var legacyKDFSalt = []byte("badsharing-passphrase-salt-v1")

// PassphraseSaltSize is the required random per-transfer salt size.
const PassphraseSaltSize = 16

// GeneratePassphraseSalt returns a fresh cryptographically random salt.
// The salt is public and must accompany the encrypted transfer metadata.
func GeneratePassphraseSalt() ([PassphraseSaltSize]byte, error) {
	var salt [PassphraseSaltSize]byte
	_, err := io.ReadFull(rand.Reader, salt[:])
	return salt, err
}

// DeriveKeyFromPassphraseWithSalt uses Argon2id with a unique per-transfer salt.
// The passphrase must be supplied independently; salts need not be secret.
func DeriveKeyFromPassphraseWithSalt(passphrase string, salt [PassphraseSaltSize]byte) [32]byte {
	var key [32]byte
	derived := argon2.IDKey([]byte(passphrase), salt[:], 3, 64*1024, 4, 32)
	copy(key[:], derived)
	return key
}

const (
	// DefaultWindowSize is the default sliding window convolution depth in badrlnc.
	DefaultWindowSize = 32

	// DefaultRedundancyRatio specifies the default parity shard frequency (e.g. 0.25 = 1 parity per 4 data).
	DefaultRedundancyRatio = 0.25
)

// SessionConfig configures parameters for a secure, resilient file transfer session.
type SessionConfig struct {
	SessionID       uint64
	SharedKey       [32]byte
	WindowSize      int
	GenerationSize  int
	RedundancyRatio float64
	// SequenceStart is the absolute RLNC sequence number for a scoped sender.
	SequenceStart uint64
}

// GenerateRandomKey creates a cryptographically secure 32-byte session secret.
func GenerateRandomKey() ([32]byte, error) {
	var key [32]byte
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		return key, fmt.Errorf("badsharing: failed to generate random key: %w", err)
	}
	return key, nil
}

// DeriveKeyFromPassphrase is provided only for backward compatibility with v1 clients.
// Deprecated: uses a fixed salt; use DeriveKeyFromPassphraseWithSalt and GeneratePassphraseSalt.
func DeriveKeyFromPassphrase(passphrase string) [32]byte {
	var key [32]byte
	derived := pbkdf2.Key([]byte(passphrase), legacyKDFSalt, 100_000, 32, sha256.New)
	copy(key[:], derived)
	return key
}

// GenerateSessionID returns a cryptographically random 64-bit session identifier.
func GenerateSessionID() uint64 {
	var b [8]byte
	_, _ = io.ReadFull(rand.Reader, b[:])
	return binary.BigEndian.Uint64(b[:])
}

// CreateSessionAEAD initializes a directional or bidirectional ShardAEAD instance.
func CreateSessionAEAD(key [32]byte, sessionID uint64) (*badcrypt.ShardAEAD, error) {
	aeadKey := badcrypt.DeriveAEADKeyFromSecret(key[:])
	return badcrypt.NewShardAEADWithSession(aeadKey, sessionID)
}
