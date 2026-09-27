package badsharing

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/ihatemyfcklife/badcrypt"
	"golang.org/x/crypto/pbkdf2"
)

// kdfSalt is the cryptographic domain separation salt for PBKDF2 key stretching.
var kdfSalt = []byte("badsharing-passphrase-salt-v1")

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
	RedundancyRatio float64
}

// GenerateRandomKey creates a cryptographically secure 32-byte session secret.
func GenerateRandomKey() ([32]byte, error) {
	var key [32]byte
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		return key, fmt.Errorf("badsharing: failed to generate random key: %w", err)
	}
	return key, nil
}

// DeriveKeyFromPassphrase derives a 32-byte session key from a user passphrase using
// PBKDF2 with 100,000 iterations of HMAC-SHA256, protecting against GPU dictionary attacks.
func DeriveKeyFromPassphrase(passphrase string) [32]byte {
	var key [32]byte
	derived := pbkdf2.Key([]byte(passphrase), kdfSalt, 100_000, 32, sha256.New)
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
