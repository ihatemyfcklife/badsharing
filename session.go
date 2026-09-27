package badsharing

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/ihatemyfcklife/badcrypt"
)

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

// DeriveKeyFromPassphrase derives a 32-byte session key from a user passphrase using SHA-256.
func DeriveKeyFromPassphrase(passphrase string) [32]byte {
	return sha256.Sum256([]byte("badsharing-passphrase-v1:" + passphrase))
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
