package badsharing

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/ihatemyfcklife/badcrypt"
)

// PeerMesh provides an optional UDP control plane for authenticated peer discovery,
// reciprocal UDP hole-punch attempts, and encrypted-frame fan-out.
// It does NOT provide STUN/TURN/ICE, guaranteed NAT traversal, or file scheduling.
// All peers in the same mesh must share a strong 32-byte secret.
const (
	peerMagic          = "BSD1"
	peerHello     byte = 1
	peerWelcome   byte = 2
	peerIntroduce byte = 3
	peerHeaderSize     = 13 // magic (4) + type (1) + unix timestamp (8)
	peerMACSize        = 32
	peerMaxPacket      = 256
	peerMaxMembers     = 64
	peerTTL            = 2 * time.Minute
	peerClockSkew      = 2 * time.Minute
)

type PeerMesh struct {
	conn net.PacketConn
	key  [32]byte

	mu    sync.Mutex
	peers map[string]time.Time
	seen  map[[32]byte]time.Time
}

func NewPeerMesh(conn net.PacketConn, key [32]byte) (*PeerMesh, error) {
	if conn == nil {
		return nil, errors.New("badsharing: peer mesh requires a UDP packet connection")
	}
	if key == ([32]byte{}) {
		return nil, errors.New("badsharing: peer mesh requires a non-zero shared key")
	}
	// Domain-separate the control-plane MAC key from data-plane AEAD keys.
	controlKey := sha256.Sum256(append([]byte("badsharing-peer-control-v1:"), key[:]...))
	return &PeerMesh{conn: conn, key: controlKey, peers: make(map[string]time.Time), seen: make(map[[32]byte]time.Time)}, nil
}

func validPeerAddr(s string) bool {
	a, err := netip.ParseAddrPort(s)
	return err == nil && a.Port() > 0 && !a.Addr().IsUnspecified() && !a.Addr().IsMulticast()
}

func (m *PeerMesh) sendControl(kind byte, payload []byte, addr string) error {
	if !validPeerAddr(addr) || len(payload)+peerHeaderSize+peerMACSize > peerMaxPacket {
		return errors.New("badsharing: invalid discovery endpoint or payload")
	}
	dst, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	frame := make([]byte, peerHeaderSize+len(payload)+peerMACSize)
	copy(frame, peerMagic)
	frame[4] = kind
	binary.BigEndian.PutUint64(frame[5:13], uint64(time.Now().Unix()))
	copy(frame[13:], payload)
	mac := hmac.New(sha256.New, m.key[:])
	_, _ = mac.Write(frame[:len(frame)-peerMACSize])
	copy(frame[len(frame)-peerMACSize:], mac.Sum(nil))
	_, err = m.conn.WriteTo(frame, dst)
	return err
}

// Announce contacts a known reachable peer or a small publicly reachable bootstrap
// peer. The peer introduces other authenticated participants to each other.
func (m *PeerMesh) Announce(bootstrap string) error {
	addr, err := net.ResolveUDPAddr("udp", bootstrap)
	if err != nil {
		return fmt.Errorf("badsharing: resolve bootstrap: %w", err)
	}
	return m.sendControl(peerHello, nil, addr.String())
}

func (m *PeerMesh) markPeer(addr string, now time.Time) (prior []string, added bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for peer, last := range m.peers {
		if now.Sub(last) > peerTTL {
			delete(m.peers, peer)
		}
	}
	if _, found := m.peers[addr]; found {
		m.peers[addr] = now
		return nil, false
	}
	if len(m.peers) >= peerMaxMembers {
		return nil, false
	}
	prior = make([]string, 0, len(m.peers))
	for peer := range m.peers {
		prior = append(prior, peer)
	}
	m.peers[addr] = now
	sort.Strings(prior)
	return prior, true
}

// Peers returns currently observed, authenticated UDP endpoints, excluding
// candidates that have only been introduced but never answered a greeting.
func (m *PeerMesh) Peers() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	result := make([]string, 0, len(m.peers))
	for peer, last := range m.peers {
		if now.Sub(last) > peerTTL {
			delete(m.peers, peer)
			continue
		}
		result = append(result, peer)
	}
	sort.Strings(result)
	return result
}

// HandlePacket processes only discovery messages; other datagrams, including
// badcrypt-encrypted file frames, are returned to the caller as unconsumed.
func (m *PeerMesh) HandlePacket(data []byte, from net.Addr) (bool, error) {
	if !bytes.HasPrefix(data, []byte(peerMagic)) {
		return false, nil
	}
	if len(data) < peerHeaderSize+peerMACSize || len(data) > peerMaxPacket || from == nil || !validPeerAddr(from.String()) {
		return true, errors.New("badsharing: invalid discovery packet")
	}
	mac := hmac.New(sha256.New, m.key[:])
	_, _ = mac.Write(data[:len(data)-peerMACSize])
	if !hmac.Equal(data[len(data)-peerMACSize:], mac.Sum(nil)) {
		return true, errors.New("badsharing: unauthenticated discovery packet")
	}
	now := time.Now()
	stamp := int64(binary.BigEndian.Uint64(data[5:13]))
	if stamp < now.Add(-peerClockSkew).Unix() || stamp > now.Add(peerClockSkew).Unix() {
		return true, errors.New("badsharing: stale discovery packet")
	}
	// Ignore duplicate authenticated control messages to prevent replay amplification.
	fingerprint := sha256.Sum256(append(append([]byte(nil), data...), []byte(from.String())...))
	m.mu.Lock()
	for hash, seenAt := range m.seen {
		if now.Sub(seenAt) > peerClockSkew {
			delete(m.seen, hash)
		}
	}
	if _, exists := m.seen[fingerprint]; exists {
		m.mu.Unlock()
		return true, nil
	}
	if len(m.seen) >= 1024 {
		m.mu.Unlock()
		return true, errors.New("badsharing: discovery replay cache full")
	}
	m.seen[fingerprint] = now
	m.mu.Unlock()

	payload := data[peerHeaderSize : len(data)-peerMACSize]
	peer := from.String()
	switch data[4] {
	case peerHello:
		if len(payload) != 0 {
			return true, errors.New("badsharing: invalid hello payload")
		}
		prior, added := m.markPeer(peer, now)
		if err := m.sendControl(peerWelcome, nil, peer); err != nil {
			return true, err
		}
		if added {
			// Both endpoints send a hello, opening reciprocal NAT mappings where supported.
			for _, other := range prior {
				_ = m.sendControl(peerIntroduce, []byte(other), peer)
				_ = m.sendControl(peerIntroduce, []byte(peer), other)
			}
		}
	case peerWelcome:
		if len(payload) != 0 {
			return true, errors.New("badsharing: invalid welcome payload")
		}
		m.markPeer(peer, now)
	case peerIntroduce:
		candidate := string(payload)
		if !validPeerAddr(candidate) || candidate == peer || len(candidate) > 64 {
			return true, errors.New("badsharing: invalid peer introduction")
		}
		if candidate != m.conn.LocalAddr().String() {
			return true, m.sendControl(peerHello, nil, candidate)
		}
	default:
		return true, errors.New("badsharing: unknown discovery message")
	}
	return true, nil
}

// BroadcastFrame sends a previously encrypted and authenticated badcrypt wire
// frame to all known peers. The caller decides which shards to broadcast or
// recode and must maintain application-level rate limits and congestion control.
func (m *PeerMesh) BroadcastFrame(frame []byte) (int, error) {
	if len(frame) != badcrypt.ConstantWireFrameSize {
		return 0, ErrInvalidFrameSize
	}
	peers := m.Peers()
	sent := 0
	var failures []error
	for _, peer := range peers {
		addr, err := net.ResolveUDPAddr("udp", peer)
		if err == nil {
			_, err = m.conn.WriteTo(frame, addr)
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("peer %s: %w", peer, err))
		} else {
			sent++
		}
	}
	return sent, errors.Join(failures...)
}

// Serve reads from its UDP connection until cancellation. onFrame receives raw
// encrypted file frames and should pass them to Receiver.IngestFrame. Only one
// reader should own the UDP connection. The caller retains ownership of conn.
func (m *PeerMesh) Serve(ctx context.Context, onFrame func([]byte, net.Addr)) error {
	if ctx == nil {
		return errors.New("badsharing: nil context")
	}
	buffer := make([]byte, 2048)
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		if err := m.conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			return err
		}
		n, from, err := m.conn.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if e, ok := err.(net.Error); ok && e.Timeout() {
				continue
			}
			return err
		}
		consumed, err := m.HandlePacket(buffer[:n], from)
		if consumed {
			// Invalid control packets are dropped without affecting the data flow.
			_ = err
			continue
		}
		if onFrame != nil && n == badcrypt.ConstantWireFrameSize {
			frame := append([]byte(nil), buffer[:n]...)
			onFrame(frame, from)
		}
	}
}

// Maintain keeps observed peers and bootstrap nodes reachable, so NAT mappings
// remain warm. Bootstrap peers are ordinary authenticated participants.
func (m *PeerMesh) Maintain(ctx context.Context, bootstrap []string) {
	if ctx == nil {
		return
	}
	announce := func() {
		seen := make(map[string]bool)
		for _, peer := range append(append([]string(nil), bootstrap...), m.Peers()...) {
			if seen[peer] {
				continue
			}
			seen[peer] = true
			_ = m.Announce(peer)
		}
	}
	announce()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			announce()
		}
	}
}
