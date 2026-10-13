package badsharing

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/ihatemyfcklife/badcrypt"
)

func TestPassphraseSaltedArgon2id(t *testing.T) {
	first, err := GeneratePassphraseSalt()
	if err != nil {
		t.Fatal(err)
	}
	second, err := GeneratePassphraseSalt()
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("two sessions unexpectedly share the same salt")
	}
	key := DeriveKeyFromPassphraseWithSalt("very long passphrase", first)
	if key != DeriveKeyFromPassphraseWithSalt("very long passphrase", first) {
		t.Fatal("argon2id derivation must be deterministic for the same salt")
	}
	if key == DeriveKeyFromPassphraseWithSalt("very long passphrase", second) {
		t.Fatal("different salts must derive different keys")
	}
	if key == DeriveKeyFromPassphraseWithSalt("a different passphrase", first) {
		t.Fatal("different passphrases must derive different keys")
	}
}

func TestPeerMeshAuthentication(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var secret [32]byte
	_, _ = rand.Read(secret[:])
	mesh, err := NewPeerMesh(conn, secret)
	if err != nil {
		t.Fatal(err)
	}
	spoof := []byte("BSD1\x01untrusted-control-packet")
	consumed, err := mesh.HandlePacket(spoof, conn.LocalAddr())
	if !consumed || err == nil {
		t.Fatalf("unauthenticated discovery must be rejected, consumed=%v err=%v", consumed, err)
	}
	if len(mesh.Peers()) != 0 {
		t.Fatal("unauthenticated endpoint was added to peer table")
	}
}

func TestPeerMeshDiscoveryAndFanout(t *testing.T) {
	var key [32]byte
	_, _ = rand.Read(key[:])
	const members = 3
	meshes := make([]*PeerMesh, members)
	conns := make([]net.PacketConn, members)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for i := range meshes {
		conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		conns[i] = conn
		defer conn.Close()
		meshes[i], err = NewPeerMesh(conn, key)
		if err != nil {
			t.Fatal(err)
		}
	}
	got := make(chan []byte, 8)
	for i, mesh := range meshes {
		index := i
		go func() {
			_ = mesh.Serve(ctx, func(frame []byte, _ net.Addr) {
				if index == 2 {
					got <- frame
				}
			})
		}()
	}
	// B is an ordinary bootstrap peer; it introduces A and C to each other.
	if err := meshes[0].Announce(conns[1].LocalAddr().String()); err != nil {
		t.Fatal(err)
	}
	if err := meshes[2].Announce(conns[1].LocalAddr().String()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if len(meshes[0].Peers()) == 2 && len(meshes[1].Peers()) == 2 && len(meshes[2].Peers()) == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	for i, mesh := range meshes {
		if peers := mesh.Peers(); len(peers) != 2 {
			t.Fatalf("node %d discovered %d peers instead of 2: %v", i, len(peers), peers)
		}
	}
	frame := make([]byte, badcrypt.ConstantWireFrameSize)
	_, _ = rand.Read(frame)
	n, err := meshes[0].BroadcastFrame(frame)
	if err != nil || n != 2 {
		t.Fatalf("broadcast delivered %d frames, err=%v", n, err)
	}
	select {
	case received := <-got:
		if !bytes.Equal(frame, received) {
			t.Fatal("mesh corrupted an opaque frame")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("broadcast did not reach newly discovered peer")
	}
}
