package badsharing

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerationManifestRejectsTampering(t *testing.T) {
	payload := make([]byte, 220000)
	_, _ = rand.Read(payload)
	meta, err := NewFileMetadata("file.bin", bytes.NewReader(payload))
	if err != nil { t.Fatal(err) }
	key, _ := GenerateRandomKey()
	manifest, err := BuildGenerationManifest(*meta, bytes.NewReader(payload), key)
	if err != nil { t.Fatal(err) }
	if err := manifest.Verify(key); err != nil { t.Fatal(err) }
	if len(manifest.Hashes) < 2 { t.Fatal("expected multiple generations") }
	manifest.Hashes[1][0] ^= 0x01
	if err := manifest.Verify(key); err == nil { t.Fatal("tampered generation hash accepted") }
	manifest.Hashes[1][0] ^= 0x01
	wrong, _ := GenerateRandomKey()
	if err := manifest.Verify(wrong); err == nil { t.Fatal("wrong manifest key accepted") }
}

func TestGenerationTransferOutOfOrderMultiSender(t *testing.T) {
	payload := make([]byte, 218345)
	_, _ = rand.Read(payload)
	meta, err := NewFileMetadata("file.bin", bytes.NewReader(payload))
	if err != nil { t.Fatal(err) }
	key, _ := GenerateRandomKey()
	manifest, err := BuildGenerationManifest(*meta, bytes.NewReader(payload), key)
	if err != nil { t.Fatal(err) }
	output, err := os.Create(filepath.Join(t.TempDir(), "received.bin"))
	if err != nil { t.Fatal(err) }
	defer output.Close()
	n := int(meta.TotalGenerations())
	decoders := make([]*GenerationReceiver, n)
	all := make([][][]byte, n)
	for g := 0; g < n; g++ {
		decoders[g], err = NewGenerationReceiver(manifest, output, key, uint64(g))
		if err != nil { t.Fatal(err) }
		for senderIndex := 0; senderIndex < 2; senderIndex++ {
			sender, err := NewGenerationSender(manifest, bytes.NewReader(payload), key, uint64(g), 0.8)
			if err != nil { t.Fatal(err) }
			for {
				frame, eof, err := sender.NextFrame()
				if err != nil { t.Fatal(err) }
				if eof { break }
				all[g] = append(all[g], frame)
			}
		}
		mrand.Shuffle(len(all[g]), func(i, j int) { all[g][i], all[g][j] = all[g][j], all[g][i] })
	}
	// Process generations in reverse order and drop some shards within each.
	for g := n-1; g >= 0; g-- {
		for i, frame := range all[g] {
			if i%9 == 0 { continue }
			_, err := decoders[g].IngestFrame(frame)
			if err != nil { t.Fatalf("generation %d: %v", g, err) }
			if decoders[g].Complete() { break }
		}
		if !decoders[g].Complete() {
			t.Fatalf("generation %d not recovered after redundancy", g)
		}
	}
	if _, err := output.Seek(0, io.SeekStart); err != nil { t.Fatal(err) }
	received, err := io.ReadAll(output)
	if err != nil { t.Fatal(err) }
	if !bytes.Equal(received, payload) { t.Fatal("multi-source out-of-order file differs from source") }
}

func TestGenerationRejectsWrongSourceAndWriteFailures(t *testing.T) {
	payload := []byte("test generation")
	meta, _ := NewFileMetadata("test", bytes.NewReader(payload))
	key, _ := GenerateRandomKey()
	manifest, _ := BuildGenerationManifest(*meta, bytes.NewReader(payload), key)
	bad := newFailingWriterAt(errors.New("disk full"))
	receiver, err := NewGenerationReceiver(manifest, bad, key, 0)
	if err != nil { t.Fatal(err) }
	sender, err := NewGenerationSender(manifest, bytes.NewReader(payload), key, 0, 0.3)
	if err != nil { t.Fatal(err) }
	frame, _, err := sender.NextFrame()
	if err != nil { t.Fatal(err) }
	_, err = receiver.IngestFrame(frame)
	if !errors.Is(err, bad.err) { t.Fatalf("write error got %v", err) }

	receiver2, err := NewGenerationReceiver(manifest, bad, key, 0)
	if err != nil { t.Fatal(err) }
	frame[len(frame)-1] ^= 1
	if _, err := receiver2.IngestFrame(frame); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}

type failingWriterAt struct {err error}
func newFailingWriterAt(err error) *failingWriterAt { return &failingWriterAt{err: err} }
func (f *failingWriterAt) WriteAt(_ []byte, _ int64) (int, error) {return 0, f.err}
