package badsharing

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"io"
	mrand "math/rand/v2"
	"sync"
	"testing"
)

// TestMetadata_RoundTrip verifies that FileMetadata serializes and deserializes accurately.
func TestMetadata_RoundTrip(t *testing.T) {
	data := []byte("Testing Badsharing metadata serialization and verification.")
	meta, err := NewFileMetadata("test-document.pdf", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("NewFileMetadata failed: %v", err)
	}

	buf, err := meta.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	var parsed FileMetadata
	if err := parsed.UnmarshalBinary(buf); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}

	if parsed.Name != meta.Name {
		t.Fatalf("name mismatch: expected %q, got %q", meta.Name, parsed.Name)
	}
	if parsed.Size != meta.Size {
		t.Fatalf("size mismatch: expected %d, got %d", meta.Size, parsed.Size)
	}
	if !bytes.Equal(parsed.Checksum[:], meta.Checksum[:]) {
		t.Fatalf("checksum mismatch")
	}
	if parsed.TotalChunks != meta.TotalChunks {
		t.Fatalf("total chunks mismatch: expected %d, got %d", meta.TotalChunks, parsed.TotalChunks)
	}
}

// TestFileTransfer_Lossless tests end-to-end file streaming over an ideal network with 0% loss.
func TestFileTransfer_Lossless(t *testing.T) {
	const fileSize = 64 * 1024 // 64 KB
	sourceData := make([]byte, fileSize)
	_, _ = io.ReadFull(rand.Reader, sourceData)

	meta, err := NewFileMetadata("payload-64k.bin", bytes.NewReader(sourceData))
	if err != nil {
		t.Fatalf("NewFileMetadata failed: %v", err)
	}

	key, _ := GenerateRandomKey()
	sessionID := GenerateSessionID()

	cfg := SessionConfig{
		SessionID:       sessionID,
		SharedKey:       key,
		WindowSize:      32,
		RedundancyRatio: 0.20,
	}

	sender, err := NewSender(meta, bytes.NewReader(sourceData), cfg)
	if err != nil {
		t.Fatalf("NewSender failed: %v", err)
	}

	var destBuf bytes.Buffer
	receiver, err := NewReceiver(meta, &destBuf, cfg)
	if err != nil {
		t.Fatalf("NewReceiver failed: %v", err)
	}

	for {
		frame, eof, err := sender.NextFrame()
		if err != nil {
			t.Fatalf("NextFrame failed: %v", err)
		}
		if eof {
			break
		}

		if _, err := receiver.IngestFrame(frame); err != nil {
			t.Fatalf("IngestFrame failed: %v", err)
		}
	}

	if err := receiver.Close(); err != nil {
		t.Fatalf("receiver Close/Verify failed: %v", err)
	}

	if !bytes.Equal(destBuf.Bytes(), sourceData) {
		t.Fatalf("reconstructed data does not match original source data")
	}

	dataSent, paritySent := sender.Stats()
	t.Logf("Lossless: Data=%d, Parity=%d, FileSize=%d bytes", dataSent, paritySent, fileSize)
}

// TestFileTransfer_SimulatedLoss_20Percent tests RLNC recovery under 20% random packet drops.
func TestFileTransfer_SimulatedLoss_20Percent(t *testing.T) {
	const fileSize = 100 * 1024 // 100 KB
	sourceData := make([]byte, fileSize)
	_, _ = io.ReadFull(rand.Reader, sourceData)

	meta, err := NewFileMetadata("loss-test-100k.bin", bytes.NewReader(sourceData))
	if err != nil {
		t.Fatalf("NewFileMetadata failed: %v", err)
	}

	key := DeriveKeyFromPassphrase("super-secure-decentralized-passphrase")
	sessionID := uint64(0xDEADBEEFCAFE1337)

	// 50% parity redundancy to comfortably overcome 20% random losses
	cfg := SessionConfig{
		SessionID:       sessionID,
		SharedKey:       key,
		WindowSize:      32,
		RedundancyRatio: 0.50,
	}

	sender, err := NewSender(meta, bytes.NewReader(sourceData), cfg)
	if err != nil {
		t.Fatalf("NewSender failed: %v", err)
	}

	var destBuf bytes.Buffer
	receiver, err := NewReceiver(meta, &destBuf, cfg)
	if err != nil {
		t.Fatalf("NewReceiver failed: %v", err)
	}

	totalFrames := 0
	droppedFrames := 0

	for {
		frame, eof, err := sender.NextFrame()
		if err != nil {
			t.Fatalf("NextFrame failed: %v", err)
		}
		if eof {
			break
		}

		totalFrames++

		// Simulate 20% network packet drop
		if mrand.Float64() < 0.20 {
			droppedFrames++
			continue
		}

		_, _ = receiver.IngestFrame(frame)
	}

	if err := receiver.Close(); err != nil {
		t.Fatalf("receiver Close/Verify failed with 20%% loss: %v", err)
	}

	if !bytes.Equal(destBuf.Bytes(), sourceData) {
		t.Fatalf("reconstructed data mismatch under 20%% loss")
	}

	t.Logf("20%% Loss Recovery: Total Frames=%d, Dropped=%d (%.1f%%), Verified SHA256=100%%",
		totalFrames, droppedFrames, (float64(droppedFrames)/float64(totalFrames))*100.0)
}

// TestFileTransfer_SimulatedLoss_30Percent tests RLNC recovery under 30% heavy loss.
func TestFileTransfer_SimulatedLoss_30Percent(t *testing.T) {
	const fileSize = 80 * 1024 // 80 KB
	sourceData := make([]byte, fileSize)
	_, _ = io.ReadFull(rand.Reader, sourceData)

	meta, err := NewFileMetadata("heavy-loss-80k.bin", bytes.NewReader(sourceData))
	if err != nil {
		t.Fatalf("NewFileMetadata failed: %v", err)
	}

	key, _ := GenerateRandomKey()
	sessionID := GenerateSessionID()

	// 65% parity redundancy to handle 30% loss comfortably
	cfg := SessionConfig{
		SessionID:       sessionID,
		SharedKey:       key,
		WindowSize:      48,
		RedundancyRatio: 0.65,
	}

	sender, err := NewSender(meta, bytes.NewReader(sourceData), cfg)
	if err != nil {
		t.Fatalf("NewSender failed: %v", err)
	}

	var destBuf bytes.Buffer
	receiver, err := NewReceiver(meta, &destBuf, cfg)
	if err != nil {
		t.Fatalf("NewReceiver failed: %v", err)
	}

	totalFrames := 0
	droppedFrames := 0

	for {
		frame, eof, err := sender.NextFrame()
		if err != nil {
			t.Fatalf("NextFrame failed: %v", err)
		}
		if eof {
			break
		}

		totalFrames++

		// Simulate 30% network packet drop
		if mrand.Float64() < 0.30 {
			droppedFrames++
			continue
		}

		_, _ = receiver.IngestFrame(frame)
	}

	if err := receiver.Close(); err != nil {
		t.Fatalf("receiver Close/Verify failed with 30%% loss: %v", err)
	}

	if !bytes.Equal(destBuf.Bytes(), sourceData) {
		t.Fatalf("reconstructed data mismatch under 30%% loss")
	}

	t.Logf("30%% Loss Recovery: Total Frames=%d, Dropped=%d (%.1f%%), Verified SHA256=100%%",
		totalFrames, droppedFrames, (float64(droppedFrames)/float64(totalFrames))*100.0)
}

// TestFileTransfer_PollutionAttackResistance tests that forged/corrupted frames are rejected by AEAD.
func TestFileTransfer_PollutionAttackResistance(t *testing.T) {
	sourceData := []byte("Sensitive data stream protected against network coding pollution attacks!")
	meta, err := NewFileMetadata("sensitive.txt", bytes.NewReader(sourceData))
	if err != nil {
		t.Fatalf("NewFileMetadata failed: %v", err)
	}

	key, _ := GenerateRandomKey()
	sessionID := GenerateSessionID()

	cfg := SessionConfig{
		SessionID:       sessionID,
		SharedKey:       key,
		WindowSize:      16,
		RedundancyRatio: 0.30,
	}

	sender, _ := NewSender(meta, bytes.NewReader(sourceData), cfg)
	var destBuf bytes.Buffer
	receiver, _ := NewReceiver(meta, &destBuf, cfg)

	for {
		frame, eof, err := sender.NextFrame()
		if err != nil {
			t.Fatalf("NextFrame failed: %v", err)
		}
		if eof {
			break
		}

		// Inject a tampered packet before sending legitimate one
		corruptedFrame := make([]byte, len(frame))
		copy(corruptedFrame, frame)
		corruptedFrame[len(corruptedFrame)-1] ^= 0xFF // Flip bits in Poly1305 authentication tag

		// Tampered frame MUST return an error and be discarded
		if _, err := receiver.IngestFrame(corruptedFrame); err == nil {
			t.Fatalf("expected error on tampered frame, got nil")
		}

		// Legitimate frame is ingested successfully
		if _, err := receiver.IngestFrame(frame); err != nil {
			t.Fatalf("failed to ingest legitimate frame: %v", err)
		}
	}

	if err := receiver.Close(); err != nil {
		t.Fatalf("receiver Close failed after pollution attack: %v", err)
	}

	if !bytes.Equal(destBuf.Bytes(), sourceData) {
		t.Fatalf("content corrupted by pollution attack")
	}

	recvFrames, droppedFrames := receiver.Stats()
	if droppedFrames == 0 {
		t.Fatalf("expected dropped frames from pollution attack, got 0")
	}
	t.Logf("Pollution Defense: Received=%d, Dropped=%d, File Verified=100%%", recvFrames, droppedFrames)
}

// TestFileTransfer_ReplayAttackResistance tests that replaying previously received frames is blocked.
func TestFileTransfer_ReplayAttackResistance(t *testing.T) {
	sourceData := []byte("Replay attack verification payload.")
	meta, _ := NewFileMetadata("replay.txt", bytes.NewReader(sourceData))

	key, _ := GenerateRandomKey()
	sessionID := GenerateSessionID()

	cfg := SessionConfig{
		SessionID:       sessionID,
		SharedKey:       key,
		WindowSize:      16,
		RedundancyRatio: 0.20,
	}

	sender, _ := NewSender(meta, bytes.NewReader(sourceData), cfg)
	var destBuf bytes.Buffer
	receiver, _ := NewReceiver(meta, &destBuf, cfg)

	var firstFrame []byte

	for {
		frame, eof, err := sender.NextFrame()
		if err != nil {
			t.Fatalf("NextFrame failed: %v", err)
		}
		if eof {
			break
		}

		if firstFrame == nil {
			firstFrame = make([]byte, len(frame))
			copy(firstFrame, frame)
		}

		_, _ = receiver.IngestFrame(frame)
	}

	// Attempt to replay the first frame
	if _, err := receiver.IngestFrame(firstFrame); err == nil {
		t.Fatalf("expected replay attack detection error, got nil")
	}

	if err := receiver.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if !bytes.Equal(destBuf.Bytes(), sourceData) {
		t.Fatalf("data mismatch")
	}
}

// BenchmarkFileTransfer benchmarks end-to-end throughput of Sender -> Wire -> Receiver.
func BenchmarkFileTransfer(b *testing.B) {
	chunk := make([]byte, DefaultChunkSize)
	_, _ = io.ReadFull(rand.Reader, chunk)

	meta := &FileMetadata{
		Name:        "bench.bin",
		Size:        uint64(len(chunk) * b.N),
		Checksum:    sha256.Sum256(chunk),
		ChunkSize:   DefaultChunkSize,
		TotalChunks: uint64(b.N),
	}

	key, _ := GenerateRandomKey()
	sessionID := GenerateSessionID()
	cfg := SessionConfig{
		SessionID:       sessionID,
		SharedKey:       key,
		WindowSize:      32,
		RedundancyRatio: 0.20,
	}

	sender, _ := NewSender(meta, bytes.NewReader(chunk), cfg)
	receiver, _ := NewReceiver(meta, io.Discard, cfg)

	b.SetBytes(int64(meta.ChunkSize))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		frame, _, err := sender.NextFrame()
		if err != nil || frame == nil {
			break
		}
		_, _ = receiver.IngestFrame(frame)
	}
}

// TestMetadata_PathTraversalProtection verifies that directory traversal attacks in metadata are neutralized.
func TestMetadata_PathTraversalProtection(t *testing.T) {
	cases := []struct {
		inputName    string
		expectedName string
	}{
		{"../../../../etc/passwd", "passwd"},
		{"/root/.ssh/id_rsa", "id_rsa"},
		{"normal_file.txt", "normal_file.txt"},
		{"sub/folder/data.csv", "data.csv"},
		{"", "unnamed.bin"},
		{".", "unnamed.bin"},
	}

	for _, tc := range cases {
		meta := FileMetadata{
			Name:        tc.inputName,
			Size:        100,
			ChunkSize:   DefaultChunkSize,
			TotalChunks: 1,
		}
		buf, err := meta.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary failed for %q: %v", tc.inputName, err)
		}

		var parsed FileMetadata
		if err := parsed.UnmarshalBinary(buf); err != nil {
			t.Fatalf("UnmarshalBinary failed for %q: %v", tc.inputName, err)
		}

		if parsed.Name != tc.expectedName {
			t.Fatalf("path traversal not sanitized: input %q, expected %q, got %q",
				tc.inputName, tc.expectedName, parsed.Name)
		}
	}
}

// TestMetadata_InvalidChunkSize verifies that chunk size bounds are enforced.
func TestMetadata_InvalidChunkSize(t *testing.T) {
	// Zero chunk size
	metaZero := FileMetadata{
		Name:        "test.txt",
		Size:        100,
		ChunkSize:   0,
		TotalChunks: 1,
	}
	bufZero, err := metaZero.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}
	var parsedZero FileMetadata
	if err := parsedZero.UnmarshalBinary(bufZero); err != ErrInvalidChunkSize {
		t.Fatalf("expected ErrInvalidChunkSize for ChunkSize=0, got %v", err)
	}

	// Oversized chunk size
	metaHuge := FileMetadata{
		Name:        "test.txt",
		Size:        100,
		ChunkSize:   MaxChunkSize + 1,
		TotalChunks: 1,
	}
	bufHuge, err := metaHuge.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}
	var parsedHuge FileMetadata
	if err := parsedHuge.UnmarshalBinary(bufHuge); err != ErrInvalidChunkSize {
		t.Fatalf("expected ErrInvalidChunkSize for ChunkSize > MaxChunkSize, got %v", err)
	}
}

// TestConcurrentIngest validates thread-safety and race-free concurrent frame ingestion.
func TestConcurrentIngest(t *testing.T) {
	const fileSize = 128 * 1024 // 128 KB
	sourceData := make([]byte, fileSize)
	_, _ = io.ReadFull(rand.Reader, sourceData)

	meta, err := NewFileMetadata("concurrent-test.bin", bytes.NewReader(sourceData))
	if err != nil {
		t.Fatalf("NewFileMetadata failed: %v", err)
	}

	key, _ := GenerateRandomKey()
	sessionID := GenerateSessionID()

	cfg := SessionConfig{
		SessionID:       sessionID,
		SharedKey:       key,
		WindowSize:      32,
		RedundancyRatio: 0.30,
	}

	sender, err := NewSender(meta, bytes.NewReader(sourceData), cfg)
	if err != nil {
		t.Fatalf("NewSender failed: %v", err)
	}

	// Collect all frames from sender
	var frames [][]byte
	for {
		frame, eof, err := sender.NextFrame()
		if err != nil {
			t.Fatalf("NextFrame failed: %v", err)
		}
		if eof {
			break
		}
		frames = append(frames, frame)
	}

	var destBuf bytes.Buffer
	receiver, err := NewReceiver(meta, &destBuf, cfg)
	if err != nil {
		t.Fatalf("NewReceiver failed: %v", err)
	}

	// Concurrently feed frames from 4 goroutines
	numWorkers := 4
	var wg sync.WaitGroup
	frameChan := make(chan []byte, len(frames))
	for _, f := range frames {
		frameChan <- f
	}
	close(frameChan)

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for f := range frameChan {
				_, _ = receiver.IngestFrame(f)
				_, _, _ = receiver.Progress()
			}
		}()
	}

	wg.Wait()

	if err := receiver.Close(); err != nil {
		t.Fatalf("receiver Close failed in concurrent test: %v", err)
	}

	if !bytes.Equal(destBuf.Bytes(), sourceData) {
		t.Fatalf("reconstructed data mismatch under concurrent ingestion")
	}
}

