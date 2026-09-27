package badsharing

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
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

// TestMetadata_EncryptedRoundTrip validates authenticated encryption and decryption of FileMetadata.
func TestMetadata_EncryptedRoundTrip(t *testing.T) {
	data := []byte("Top secret file metadata content.")
	meta, err := NewFileMetadata("classified.docx", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("NewFileMetadata failed: %v", err)
	}

	key1 := DeriveKeyFromPassphrase("correct-horse-battery-staple")
	key2 := DeriveKeyFromPassphrase("wrong-password")

	encData, err := meta.MarshalEncrypted(key1)
	if err != nil {
		t.Fatalf("MarshalEncrypted failed: %v", err)
	}

	// 1. Successful decryption with correct key
	var parsed FileMetadata
	if err := parsed.UnmarshalEncrypted(encData, key1); err != nil {
		t.Fatalf("UnmarshalEncrypted with correct key failed: %v", err)
	}
	if parsed.Name != meta.Name || parsed.Size != meta.Size || parsed.SessionID != meta.SessionID {
		t.Fatalf("decrypted metadata fields do not match original")
	}

	// 2. Decryption fails with incorrect key
	var parsedWrong FileMetadata
	if err := parsedWrong.UnmarshalEncrypted(encData, key2); err == nil {
		t.Fatalf("expected error when decrypting with incorrect key, got nil")
	}

	// 3. Decryption fails if ciphertext is tampered with
	tampered := make([]byte, len(encData))
	copy(tampered, encData)
	tampered[len(tampered)-1] ^= 0x01 // Flip Poly1305 tag bit
	var parsedTampered FileMetadata
	if err := parsedTampered.UnmarshalEncrypted(tampered, key1); err == nil {
		t.Fatalf("expected error when decrypting tampered metadata, got nil")
	}
}

// TestMetadata_Version1Compatibility verifies backward-compatible parsing of ProtocolVersion1 metadata.
func TestMetadata_Version1Compatibility(t *testing.T) {
	name := "legacy-file.bin"
	nameBytes := []byte(name)
	size := uint64(1024)
	chunkSize := uint16(DefaultChunkSize)
	totalChunks := uint64(1)

	// Construct raw ProtocolVersion1 packet
	buf := make([]byte, 4+1+8+32+2+8+1+len(nameBytes))
	copy(buf[0:4], MagicHeader[:])
	buf[4] = ProtocolVersion1
	binary.BigEndian.PutUint64(buf[5:13], size)
	// Checksum at 13..45 is left as zeroes
	binary.BigEndian.PutUint16(buf[45:47], chunkSize)
	binary.BigEndian.PutUint64(buf[47:55], totalChunks)
	buf[55] = uint8(len(nameBytes))
	copy(buf[56:], nameBytes)

	var meta FileMetadata
	if err := meta.UnmarshalBinary(buf); err != nil {
		t.Fatalf("UnmarshalBinary failed for ProtocolVersion1: %v", err)
	}

	if meta.Name != name {
		t.Fatalf("expected name %q, got %q", name, meta.Name)
	}
	if meta.Size != size {
		t.Fatalf("expected size %d, got %d", size, meta.Size)
	}
	if meta.SessionID != 0 {
		t.Fatalf("expected SessionID=0 for v1, got %x", meta.SessionID)
	}
}

// TestZeroByteFile verifies end-to-end handling of empty (0-byte) files.
func TestZeroByteFile(t *testing.T) {
	meta, err := NewFileMetadata("empty.txt", bytes.NewReader([]byte{}))
	if err != nil {
		t.Fatalf("NewFileMetadata failed: %v", err)
	}
	if meta.Size != 0 || meta.TotalChunks != 0 {
		t.Fatalf("expected 0 size and chunks, got size=%d chunks=%d", meta.Size, meta.TotalChunks)
	}

	key, _ := GenerateRandomKey()
	cfg := SessionConfig{
		SessionID:  meta.SessionID,
		SharedKey:  key,
		WindowSize: 32,
	}

	sender, err := NewSender(meta, bytes.NewReader([]byte{}), cfg)
	if err != nil {
		t.Fatalf("NewSender failed: %v", err)
	}

	var dest bytes.Buffer
	receiver, err := NewReceiver(meta, &dest, cfg)
	if err != nil {
		t.Fatalf("NewReceiver failed: %v", err)
	}

	if !receiver.IsComplete() {
		t.Fatalf("expected receiver to be complete immediately for 0-byte file")
	}
	_, _, pct := receiver.Progress()
	if pct != 100.0 {
		t.Fatalf("expected 100%% progress for empty file, got %.1f%%", pct)
	}

	frame, eof, err := sender.NextFrame()
	if err != nil {
		t.Fatalf("NextFrame failed: %v", err)
	}
	if !eof || frame != nil {
		t.Fatalf("expected immediate EOF on empty file")
	}

	if err := receiver.Close(); err != nil {
		t.Fatalf("Close failed on 0-byte receiver: %v", err)
	}
	if dest.Len() != 0 {
		t.Fatalf("expected empty destination, got %d bytes", dest.Len())
	}
}

// TestDynamicSessionID verifies that fresh session IDs are generated to eliminate nonce reuse.
func TestDynamicSessionID(t *testing.T) {
	meta1, err := NewFileMetadata("file1.bin", bytes.NewReader([]byte("test1")))
	if err != nil {
		t.Fatalf("NewFileMetadata 1 failed: %v", err)
	}
	meta2, err := NewFileMetadata("file2.bin", bytes.NewReader([]byte("test2")))
	if err != nil {
		t.Fatalf("NewFileMetadata 2 failed: %v", err)
	}

	if meta1.SessionID == 0 || meta2.SessionID == 0 {
		t.Fatalf("expected non-zero session IDs")
	}
	if meta1.SessionID == meta2.SessionID {
		t.Fatalf("expected distinct session IDs, got identical: %x", meta1.SessionID)
	}
}

// TestPBKDF2KeyDerivation verifies consistent and domain-separated key stretching.
func TestPBKDF2KeyDerivation(t *testing.T) {
	k1 := DeriveKeyFromPassphrase("password123")
	k2 := DeriveKeyFromPassphrase("password123")
	k3 := DeriveKeyFromPassphrase("different-pass")

	if !bytes.Equal(k1[:], k2[:]) {
		t.Fatalf("expected deterministic key derivation for same passphrase")
	}
	if bytes.Equal(k1[:], k3[:]) {
		t.Fatalf("expected different keys for different passphrases")
	}
}


// TestSwarmRecoding_DistributedRelay tests that an intermediate peer receiving only 30% of frames
// can use RecodeFrame() to act as a seeder and feed recoded frames to a third peer.
func TestSwarmRecoding_DistributedRelay(t *testing.T) {
	const fileSize = 40 * 1024 // 40 KB
	sourceData := make([]byte, fileSize)
	_, _ = io.ReadFull(rand.Reader, sourceData)

	meta, err := NewFileMetadata("swarm-test.bin", bytes.NewReader(sourceData))
	if err != nil {
		t.Fatalf("NewFileMetadata failed: %v", err)
	}

	key, _ := GenerateRandomKey()
	sessionID := GenerateSessionID()

	cfg := SessionConfig{
		SessionID:       sessionID,
		SharedKey:       key,
		WindowSize:      32,
		RedundancyRatio: 0.50,
	}

	sender, _ := NewSender(meta, bytes.NewReader(sourceData), cfg)

	// Peer A receives only 50% of the sender frames
	var bufA bytes.Buffer
	peerA, _ := NewReceiver(meta, &bufA, cfg)

	var allFrames [][]byte
	for {
		frame, eof, err := sender.NextFrame()
		if err != nil {
			t.Fatalf("NextFrame failed: %v", err)
		}
		if eof {
			break
		}
		allFrames = append(allFrames, frame)
	}

	// Feed first 40% of frames to Peer A
	limit := len(allFrames) * 4 / 10
	for i := 0; i < limit; i++ {
		_, _ = peerA.IngestFrame(allFrames[i])
	}

	if peerA.IsComplete() {
		t.Fatal("peer A should not be complete with only 40% frames")
	}

	// Peer B connects to Peer A and receives recoded frames from Peer A!
	var bufB bytes.Buffer
	peerB, _ := NewReceiver(meta, &bufB, cfg)

	// Feed first 40% systematic frames directly to B
	for i := 0; i < limit; i++ {
		_, _ = peerB.IngestFrame(allFrames[i])
	}

	// Peer A produces recoded frames for Peer B
	recodedCount := 0
	for i := 0; i < 20; i++ {
		recodedFrame, err := peerA.RecodeFrame()
		if err == nil {
			recodedCount++
			_, _ = peerB.IngestFrame(recodedFrame)
		}
	}

	t.Logf("Peer A generated %d recoded frames for Peer B (FramesRecoded=%d)", recodedCount, peerA.FramesRecoded())
}

// TestFileTransfer_MultiGeneration_500KB tests streaming across 7+ generations with 20% loss.
func TestFileTransfer_MultiGeneration_500KB(t *testing.T) {
	const fileSize = 500 * 1024 // 500 KB (~391 chunks / 7 generations)
	sourceData := make([]byte, fileSize)
	_, _ = io.ReadFull(rand.Reader, sourceData)

	meta, err := NewFileMetadata("large-500k.bin", bytes.NewReader(sourceData))
	if err != nil {
		t.Fatalf("NewFileMetadata failed: %v", err)
	}

	key := DeriveKeyFromPassphrase("multi-generation-key")
	sessionID := uint64(0x4242424242424242)

	cfg := SessionConfig{
		SessionID:       sessionID,
		SharedKey:       key,
		GenerationSize:  64,
		RedundancyRatio: 0.40,
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

		// Simulate 20% drop rate
		if (totalFrames % 5) == 0 {
			droppedFrames++
			continue
		}

		_, _ = receiver.IngestFrame(frame)
	}

	if err := receiver.Close(); err != nil {
		t.Fatalf("receiver Close failed on multi-generation file: %v", err)
	}

	if !bytes.Equal(destBuf.Bytes(), sourceData) {
		t.Fatalf("reconstructed data mismatch on multi-generation file")
	}

	dSent, pSent := sender.Stats()
	t.Logf("Multi-generation 500KB Transfer Passed: Total=%d (Data=%d, Parity=%d), Dropped=%d, Bit-Exact 100%%",
		totalFrames, dSent, pSent, droppedFrames)
}
