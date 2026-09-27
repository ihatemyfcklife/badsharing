package badsharing

import (
	"errors"
	"fmt"
	"io"

	"github.com/ihatemyfcklife/badcrypt"
	"github.com/ihatemyfcklife/badrlnc"
)

// Sender coordinates file streaming, sliding-window RLNC encoding, and badcrypt AEAD frame sealing.
type Sender struct {
	meta              *FileMetadata
	reader            io.Reader
	encoder           *badrlnc.SlidingWindowEncoder
	aead              *badcrypt.ShardAEAD
	redundancyRatio   float64
	dataPacketsSent   uint64
	parityPacketsSent uint64
	eof               bool
	flushedCount      int
	maxTailFlushes    int

	chunkBuf []byte
	plainBuf []byte
	wireBuf  []byte

	pendingParity *badrlnc.Shard
}

// NewSender creates a new file streaming Sender.
func NewSender(meta *FileMetadata, r io.Reader, cfg SessionConfig) (*Sender, error) {
	if meta == nil {
		return nil, errors.New("badsharing: metadata cannot be nil")
	}
	if r == nil {
		return nil, errors.New("badsharing: reader cannot be nil")
	}

	windowSize := cfg.WindowSize
	if windowSize <= 0 {
		windowSize = DefaultWindowSize
	}

	redundancy := cfg.RedundancyRatio
	if redundancy <= 0 {
		redundancy = DefaultRedundancyRatio
	}

	aead, err := CreateSessionAEAD(cfg.SharedKey, cfg.SessionID)
	if err != nil {
		return nil, fmt.Errorf("badsharing: failed to create AEAD: %w", err)
	}

	enc := badrlnc.NewSlidingEncoder(badrlnc.EncoderConfig{
		WindowSize: windowSize,
		SymbolSize: int(meta.ChunkSize),
		Checksum:   true,
		ZeroCopy:   false,
	})

	// Calibrate tail parity count to window size to ensure tail packets survive loss
	tailFlushes := windowSize / 4
	if tailFlushes < 2 {
		tailFlushes = 2
	}

	return &Sender{
		meta:            meta,
		reader:          r,
		encoder:         enc,
		aead:            aead,
		redundancyRatio: redundancy,
		chunkBuf:        make([]byte, meta.ChunkSize),
		plainBuf:        make([]byte, badcrypt.DefaultPlaintextFrameSize),
		wireBuf:         make([]byte, badcrypt.ConstantWireFrameSize),
		maxTailFlushes:  tailFlushes,
	}, nil
}

// NextFrame reads the next chunk, encodes it into a shard, and seals it into a 1380-byte encrypted frame.
// Returns (frame, eof, error). When eof is true, all file chunks and tail parity shards have been emitted.
func (s *Sender) NextFrame() ([]byte, bool, error) {
	// 1. If we have a pending interleaved parity shard to emit, emit it first
	if s.pendingParity != nil {
		shard := *s.pendingParity
		s.pendingParity = nil
		s.parityPacketsSent++
		return s.sealShard(shard)
	}

	// 2. Read next raw source chunk if not yet EOF
	if !s.eof {
		n, err := io.ReadFull(s.reader, s.chunkBuf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return nil, false, fmt.Errorf("badsharing: read failed: %w", err)
		}

		if err == io.EOF || err == io.ErrUnexpectedEOF {
			s.eof = true
		}

		if n > 0 {
			shard, encErr := s.encoder.Push(s.chunkBuf[:n])
			if encErr != nil {
				return nil, false, fmt.Errorf("badsharing: RLNC push failed: %w", encErr)
			}
			s.dataPacketsSent++

			// Check if we should schedule a parity shard
			expectedParity := uint64(float64(s.dataPacketsSent) * s.redundancyRatio)
			if expectedParity > s.parityPacketsSent {
				if parity, pErr := s.encoder.GenerateParity(); pErr == nil {
					s.pendingParity = &parity
				}
			}

			return s.sealShard(shard)
		}
	}

	// 3. File data is fully consumed; emit tail parity flushes to protect burst end
	if s.flushedCount < s.maxTailFlushes {
		tailShard, err := s.encoder.FlushParity()
		if err == nil {
			s.flushedCount++
			s.parityPacketsSent++
			return s.sealShard(tailShard)
		}
		s.flushedCount = s.maxTailFlushes
	}

	return nil, true, nil
}

// sealShard serializes a Shard into plainBuf (padded to 1344B) and seals it with badcrypt AEAD.
func (s *Sender) sealShard(shard badrlnc.Shard) ([]byte, bool, error) {
	// Clear the 1344-byte buffer
	clear(s.plainBuf)

	// Serialize shard to plainBuf
	n, err := shard.EncodeTo(s.plainBuf)
	if err != nil {
		return nil, false, fmt.Errorf("badsharing: shard encoding failed: %w", err)
	}

	// Pad remaining bytes of plainBuf with 0
	clear(s.plainBuf[n:])

	// Seal into wireBuf (1380 bytes)
	sealedFrame, err := s.aead.SealFrame(s.wireBuf, s.plainBuf)
	if err != nil {
		return nil, false, fmt.Errorf("badsharing: AEAD seal failed: %w", err)
	}

	// Return a copy so caller owns the frame data
	out := make([]byte, len(sealedFrame))
	copy(out, sealedFrame)
	return out, false, nil
}

// Stats returns data and parity transmission statistics.
func (s *Sender) Stats() (dataPackets, parityPackets uint64) {
	return s.dataPacketsSent, s.parityPacketsSent
}
