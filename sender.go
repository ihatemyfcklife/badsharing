package badsharing
 
import (
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/ihatemyfcklife/badcrypt"
	"github.com/ihatemyfcklife/badrlnc"
)

// Sender coordinates file streaming, generation-based RLNC encoding, and badcrypt AEAD frame sealing.
type Sender struct {
	mu                sync.Mutex
	meta              *FileMetadata
	reader            io.Reader
	encoder           *badrlnc.SlidingWindowEncoder
	aead              *badcrypt.ShardAEAD
	redundancyRatio   float64
	dataPacketsSent   uint64
	parityPacketsSent uint64
	eof               bool

	generationSize   int
	currentGen       uint64
	genChunksRead    int
	genParityEmitted int
	targetGenParity  int

	chunkBuf []byte
	plainBuf []byte
	wireBuf  []byte
}

// NewSender creates a new file streaming Sender with generation-based partitioning.
func NewSender(meta *FileMetadata, r io.Reader, cfg SessionConfig) (*Sender, error) {
	if meta == nil {
		return nil, errors.New("badsharing: metadata cannot be nil")
	}
	if r == nil {
		return nil, errors.New("badsharing: reader cannot be nil")
	}

	genSize := int(meta.GenerationSize)
	if genSize <= 0 {
		genSize = DefaultGenerationSize
	}
	if cfg.GenerationSize > 0 {
		genSize = cfg.GenerationSize
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
		WindowSize: genSize,
		SymbolSize: int(meta.ChunkSize),
		Checksum:   true,
		ZeroCopy:   false,
		InitialSeq: 0,
	})

	return &Sender{
		meta:            meta,
		reader:          r,
		encoder:         enc,
		aead:            aead,
		redundancyRatio: redundancy,
		generationSize:  genSize,
		chunkBuf:        make([]byte, meta.ChunkSize),
		plainBuf:        make([]byte, badcrypt.DefaultPlaintextFrameSize),
		wireBuf:         make([]byte, badcrypt.ConstantWireFrameSize),
		eof:             meta.Size == 0,
	}, nil
}

// NextFrame reads the next chunk, encodes it into a shard, and seals it into a 1380-byte encrypted frame.
// Returns (frame, eof, error). When eof is true, all file chunks and generation parities have been emitted.
func (s *Sender) NextFrame() ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.eof && s.genChunksRead == 0 {
		return nil, true, nil
	}

	// 1. If we are currently emitting parity shards for the current generation
	if s.genParityEmitted < s.targetGenParity {
		shard, err := s.encoder.FlushParity()
		if err == nil {
			s.genParityEmitted++
			s.parityPacketsSent++
			return s.sealShard(shard)
		}
		s.genParityEmitted = s.targetGenParity
	}

	// 2. If the current generation is completed (all chunks read and parities emitted)
	if (s.genChunksRead >= s.generationSize || s.eof) && s.targetGenParity > 0 && s.genParityEmitted >= s.targetGenParity {
		if s.eof {
			return nil, true, nil
		}

		s.currentGen++
		s.genChunksRead = 0
		s.genParityEmitted = 0
		s.targetGenParity = 0

		s.encoder = badrlnc.NewSlidingEncoder(badrlnc.EncoderConfig{
			WindowSize: s.generationSize,
			SymbolSize: int(s.meta.ChunkSize),
			Checksum:   true,
			ZeroCopy:   false,
			InitialSeq: s.currentGen * uint64(s.generationSize),
		})
	}

	// 3. Read and emit the next data chunk for the current generation
	if !s.eof && s.genChunksRead < s.generationSize {
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
			s.genChunksRead++
			s.dataPacketsSent++

			// When generation is full or EOF is reached, calibrate parity count for this generation
			if s.genChunksRead == s.generationSize || s.eof {
				s.targetGenParity = int(float64(s.genChunksRead)*s.redundancyRatio + 0.999) + 4
				minParity := int(float64(s.generationSize) * s.redundancyRatio)
				if minParity < 4 {
					minParity = 4
				}
				if s.targetGenParity < minParity {
					s.targetGenParity = minParity
				}
			}

			return s.sealShard(shard)
		}
	}

	// 4. If EOF was reached and target parity not yet calculated for this final generation
	if s.eof && s.targetGenParity == 0 && s.genChunksRead > 0 {
		s.targetGenParity = int(float64(s.genChunksRead)*s.redundancyRatio + 0.999) + 4
		minParity := int(float64(s.generationSize) * s.redundancyRatio)
		if minParity < 4 {
			minParity = 4
		}
		if s.targetGenParity < minParity {
			s.targetGenParity = minParity
		}
	}

	// 5. If we have parity shards to emit for the final generation
	if s.genParityEmitted < s.targetGenParity {
		shard, err := s.encoder.FlushParity()
		if err == nil {
			s.genParityEmitted++
			s.parityPacketsSent++
			return s.sealShard(shard)
		}
		s.genParityEmitted = s.targetGenParity
	}

	if s.eof && s.genParityEmitted >= s.targetGenParity {
		return nil, true, nil
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
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dataPacketsSent, s.parityPacketsSent
}

// CurrentGeneration returns the active generation index being transmitted.
func (s *Sender) CurrentGeneration() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.currentGen
}
