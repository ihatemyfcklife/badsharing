// Package swarm coordinates authenticated, generation-scoped RLNC transfer
// across multiple independent packet links. It is transport agnostic.
package swarm

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/ihatemyfcklife/badsharing"
	"github.com/ihatemyfcklife/badcrypt"
)

const (
	wireMagic = "BSW1"
	wireWant byte = 1
	wireShard byte = 2
	wireDone byte = 3
	wireHeader = 13
)

// Link is a bidirectional message transport. Implementations must support
// a single receiver plus concurrent sends. WebRTC DataChannels are suitable.
// Transport security must authenticate the remote peer before use.
type Link interface {
	Send(context.Context, []byte) error
	Recv(context.Context) ([]byte, error)
	Close() error
}

type Peer struct {
	ID string
	Link Link
	// Have contains the generation indices this peer can seed. Nil means it
	// advertises the complete file; an empty non-nil map means no generations.
	Have map[uint64]bool
	RTTMillis float64
	Loss float64 // estimate between 0 and 1
}

func pack(kind byte, gen uint64, payload []byte) []byte {
	wire := make([]byte, wireHeader+len(payload))
	copy(wire, wireMagic)
	wire[4] = kind
	binary.BigEndian.PutUint64(wire[5:13], gen)
	copy(wire[13:], payload)
	return wire
}

func unpack(data []byte) (kind byte, gen uint64, payload []byte, err error) {
	if len(data) < wireHeader || string(data[:4]) != wireMagic {
		return 0, 0, nil, errors.New("swarm: invalid control envelope")
	}
	kind = data[4]
	gen = binary.BigEndian.Uint64(data[5:13])
	payload = data[wireHeader:]
	switch kind {
	case wireWant, wireDone:
		if len(payload) != 0 { return 0, 0, nil, errors.New("swarm: unexpected control payload") }
	case wireShard:
		if len(payload) != badcrypt.ConstantWireFrameSize {
			return 0, 0, nil, badsharing.ErrInvalidFrameSize
		}
	default:
		return 0, 0, nil, errors.New("swarm: unknown control kind")
	}
	return kind, gen, payload, nil
}

// Source serves verified generations from a seekable file. Each request gets
// a fresh randomized badcrypt sender SessionID to avoid nonce reuse.
type Source struct {
	Manifest *badsharing.GenerationManifest
	Reader io.ReaderAt
	Key [32]byte
	// Have may restrict which generations this source is allowed to seed.
	Have map[uint64]bool
	Redundancy float64
}

func (s *Source) Serve(ctx context.Context, link Link) error {
	if s == nil || s.Reader == nil || s.Manifest == nil || link == nil {
		return errors.New("swarm: source not configured")
	}
	if err := s.Manifest.Verify(s.Key); err != nil { return err }
	if ctx == nil { return errors.New("swarm: nil context") }
	defer link.Close()
	for {
		packet, err := link.Recv(ctx)
		if err != nil { if ctx.Err() != nil { return nil }; return err }
		kind, gen, _, err := unpack(packet)
		if err != nil { return err }
		if kind != wireWant { return errors.New("swarm: source expected generation request") }
		total := s.Manifest.Metadata.TotalGenerations()
		if s.Manifest.Metadata.Size == 0 {total=0}
		if gen >= total || (s.Have != nil && !s.Have[gen]) {
			// No data is sent for generations this peer doesn't possess.
			if err := link.Send(ctx, pack(wireDone, gen, nil)); err != nil {return err}
			continue
		}
		sender, err := badsharing.NewGenerationSender(s.Manifest, s.Reader, s.Key, gen, s.Redundancy)
		if err != nil { return err }
		for {
			frame, eof, err := sender.NextFrame()
			if err != nil {return err}
			if eof {break}
			if err := link.Send(ctx, pack(wireShard, gen, frame)); err != nil {return err}
		}
		if err := link.Send(ctx, pack(wireDone, gen, nil)); err != nil {return err}
	}
}

// Scheduler prioritizes generations with scarce availability while preferring
// the lowest-loss, lowest-latency peer with available transfer capacity.
type Scheduler struct {
	mu sync.Mutex
	peers []Peer
	busy map[string]int
	order []uint64
	cursor int
	queuedTotal uint64
}
func NewScheduler(peers []Peer) (*Scheduler, error) {
	if len(peers) == 0 {return nil, errors.New("swarm: no peers")}
	seen:=make(map[string]struct{},len(peers))
	for _,p:=range peers {
		if p.ID==""||p.Link==nil {return nil,errors.New("swarm: invalid peer")}
		if _,ok:=seen[p.ID];ok{return nil,errors.New("swarm: duplicate peer ID")}
		if p.Loss<0||p.Loss>=1||p.RTTMillis<0{return nil,errors.New("swarm: invalid peer telemetry")}
		seen[p.ID]=struct{}{}
	}
	return &Scheduler{peers:append([]Peer(nil),peers...),busy:make(map[string]int)},nil
}
func (s *Scheduler) availability(gen uint64) int {
	n:=0
	for _,p:=range s.peers {if p.Have==nil||p.Have[gen] {n++}}
	return n
}
// NextGeneration selects a rarest-available incomplete generation.
// It returns false if no peer claims any of the remaining generations.
func (s *Scheduler) NextGeneration(total uint64, completed, active map[uint64]bool) (uint64,bool) {
	s.mu.Lock();defer s.mu.Unlock()
	if s.order==nil||s.queuedTotal!=total {
		s.order=make([]uint64,0,total)
		for g:=uint64(0);g<total;g++ {
			if s.availability(g)>0 {s.order=append(s.order,g)}
		}
		sort.Slice(s.order,func(i,j int)bool{
			a,b:=s.availability(s.order[i]),s.availability(s.order[j])
			if a==b {return s.order[i]<s.order[j]}
			return a<b
		})
		s.queuedTotal=total
		s.cursor=0
	}
	for s.cursor<len(s.order) {
		g:=s.order[s.cursor]
		s.cursor++
		if !completed[g]&&!active[g] {return g,true}
	}
	return 0,false
}
func (s *Scheduler) Preferred(gen uint64, exclude map[string]bool) []Peer {
	s.mu.Lock();defer s.mu.Unlock()
	var out []Peer
	for _,p:=range s.peers {
		if (p.Have==nil||p.Have[gen]) && !exclude[p.ID] {out=append(out,p)}
	}
	sort.Slice(out,func(i,j int)bool{
		a,b:=out[i],out[j]
		score:=func(p Peer)float64{return (1+p.RTTMillis/100)*(1+4*p.Loss)*float64(1+s.busy[p.ID])}
		if score(a)==score(b){return a.ID<b.ID}
		return score(a)<score(b)
	})
	return out
}
func (s *Scheduler) Claim(peer string) {s.mu.Lock();s.busy[peer]++;s.mu.Unlock()}
func (s *Scheduler) Release(peer string) {s.mu.Lock();if s.busy[peer]>0 {s.busy[peer]--};s.mu.Unlock()}

// VerifyExisting checks on-disk generations before attempting a resume. It
// does not trust the checkpoint alone: each generation is re-hashed.
func VerifyExisting(m *badsharing.GenerationManifest, r io.ReaderAt, key [32]byte) (map[uint64]bool,error) {
	if m==nil||r==nil {return nil,errors.New("swarm: nil manifest or resume reader")}
	if err:=m.Verify(key);err!=nil{return nil,err}
	done:=make(map[uint64]bool)
	total:=m.Metadata.TotalGenerations()
	if m.Metadata.Size==0 {total=0}
	chunk:=make([]byte, int(m.Metadata.ChunkSize)*int(max(uint16(1), m.Metadata.GenerationSize)))
	for g:=uint64(0);g<total;g++ {
		off,n,err:=badsharing.GenerationRange(m.Metadata,g)
		if err!=nil{return nil,err}
		buf:=chunk[:int(n)]
		read,err:=r.ReadAt(buf,off)
		if err!=nil||read!=len(buf){continue}
		if sum:=hashChunk(buf);sum==m.Hashes[g] {done[g]=true}
	}
	return done,nil
}
func hashChunk(payload []byte) [32]byte {
	return sha256.Sum256(payload)
}

// Verifies the complete file at the end of the download when a reader is provided.
func VerifyFile(m *badsharing.GenerationManifest, r io.ReaderAt) error {
	if m==nil||r==nil {return errors.New("swarm: missing verify reader")}
	h:=sha256.New()
	if _,err:=io.Copy(h,io.NewSectionReader(r,0,int64(m.Metadata.Size)));err!=nil{return err}
	var sum [32]byte;copy(sum[:],h.Sum(nil))
	if sum!=m.Metadata.Checksum {return fmt.Errorf("swarm: reconstructed file checksum mismatch")}
	return nil
}
