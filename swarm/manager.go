package swarm

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/ihatemyfcklife/badsharing"
	"github.com/ihatemyfcklife/badcrypt"
)

type DownloadOptions struct {
	MaxActiveGenerations int
	MaxAttempts int
	RetryInterval time.Duration
	// ReaderAt is the same file as WriterAt, used to verify existing generations
	// before resuming and the entire file after completion.
	ReaderAt io.ReaderAt
}

type DownloadStats struct {
	Completed uint64
	Total uint64
	Resumed uint64
	FrameCount uint64
	Requests uint64
}
type receivedFrame struct {
	peer string
	data []byte
	err error
}
type activeGeneration struct {
	receiver *badsharing.GenerationReceiver
	requested map[string]bool
	tries int
	lastRequest time.Time
}

// Download retrieves authenticated generations concurrently from multiple
// source links, retries stalled generations using alternative peers, and
// resumes already verified data from disk when ReaderAt is configured.
// The caller supplies authenticated links and an authenticated manifest.
func Download(ctx context.Context, manifest *badsharing.GenerationManifest, destination io.WriterAt, key [32]byte, peers []Peer, opts DownloadOptions) (DownloadStats, error) {
	var stats DownloadStats
	if ctx == nil || manifest == nil || destination == nil {
		return stats, errors.New("swarm: missing context, manifest or destination")
	}
	if err := manifest.Verify(key); err != nil {return stats,err}
	scheduler, err := NewScheduler(peers)
	if err != nil {return stats,err}
	total:=manifest.Metadata.TotalGenerations()
	if manifest.Metadata.Size==0 {total=0}
	stats.Total=total
	if total==0 {return stats,nil}
	completed:=make(map[uint64]bool)
	if opts.ReaderAt!=nil {
		completed,err=VerifyExisting(manifest,opts.ReaderAt,key)
		if err!=nil{return stats,err}
		stats.Resumed=uint64(len(completed))
		stats.Completed=stats.Resumed
	}
	if stats.Completed==total {
		if opts.ReaderAt!=nil {return stats,VerifyFile(manifest,opts.ReaderAt)}
		return stats,nil
	}
	maxActive:=opts.MaxActiveGenerations
	if maxActive<=0 {maxActive=8}
	if maxActive>32 {maxActive=32}
	maxAttempts:=opts.MaxAttempts
	if maxAttempts<=0 {maxAttempts=8}
	retry:=opts.RetryInterval
	if retry<=0 {retry=1500*time.Millisecond}
	runCtx,cancel:=context.WithCancel(ctx)
	defer cancel()
	events:=make(chan receivedFrame,128)
	var readers sync.WaitGroup
	active:=make(map[uint64]*activeGeneration)
	peerMap:=make(map[string]Peer,len(peers))
	offline:=make(map[string]bool,len(peers))
	for _, p:=range peers {
		peerMap[p.ID]=p
		readers.Add(1)
		go func(p Peer) {
			defer readers.Done()
			for {
				data,err:=p.Link.Recv(runCtx)
				if err!=nil {
					select {case events<-receivedFrame{peer:p.ID,err:err}:case <-runCtx.Done():}
					return
				}
				select {
				case events<-receivedFrame{peer:p.ID,data:data}:
				case <-runCtx.Done():return
				}
			}
		}(p)
	}
	defer func(){cancel();for _,p:=range peers {_=p.Link.Close()};readers.Wait()}()
	// Track scheduled generations to avoid duplicate request work.
	inflight:=make(map[uint64]bool)
	sendRequest:=func(gen uint64, task *activeGeneration) error {
		excluded:=make(map[string]bool)
		for id:=range task.requested {excluded[id]=true}
		for id:=range offline {excluded[id]=true}
		options:=scheduler.Preferred(gen,excluded)
		if len(options)==0 {
			// Retry a previously used peer with a fresh nonce/session, but never
			// include known-disconnected peers.
			excluded=make(map[string]bool,len(offline))
			for id:=range offline {excluded[id]=true}
			options=scheduler.Preferred(gen,excluded)
		}
		if len(options)==0 {return fmt.Errorf("swarm: no reachable source for generation %d",gen)}
		if task.tries>=maxAttempts {return fmt.Errorf("swarm: generation %d exhausted retry budget",gen)}
		p:=options[0]
		task.requested[p.ID]=true
		task.tries++
		task.lastRequest=time.Now()
		scheduler.Claim(p.ID)
		defer scheduler.Release(p.ID)
		sendCtx,stop:=context.WithTimeout(runCtx,5*time.Second)
		defer stop()
		// Initial redundancy follows measured peer loss; retries increase
		// available rank when previous coded shards were insufficient.
		ratio:=0.35+2*p.Loss+0.2*float64(task.tries-1)
		if ratio>2 {ratio=2}
		var wanted [2]byte
		binary.BigEndian.PutUint16(wanted[:],uint16(ratio*1000))
		if err:=p.Link.Send(sendCtx,pack(wireWant,gen,wanted[:]));err!=nil {return fmt.Errorf("swarm: asking %s for generation %d: %w",p.ID,gen,err)}
		stats.Requests++
		return nil
	}
	launch:=func()error {
		for len(active)<maxActive && stats.Completed+uint64(len(active))<total {
			g,ok:=scheduler.NextGeneration(total,completed,inflight)
			if !ok {return errors.New("swarm: remaining generations have no available source")}
			receiver,err:=badsharing.NewGenerationReceiver(manifest,destination,key,g)
			if err!=nil{return err}
			task:=&activeGeneration{receiver:receiver,requested:make(map[string]bool)}
			active[g]=task;inflight[g]=true
			if err:=sendRequest(g,task);err!=nil{return err}
			// Request a second peer to aggregate independent RLNC shards if available.
			if len(peers)>1 {
				other:=scheduler.Preferred(g,task.requested)
				if len(other)>0 {
					if err:=sendRequest(g,task);err!=nil{return err}
				}
			}
		}
		return nil
	}
	if err:=launch();err!=nil{return stats,err}
	ticker:=time.NewTicker(200*time.Millisecond)
	defer ticker.Stop()
	for stats.Completed<total {
		select {
		case <-ctx.Done():return stats,ctx.Err()
		case event:=<-events:
			if event.err!=nil {
				if !offline[event.peer] {offline[event.peer]=true}
				continue
			}
			kind,g,payload,err:=unpack(event.data)
			if err!=nil {
				// Ignore untrusted or malformed packets; peers are individually
				// authenticated at the Link layer.
				continue
			}
			task:=active[g]
			if task==nil {continue}
			if kind==wireShard {
				task.lastRequest=time.Now() // progress resets the idle retry timer
				stats.FrameCount++
				done,err:=task.receiver.IngestFrame(payload)
				if err!=nil {
					if errors.Is(err,badcrypt.ErrReplayedPacket) {continue}
					return stats,fmt.Errorf("swarm: generation %d from %s: %w",g,event.peer,err)
				}
				if done {
					completed[g]=true
					stats.Completed++
					delete(active,g)
					delete(inflight,g)
					if err:=launch();err!=nil{return stats,err}
				}
			}
			// wireDone simply indicates source exhaustion, not proof of recovery.
		case <-ticker.C:
			for g,task:=range active {
				if time.Since(task.lastRequest)>=retry {
					if err:=sendRequest(g,task);err!=nil {
						return stats,err
					}
				}
			}
		}
	}
	if opts.ReaderAt!=nil {
		if err:=VerifyFile(manifest,opts.ReaderAt);err!=nil{return stats,err}
	}
	return stats,nil
}
