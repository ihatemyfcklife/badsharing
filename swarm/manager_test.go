package swarm

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ihatemyfcklife/badsharing"
)

type memoryLink struct {
	in <-chan []byte
	out chan<- []byte
	done chan struct{}
	once sync.Once
}
func pairLinks() (*memoryLink,*memoryLink) {
	a,b:=make(chan []byte,1024),make(chan []byte,1024)
	return &memoryLink{in:a,out:b,done:make(chan struct{})},&memoryLink{in:b,out:a,done:make(chan struct{})}
}
func (m *memoryLink) Send(ctx context.Context,payload []byte) error {
	p:=bytes.Clone(payload)
	select {case m.out<-p:return nil;case <-m.done:return io.EOF;case <-ctx.Done():return ctx.Err()}
}
func (m *memoryLink) Recv(ctx context.Context) ([]byte,error) {
	select {case x:=<-m.in:return x,nil;case <-m.done:return nil,io.EOF;case <-ctx.Done():return nil,ctx.Err()}
}
func (m *memoryLink) Close() error {m.once.Do(func(){close(m.done)});return nil}

func TestSwarmConcurrentSourcesAndResume(t *testing.T) {
	payload:=make([]byte, 343219)
	if _,err:=rand.Read(payload);err!=nil {t.Fatal(err)}
	meta,err:=badsharing.NewFileMetadata("test.bin",bytes.NewReader(payload))
	if err!=nil {t.Fatal(err)}
	key,_:=badsharing.GenerateRandomKey()
	manifest,err:=badsharing.BuildGenerationManifest(*meta,bytes.NewReader(payload),key)
	if err!=nil {t.Fatal(err)}
	partial,err:=os.OpenFile(filepath.Join(t.TempDir(),"download.part"),os.O_RDWR|os.O_CREATE,0600)
	if err!=nil {t.Fatal(err)}
	defer partial.Close()
	g0,err:=badsharing.GenerationRange(*meta,0)
	_ = g0
	_ = err
	off,n,err:=badsharing.GenerationRange(*meta,0)
	if err!=nil {t.Fatal(err)}
	if _,err:=partial.WriteAt(payload[off:off+n],off);err!=nil {t.Fatal(err)}
	ctx,cancel:=context.WithTimeout(context.Background(),12*time.Second)
	defer cancel()
	var peers []Peer
	workerErrors:=make(chan error,2)
	for i:=0;i<2;i++ {
		client,server:=pairLinks()
		have:=make(map[uint64]bool)
		for gen:=uint64(0);gen<meta.TotalGenerations();gen++ {
			if gen%2==uint64(i) {have[gen]=true}
		}
		peers=append(peers,Peer{ID:string(rune('A'+i)),Link:client,Have:have})
		source:=&Source{Manifest:manifest,Reader:bytes.NewReader(payload),Key:key,Have:have,Redundancy:0.7}
		go func(){workerErrors<-source.Serve(ctx,server)}()
	}
	stat,err:=Download(ctx,manifest,partial,key,peers,DownloadOptions{ReaderAt:partial,MaxActiveGenerations:4,RetryInterval:400*time.Millisecond})
	if err!=nil {t.Fatalf("download error: %v",err)}
	if stat.Resumed!=1||stat.Completed!=stat.Total||stat.FrameCount==0 {
		t.Fatalf("unexpected transfer stats: %+v",stat)
	}
	received:=make([]byte,len(payload))
	if n,err:=partial.ReadAt(received,0);err!=nil||n!=len(payload) {t.Fatalf("readback: %d, %v",n,err)}
	if !bytes.Equal(payload,received) {t.Fatal("download corrupted")}
	for i:=0;i<2;i++ {
		select {case <-workerErrors: case <-time.After(time.Second):t.Fatal("source goroutine leak")}
	}
}

func TestSchedulerPrefersRareAvailableGeneration(t *testing.T) {
	a,b:=pairLinks();defer a.Close();defer b.Close()
	c,d:=pairLinks();defer c.Close();defer d.Close()
	s,err:=NewScheduler([]Peer{{ID:"alpha",Link:a,Have:map[uint64]bool{0:true,1:true}}, {ID:"beta",Link:c,Have:map[uint64]bool{1:true}}})
	if err!=nil {t.Fatal(err)}
	g,ok:=s.NextGeneration(2,map[uint64]bool{},map[uint64]bool{})
	if !ok||g!=0 {t.Fatalf("rarest generation expected 0, got %d",g)}
	if len(s.Preferred(0,nil))!=1 {t.Fatal("scheduler included an unavailable peer")}
}
