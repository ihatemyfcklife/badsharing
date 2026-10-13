package webrtclink

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ihatemyfcklife/badsharing"
	"github.com/ihatemyfcklife/badsharing/swarm"
)

func TestWebRTCEndToEndEncryptedSwarm(t *testing.T) {
	ctx,cancel:=context.WithTimeout(context.Background(),20*time.Second)
	defer cancel()
	key,err:=badsharing.GenerateRandomKey()
	if err!=nil {t.Fatal(err)}
	payload:=make([]byte,100123)
	if _,err:=rand.Read(payload);err!=nil {t.Fatal(err)}
	meta,err:=badsharing.NewFileMetadata("file.bin",bytes.NewReader(payload))
	if err!=nil {t.Fatal(err)}
	manifest,err:=badsharing.BuildGenerationManifest(*meta,bytes.NewReader(payload),key)
	if err!=nil {t.Fatal(err)}
	var receivers []swarm.Peer
	for i:=0;i<2;i++ {
		sendLink,err:=New(ICEConfig{},true)
		if err!=nil {t.Fatal(err)}
		defer sendLink.Close()
		receiveLink,err:=New(ICEConfig{},false)
		if err!=nil {t.Fatal(err)}
		defer receiveLink.Close()
		offer,err:=sendLink.Offer(ctx)
		if err!=nil {t.Fatal(err)}
		answer,err:=receiveLink.Answer(ctx,offer)
		if err!=nil {t.Fatal(err)}
		if err:=sendLink.AcceptAnswer(answer);err!=nil {t.Fatal(err)}
		if err:=sendLink.WaitReady(ctx);err!=nil {t.Fatal(err)}
		if err:=receiveLink.WaitReady(ctx);err!=nil {t.Fatal(err)}
		source:=&swarm.Source{Manifest:manifest,Reader:bytes.NewReader(payload),Key:key,Redundancy:0.9}
		go func() {
			if err:=swarm.SendManifest(ctx,sendLink,manifest);err==nil {
				_ = source.Serve(ctx,sendLink)
			}
		}()
		receivedManifest,err:=swarm.ReceiveManifest(ctx,receiveLink,key)
		if err!=nil {t.Fatal(err)}
		if receivedManifest.Metadata.Checksum!=manifest.Metadata.Checksum {t.Fatal("manifest mismatch")}
		receivers=append(receivers,swarm.Peer{ID:string(rune('a'+i)),Link:receiveLink})
	}
	out,err:=os.Create(filepath.Join(t.TempDir(),"received.bin"))
	if err!=nil {t.Fatal(err)}
	defer out.Close()
	stats,err:=swarm.Download(ctx,manifest,out,key,receivers,swarm.DownloadOptions{ReaderAt:out,RetryInterval:time.Second})
	if err!=nil {t.Fatal(err)}
	if stats.Completed!=stats.Total {t.Fatalf("incomplete: %+v",stats)}
	actual:=make([]byte,len(payload))
	if _,err:=out.ReadAt(actual,0);err!=nil {t.Fatal(err)}
	if !bytes.Equal(actual,payload) {t.Fatal("WebRTC reconstructed file differs")}
}
