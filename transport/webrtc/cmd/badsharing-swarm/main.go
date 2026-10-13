package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ihatemyfcklife/badsharing"
	"github.com/ihatemyfcklife/badsharing/signaling"
	"github.com/ihatemyfcklife/badsharing/swarm"
	webrtclink "github.com/ihatemyfcklife/badsharing/transport/webrtc"
)

type availableSource struct {
	peer swarm.Peer
	manifest *badsharing.GenerationManifest
}

func envKey(name string) [32]byte {
	decoded,err:=hex.DecodeString(os.Getenv(name))
	if err!=nil||len(decoded)!=32 {log.Fatalf("%s must be 64 hex characters (32 random bytes)",name)}
	var key [32]byte
	copy(key[:],decoded)
	return key
}

func main() {
	mode:=flag.String("mode","","send or recv")
	fileName:=flag.String("file","","file to share when mode=send")
	output:=flag.String("out","","destination filename for recv")
	signalURL:=flag.String("signal","http://127.0.0.1:8088","HTTPS signaling server URL")
	room:=flag.String("room","","private signaling room identifier")
	peerID:=flag.String("id","","optional local peer ID")
	sources:=flag.Int("sources",1,"number of peer sources to collect before downloading")
	wait:=flag.Duration("gather",4*time.Second,"time to collect extra peers after first connection")
	stun:=flag.String("stun","","comma-separated STUN URL(s)")
	turn:=flag.String("turn","","comma-separated TURN URL(s)")
	relayOnly:=flag.Bool("relay-only",false,"require TURN relay candidates")
	flag.Parse()
	if *mode!="send"&&*mode!="recv" {log.Fatal("-mode must be send or recv")}
	if *room=="" {log.Fatal("-room is required")}
	if *sources<1||*sources>32 {log.Fatal("-sources must be 1..32")}
	if *mode=="send"&&*fileName=="" {log.Fatal("-file is required")}
	key:=envKey("BADSHARING_KEY_HEX")
	token:=os.Getenv("BADSHARING_SIGNAL_TOKEN")
	if len(token)<32 {log.Fatal("set BADSHARING_SIGNAL_TOKEN to a random 32+ character secret")}
	if *peerID=="" {
		var seed [12]byte
		if _,err:=rand.Read(seed[:]);err!=nil {log.Fatal(err)}
		*peerID=hex.EncodeToString(seed[:])
	}
	ctx,cancel:=signal.NotifyContext(context.Background(),os.Interrupt,syscall.SIGTERM)
	defer cancel()
	var stunURLs,turnURLs []string
	if *stun!="" {stunURLs=strings.Split(*stun,",")}
	if *turn!="" {turnURLs=strings.Split(*turn,",")}
	client:=&signaling.Client{BaseURL:*signalURL,Room:*room,PeerID:*peerID,Token:token}
	coordinator:=&webrtclink.Coordinator{Signaling:client,ICE:webrtclink.ICEConfig{
		STUN:stunURLs,TURN:turnURLs,
		TURNUsername:os.Getenv("BADSHARING_TURN_USER"),
		TURNPassword:os.Getenv("BADSHARING_TURN_PASSWORD"),
		ForceRelay:*relayOnly,
	}}
	if *mode=="send" {
		input,err:=os.Open(*fileName);if err!=nil {log.Fatal(err)}
		defer input.Close()
		meta,err:=badsharing.NewFileMetadata(*fileName,input);if err!=nil {log.Fatal(err)}
		// All seeds of identical content must publish the same manifest identity.
		// This ID is metadata only; each encrypted frame uses a fresh random SID.
		idMAC:=hmac.New(sha256.New,key[:])
		_,_ = idMAC.Write([]byte("badsharing-content-manifest-v1"))
		_,_ = idMAC.Write(meta.Checksum[:])
		meta.SessionID=binary.BigEndian.Uint64(idMAC.Sum(nil)[:8])
		if meta.SessionID==0 {meta.SessionID=1}
		manifest,err:=badsharing.BuildGenerationManifest(*meta,input,key)
		if err!=nil {log.Fatal(err)}
		fmt.Printf("Sharing %s (%d bytes, %d generations) in room %s as %s\n",meta.Name,meta.Size,meta.TotalGenerations(),*room,*peerID)
		err=coordinator.Run(ctx,func(id string,link *webrtclink.Link){
			fmt.Println("Connected to downloader:",id)
			go func() {
				if err:=swarm.SendManifest(ctx,link,manifest);err!=nil {log.Print(err);_=link.Close();return}
				source:=&swarm.Source{Manifest:manifest,Reader:input,Key:key,Redundancy:0.6}
				if err:=source.Serve(ctx,link);err!=nil&&ctx.Err()==nil {log.Print("source: ",err)}
			}()
		})
		if err!=nil&&ctx.Err()==nil {log.Fatal(err)}
		return
	}
	connected:=make(chan availableSource,32)
	go func(){
		err:=coordinator.Run(ctx,func(id string,link *webrtclink.Link){
			go func(){
				m,err:=swarm.ReceiveManifest(ctx,link,key)
				if err!=nil {log.Print("manifest from ",id,": ",err);_=link.Close();return}
				select {case connected<-availableSource{peer:swarm.Peer{ID:id,Link:link},manifest:m}:case <-ctx.Done():}
			}()
		})
		if err!=nil&&ctx.Err()==nil {log.Print("coordinator: ",err);cancel()}
	}()
	var got []availableSource
	select {case first:=<-connected:got=append(got,first);case <-ctx.Done():log.Fatal(ctx.Err())}
	gatherCtx,stop:=context.WithTimeout(ctx,*wait)
	defer stop()
	for len(got)<*sources {
		select {
		case source:=<-connected:
			if bytes.Equal(source.manifest.Signature[:],got[0].manifest.Signature[:]) {
				got=append(got,source)
			} else {
				log.Printf("skipping %s: different file manifest",source.peer.ID)
				_=source.peer.Link.Close()
			}
		case <-gatherCtx.Done():goto ready
		}
	}
ready:
	manifest:=got[0].manifest
	name:=*output
	if name=="" {name=manifest.Metadata.Name}
	if _,err:=os.Stat(name);err==nil {
		log.Fatalf("destination %q already exists; choose a new -out path",name)
	} else if !errors.Is(err,os.ErrNotExist) {log.Fatal(err)}
	partial:=name+".part"
	out,err:=os.OpenFile(partial,os.O_RDWR|os.O_CREATE,0600)
	if err!=nil {log.Fatal(err)}
	var peerLinks []swarm.Peer
	for _,src:=range got {peerLinks=append(peerLinks,src.peer)}
	fmt.Printf("Receiving %s from %d peer(s); authenticated generations=%d\n",name,len(peerLinks),manifest.Metadata.TotalGenerations())
	stats,err:=swarm.Download(ctx,manifest,out,key,peerLinks,swarm.DownloadOptions{ReaderAt:out,MaxActiveGenerations:8})
	if err!=nil {_=out.Close();log.Fatalf("download failed: %v (partial data remains at %s)",err,partial)}
	// Remove any stale trailing bytes from a previous, larger .part file.
	if err:=out.Truncate(int64(manifest.Metadata.Size));err!=nil {log.Fatal(err)}
	if err:=out.Sync();err!=nil{log.Fatal(err)}
	if err:=out.Close();err!=nil{log.Fatal(err)}
	if err:=os.Rename(partial,name);err!=nil{log.Fatal(err)}
	fmt.Printf("Verified %s: %d/%d generations, %d resumed, %d authenticated frames\n",name,stats.Completed,stats.Total,stats.Resumed,stats.FrameCount)
}
