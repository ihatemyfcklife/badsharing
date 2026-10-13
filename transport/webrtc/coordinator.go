package webrtclink

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/ihatemyfcklife/badsharing/signaling"
)

// Coordinator automatically discovers authenticated room members, exchanges
// fully gathered SDP via the signaling broker, and establishes DataChannels.
// Peers with lexicographically smaller IDs create offers to avoid collisions.
// Connections use ICE for direct paths and configured TURN for fallback.
type Coordinator struct {
	Signaling *signaling.Client
	ICE ICEConfig
	MaxPeers int
}

func (c *Coordinator) Run(ctx context.Context, onConnected func(peerID string, link *Link)) error {
	if c==nil||c.Signaling==nil||onConnected==nil||ctx==nil {
		return errors.New("webrtc: invalid coordinator configuration")
	}
	limit:=c.MaxPeers
	if limit<=0||limit>32 {limit=32}
	links:=make(map[string]*Link)
	defer func(){for _,p:=range links {_=p.Close()}}()
	notify:=func(peer string,l *Link) {
		go func(){
			// The application owns onConnected's lifetime; it must honor ctx.
			if err:=l.WaitReady(ctx);err==nil {onConnected(peer,l)}
		}()
	}
	gather:=func(ctx context.Context)([]string,error){
		peers,err:=c.Signaling.Peers(ctx)
		if err!=nil{return nil,err}
		sort.Strings(peers)
		return peers,nil
	}
	// GET /v1/peers also registers our presence on the rendezvous server.
	if _,err:=gather(ctx);err!=nil{return err}
	ticker:=time.NewTicker(2*time.Second)
	defer ticker.Stop()
	for {
		select {case <-ctx.Done():return ctx.Err();default:}
		peers,err:=gather(ctx)
		if err!=nil{return err}
		for _,peer:=range peers {
			if len(links)>=limit {break}
			if peer<=c.Signaling.PeerID||links[peer]!=nil {continue}
			l,err:=New(c.ICE,true)
			if err!=nil{return err}
			links[peer]=l
			offerCtx,cancel:=context.WithTimeout(ctx,30*time.Second)
			sdp,err:=l.Offer(offerCtx)
			cancel()
			if err!=nil {_=l.Close();delete(links,peer);continue}
			if err:=c.Signaling.Send(ctx,peer,"offer",sdp);err!=nil {_=l.Close();delete(links,peer);continue}
			notify(peer,l)
		}
		messages,err:=c.Signaling.Receive(ctx)
		if err!=nil{return err}
		for _,m:=range messages {
			if m.To!=c.Signaling.PeerID||m.From==c.Signaling.PeerID {continue}
			switch m.Type {
			case "offer":
				if m.From>=c.Signaling.PeerID || links[m.From]!=nil||len(links)>=limit {continue}
				l,err:=New(c.ICE,false)
				if err!=nil{return err}
				links[m.From]=l
				answerCtx,cancel:=context.WithTimeout(ctx,30*time.Second)
				sdp,err:=l.Answer(answerCtx,m.Data)
				cancel()
				if err!=nil {_=l.Close();delete(links,m.From);continue}
				if err:=c.Signaling.Send(ctx,m.From,"answer",sdp);err!=nil {_=l.Close();delete(links,m.From);continue}
				notify(m.From,l)
			case "answer":
				l:=links[m.From]
				if l!=nil {if err:=l.AcceptAnswer(m.Data);err!=nil {_=l.Close();delete(links,m.From)}}
			}
		}
		select {case <-ctx.Done():return ctx.Err();case <-ticker.C:}
	}
}

// The run loop is intentionally serial and uses full SDP gathering rather than
// trickle ICE; candidate updates are embedded in the offer/answer. No file
// payload is transported by the signaling broker.
func (c *Coordinator) String() string {
	if c==nil||c.Signaling==nil {return "webrtc coordinator (unconfigured)"}
	return fmt.Sprintf("webrtc coordinator (%s/%s)",c.Signaling.Room,c.Signaling.PeerID)
}
