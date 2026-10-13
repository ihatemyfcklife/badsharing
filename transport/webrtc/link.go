// Package webrtclink implements swarm.Link over Pion WebRTC DataChannels.
// ICE/STUN/TURN are handled by Pion. No file content is sent to signaling.
package webrtclink

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/pion/webrtc/v4"
)

const maxBufferedAmount = 2 << 20

// ICEConfig supplies real ICE servers. TURN credentials must be short-lived.
// When ForceRelay is enabled, candidate selection is restricted to TURN.
type ICEConfig struct {
	STUN []string
	TURN []string
	TURNUsername string
	TURNPassword string
	ForceRelay bool
}

func (cfg ICEConfig) configuration() (webrtc.Configuration,error) {
	var servers []webrtc.ICEServer
	if len(cfg.STUN)>0 {servers=append(servers,webrtc.ICEServer{URLs:cfg.STUN})}
	if len(cfg.TURN)>0 {
		if cfg.TURNUsername==""||cfg.TURNPassword=="" {return webrtc.Configuration{},errors.New("webrtc: TURN credentials are required")}
		servers=append(servers,webrtc.ICEServer{
			URLs:cfg.TURN,Username:cfg.TURNUsername,Credential:cfg.TURNPassword,
		})
	}
	out:=webrtc.Configuration{ICEServers:servers}
	if cfg.ForceRelay {
		if len(cfg.TURN)==0 {return out,errors.New("webrtc: relay-only mode requires TURN")}
		out.ICETransportPolicy=webrtc.ICETransportPolicyRelay
	}
	return out,nil
}

// Link is a negotiated peer connection, satisfying swarm.Link.
// Create with initiator=true for the offerer and false for the answerer.
type Link struct {
	pc *webrtc.PeerConnection
	mu sync.Mutex
	channel *webrtc.DataChannel
	received chan []byte
	ready chan struct{}
	closed chan struct{}
	readyOnce sync.Once
	closeOnce sync.Once
}
func New(ice ICEConfig,initiator bool) (*Link,error) {
	cfg,err:=ice.configuration()
	if err!=nil{return nil,err}
	pc,err:=webrtc.NewPeerConnection(cfg)
	if err!=nil{return nil,err}
	p:=&Link{pc:pc,received:make(chan []byte,256),ready:make(chan struct{}),closed:make(chan struct{})}
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState){
		if state==webrtc.PeerConnectionStateClosed||state==webrtc.PeerConnectionStateFailed { _ = p.Close() }
	})
	pc.OnDataChannel(func(dc *webrtc.DataChannel){p.attach(dc)})
	if initiator {
		ordered:=false
		retransmits:=uint16(0)
		dc,err:=pc.CreateDataChannel("badsharing-rlnc",&webrtc.DataChannelInit{
			Ordered:&ordered,MaxRetransmits:&retransmits,
		})
		if err!=nil {_=pc.Close();return nil,err}
		p.attach(dc)
	}
	return p,nil
}
func (p *Link) attach(dc *webrtc.DataChannel) {
	if dc.Label()!="badsharing-rlnc" {_=dc.Close();return}
	p.mu.Lock()
	if p.channel!=nil&&p.channel!=dc {
		p.mu.Unlock();_ =dc.Close();return
	}
	p.channel=dc
	p.mu.Unlock()
	dc.OnOpen(func(){p.readyOnce.Do(func(){close(p.ready)})})
	dc.OnMessage(func(msg webrtc.DataChannelMessage){
		if !msg.IsString&&len(msg.Data)>0&&len(msg.Data)<=8192 {
			payload:=append([]byte(nil),msg.Data...)
			select {case p.received<-payload:case <-p.closed:default:_=p.Close()}
		}
	})
	dc.OnClose(func(){_ = p.Close()})
}

// Offer gathers ICE candidates (including TURN relays) and returns SDP.
// Send the SDP through authenticated signaling, never through a public channel.
func (p *Link) Offer(ctx context.Context) (string,error) {
	offer,err:=p.pc.CreateOffer(nil)
	if err!=nil{return "",err}
	gather:=webrtc.GatheringCompletePromise(p.pc)
	if err:=p.pc.SetLocalDescription(offer);err!=nil{return "",err}
	select {case <-gather:case <-ctx.Done():return "",ctx.Err()}
	desc:=p.pc.LocalDescription()
	if desc==nil {return "",errors.New("webrtc: local description unavailable")}
	return desc.SDP,nil
}
func (p *Link) Answer(ctx context.Context,offer string) (string,error) {
	if err:=p.pc.SetRemoteDescription(webrtc.SessionDescription{Type:webrtc.SDPTypeOffer,SDP:offer});err!=nil{return "",err}
	answer,err:=p.pc.CreateAnswer(nil)
	if err!=nil{return "",err}
	gather:=webrtc.GatheringCompletePromise(p.pc)
	if err:=p.pc.SetLocalDescription(answer);err!=nil{return "",err}
	select {case <-gather:case <-ctx.Done():return "",ctx.Err()}
	desc:=p.pc.LocalDescription()
	if desc==nil {return "",errors.New("webrtc: local answer unavailable")}
	return desc.SDP,nil
}
func (p *Link) AcceptAnswer(sdp string) error {
	return p.pc.SetRemoteDescription(webrtc.SessionDescription{Type:webrtc.SDPTypeAnswer,SDP:sdp})
}
func (p *Link) WaitReady(ctx context.Context) error {
	select {
	case <-p.ready:return nil
	case <-p.closed:return errors.New("webrtc: connection closed")
	case <-ctx.Done():return ctx.Err()
	}
}
func (p *Link) Send(ctx context.Context,data []byte) error {
	if len(data)==0||len(data)>8192 {return errors.New("webrtc: invalid frame length")}
	if err:=p.WaitReady(ctx);err!=nil{return err}
	for {
		p.mu.Lock()
		ch:=p.channel
		if ch==nil {p.mu.Unlock();return errors.New("webrtc: data channel missing")}
		if ch.BufferedAmount()<maxBufferedAmount {
			err:=ch.Send(data)
			p.mu.Unlock()
			return err
		}
		p.mu.Unlock()
		select {
		case <-p.closed:return errors.New("webrtc: connection closed")
		case <-ctx.Done():return ctx.Err()
		case <-time.After(10*time.Millisecond):
		}
	}
}
func (p *Link) Recv(ctx context.Context) ([]byte,error) {
	if err:=p.WaitReady(ctx);err!=nil{return nil,err}
	select {
	case data:=<-p.received:return data,nil
	case <-p.closed:return nil,errors.New("webrtc: peer disconnected")
	case <-ctx.Done():return nil,ctx.Err()
	}
}
func (p *Link) Close() error {
	var err error
	p.closeOnce.Do(func(){
		close(p.closed)
		err=p.pc.Close()
	})
	return err
}
func (p *Link) String() string {
	return fmt.Sprintf("webrtc:%s",p.pc.ConnectionState().String())
}
