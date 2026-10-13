package webrtclink

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestLocalICEDataChannel(t *testing.T) {
	ctx,cancel:=context.WithTimeout(context.Background(),12*time.Second)
	defer cancel()
	a,err:=New(ICEConfig{},true)
	if err!=nil {t.Fatal(err)}
	defer a.Close()
	b,err:=New(ICEConfig{},false)
	if err!=nil {t.Fatal(err)}
	defer b.Close()
	offer,err:=a.Offer(ctx)
	if err!=nil {t.Fatal(err)}
	answer,err:=b.Answer(ctx,offer)
	if err!=nil {t.Fatal(err)}
	if err:=a.AcceptAnswer(answer);err!=nil {t.Fatal(err)}
	if err:=a.WaitReady(ctx);err!=nil {t.Fatal(err)}
	if err:=b.WaitReady(ctx);err!=nil {t.Fatal(err)}
	payload:=bytes.Repeat([]byte{0x5a,0x03},690)
	if err:=a.Send(ctx,payload);err!=nil {t.Fatal(err)}
	got,err:=b.Recv(ctx)
	if err!=nil {t.Fatal(err)}
	if !bytes.Equal(got,payload) {t.Fatal("DataChannel payload mismatch")}
}

func TestRelayRequiresCredentials(t *testing.T) {
	if _,err:=New(ICEConfig{ForceRelay:true},true);err==nil {t.Fatal("relay-only without TURN accepted")}
	if _,err:=New(ICEConfig{TURN:[]string{"turn:127.0.0.1:3478"}},true);err==nil {t.Fatal("TURN without credentials accepted")}
}
