package signaling

import (
	"context"
	"net/http/httptest"
	"net/http"
	"strings"
	"sync"
	"testing"
)

func TestRendezvousAuthorizationAndDelivery(t *testing.T) {
	token:=strings.Repeat("secret",8)
	broker,err:=NewServer(token)
	if err!=nil{t.Fatal(err)}
	server:=httptest.NewServer(broker)
	defer server.Close()
	makeClient:=func(id,room string)*Client{return &Client{BaseURL:server.URL,Room:room,PeerID:id,Token:token}}
	a,b:=makeClient("Alice","room-1"),makeClient("Bob","room-1")
	ctx:=context.Background()
	if _,err:=a.Peers(ctx);err!=nil{t.Fatal(err)}
	if peers,err:=b.Peers(ctx);err!=nil||len(peers)!=1||peers[0]!="Alice"{
		t.Fatalf("unexpected room members: %v, %v",peers,err)
	}
	if err:=a.Send(ctx,"Bob","offer","fake-sdp");err!=nil{t.Fatal(err)}
	messages,err:=b.Receive(ctx)
	if err!=nil||len(messages)!=1||messages[0].Data!="fake-sdp"{
		t.Fatalf("signal delivery failed %v %v",messages,err)
	}
	if messages,err:=b.Receive(ctx);err!=nil||len(messages)!=0 {
		t.Fatalf("message not drained %v %v",messages,err)
	}
	other:=makeClient("Alice","another-room")
	if peers,err:=other.Peers(ctx);err!=nil||len(peers)!=0 {t.Fatalf("room leaked %v %v",peers,err)}
	attacker:=makeClient("Mallory","room-1");attacker.Token=strings.Repeat("x",48)
	if _,err:=attacker.Peers(ctx);err==nil{t.Fatal("unauthorized peer joined")}
}

func TestConcurrentSignalingRequests(t *testing.T) {
	token:=strings.Repeat("a",48)
	broker,_:=NewServer(token)
	server:=httptest.NewServer(broker);defer server.Close()
	ctx:=context.Background()
	var wg sync.WaitGroup
	for n:=0;n<20;n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			peers:=&Client{BaseURL:server.URL,Token:token,Room:"benchmark",PeerID:"node",HTTP:server.Client()}
			if _,err:=peers.Peers(ctx);err!=nil {t.Error(err)}
		}()
	}
	wg.Wait()
}

func TestCORSRequiresExplicitOrigin(t *testing.T) {
	token:=strings.Repeat("z",48)
	broker,_:=NewServer(token)
	if err:=broker.AllowOrigin("https://ihatemyfcklife.github.io");err!=nil {t.Fatal(err)}
	for _,tc:=range []struct{origin string;status int}{
		{"https://ihatemyfcklife.github.io",http.StatusNoContent},
		{"https://untrusted.example",http.StatusForbidden},
	} {
		request:=httptest.NewRequest(http.MethodOptions,"/v1/signal?room=room&peer=peer",nil)
		request.Header.Set("Origin",tc.origin)
		w:=httptest.NewRecorder()
		broker.ServeHTTP(w,request)
		if w.Code!=tc.status {t.Fatalf("%s returned %d, wanted %d",tc.origin,w.Code,tc.status)}
	}
}
