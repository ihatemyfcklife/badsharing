package signaling

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client works with Server over HTTPS. Use cryptographically random peer IDs,
// and distribute bearer tokens securely; signaling messages are not encrypted
// by this package (transport TLS is mandatory outside local development).
type Client struct {
	BaseURL string
	Room string
	PeerID string
	Token string
	HTTP *http.Client
}

func (c *Client) request(ctx context.Context, method, path string, body []byte, target interface{}) error {
	if c==nil||!validID(c.Room)||!validID(c.PeerID)||len(c.Token)<32 {
		return errors.New("signaling: invalid client configuration")
	}
	u,err:=url.Parse(c.BaseURL)
	if err!=nil{return err}
	if u.Scheme!="https" {
		h:=u.Hostname()
		if u.Scheme!="http"||(h!="localhost"&&h!="127.0.0.1"&&h!="::1") {
			return errors.New("signaling: HTTPS is required outside loopback")
		}
	}
	u.Path=strings.TrimRight(u.Path,"/")+path
	q:=u.Query();q.Set("room",c.Room);q.Set("peer",c.PeerID);u.RawQuery=q.Encode()
	req,err:=http.NewRequestWithContext(ctx,method,u.String(),bytes.NewReader(body))
	if err!=nil{return err}
	req.Header.Set("Authorization","Bearer "+c.Token)
	req.Header.Set("Content-Type","application/json")
	httpClient:=c.HTTP
	if httpClient==nil {httpClient=&http.Client{Timeout:10*time.Second}}
	res,err:=httpClient.Do(req)
	if err!=nil{return err}
	defer res.Body.Close()
	if res.StatusCode<200||res.StatusCode>=300 {
		msg,_:=io.ReadAll(io.LimitReader(res.Body,2048))
		return fmt.Errorf("signaling: HTTP %d: %s",res.StatusCode,strings.TrimSpace(string(msg)))
	}
	if target!=nil {return json.NewDecoder(io.LimitReader(res.Body,4<<20)).Decode(target)}
	return nil
}

func (c *Client) Peers(ctx context.Context) ([]string,error) {
	var peers []string
	if err:=c.request(ctx,http.MethodGet,"/v1/peers",nil,&peers);err!=nil{return nil,err}
	return peers,nil
}
func (c *Client) Send(ctx context.Context, target, kind, data string) error {
	msg:=Message{From:c.PeerID,To:target,Type:kind,Data:data}
	if !validID(target)||len(data)>maxMessage-256{return errors.New("signaling: invalid recipient or oversized data")}
	raw,err:=json.Marshal(msg)
	if err!=nil{return err}
	return c.request(ctx,http.MethodPost,"/v1/signal",raw,nil)
}
func (c *Client) Receive(ctx context.Context) ([]Message,error) {
	var messages []Message
	if err:=c.request(ctx,http.MethodGet,"/v1/signal",nil,&messages);err!=nil{return nil,err}
	return messages,nil
}
