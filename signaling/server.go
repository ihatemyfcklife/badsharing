// Package signaling implements a bounded HTTP rendezvous service for WebRTC
// SDP/ICE exchange. It never sees unencrypted file data or relay payloads.
package signaling

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	maxPeersPerRoom=128
	maxRooms=256
	maxQueue=64
	maxMessage=65536
	peerTTL=5*time.Minute
)

type Message struct {
	From string `json:"from"`
	To string `json:"to"`
	// Type is offer, answer, or ice.
	Type string `json:"type"`
	// Data holds SDP text or serialized RTCIceCandidateInit JSON.
	Data string `json:"data"`
}

type inbox struct {
	last time.Time
	pending []Message
}

type Server struct {
	mu sync.Mutex
	token string
	rooms map[string]map[string]*inbox
}

// NewServer requires a random, private bearer token. Run it only behind HTTPS
// in production; both SDP and bearer tokens must be protected in transit.
func NewServer(token string) (*Server,error) {
	if len(token)<32 {return nil,errors.New("signaling: require a strong >=32-character token")}
	return &Server{token:token,rooms:make(map[string]map[string]*inbox)},nil
}

func validID(s string) bool {
	if len(s)==0||len(s)>96 {return false}
	for _,c:=range s {
		if !(c>='a'&&c<='z'||c>='A'&&c<='Z'||c>='0'&&c<='9'||c=='-'||c=='_') {return false}
	}
	return true
}

func (s *Server) authorize(w http.ResponseWriter,r *http.Request) bool {
	authorization:=r.Header.Get("Authorization")
	prefix:="Bearer "
	provided:=""
	if strings.HasPrefix(authorization,prefix){provided=authorization[len(prefix):]}
	if subtle.ConstantTimeCompare([]byte(provided),[]byte(s.token))!=1 {
		http.Error(w,"unauthorized",http.StatusUnauthorized);return false
	}
	return true
}

func (s *Server) cleanLocked(now time.Time) {
	for room,peers:=range s.rooms {
		for id,p:=range peers {
			if now.Sub(p.last)>peerTTL {delete(peers,id)}
		}
		if len(peers)==0 {delete(s.rooms,room)}
	}
}

func (s *Server) registerLocked(room,id string,now time.Time) error {
	if s.rooms[room]==nil {
		if len(s.rooms)>=maxRooms{return errors.New("too many rooms")}
		s.rooms[room]=make(map[string]*inbox)
	}
	if s.rooms[room][id]==nil {
		if len(s.rooms[room])>=maxPeersPerRoom {return errors.New("room full")}
		s.rooms[room][id]=&inbox{}
	}
	s.rooms[room][id].last=now
	return nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter,r *http.Request) {
	w.Header().Set("Cache-Control","no-store")
	w.Header().Set("X-Content-Type-Options","nosniff")
	if !s.authorize(w,r){return}
	room:=r.URL.Query().Get("room")
	id:=r.URL.Query().Get("peer")
	if !validID(room)||!validID(id) {
		http.Error(w,"invalid room or peer ID",http.StatusBadRequest);return
	}
	if r.URL.Path!="/v1/peers"&&r.URL.Path!="/v1/signal" {
		http.NotFound(w,r);return
	}
	var incoming Message
	if r.URL.Path=="/v1/signal"&&r.Method==http.MethodPost {
		// Never hold the global room mutex while reading untrusted request bodies.
		raw,err:=io.ReadAll(io.LimitReader(r.Body,maxMessage+1))
		if err!=nil||len(raw)>maxMessage {
			http.Error(w,"signal too large",http.StatusRequestEntityTooLarge);return
		}
		if json.Unmarshal(raw,&incoming)!=nil||incoming.From!=id||!validID(incoming.To)||incoming.To==id||
			(incoming.Type!="offer"&&incoming.Type!="answer"&&incoming.Type!="ice")||len(incoming.Data)==0 {
			http.Error(w,"invalid signal",http.StatusBadRequest);return
		}
	}
	now:=time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanLocked(now)
	if err:=s.registerLocked(room,id,now);err!=nil {
		http.Error(w,err.Error(),http.StatusTooManyRequests);return
	}
	w.Header().Set("Content-Type","application/json")
	if r.URL.Path=="/v1/peers" {
		if r.Method!=http.MethodGet {http.Error(w,"method not allowed",http.StatusMethodNotAllowed);return}
		list:=make([]string,0,len(s.rooms[room]))
		for peer:=range s.rooms[room] {if peer!=id{list=append(list,peer)}}
		sort.Strings(list)
		_ = json.NewEncoder(w).Encode(list)
		return
	}
	if r.Method==http.MethodGet {
		queue:=s.rooms[room][id].pending
		s.rooms[room][id].pending=nil
		if queue==nil {queue=[]Message{}}
		_ = json.NewEncoder(w).Encode(queue)
		return
	}
	if r.Method!=http.MethodPost {
		http.Error(w,"method not allowed",http.StatusMethodNotAllowed);return
	}
	msg:=incoming
	target:=s.rooms[room][msg.To]
	if target==nil {
		http.Error(w,"unknown peer",http.StatusNotFound);return
	}
	if len(target.pending)>=maxQueue {
		http.Error(w,"receiver queue full",http.StatusTooManyRequests);return
	}
	target.pending=append(target.pending,msg)
	w.WriteHeader(http.StatusAccepted)
}
