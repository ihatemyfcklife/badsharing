package swarm

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/ihatemyfcklife/badsharing"
)

const (
	manifestMagic="BSM1"
	manifestHeader=12
	maxManifestWireSize=36<<20
	manifestChunkSize=2048
)

// SendManifest sends a bounded authenticated manifest over a reliable ordered
// control channel. Do not send manifest chunks over an unreliable DataChannel.
func SendManifest(ctx context.Context,link Link,manifest *badsharing.GenerationManifest) error {
	if link==nil||manifest==nil {return errors.New("swarm: missing manifest or link")}
	data,err:=manifest.MarshalBinary()
	if err!=nil{return err}
	if len(data)>maxManifestWireSize {return errors.New("swarm: oversized manifest")}
	for offset:=0;offset<len(data);offset+=manifestChunkSize {
		end:=min(offset+manifestChunkSize,len(data))
		frame:=make([]byte,manifestHeader+end-offset)
		copy(frame[:4],manifestMagic)
		binary.BigEndian.PutUint32(frame[4:8],uint32(len(data)))
		binary.BigEndian.PutUint32(frame[8:12],uint32(offset))
		copy(frame[12:],data[offset:end])
		if err:=link.Send(ctx,frame);err!=nil{return err}
	}
	return nil
}

func ReceiveManifest(ctx context.Context,link Link,key [32]byte) (*badsharing.GenerationManifest,error) {
	if ctx==nil||link==nil{return nil,errors.New("swarm: missing context or link")}
	var data []byte
	position:=0
	for {
		packet,err:=link.Recv(ctx)
		if err!=nil{return nil,err}
		if len(packet)<manifestHeader||string(packet[:4])!=manifestMagic {
			return nil,errors.New("swarm: expected authenticated manifest chunk")
		}
		n:=uint64(binary.BigEndian.Uint32(packet[4:8]))
		offset:=int(binary.BigEndian.Uint32(packet[8:12]))
		if n==0||n>maxManifestWireSize||len(packet)==manifestHeader {
			return nil,errors.New("swarm: bad manifest size")
		}
		if data==nil {data=make([]byte,n)}
		if len(data)!=int(n)||offset!=position||position+len(packet)-manifestHeader>len(data) {
			return nil,fmt.Errorf("swarm: malformed, lost or out-of-order manifest fragment")
		}
		copy(data[position:],packet[manifestHeader:])
		position+=len(packet)-manifestHeader
		if position==len(data) {
			return badsharing.ParseGenerationManifest(data,key)
		}
	}
}
