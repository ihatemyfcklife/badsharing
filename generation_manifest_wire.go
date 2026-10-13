package badsharing

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// MarshalBinary serializes a GenerationManifest with bounded, versioned framing.
// The signature remains an HMAC over metadata plus all generation SHA-256 digests.
func (m *GenerationManifest) MarshalBinary() ([]byte,error) {
	if m==nil {return nil,errors.New("badsharing: nil generation manifest")}
	if err:=validateGenerationMetadata(m.Metadata);err!=nil{return nil,err}
	meta,err:=m.Metadata.MarshalBinary()
	if err!=nil{return nil,err}
	count:=m.Metadata.TotalGenerations()
	if m.Metadata.Size==0 {count=0}
	if uint64(len(m.Hashes))!=count {return nil,errors.New("badsharing: missing generation hashes")}
	out:=make([]byte,12+len(meta)+len(m.Hashes)*32+32)
	copy(out[:4],"BSGM")
	binary.BigEndian.PutUint32(out[4:8],uint32(len(meta)))
	binary.BigEndian.PutUint32(out[8:12],uint32(len(m.Hashes)))
	copy(out[12:],meta)
	offset:=12+len(meta)
	for _,sum:=range m.Hashes {
		copy(out[offset:offset+32],sum[:])
		offset+=32
	}
	copy(out[offset:],m.Signature[:])
	return out,nil
}

// ParseGenerationManifest verifies size bounds and the authenticated HMAC
// before accepting a manifest received from an untrusted peer.
func ParseGenerationManifest(data []byte,key [32]byte) (*GenerationManifest,error) {
	if len(data)<12+32||string(data[:4])!="BSGM" {
		return nil,errors.New("badsharing: invalid generation manifest magic")
	}
	nMeta:=uint64(binary.BigEndian.Uint32(data[4:8]))
	nHashes:=uint64(binary.BigEndian.Uint32(data[8:12]))
	if nMeta<56||nMeta>1024||nHashes>MaxManifestGenerations {
		return nil,errors.New("badsharing: invalid generation manifest sizes")
	}
	expected:=uint64(12)+nMeta+nHashes*32+32
	if uint64(len(data))!=expected {return nil,fmt.Errorf("badsharing: malformed manifest length")}
	m:=&GenerationManifest{}
	if err:=m.Metadata.UnmarshalBinary(data[12:12+nMeta]);err!=nil{return nil,err}
	m.Hashes=make([][32]byte,nHashes)
	at:=12+nMeta
	for i:=range m.Hashes {copy(m.Hashes[i][:],data[at:at+32]);at+=32}
	copy(m.Signature[:],data[at:])
	if err:=m.Verify(key);err!=nil{return nil,err}
	return m,nil
}
