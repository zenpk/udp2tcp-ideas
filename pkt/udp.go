package pkt

import (
	"errors"
	"github.com/zenpk/udp2tcp-ideas/util"
)

type Udp struct {
	Header UdpHeader
	Body   []byte
}

type UdpHeader struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
}

func (u *Udp) ReadFromBytes(bytes []byte) error {
	if len(bytes) < util.UdpHeaderSize {
		return errors.New("UDP packet size should at least larger than the header size")
	}
	u.Header = UdpHeader{
		SrcPort:  uint16(bytes[0])<<8 + uint16(bytes[1]),
		DstPort:  uint16(bytes[2])<<8 + uint16(bytes[3]),
		Length:   uint16(bytes[4])<<8 + uint16(bytes[5]),
		Checksum: uint16(bytes[6])<<8 + uint16(bytes[7]),
	}
	u.Body = bytes[util.UdpHeaderSize:]
	return nil
}

func (u *Udp) WriteToBytes() []byte {
	res := u.WriteHeaderToBytes()
	res = append(res, u.Body...)
	return res
}

func (u *Udp) WriteHeaderToBytes() []byte {
	return []byte{
		byte(u.Header.SrcPort >> 8),
		byte(u.Header.SrcPort & 0xff),
		byte(u.Header.DstPort >> 8),
		byte(u.Header.DstPort & 0xff),
		byte(u.Header.Length >> 8),
		byte(u.Header.Length & 0xff),
		byte(u.Header.Checksum >> 8),
		byte(u.Header.Checksum & 0xff),
	}
}

func (u *Udp) GetSrcPort() uint16 {
	return u.Header.SrcPort
}
