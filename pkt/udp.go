package pkt

import "errors"

type Udp struct {
	Header UdpHeader
	Body   []byte
}

type UdpHeader struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum []byte
}

func (u *Udp) ReadFromBytes(bytes []byte) error {
	const headerSize = 8
	if len(bytes) < headerSize {
		return errors.New("bad UDP bytes")
	}
	u.Header = UdpHeader{
		SrcPort:  uint16(bytes[0])<<8 + uint16(bytes[1]),
		DstPort:  uint16(bytes[2])<<8 + uint16(bytes[3]),
		Length:   uint16(bytes[4])<<8 + uint16(bytes[5]),
		Checksum: bytes[6:8],
	}
	u.Body = bytes[headerSize:]
	return nil
}

func (u *Udp) WriteToBytes() ([]byte, error) {
	res := []byte{
		byte(u.Header.SrcPort >> 8),
		byte(u.Header.SrcPort & 0xff),
		byte(u.Header.DstPort >> 8),
		byte(u.Header.DstPort & 0xff),
		byte(u.Header.Length >> 8),
		byte(u.Header.Length & 0xff),
		u.Header.Checksum[0],
		u.Header.Checksum[1],
	}
	res = append(res, u.Body...)
	return res, nil
}

func (u *Udp) GetSrcPort() uint16 {
	return u.Header.SrcPort
}
