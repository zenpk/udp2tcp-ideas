package pkt

import "errors"

type Tcp struct {
	Header TcpHeader
	Body   []byte
}

type TcpHeader struct {
	SrcPort       uint16
	DstPort       uint16
	SeqNum        uint32
	AckNum        uint32
	Offset        uint8
	Reserved      uint8
	Cwr           bool
	Ece           bool
	Urg           bool
	Ack           bool
	Psh           bool
	Rst           bool
	Syn           bool
	Fin           bool
	WindowSize    uint16
	Checksum      []byte
	UrgentPointer uint16
}

func (t *Tcp) ReadFromBytes(bytes []byte) error {
	const headerSize = 20
	if len(bytes) < headerSize {
		return errors.New("bad TCP bytes")
	}
	t.Header = TcpHeader{
		SrcPort:       uint16(bytes[0])<<8 + uint16(bytes[1]),
		DstPort:       uint16(bytes[2])<<8 + uint16(bytes[3]),
		SeqNum:        uint32(bytes[4])<<24 + uint32(bytes[5])<<16 + uint32(bytes[6])<<8 + uint32(bytes[7]),
		AckNum:        uint32(bytes[8])<<24 + uint32(bytes[9])<<16 + uint32(bytes[10])<<8 + uint32(bytes[11]),
		Offset:        bytes[12] >> 4,
		Reserved:      bytes[12] & 0x0f,
		Cwr:           bytes[13]&0x80 > 0,
		Ece:           bytes[13]&0x40 > 0,
		Urg:           bytes[13]&0x20 > 0,
		Ack:           bytes[13]&0x10 > 0,
		Psh:           bytes[13]&0x08 > 0,
		Rst:           bytes[13]&0x04 > 0,
		Syn:           bytes[13]&0x02 > 0,
		Fin:           bytes[13]&0x01 > 0,
		WindowSize:    uint16(bytes[14])<<8 + uint16(bytes[15]),
		Checksum:      bytes[16:17],
		UrgentPointer: uint16(bytes[18])<<8 + uint16(bytes[19]),
	}
	t.Body = bytes[headerSize:]
	return nil
}

func (t *Tcp) WriteToBytes() ([]byte, error) {
	res := []byte{
		byte(t.Header.SrcPort >> 8),
		byte(t.Header.SrcPort & 0x0f),
		byte(t.Header.DstPort >> 8),
		byte(t.Header.DstPort & 0x0f),
		byte(t.Header.SeqNum >> 24),
		byte(t.Header.SeqNum >> 16 & 0x0f),
		byte(t.Header.SeqNum >> 8 & 0x0f),
		byte(t.Header.SeqNum & 0x0f),
		byte(t.Header.AckNum >> 24),
		byte(t.Header.AckNum >> 16 & 0x0f),
		byte(t.Header.AckNum >> 8 & 0x0f),
		byte(t.Header.AckNum & 0x0f),
		t.Header.Offset,
		t.Header.Reserved,
		t.combineBools(),
	}
	res = append(res, t.Header.Checksum...)
	res = append(res, byte(t.Header.UrgentPointer>>8), byte(t.Header.UrgentPointer&0x0f))
	res = append(res, t.Body...)
	return res, nil
}

func (t *Tcp) combineBools() byte {
	res := byte(0)
	if t.Header.Cwr {
		res += 1 << 7
	}
	if t.Header.Ece {
		res += 1 << 6
	}
	if t.Header.Urg {
		res += 1 << 5
	}
	if t.Header.Ack {
		res += 1 << 4
	}
	if t.Header.Psh {
		res += 1 << 3
	}
	if t.Header.Rst {
		res += 1 << 2
	}
	if t.Header.Syn {
		res += 1 << 1
	}
	if t.Header.Fin {
		res += 1
	}
	return res
}
