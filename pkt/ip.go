package pkt

import (
	"errors"
	"fmt"
	"github.com/zenpk/udp2tcp-ideas/util"
	"strconv"
	"strings"
)

type Ip struct {
	Header IpHeader
	Body   []byte
}

type IpHeader struct {
	Version        uint8
	IHL            uint8
	Dscp           uint8
	Ecn            uint8
	TotalLength    uint16
	Identification uint16
	Flags          uint8
	FragmentOffset uint16
	Ttl            uint8
	Protocol       uint8
	HeaderChecksum uint16
	SrcIp          string
	DstIp          string
}

func (i *Ip) ReadFromBytes(bytes []byte) error {
	if len(bytes) < util.IpHeaderSize {
		return errors.New("IP packet size should at least larger than the header size")
	}
	i.Header = IpHeader{
		Version:        bytes[0] >> 4,
		IHL:            bytes[0] & 0x0f,
		Dscp:           bytes[1] >> 2,
		Ecn:            bytes[1] & 0x03,
		TotalLength:    uint16(bytes[2])<<8 + uint16(bytes[3]),
		Identification: uint16(bytes[4])<<8 + uint16(bytes[5]),
		Flags:          bytes[6] >> 5,
		FragmentOffset: uint16(bytes[6]&0x1f)<<8 + uint16(bytes[7]),
		Ttl:            bytes[8],
		Protocol:       bytes[9],
		HeaderChecksum: uint16(bytes[10])<<8 + uint16(bytes[11]),
		SrcIp:          fmt.Sprintf("%v.%v.%v.%v", bytes[12], bytes[13], bytes[14], bytes[15]),
		DstIp:          fmt.Sprintf("%v.%v.%v.%v", bytes[16], bytes[17], bytes[18], bytes[19]),
	}
	i.Body = bytes[util.IpHeaderSize:]
	return nil
}

func (i *Ip) WriteToBytes() ([]byte, error) {
	res, err := i.WriteHeaderToBytes()
	if err != nil {
		return nil, err
	}
	res = append(res, i.Body...)
	return res, nil
}

func (i *Ip) WriteHeaderToBytes() ([]byte, error) {
	res := []byte{
		i.Header.Version<<4 + i.Header.IHL,
		i.Header.Dscp<<2 + i.Header.Ecn,
		byte(i.Header.TotalLength >> 8),
		byte(i.Header.TotalLength & 0xff),
		byte(i.Header.Identification >> 8),
		byte(i.Header.Identification & 0xff),
		i.Header.Flags<<5 + byte(i.Header.FragmentOffset>>8),
		byte(i.Header.FragmentOffset & 0xff),
		i.Header.Ttl,
		i.Header.Protocol,
		byte(i.Header.HeaderChecksum >> 8),
		byte(i.Header.HeaderChecksum & 0xff),
	}
	srcIpBytes, err := i.ipToBytes(i.Header.SrcIp)
	if err != nil {
		return nil, err
	}
	dstIpBytes, err := i.ipToBytes(i.Header.DstIp)
	if err != nil {
		return nil, err
	}
	res = append(res, srcIpBytes...)
	res = append(res, dstIpBytes...)
	return res, nil
}

func (i *Ip) ipToBytes(ip string) ([]byte, error) {
	var res []byte
	nums := strings.Split(ip, ".")
	if len(nums) > 4 || len(nums) < 0 {
		return nil, errors.New("bad IP format when trying to convert IP to bytes")
	}
	for _, numStr := range nums {
		num, err := strconv.Atoi(numStr)
		if err != nil {
			return nil, err
		}
		if num > 255 || num < 0 {
			return nil, errors.New("numbers should be between 0 and 255 in IPv4")
		}
		res = append(res, byte(num))
	}
	return res, nil
}
