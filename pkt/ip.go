package pkt

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type Ip struct {
	Header IpHeader
	Body   []byte
}

type IpHeader struct {
	Version     uint8
	IHL         uint8
	TotalLength uint16
	Ttl         uint8
	Protocol    uint8
	SrcIp       string
	DstIp       string
}

func (i *Ip) ReadFromBytes(bytes []byte) error {
	const headerSize = 20
	if len(bytes) < headerSize {
		return errors.New("bad IP bytes")
	}
	i.Header = IpHeader{
		Version:     bytes[0] >> 4,
		IHL:         bytes[0] & 0x0f,
		TotalLength: uint16(bytes[2])<<8 + uint16(bytes[3]),
		Ttl:         bytes[8],
		Protocol:    bytes[9],
		SrcIp:       fmt.Sprintf("%v.%v.%v.%v", bytes[12], bytes[13], bytes[14], bytes[15]),
		DstIp:       fmt.Sprintf("%v.%v.%v.%v", bytes[16], bytes[17], bytes[18], bytes[19]),
	}
	i.Body = bytes[headerSize:]
	return nil
}

func (i *Ip) WriteToBytes() ([]byte, error) {
	res := []byte{
		i.Header.Version,
		i.Header.IHL,
		byte(i.Header.TotalLength >> 8),
		byte(i.Header.TotalLength & 0x0f),
		i.Header.Ttl,
		i.Header.Protocol,
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
	res = append(res, i.Body...)
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
