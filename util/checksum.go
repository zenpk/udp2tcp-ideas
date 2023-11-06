package util

import (
	"encoding/binary"
)

func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1])
	}
	sum += sum >> 16
	return uint16(^sum)
}

func TcpChecksum(ipHeader, tcpHeader, tcpBody []byte) uint16 {
	length := len(tcpHeader) + len(tcpBody)
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], ipHeader[12:16])
	copy(pseudoHeader[4:8], ipHeader[16:20])
	pseudoHeader[8] = 0
	pseudoHeader[9] = ipHeader[9]
	pseudoHeader[10] = byte(length >> 8)
	pseudoHeader[11] = byte(length & 0xff)
	data := append(pseudoHeader, tcpHeader...)
	data = append(data, tcpBody...)
	return checksum(data)
}
