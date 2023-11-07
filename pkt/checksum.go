package pkt

import (
	"github.com/google/gopacket/layers"
)

func TcpChecksum(ipPacket Ip, tcpPacket Tcp) (uint16, error) {
	tcpLayer := &layers.TCP{
		BaseLayer:  layers.BaseLayer{Payload: tcpPacket.Body},
		SrcPort:    layers.TCPPort(tcpPacket.Header.SrcPort),
		DstPort:    layers.TCPPort(tcpPacket.Header.DstPort),
		Seq:        tcpPacket.Header.SeqNum,
		Ack:        tcpPacket.Header.AckNum,
		DataOffset: tcpPacket.Header.Offset,
		FIN:        tcpPacket.Header.Fin,
		SYN:        tcpPacket.Header.Syn,
		RST:        tcpPacket.Header.Rst,
		PSH:        tcpPacket.Header.Psh,
		ACK:        tcpPacket.Header.Ack,
		URG:        tcpPacket.Header.Urg,
		ECE:        tcpPacket.Header.Ece,
		CWR:        tcpPacket.Header.Cwr,
		Window:     tcpPacket.Header.WindowSize,
		Checksum:   0,
		Urgent:     tcpPacket.Header.UrgentPointer,
	}

	srcIp, err := ipPacket.ipToBytes(ipPacket.Header.SrcIp)
	if err != nil {
		return 0, err
	}
	dstIp, err := ipPacket.ipToBytes(ipPacket.Header.DstIp)
	if err != nil {
		return 0, err
	}
	ipv4Layer := &layers.IPv4{
		SrcIP:    srcIp,
		DstIP:    dstIp,
		Protocol: layers.IPProtocolTCP,
	}

	if err := tcpLayer.SetNetworkLayerForChecksum(ipv4Layer); err != nil {
		return 0, err
	}
	checksum, err := tcpLayer.ComputeChecksum()
	if err != nil {
		return 0, err
	}
	return checksum, nil
}

//func checksum(data []byte) uint16 {
//	var sum uint32
//	for i := 0; i < len(data)-1; i += 2 {
//		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
//	}
//	if len(data)%2 == 1 {
//		sum += uint32(data[len(data)-1])
//	}
//	sum += sum >> 16
//	return uint16(^sum)
//}
//
//func TcpChecksum(ipHeader, tcpHeader, tcpBody []byte) uint16 {
//	length := len(tcpHeader) + len(tcpBody)
//	pseudoHeader := make([]byte, 12)
//	copy(pseudoHeader[0:4], ipHeader[12:16])
//	copy(pseudoHeader[4:8], ipHeader[16:20])
//	pseudoHeader[8] = 0
//	pseudoHeader[9] = ipHeader[9]
//	pseudoHeader[10] = byte(length >> 8)
//	pseudoHeader[11] = byte(length & 0xff)
//	data := append(pseudoHeader, tcpHeader...)
//	data = append(data, tcpBody...)
//	return checksum(data)
//}
