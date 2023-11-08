package main

import (
	"math"

	"github.com/zenpk/udp2tcp-ideas/pkt"
	"github.com/zenpk/udp2tcp-ideas/tun"
	"github.com/zenpk/udp2tcp-ideas/util"

	"github.com/labulakalia/water"
)

type senderReceiver struct {
	device   *water.Interface
	platform string
	mode     string
	dstIp    string
	dstPort  uint16
}

func (r senderReceiver) start() {
	if r.platform == util.PlatformDarwin {
		r.device = tun.CreateDarwin()
	}
	if r.platform == util.PlatformLinux {
		r.device = tun.CreateLinux()
	}
	if r.platform == util.PlatformWindows {
		r.device = tun.CreateWindows()
	}
	defer r.device.Close()

	buffer := make([]byte, math.MaxInt32)

	for {
		n, err := r.device.Read(buffer)
		if err != nil {
			panic(err)
		}
		if n > 0 {
			go func() {
				if r.mode == util.ModeReceiver {
				}
				if r.mode == util.ModeSender {
					if err := r.handleSender(append([]byte(nil), buffer[:n]...)); err != nil {
						panic(err)
					}
				}
			}()
		}
	}
}

func (r senderReceiver) handleSender(data []byte) error {
	util.PrintBytesAsHex("original: ", data)
	ipPacket, err := r.extractIpPacket(data)
	if err != nil {
		return err
	}
	udpPacket, err := r.extractUdpPacket(ipPacket)
	if err != nil {
		return err
	}
	dynamicIp, dynamicPort := r.getDynamicIpPort(ipPacket, &udpPacket)
	util.Log.Debug("dynamic IP: %v, dynamic port: %v\n", dynamicIp, dynamicPort)
	tcpPacket, err := r.udpToFakeTcp(udpPacket)
	if err != nil {
		return err
	}
	encapsulatedIpPacket, err := r.encapsulateFakePacket(tcpPacket, ipPacket)
	if err != nil {
		return err
	}
	temp, _ := encapsulatedIpPacket.WriteToBytes()
	util.PrintBytesAsHex("encapsulated: ", temp)
	if err := r.sendIp(encapsulatedIpPacket); err != nil {
		return err
	}
	// TODO edge case
	// const headerLen = 40 // IP header: 20, TCP header: 20
	// if len(udpPacket.Body) > math.MaxInt32-headerLen {
	// 	tcpPacket.Body = udpPacket.Body[0 : math.MaxInt32-headerLen]

	// 	r.sendRemainder(ipPacket.Header, udpPacket.Body[math.MaxInt32-headerLen:])
	// } else {

	// }
	return nil
}

// extractIpPacket extracts the IP packet from the data bytes
func (r senderReceiver) extractIpPacket(data []byte) (pkt.Ip, error) {
	var ipPacket pkt.Ip
	if err := ipPacket.ReadFromBytes(data); err != nil {
		return pkt.Ip{}, err
	}
	util.Log.Debug("IP header: %v\n", ipPacket.Header)
	util.Log.Debug("IP content: %s\n", string(ipPacket.Body))
	return ipPacket, nil
}

// extractUdpPacket extracts the UDP packet from the IP packet body
func (r senderReceiver) extractUdpPacket(ipPacket pkt.Ip) (pkt.Udp, error) {
	var udpPacket pkt.Udp
	if err := udpPacket.ReadFromBytes(ipPacket.Body); err != nil {
		return pkt.Udp{}, err
	}
	util.Log.Debug("UDP header: %v\n", udpPacket.Header)
	util.Log.Debug("UDP content: %s\n", string(udpPacket.Body))
	return udpPacket, nil
}

// extractFakeTcpPacket extracts the fake TCP packet from the IP packet
func (r senderReceiver) extractFakeTcpPacket(ipPacket pkt.Ip) (pkt.Tcp, error) {
	var tcpPacket pkt.Tcp
	if err := tcpPacket.ReadFromBytes(ipPacket.Body); err != nil {
		return pkt.Tcp{}, err
	}
	util.Log.Debug("fake TCP header: %v\n", tcpPacket.Header)
	util.Log.Debug("fake TCP content: %s\n", string(tcpPacket.Body))
	return tcpPacket, nil
}

// getDynamicIpPort returns the dynamic IP and port from IP and UDP (or fake TCP) packet
func (r senderReceiver) getDynamicIpPort(ipPacket pkt.Ip, udpOrTcp pkt.UdpOrTcp) (string, uint16) {
	return ipPacket.Header.SrcIp, udpOrTcp.GetSrcPort()
}

// fakeTcpToUdp converts the fake TCP packet to a UDP packet
// the sender should provide the dynamic port
func (r senderReceiver) fakeTcpToUdp(tcpPacket pkt.Tcp, dynamicPort ...uint16) pkt.Udp {
	var dstPort uint16
	if len(dynamicPort) > 0 { // sender, send back to the source application
		dstPort = dynamicPort[0]
	} else {
		dstPort = r.dstPort // receiver, send to the target application
	}
	udpPacket := pkt.Udp{
		Header: pkt.UdpHeader{
			SrcPort:  tcpPacket.Header.SrcPort,
			DstPort:  dstPort,
			Length:   uint16(tcpPacket.Header.SeqNum), // temp
			Checksum: tcpPacket.Header.Checksum,
		},
		Body: tcpPacket.Body,
	}
	util.Log.Debug("UDP header: %v\n", udpPacket.Header)
	util.Log.Debug("UDP content: %s\n", string(udpPacket.Body))
	return udpPacket
}

// udpToFakeTcp converts the UDP packet to a fake TCP packet
// the receiver should provide the dynamic port
func (r senderReceiver) udpToFakeTcp(udpPacket pkt.Udp, dynamicPort ...uint16) (pkt.Tcp, error) {
	var dstPort uint16
	if len(dynamicPort) > 0 { // receiver, send back to the sender TUN device
		dstPort = dynamicPort[0]
	} else {
		dstPort = r.dstPort // sender, send to the receiver TUN device
	}
	tcpPacket := pkt.Tcp{
		Header: pkt.TcpHeader{
			SrcPort:       udpPacket.Header.SrcPort,
			DstPort:       dstPort,
			SeqNum:        uint32(udpPacket.Header.Length), // temp
			AckNum:        0,
			Offset:        5, // 20 bytes header / 4 bytes per word
			Reserved:      0,
			Cwr:           false,
			Ece:           false,
			Urg:           false,
			Ack:           false,
			Psh:           false,
			Rst:           false,
			Syn:           false,
			Fin:           false,
			WindowSize:    math.MaxUint16,
			Checksum:      0, // will be calculated when encapsulated into IP packet
			UrgentPointer: 0,
		},
		Body: udpPacket.Body,
	}
	return tcpPacket, nil
}

// encapsulateUdpPacket encapsulates the UDP packet into the IP packet
// the sender should provide the dynamic IP
func (r senderReceiver) encapsulateUdpPacket(udpPacket pkt.Udp, ipPacket pkt.Ip, dynamicIp ...string) (pkt.Ip, error) {
	udpBytes := udpPacket.WriteToBytes()
	ipPacket.Body = udpBytes
	ipPacket.Header.Protocol = 17 // change protocol to UDP
	ipPacket.Header.SrcIp = ipPacket.Header.DstIp
	if len(dynamicIp) > 0 { // sender, send back to the source application
		ipPacket.Header.DstIp = dynamicIp[0]
	} else { // receiver, send to the target application
		ipPacket.Header.DstIp = r.dstIp
	}
	ipPacket.Header.TotalLength -= 12 // TCP header is 12 bytes more than UDP
	ipPacket.Header.HeaderChecksum = 0
	//ipHeaderBytes, err := ipPacket.WriteHeaderToBytes()
	//if err != nil {
	//	return pkt.Ip{}, err
	//}

	// TODO edge case
	return ipPacket, nil
}

// encapsulateFakePacket encapsulates the fake TCP packet into the IP packet
// the receiver should provide the dynamic IP
func (r senderReceiver) encapsulateFakePacket(tcpPacket pkt.Tcp, ipPacket pkt.Ip, dynamicIp ...string) (pkt.Ip, error) {
	ipPacket.Header.Protocol = 6 // change protocol to TCP
	ipPacket.Header.SrcIp = ipPacket.Header.DstIp
	if len(dynamicIp) > 0 { // receiver, send back to the sender TUN device
		ipPacket.Header.DstIp = dynamicIp[0]
	} else { // sender, send to the receiver TUN device
		ipPacket.Header.DstIp = r.dstIp
	}
	ipPacket.Header.TotalLength += 12 // TCP header is 12 bytes more than UDP
	ipPacket.Header.HeaderChecksum = 0
	tcpPacket.Header.Checksum = 0
	ipHeaderBytes, err := ipPacket.WriteHeaderToBytes()
	if err != nil {
		return pkt.Ip{}, err
	}
	tcpHeaderBytes := tcpPacket.WriteHeaderToBytes()
	tcpPacket.Header.Checksum = pkt.TcpChecksum(ipHeaderBytes, tcpHeaderBytes, tcpPacket.Body)
	ipPacket.Body = tcpPacket.WriteToBytes()
	// TODO IP checksum
	// TODO edge case
	return ipPacket, nil
}

// sendIp sends an IP packet to the other TUN device
func (r senderReceiver) sendIp(packet pkt.Ip) error {
	ipBytes, err := packet.WriteToBytes()
	if err != nil {
		return err
	}
	n, err := r.device.Write(ipBytes)
	if err != nil {
		return err
	}
	util.Log.Info("%v bytes of IP packet sent", n)
	return nil
}

// sendUdp sends a UDP packet to the application
func (r senderReceiver) sendUdp(packet pkt.Udp) error {
	return nil
}

// sendRemainder when faking UDP to TCP packet, an additional 12 bytes of header will be added
// thus may cause a body overflow. The packet will be sent as two packets.
// This should be a rare edge case.
func (r senderReceiver) sendRemainder(header pkt.IpHeader, remainder []byte) error {
	// TODO
	util.Log.Warn("WARN: remainder happened")
	if len(remainder) > 12 {
		util.Log.Warn("ERROR: remainder shouldn't be larger than 12 bytes\n")
		util.Log.Debug("    header: %v\n    remainder: %v\n", header, remainder)
		return nil
	}
	return nil
}
