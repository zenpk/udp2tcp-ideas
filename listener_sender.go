package main

import (
	"github.com/zenpk/udp2tcp-ideas/pkt"
	"github.com/zenpk/udp2tcp-ideas/tun"
	"github.com/zenpk/udp2tcp-ideas/util"
	"math"

	"github.com/labulakalia/water"
)

type listenerSender struct {
	platform string
	mode     string
	dst      string
}

func (l listenerSender) start() {
	var device *water.Interface
	if l.platform == util.PlatformDarwin {
		device = tun.CreateDarwin()
	}
	if l.platform == util.PlatformLinux {
		device = tun.CreateLinux()
	}
	if l.platform == util.PlatformWindows {
		device = tun.CreateWindows()
	}

	buffer := make([]byte, math.MaxInt32)

	for {
		n, err := device.Read(buffer)
		if err != nil {
			panic(err)
		}
		if n > 0 {
			go func() {
				if l.mode == util.ModeListener {

				}
				if l.mode == util.ModeSender {
					if err := l.handleSender(append([]byte(nil), buffer[:n]...)); err != nil {
						panic(err)
					}
				}
			}()
		}
	}
}

func (l listenerSender) handleSender(data []byte) error {
	ipPacket, err := l.extractIpPacket(data)
	if err != nil {
		return err
	}
	udpPacket, err := l.extractUdpPacket(ipPacket)
	if err != nil {
		return err
	}
	tcpPacket := l.fakeUdpToTcp(udpPacket)
	encapsulated, err := l.encapsulateFakePacket(tcpPacket, ipPacket)
	if err != nil {
		return err
	}
	// TODO send
	// TODO edge case
	// const headerLen = 40 // IP header: 20, TCP header: 20
	// if len(udpPacket.Body) > math.MaxInt32-headerLen {
	// 	tcpPacket.Body = udpPacket.Body[0 : math.MaxInt32-headerLen]

	// 	l.sendRemainder(ipPacket.Header, udpPacket.Body[math.MaxInt32-headerLen:])
	// } else {

	// }
	return nil
}

// extractIpPacket extracts the IP packet from the data bytes
func (l listenerSender) extractIpPacket(data []byte) (pkt.Ip, error) {
	var ipPacket pkt.Ip
	if err := ipPacket.ReadFromBytes(data); err != nil {
		return pkt.Ip{}, err
	}
	util.Log.Debug("IP header: %v\n", ipPacket.Header)
	util.Log.Debug("IP content: %s\n", string(ipPacket.Body))
	return ipPacket, nil
}

// extractUdpPacket extracts the UDP packet from the IP packet body
func (l listenerSender) extractUdpPacket(ipPacket pkt.Ip) (pkt.Udp, error) {
	var udpPacket pkt.Udp
	if err := udpPacket.ReadFromBytes(ipPacket.Body); err != nil {
		return pkt.Udp{}, err
	}
	util.Log.Debug("UDP header: %v\n", udpPacket.Header)
	util.Log.Debug("UDP content: %s\n", string(udpPacket.Body))
	return udpPacket, nil
}

// extractFakePacket extracts the fake TCP packet from the IP packet
func (l listenerSender) extractFakePacket(ipPacket pkt.Ip) (pkt.Udp, error) {
	var tcpPacket pkt.Tcp
	if err := tcpPacket.ReadFromBytes(ipPacket.Body); err != nil {
		return pkt.Udp{}, err
	}
	udpPacket := pkt.Udp{
		Header: pkt.UdpHeader{
			SrcPort:  tcpPacket.Header.SrcPort,
			DstPort:  tcpPacket.Header.DstPort,
			Length:   uint16(tcpPacket.Header.SeqNum),
			Checksum: tcpPacket.Header.Checksum,
		},
		Body: tcpPacket.Body,
	}
	util.Log.Debug("UDP header: %v\n", udpPacket.Header)
	util.Log.Debug("UDP content: %s\n", string(udpPacket.Body))
	return udpPacket, nil
}

// fakeUdpToTcp converts the UDP packet to a fake TCP packet
func (l listenerSender) fakeUdpToTcp(udpPacket pkt.Udp) pkt.Tcp {
	return pkt.Tcp{
		Header: pkt.TcpHeader{
			SrcPort:       udpPacket.Header.SrcPort,
			DstPort:       udpPacket.Header.DstPort,
			SeqNum:        uint32(udpPacket.Header.Length), // temp
			AckNum:        0,
			Offset:        0,
			Reserved:      0,
			Cwr:           false,
			Ece:           false,
			Urg:           false,
			Ack:           false,
			Psh:           false,
			Rst:           false,
			Syn:           false,
			Fin:           false,
			WindowSize:    0,
			Checksum:      udpPacket.Header.Checksum,
			UrgentPointer: 0,
		},
		Body: udpPacket.Body,
	}
}

// encapsulateUdpPacket encapsulates the UDP packet into the IP packet
func (l listenerSender) encapsulateUdpPacket(udpPacket pkt.Udp, ipPacket pkt.Ip) ([]byte, error) {
	udpBytes, err := udpPacket.WriteToBytes()
	if err != nil {
		return nil, err
	}
	ipPacket.Body = udpBytes
	// change protocol to UDP
	ipPacket.Header.Protocol = 17 // UDP
	// TODO edge case
	ipPacket.Header.TotalLength -= 8 // TCP header is 8 bytes more than UDP
	return ipPacket.WriteToBytes()
}

// encapsulateFakePacket encapsulates the fake TCP packet into the IP packet
func (l listenerSender) encapsulateFakePacket(tcpPacket pkt.Tcp, ipPacket pkt.Ip) ([]byte, error) {
	tcpBytes, err := tcpPacket.WriteToBytes()
	if err != nil {
		return nil, err
	}
	ipPacket.Body = tcpBytes
	// change protocol in IP packet
	ipPacket.Header.Protocol = 6 // TCP
	// TODO edge case
	ipPacket.Header.TotalLength += 8 // TCP header is 8 bytes more than UDP
	return ipPacket.WriteToBytes()
}

// sendIp sends an IP packet to the other TUN device
func (l listenerSender) sendIp(packet pkt.Ip) error {
	return nil
}

// sendUdp sends a UDP packet to the target application
func (l listenerSender) sendUdp(packet pkt.Udp) error {
	return nil
}

// sendRemainder when faking UDP to TCP packet, an additional 8 bits of data will be added
// thus may cause a body overflow. The packet will be sent as two packets.
// This should be a rare edge case.
func (l listenerSender) sendRemainder(header pkt.IpHeader, remainder []byte) error {
	util.Log.Warn("WARN: remainder happened")
	if len(remainder) > 1 {
		util.Log.Warn("ERROR: remainder shouldn't be larger than 8 bits\n")
		util.Log.Debug("    header: %v\n    remainder: %v\n", header, remainder)
		return nil
	}
}
