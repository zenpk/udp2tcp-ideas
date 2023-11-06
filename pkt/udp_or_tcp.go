package pkt

type UdpOrTcp interface {
	GetSrcPort() uint16
}
