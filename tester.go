package main

import (
	"fmt"
	"github.com/zenpk/udp2tcp-ideas/util"
	"net"
	"os"
)

func test() {
	message := []byte("Hello UDP server!")
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%v:%v", util.TunOuterIp, 8080))

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	conn, err := net.DialUDP("udp", nil, addr)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	defer conn.Close()

	_, err = conn.Write(message)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("Message sent!")
}
