package main

import (
	"flag"
	"github.com/zenpk/udp2tcp-ideas/util"
	"strconv"
	"strings"
)

var (
	mode     string
	platform string
	dst      string
	logLevel int
)

func main() {
	flag.StringVar(&mode, "mode", "sender", "sender | receiver | tester")
	flag.StringVar(&platform, "platform", "darwin", "linux | darwin | windows")
	flag.StringVar(&dst, "dst", "", "destination ip:port")
	flag.IntVar(&logLevel, "loglevel", util.LogLevelDebug, "log level")
	flag.Parse()
	mode = strings.ToLower(mode)
	platform = strings.ToLower(platform)
	util.Log.Loglevel = logLevel
	util.Log.Info("working on %v, in %v mode\n", platform, mode)

	if mode == util.ModeTester {
		test()
	} else {
		if dst == "" {
			panic("invalid destination ip:port")
		}
		dstSplit := strings.Split(dst, ":")
		if len(dstSplit) != 2 {
			panic("wrong dst format")
		}
		dstIp := dstSplit[0]
		dstPort, err := strconv.Atoi(dstSplit[1])
		if err != nil {
			util.Log.Error("wrong dst port format: %v", err)
			panic(err)
		}

		sr := senderReceiver{
			platform: platform,
			mode:     mode,
			dstIp:    dstIp,
			dstPort:  uint16(dstPort),
		}
		sr.start()
	}
}
