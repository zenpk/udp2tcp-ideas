package main

import (
	"flag"
	"github.com/zenpk/udp2tcp-ideas/util"
	"strings"
)

var (
	mode     string
	platform string
	dst      string
	logLevel int
)

func main() {
	flag.StringVar(&mode, "mode", "sender", "listener | sender | tester")
	flag.StringVar(&platform, "platform", "darwin", "linux | darwin | windows")
	flag.StringVar(&dst, "dst", "", "destination ip:port")
	flag.IntVar(&logLevel, "loglevel", util.LogLevelDebug, "log level")
	flag.Parse()
	mode = strings.ToLower(mode)
	platform = strings.ToLower(platform)
	util.Log.Loglevel = logLevel

	ls := listenerSender{
		platform: platform,
		mode:     mode,
		dst:      dst,
	}

	util.Log.Info("working on %v, in %v mode\n", platform, mode)
	if mode == util.ModeTester {
		test()
	} else {
		if dst == "" {
			panic("invalid destination ip:port")
		}
		ls.start()
	}
}
