package tun

import (
	"fmt"
	"github.com/labulakalia/water"
	"github.com/zenpk/udp2tcp-ideas/util"
	"log"
	"os/exec"
)

func CreateDarwin() *water.Interface {
	tun := createTun()
	if err := exec.Command("sudo", "ifconfig", tun.Name(), util.TunInnerIp, util.TunOuterIp, "up").Run(); err != nil {
		panic(err)
	}
	util.Log.Info("%s started\n", tun.Name())
	return tun
}
func CreateLinux() *water.Interface {
	tun := createTun()
	if err := exec.Command("sudo", "ip", "addr", "add", fmt.Sprintf("%s/24", util.TunInnerIp), "peer", util.TunOuterIp, "dev", tun.Name()).Run(); err != nil {
		panic(err)
	}
	if err := exec.Command("sudo", "ip", "link", "set", "dev", tun.Name(), "up").Run(); err != nil {
		panic(err)
	}
	util.Log.Info("%s started\n", tun.Name())
	return tun
}

func CreateWindows() *water.Interface {
	log.Fatalln("not implemented")
	return nil
	//tun := createTun()
	//if err := exec.Command("netsh", "interface", "ip", "set", "address", fmt.Sprintf("name=%s", tun.Name()), "source=static", "addr=10.1.0.10", "mask=255.255.255.0", "gateway=none").Run(); err != nil {
	//	panic(err)
	//}
	//util.Log.Info("%s started\n", tun.Name())
	//return tun
}

func createTun() *water.Interface {
	tun, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		panic(err)
	}
	util.Log.Info("TUN interface name: %s\n", tun.Name())
	return tun
}
