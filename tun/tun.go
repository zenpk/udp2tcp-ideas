package tun

import (
	"github.com/labulakalia/water"
	"github.com/zenpk/udp2tcp-ideas/util"
	"os/exec"
)

func CreateDarwin() *water.Interface {
	tun := createTun()
	err := exec.Command("sudo", "ifconfig", tun.Name(), util.TunInnerIp, util.TunOuterIp, "up").Run()
	if err != nil {
		panic(err)
	}
	return tun
}
func CreateLinux() *water.Interface {
	tun := createTun()
	err := exec.Command("sudo", "ifconfig", tun.Name(), util.TunInnerIp, util.TunOuterIp, "up").Run()
	if err != nil {
		panic(err)
	}
	return tun
}

func CreateWindows() *water.Interface {
	tun := createTun()
	if err := exec.Command("netsh", "interface", "ip", "source=static", " addr=10.1.0.10", "mask=255.255.255.0 ", "gateway=none").Run(); err != nil {
		panic(err)
	}
	return tun
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
