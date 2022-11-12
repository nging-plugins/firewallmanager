package firewall

import (
	"sync"

	"github.com/nging-plugins/firewallmanager/application/library/driver"
	"github.com/nging-plugins/firewallmanager/application/library/driver/iptables"
)

var engineIPv4 driver.Driver
var engonceIPv4 sync.Once
var engineIPv6 driver.Driver
var engonceIPv6 sync.Once

func initEngineIPv4() {
	var err error
	engineIPv4, err = iptables.New(iptables.ProtocolIPv4)
	if err != nil {
		panic(err)
	}
}

func EngineIPv4() driver.Driver {
	engonceIPv4.Do(initEngineIPv4)
	return engineIPv4
}

func initEngineIPv6() {
	var err error
	engineIPv6, err = iptables.New(iptables.ProtocolIPv6)
	if err != nil {
		panic(err)
	}
}

func EngineIPv6() driver.Driver {
	engonceIPv6.Do(initEngineIPv6)
	return engineIPv6
}

func Engine(ipVersionNumber string) driver.Driver {
	if ipVersionNumber == `6` {
		return EngineIPv6()
	}
	return EngineIPv4()
}
