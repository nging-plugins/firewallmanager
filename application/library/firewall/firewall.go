package firewall

import (
	"sync"

	"github.com/nging-plugins/firewallmanager/application/library/driver"
	"github.com/nging-plugins/firewallmanager/application/library/driver/iptables"
)

var engine driver.Driver
var engonce sync.Once

func initEngine() {
	var err error
	engine, err = iptables.New()
	if err != nil {
		panic(err)
	}
}

func Engine() driver.Driver {
	engonce.Do(initEngine)
	return engine
}
