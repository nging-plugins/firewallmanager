//go:build linux

/*
   Nging is a toolbox for webmasters
   Copyright (C) 2018-present  Wenhui Shen <swh@admpub.com>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published
   by the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

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
	engineIPv4, err = iptables.New(iptables.ProtocolIPv4, false)
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
	engineIPv6, err = iptables.New(iptables.ProtocolIPv6, false)
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
