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
	"github.com/nging-plugins/firewallmanager/application/library/driver/iptables"
	"github.com/webx-top/echo"
)

var TablesChains = iptables.TablesChains

var Types = echo.NewKVData().
	Add(iptables.TableFilter, `Filter`).
	Add(iptables.TableNAT, `NAT`).
	Add(iptables.TableMangle, `Mangle`).
	Add(iptables.TableRaw, `Raw`)

var Directions = echo.NewKVData().
	Add(iptables.ChainInput, `入站`).
	Add(iptables.ChainOutput, `出站`).
	Add(iptables.ChainForward, `转发`).
	Add(iptables.ChainPreRouting, `入站前`).
	Add(iptables.ChainPostRouting, `出站后`)

var IPProtocols = echo.NewKVData().
	Add(`4`, `IPv4`).
	Add(`6`, `IPv6`)

var NetProtocols = echo.NewKVData().
	Add(iptables.ProtocolTCP, `TCP`).
	Add(iptables.ProtocolUDP, `UDP`).
	Add(iptables.ProtocolICMP, `ICMP`).
	Add(iptables.ProtocolAll, `ALL`)

var Actions = echo.NewKVData().
	Add(iptables.TargetAccept, `接受`).
	Add(iptables.TargetDrop, `丢弃`).
	Add(iptables.TargetReject, `拒绝`).
	Add(iptables.TargetLog, `记录日志`)

func SetFormData(c echo.Context) {
	c.Set(`types`, Types.Slice())
	c.Set(`directions`, Directions.Slice())
	c.Set(`ipProtocols`, IPProtocols.Slice())
	c.Set(`netProtocols`, NetProtocols.Slice())
	c.Set(`actions`, Actions.Slice())
	c.Set(`tablesChains`, TablesChains)
}
