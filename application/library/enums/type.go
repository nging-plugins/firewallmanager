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

package enums

import (
	"github.com/webx-top/echo"
)

var Types = echo.NewKVData().
	Add(TableFilter, `过滤器 (Filter)`).
	Add(TableNAT, `网络地址转换器 (NAT)`)
	//Add(TableMangle, `Mangle`).
	//Add(TableRaw, `Raw`)

var Directions = echo.NewKVData().
	Add(ChainInput, `入站 (`+ChainInput+`)`).
	Add(ChainOutput, `出站 (`+ChainOutput+`)`).
	Add(ChainForward, `转发 (`+ChainForward+`)`).
	Add(ChainPreRouting, `路由之前 (`+ChainPreRouting+`)`).
	Add(ChainPostRouting, `路由之后 (`+ChainPostRouting+`)`)

const (
	IPv4str          = `4`
	IPv6str          = `6`
	ZeroIPv4         = `0.0.0.0`
	ZeroIPv6         = `::`
	ZeroIPv4WithMask = ZeroIPv4 + `/0`
	ZeroIPv6WithMask = ZeroIPv6 + `/0`
	AnyInterface     = `*`
)

func IsEmptyIP(ip string) bool {
	return len(ip) == 0 || ip == `!` || ip == ZeroIPv4 || ip == ZeroIPv6 || ip == ZeroIPv4WithMask || ip == ZeroIPv6WithMask
}

func IsEmptyPort(port string) bool {
	return len(port) == 0 || port == `!`
}

func IsEmptyIface(iface string) bool {
	return len(iface) == 0 || iface == AnyInterface
}

var IPProtocols = echo.NewKVData().
	Add(IPv4str, `IPv4`).
	Add(IPv6str, `IPv6`)

var NetProtocols = echo.NewKVData().
	Add(ProtocolTCP, `TCP`).
	Add(ProtocolUDP, `UDP`).
	Add(ProtocolICMP, `ICMP`).
	Add(ProtocolAll, `不限`)

var Actions = echo.NewKVData().
	Add(TargetAccept, `✅ 接受`).
	Add(TargetDrop, `🚮 丢弃`).
	Add(TargetReject, `🚫 拒绝`).
	Add(TargetLog, `📝 记录日志`)
