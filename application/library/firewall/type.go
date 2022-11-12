package firewall

import (
	"github.com/nging-plugins/firewallmanager/application/library/driver/iptables"
	"github.com/webx-top/echo"
)

var Types = echo.NewKVData().
	Add(iptables.TableFilter, `Filter`).
	Add(iptables.TableNAT, `NAT`).
	Add(iptables.TableMangle, `Mangle`).
	Add(iptables.TableRaw, `Raw`)

var Directions = echo.NewKVData().
	Add(iptables.ChainInput, `入站`).
	Add(iptables.ChainOutput, `出站`).
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
}
