package iptables

import (
	"github.com/admpub/go-iptables/iptables"
)

const (
	ProtocolIPv4 iptables.Protocol = iptables.ProtocolIPv4
	ProtocolIPv6 iptables.Protocol = iptables.ProtocolIPv6
)

const (
	// 传输协议
	ProtocolTCP  = `tcp`
	ProtocolUDP  = `udp`
	ProtocolICMP = `icmp`
	ProtocolAll  = `all`
)

const (
	// 规则表之间的顺序
	// raw → mangle → nat → filter
	// 规则表表
	TableFilter = `filter` // 过滤数据包。三个链：INPUT、FORWARD、OUTPUT
	TableNAT    = `nat`    // 用于网络地址转换（IP、端口）。 三个链：PREROUTING、POSTROUTING、OUTPUT
	TableMangle = `mangle` // 修改数据包的服务类型、TTL、并且可以配置路由实现QOS。五个链：PREROUTING、POSTROUTING、INPUT、OUTPUT、FORWARD
	TableRaw    = `raw`    // 决定数据包是否被状态跟踪机制处理。两个链：OUTPUT、PREROUTING
)

const (
	// 规则链之间的顺序
	// ● 入站: PREROUTING → INPUT
	// ● 出站: OUTPUT → POSTROUTING
	// ● 转发: PREROUTING → FORWARD → POSTROUTIN
	// 规则链
	ChainInput       = `INPUT`       // 进来的数据包应用此规则链中的策略
	ChainOutput      = `OUTPUT`      // 外出的数据包应用此规则链中的策略
	ChainForward     = `FORWARD`     // 转发数据包时应用此规则链中的策略
	ChainPreRouting  = `PREROUTING`  // 对数据包作路由选择前应用此链中的规则（所有的数据包进来的时侯都先由这个链处理）
	ChainPostRouting = `POSTROUTING` // 对数据包作路由选择后应用此链中的规则（所有的数据包出来的时侯都先由这个链处理）
)

const (
	// 防火墙处理数据包的四种方式
	TargetAccept = `ACCEPT` // 允许数据包通过
	TargetDrop   = `DROP`   // 直接丢弃数据包，不给任何回应信息
	TargetReject = `REJECT` // 拒绝数据包通过，必要时会给数据发送端一个响应的信息
	TargetLog    = `LOG`    // 在/var/log/messages文件中记录日志信息，然后将数据包传递给下一条规则
)
