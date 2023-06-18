package nftables

import (
	"fmt"
	"net"
	"strings"

	"github.com/admpub/nftablesutils"
	"github.com/google/nftables"
	"github.com/nging-plugins/firewallmanager/application/library/driver"
	"github.com/webx-top/echo/param"
)

func (a *NFTables) ruleNATFrom(c *nftables.Conn, rule *driver.Rule) (args nftablesutils.Exprs, err error) {
	args, err = a.buildCommonRule(c, rule)
	if err != nil {
		return
	}
	switch rule.Direction {
	case `prerouting`:
		if len(rule.NatPort) > 0 {
			port := param.AsUint16(rule.NatPort)
			err = nftablesutils.ValidatePort(port)
			if err != nil {
				return
			}
			args = args.Add(nftablesutils.RedirectTo(port)...)
			return
		}
		if len(rule.NatIP) > 0 {
			localIP := strings.SplitN(rule.LocalIP, `-`, 2)[0]
			ip := net.ParseIP(localIP)
			if a.isIPv4() {
				if ip == nil || ip.To4() == nil {
					err = fmt.Errorf(`%w: %s`, driver.ErrInvalidIPv4, localIP)
					return
				}
				args = args.Add(nftablesutils.DNAT(ip)...)
			} else {
				if ip == nil || ip.To4() != nil {
					err = fmt.Errorf(`%w: %s`, driver.ErrInvalidIPv6, localIP)
					return
				}
				args = args.Add(nftablesutils.DNATv6(ip)...)
			}
		} else {
			err = driver.ErrNatIPOrNatPortRequired
		}
	case `postrouting`:
		if len(rule.NatIP) > 0 { // 发送给访客
			remoteIP := strings.SplitN(rule.NatIP, `-`, 2)[0]
			ip := net.ParseIP(remoteIP)
			if a.isIPv4() {
				if ip == nil || ip.To4() == nil {
					err = fmt.Errorf(`%w: %s`, driver.ErrInvalidIPv4, remoteIP)
					return
				}
				args = args.Add(nftablesutils.SNAT(ip)...)
			} else {
				if ip == nil || ip.To4() != nil {
					err = fmt.Errorf(`%w: %s`, driver.ErrInvalidIPv6, remoteIP)
					return
				}
				args = args.Add(nftablesutils.SNATv6(ip)...)
			}
		} else {
			args = args.Add(nftablesutils.ExprMasquerade(1, 0))
		}
	default:
		err = fmt.Errorf(`%w: %s (table=%v)`, driver.ErrUnsupportedChain, rule.Direction, rule.Type)
	}
	return
}
