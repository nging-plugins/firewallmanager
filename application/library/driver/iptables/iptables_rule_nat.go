package iptables

import (
	"fmt"

	"github.com/nging-plugins/firewallmanager/application/library/driver"
	"github.com/nging-plugins/firewallmanager/application/library/enums"
)

func (a *IPTables) ruleNATFrom(rule *driver.Rule) (args []string, err error) {
	args, err = a.buildCommonRule(rule)
	if err != nil {
		return
	}
	switch rule.Direction {
	case enums.ChainPreRouting:
		if len(rule.NatIP) > 0 {
			args = append(args, `-j`, `DNAT`)
			toDest := rule.NatIP
			if len(rule.NatPort) > 0 {
				toDest += `:` + rule.NatPort
			}
			args = append(args, `--to-destination`, toDest)
		} else if len(rule.NatPort) > 0 {
			args = append(args, `-j`, `REDIRECT`)
			args = append(args, `--to-ports `, rule.NatPort)
		} else {
			err = driver.ErrNatIPOrNatPortRequired
			return
		}
	case enums.ChainPostRouting:
		if len(rule.NatIP) > 0 {
			args = append(args, `-j`, `SNAT`)
			toSrc := rule.NatIP
			if len(rule.NatPort) > 0 {
				toSrc += `:` + rule.NatPort
			}
			args = append(args, `--to-source`, toSrc)
		} else {
			args = append(args, `-j`, `MASQUERADE`)
			if len(rule.NatPort) > 0 {
				args = append(args, `--to-ports `, rule.NatPort)
			}
		}
	default:
		err = fmt.Errorf(`%w: %s (table=%v)`, driver.ErrUnsupportedChain, rule.Direction, rule.Type)
	}
	return
}
