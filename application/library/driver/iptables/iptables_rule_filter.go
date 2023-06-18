package iptables

import (
	"github.com/nging-plugins/firewallmanager/application/library/driver"
)

func (a *IPTables) ruleFilterFrom(rule *driver.Rule) (args []string, err error) {
	args, err = a.buildCommonRule(rule)
	if err != nil {
		return
	}
	_args, _err := a.buildStateRule(rule)
	if _err != nil {
		err = _err
		return
	}
	appendArgs(&args, _args)
	args = append(args, `-j`, rule.Action)
	return
}
