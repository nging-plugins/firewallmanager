package iptables

import (
	"github.com/webx-top/com"

	"github.com/nging-plugins/firewallmanager/application/library/driver"
	"github.com/nging-plugins/firewallmanager/application/library/enums"
)

func (a *IPTables) ruleFilterFrom(rule *driver.Rule) (args []string, err error) {
	args, err = a.buildCommonRule(rule)
	if err != nil {
		return
	}

	if com.InSlice(`state`, enums.ChainParams[rule.Direction]) {
		_args, _err := a.buildStateRule(rule)
		if _err != nil {
			err = _err
			return
		}
		appendArgs(&args, _args)
	}
	args = append(args, `-j`, rule.Action)
	return
}