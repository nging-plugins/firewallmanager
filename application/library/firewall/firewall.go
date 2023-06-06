package firewall

import (
	"github.com/nging-plugins/firewallmanager/application/library/driver"
	"github.com/webx-top/echo"
)

var IPVersions = echo.NewKVData().Add(`4`, `IPv4`).Add(`6`, `IPv6`)

func Insert(pos int, rule *driver.Rule) (err error) {
	if rule.IPVersion == `all` {
		err = Engine(`4`).Insert(pos, rule)
		if err != nil {
			return
		}
		err = Engine(`6`).Insert(pos, rule)
		return
	}
	err = Engine(rule.IPVersion).Insert(pos, rule)
	return
}

func Update(pos int, rule *driver.Rule) (err error) {
	if rule.IPVersion == `all` {
		err = Engine(`4`).Update(pos, rule)
		if err != nil {
			return
		}
		err = Engine(`6`).Update(pos, rule)
		return
	}
	err = Engine(rule.IPVersion).Update(pos, rule)
	return
}

func Delete(rule *driver.Rule) (err error) {
	if rule.IPVersion == `all` {
		err = Engine(`4`).Delete(rule)
		if err != nil {
			return
		}
		err = Engine(`6`).Delete(rule)
	} else {
		err = Engine(rule.IPVersion).Delete(rule)
	}
	return err
}
