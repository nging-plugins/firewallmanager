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
	"github.com/admpub/once"
	"github.com/coscms/webcore/library/errorslice"
	"github.com/nging-plugins/firewallmanager/application/library/driver"
)

var backend string
var backendOnce once.Once

func GetBackend() string {
	backendOnce.Do(initBackend)
	return backend
}

func ResetBackend() {
	backendOnce.Reset()
	ResetEngine()
}

func RulesGroupByIPVersion(rules []driver.Rule) map[string][]driver.Rule {
	g := map[string][]driver.Rule{}
	for _, rule := range rules {
		if rule.IPVersion == `all` {
			if _, ok := g[`4`]; !ok {
				g[`4`] = []driver.Rule{}
			}
			if _, ok := g[`6`]; !ok {
				g[`6`] = []driver.Rule{}
			}
			g[`4`] = append(g[`4`], rule)
			g[`6`] = append(g[`6`], rule)
		} else {
			if _, ok := g[rule.IPVersion]; !ok {
				g[rule.IPVersion] = []driver.Rule{}
			}
			g[rule.IPVersion] = append(g[rule.IPVersion], rule)
		}
	}
	return g
}

func Insert(rules ...driver.Rule) (err error) {
	errs := errorslice.New()
	for _ipVer, _rules := range RulesGroupByIPVersion(rules) {
		err := Engine(_ipVer).Insert(_rules...)
		if err != nil {
			errs.Add(err)
		}
	}
	err = errs.ToError()
	return
}

func Append(rules ...driver.Rule) (err error) {
	errs := errorslice.New()
	for _ipVer, _rules := range RulesGroupByIPVersion(rules) {
		err := Engine(_ipVer).Append(_rules...)
		if err != nil {
			errs.Add(err)
		}
	}
	err = errs.ToError()
	return
}

func Update(rule driver.Rule) (err error) {
	if rule.IPVersion == `all` {
		err = Engine(`4`).Update(rule)
		if err != nil {
			return
		}
		err = Engine(`6`).Update(rule)
		return
	}
	err = Engine(rule.IPVersion).Update(rule)
	return
}

func Delete(rules ...driver.Rule) (err error) {
	errs := errorslice.New()
	for _ipVer, _rules := range RulesGroupByIPVersion(rules) {
		err := Engine(_ipVer).Delete(_rules...)
		if err != nil {
			errs.Add(err)
		}
	}
	err = errs.ToError()
	return err
}

func AsWhitelist(ipVersion, table, chain string) (err error) {
	if ipVersion == `all` {
		err = Engine(`4`).AsWhitelist(table, chain)
		if err != nil {
			return
		}
		err = Engine(`6`).AsWhitelist(table, chain)
	} else {
		err = Engine(ipVersion).AsWhitelist(table, chain)
	}
	return err
}

func Clear(ipVersion string) (err error) {
	if ipVersion == `all` {
		err = Engine(`4`).Clear()
		if err != nil {
			return
		}
		err = Engine(`6`).Clear()
	} else {
		err = Engine(ipVersion).Clear()
	}
	return err
}

func AddDefault(ipVersion string) (err error) {
	if ipVersion == `all` {
		err = Engine(`4`).AddDefault()
		if err != nil {
			return
		}
		err = Engine(`6`).AddDefault()
	} else {
		err = Engine(ipVersion).AddDefault()
	}
	return err
}

func FindPositionByID(ipVersion, table, chain string, id uint) (uint, error) {
	return Engine(ipVersion).FindPositionByID(table, chain, id)
}

func ClearSet(ipVersion, table, set string) error {
	return Engine(ipVersion).ClearSet(table, set)
}

// Unban如果不指定ip则代表清空所有黑名单
func Unban(ipVersion string, ips ...string) error {
	eng := Engine(ipVersion)
	return eng.Unban(ips...)
}

// UnbanDynamic如果不指定ip则代表清空所有黑名单
func UnbanDynamic(ipVersion string, ips ...string) error {
	eng := Engine(ipVersion)
	if len(ips) == 0 {
		return eng.ClearSet(`nging_dynamic_ip`+ipVersion, `set`+ipVersion)
	}
	var err error
	for _, ipStr := range ips {
		err = eng.DeleteElementInSet(`nging_dynamic_ip`+ipVersion, `set`+ipVersion, ipStr)
		if err != nil {
			break
		}
	}
	return err
}
