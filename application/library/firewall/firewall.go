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
	"github.com/nging-plugins/firewallmanager/application/library/driver"
)

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
