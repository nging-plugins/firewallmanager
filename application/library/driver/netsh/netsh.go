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

// Package netsh for windows
package netsh

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/nging-plugins/firewallmanager/application/library/driver"
)

var _ driver.Driver = (*NetSH)(nil)

func New() (*NetSH, error) {
	t := &NetSH{
		path: `netsh`,
	}
	return t, nil
}

type NetSH struct {
	path string
}

func (a *NetSH) ruleFrom(rule *driver.Rule) ([]string, error) {
	action := `block`
	switch rule.Action {
	case `ACCEPT`:
		action = `allow`
	}
	direction := `in`
	switch rule.Direction {
	case `OUTPUT`:
		direction = `out`
	}
	localIP := `any`
	remoteIP := `any`
	if len(rule.LocalIP) > 0 {
		localIP = rule.LocalIP
	}
	if len(rule.RemoteIP) > 0 {
		remoteIP = rule.RemoteIP
	}
	return []string{
		fmt.Sprintf(`name=%q`, rule.Name),
		fmt.Sprintf(`dir=%s`, direction),
		fmt.Sprintf(`action=%s`, action),
		fmt.Sprintf(`protocol=%s`, rule.Protocol),
		fmt.Sprintf(`localport=%s`, rule.LocalPort),
		fmt.Sprintf(`localip=%s`, localIP),
		fmt.Sprintf(`remoteip=%s`, remoteIP),
	}, nil
}

func (a *NetSH) Enabled(on bool) error {
	rulespec := []string{`set`, `allprofiles`, `state`}
	if on {
		rulespec = append(rulespec, `on`)
	} else {
		rulespec = append(rulespec, `off`)
	}
	return a.run(rulespec, nil)
}

func (a *NetSH) Reset() error {
	rulespec := []string{`reset`}
	return a.run(rulespec, nil)
}

func (a *NetSH) Import(wfwFile string) error {
	rulespec := []string{`import`, fmt.Sprintf(`%q`, wfwFile)}
	return a.run(rulespec, nil)
}

func (a *NetSH) Export(wfwFile string) error {
	rulespec := []string{`export`, fmt.Sprintf(`%q`, wfwFile)}
	return a.run(rulespec, nil)
}

func (a *NetSH) Insert(rules ...driver.Rule) (err error) {
	for _, rule := range rules {
		copyRule := rule
		var _rulespec []string
		_rulespec, err = a.ruleFrom(&copyRule)
		if err != nil {
			return
		}
		rulespec := []string{`firewall`, `add`, `rule`}
		rulespec = append(rulespec, _rulespec...)
		err = a.run(rulespec, nil)
		if err != nil {
			break
		}
	}
	return
}

func (a *NetSH) AsWhitelist(table, chain string) error {
	return nil
}

func (a *NetSH) Append(rules ...driver.Rule) (err error) {
	for _, rule := range rules {
		copyRule := rule
		var _rulespec []string
		_rulespec, err = a.ruleFrom(&copyRule)
		if err != nil {
			return
		}
		rulespec := []string{`firewall`, `add`, `rule`}
		rulespec = append(rulespec, _rulespec...)
		err = a.run(rulespec, nil)
		if err != nil {
			break
		}
	}
	return
}

func (a *NetSH) Update(rule driver.Rule) error {
	//netsh advfirewall firewall set rule name="文件和打印机共享(回显请求 - ICMPv4-In)" new enable=yes action=allow localip=any remoteip=any
	rulespec := []string{`firewall`, `set`, `rule`}
	rules, err := a.ruleFrom(&rule)
	if err != nil {
		return err
	}
	newRules := append([]string{rules[0]}, `new`)
	newRules = append(newRules, rules[1:]...)
	rulespec = append(rulespec, newRules...)
	return a.run(rulespec, nil)
}

func (a *NetSH) Delete(rules ...driver.Rule) (err error) {
	for _, rule := range rules {
		copyRule := rule
		var _rulespec []string
		_rulespec, err = a.ruleFrom(&copyRule)
		if err != nil {
			return
		}
		rulespec := []string{`firewall`, `delete`, `rule`}
		rulespec = append(rulespec, _rulespec...)
		err = a.run(rulespec, nil)
		if err != nil {
			break
		}
	}
	return
}

func (a *NetSH) Exists(rule driver.Rule) (bool, error) {
	rulespec := []string{`firewall`, `show`, `rule`}
	rulespec = append(rulespec, fmt.Sprintf(`name=%q`, rule.Name))
	var stdout bytes.Buffer
	err := a.run(rulespec, &stdout)
	if err != nil {
		return false, err
	}
	return strings.Contains(stdout.String(), rule.Name), nil
}

func (a *NetSH) Stats(table, chain string) ([]map[string]string, error) {
	//TODO
	return nil, driver.ErrUnsupported
}

func (a *NetSH) List(table, chain string) ([]*driver.Rule, error) {
	// netsh advfirewall firewall show rule name=all dir=in type=dynamic status=enabled
	// dir (direction) - in or out
	// status - enabled or disabled
	rulespec := []string{`firewall`, `show`, `rule`}
	rulespec = append(rulespec, `name=all`)
	var stdout bytes.Buffer
	err := a.run(rulespec, &stdout)
	//TODO
	return nil, err
}

func (a *NetSH) run(args []string, stdout io.Writer) error {
	return driver.RunCmd(a.path, append([]string{`advfirewall`}, args...), stdout)
}
