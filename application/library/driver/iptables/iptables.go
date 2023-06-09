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

package iptables

import (
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/admpub/go-iptables/iptables"
	parser "github.com/admpub/iptables_parser"
	"github.com/admpub/log"
	"github.com/admpub/nging/v5/application/library/errorslice"
	"github.com/admpub/packer"
	"github.com/nging-plugins/firewallmanager/application/library/driver"
)

var _ driver.Driver = (*IPTables)(nil)

func New(proto iptables.Protocol, autoInstall bool) (*IPTables, error) {
	t := &IPTables{
		IPProtocol: proto,
	}
	var err error
	t.IPTables, err = iptables.New(iptables.IPFamily(t.IPProtocol))
	if err != nil && autoInstall && errors.Is(err, exec.ErrNotFound) {
		err = packer.Install(`iptables`)
		if err == nil {
			t.IPTables, err = iptables.New(iptables.IPFamily(t.IPProtocol))
		}
	}
	return t, err
}

type IPTables struct {
	IPProtocol iptables.Protocol
	*iptables.IPTables
}

func (a *IPTables) RuleFrom(rule *driver.Rule) []string {
	if len(rule.Type) == 0 {
		rule.Type = TableFilter
	}
	if len(rule.Protocol) == 0 {
		rule.Protocol = ProtocolTCP
	}
	if len(rule.Direction) == 0 {
		rule.Direction = ChainInput
	}
	args := []string{
		`-p`, rule.Protocol,
	}
	if len(rule.Interface) > 0 && rule.Interface != `*` {
		args = append(args, `-i`, rule.Interface) // 只能用于 PREROUTING、INPUT、FORWARD
	} else if len(rule.Outerface) > 0 && rule.Outerface != `*` {
		args = append(args, `-o`, rule.Outerface) // 只能用于 FORWARD、OUTPUT、POSTROUTING
	}
	if len(rule.RemoteIP) > 0 && rule.RemoteIP != `0.0.0.0/0` {
		if strings.Contains(rule.RemoteIP, `-`) {
			args = append(args, `-m`, `iprange`)
			args = append(args, `--src-range`, rule.RemoteIP)
		} else {
			args = append(args, `-s`, rule.RemoteIP)
		}
	} else if len(rule.LocalIP) > 0 && rule.LocalIP != `0.0.0.0/0` {
		if strings.Contains(rule.LocalIP, `-`) {
			args = append(args, `-m`, `iprange`)
			args = append(args, `--dst-range`, rule.LocalIP)
		} else {
			args = append(args, `-d`, rule.LocalIP)
		}
	}
	if len(rule.RemotePort) > 0 {
		if strings.Contains(rule.RemotePort, `,`) {
			args = append(args, `-m`, `multiport`)
			args = append(args, `--sports`, rule.RemotePort)
		} else {
			rule.RemotePort = strings.ReplaceAll(rule.RemotePort, `-`, `:`)
			args = append(args, `--sport`, rule.RemotePort) // 支持用“:”指定端口范围，例如 “22:25” 指端口 22-25，或者 “:22” 指端口 0-22 或者 “22:” 指端口 22-65535
		}
	} else if len(rule.LocalPort) > 0 {
		if strings.Contains(rule.LocalPort, `,`) {
			args = append(args, `-m`, `multiport`)
			args = append(args, `--dports`, rule.LocalPort)
		} else {
			rule.LocalPort = strings.ReplaceAll(rule.LocalPort, `-`, `:`)
			args = append(args, `--dport`, rule.LocalPort)
		}
	}
	if len(rule.State) > 0 {
		args = append(args, `-m`, `state`)
		args = append(args, `--state`)
		states := strings.SplitN(rule.State, ` `, 2)
		if len(states) != 2 {
			args = append(args, TCPFlagALL, rule.State)
		} else {
			args = append(args, states...)
		}
	}
	args = append(args, `-j`, rule.Action)
	return args
}

func (a *IPTables) Enabled(on bool) error {
	return driver.ErrUnsupported
}

func (a *IPTables) Reset() error {
	return driver.ErrUnsupported
}

func (a *IPTables) Import(wfwFile string) error {
	var restoreBin string
	switch a.IPProtocol {
	case ProtocolIPv6:
		restoreBin = `ip6tables-restore`
	case ProtocolIPv4:
		fallthrough
	default:
		restoreBin = `iptables-restore`
	}
	return driver.RunCmd(restoreBin, []string{`<`, wfwFile}, nil)
}

func (a *IPTables) Export(wfwFile string) error {
	var saveBin string
	switch a.IPProtocol {
	case ProtocolIPv6:
		saveBin = `ip6tables-save`
	case ProtocolIPv4:
		fallthrough
	default:
		saveBin = `iptables-save`
	}
	return driver.RunCmd(saveBin, []string{`>`, wfwFile}, nil)
}

func (a *IPTables) Insert(pos int, rule *driver.Rule) error {
	if pos <= 0 {
		pos = 1
	}
	rulespec := a.RuleFrom(rule)
	table := rule.Type
	chain := rule.Direction
	return a.IPTables.InsertUnique(table, chain, pos, rulespec...)
}

func (a *IPTables) Append(rule *driver.Rule) error {
	rulespec := a.RuleFrom(rule)
	table := rule.Type
	chain := rule.Direction
	return a.IPTables.AppendUnique(table, chain, rulespec...)
}

func (a *IPTables) AsWhitelist(table, chain string) error {
	return a.IPTables.AppendUnique(table, chain, `-j`, TargetReject)
}

// Update update rulespec in specified table/chain
func (a *IPTables) Update(pos int, rule *driver.Rule) error {
	if pos <= 0 {
		return driver.ErrInvalidRuleNumber
	}
	rulespec := a.RuleFrom(rule)
	table := rule.Type
	chain := rule.Direction
	args := []string{"-t", table, "-R", chain}
	args = append(args, strconv.Itoa(pos))
	cmd := append(args, rulespec...)
	return a.IPTables.Run(cmd...)
}

func (a *IPTables) Delete(rule *driver.Rule) error {
	var rulespec []string
	if rule.Number > 0 {
		rulespec = append(rulespec, strconv.FormatUint(rule.Number, 10))
	} else {
		rulespec = a.RuleFrom(rule)
	}
	table := rule.Type
	chain := rule.Direction
	return a.IPTables.Delete(table, chain, rulespec...)
}

func (a *IPTables) Exists(rule *driver.Rule) (bool, error) {
	rulespec := a.RuleFrom(rule)
	table := rule.Type
	chain := rule.Direction
	return a.IPTables.Exists(table, chain, rulespec...)
}

func (a *IPTables) Stats(table, chain string) ([]map[string]string, error) {
	return a.IPTables.StatsWithLineNumber(table, chain)
}

func (a *IPTables) List(table, chain string) ([]*driver.Rule, error) {
	rows, err := a.IPTables.List(table, chain)
	if err != nil {
		return nil, err
	}
	errs := errorslice.New()
	var rules []*driver.Rule
	var ipVersion string
	switch a.IPProtocol {
	case ProtocolIPv6:
		ipVersion = `6`
	case ProtocolIPv4:
		fallthrough
	default:
		ipVersion = `4`
	}
	for _, row := range rows {
		tr, err := parser.NewFromString(row)
		if err != nil {
			err = fmt.Errorf("[iptables] failed to parse rule: %s: %v", row, err)
			errs.Add(err)
			continue
		}
		//pp.Println(tr)
		rule := &driver.Rule{Type: table, Direction: chain, IPVersion: ipVersion}
		switch r := tr.(type) {
		case parser.Rule:
			log.Debugf("[iptables] rule parsed: %v", r)
			rule.Direction = r.Chain
			if r.Source != nil {
				rule.RemoteIP = r.Source.Value.String()
				if r.Source.Not {
					rule.RemoteIP = `!` + rule.RemoteIP
				}
			}
			if r.Destination != nil {
				rule.LocalIP = r.Destination.Value.String()
				if r.Destination.Not {
					rule.LocalIP = `!` + rule.LocalIP
				}
			}
			if r.Protocol != nil {
				rule.Protocol = r.Protocol.Value
				if r.Protocol.Not {
					rule.Protocol = `!` + rule.Protocol
				}
			}
			if r.Jump != nil {
				rule.Action = r.Jump.Name
			}
			for _, match := range r.Matches {
				for flagKey, flagValue := range match.Flags {
					switch flagKey {
					case `destination-port`:
						rule.LocalPort = strings.Join(flagValue.Values, ` `)
					case `source-port`:
						rule.RemotePort = strings.Join(flagValue.Values, ` `)
					}
				}
			}
		case parser.Policy:
			log.Debugf("[iptables] policy parsed: %v", r)
			// if r.UserDefined == nil || !*r.UserDefined {
			// 	continue
			// }
			rule.Action = r.Action
			rule.Direction = r.Chain
		// case parser.Comment:
		// case parser.Header:
		default:
			log.Debugf("[iptables] something else happend: %v", r)
		}
		rules = append(rules, rule)
	}
	return rules, errs.ToError()
}
