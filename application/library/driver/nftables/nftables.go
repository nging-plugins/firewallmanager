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

package nftables

import (
	"strings"

	"github.com/admpub/nftablesutils/biz"
	"github.com/admpub/nging/v5/application/library/errorslice"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/nging-plugins/firewallmanager/application/library/driver"
	"github.com/webx-top/echo/param"
)

var _ driver.Driver = (*NFTables)(nil)

func New(proto nftables.TableFamily) (*NFTables, error) {
	biz.Init
	conn, err := nftables.New(nftables.AsLasting())
	if err != nil {
		return nil, err
	}
	t := &NFTables{
		TableFamily: proto,
		Conn:        conn,
	}
	return t, nil
}

type NFTables struct {
	TableFamily nftables.TableFamily
	*nftables.Conn
}

func (a *NFTables) RuleFrom(rule *driver.Rule) []string {
	if len(rule.Type) == 0 {
		//rule.Type = TableFilter
	}
	if len(rule.Protocol) == 0 {
		//rule.Protocol = ProtocolTCP
	}
	if len(rule.Direction) == 0 {
		//rule.Direction = ChainInput
	}
	args := []string{
		`-p`, rule.Protocol,
	}
	if len(rule.Interface) > 0 {
		args = append(args, `-i`, rule.Interface) // 只能用于 PREROUTING、INPUT、FORWARD
	} else if len(rule.Outerface) > 0 {
		args = append(args, `-o`, rule.Outerface) // 只能用于 FORWARD、OUTPUT、POSTROUTING
	}
	if len(rule.RemoteIP) > 0 {
		if strings.Contains(rule.RemoteIP, `-`) {
			args = append(args, `-m`, `iprange`)
			args = append(args, `--src-range`, rule.RemoteIP)
		} else {
			args = append(args, `-s`, rule.RemoteIP)
		}
	} else if len(rule.LocalIP) > 0 {
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
			//args = append(args, TCPFlagALL, rule.State)
		} else {
			args = append(args, states...)
		}
	}
	args = append(args, `-j`, rule.Action)
	return args
}

func (a *NFTables) Enabled(on bool) error {
	return driver.ErrUnsupported
}

func (a *NFTables) Reset() error {
	return driver.ErrUnsupported
}

func (a *NFTables) getTable(name string) (*nftables.Table, error) {
	tables, err := a.Conn.ListTablesOfFamily(a.TableFamily)
	if err != nil {
		return nil, err
	}
	for _, table := range tables {
		if table.Name == name {
			return table, nil
		}
	}
	table := a.Conn.AddTable(&nftables.Table{
		Family: a.TableFamily,
		Name:   name,
	})
	return table, err
}

func (a *NFTables) getChain(tableName, chainName string) (*nftables.Chain, error) {
	table, err := a.getTable(tableName)
	if err != nil {
		return nil, err
	}
	chains, err := a.Conn.ListChainsOfTableFamily(a.TableFamily)
	if err != nil {
		return nil, err
	}
	for _, chain := range chains {
		if chain.Table.Name == tableName && chain.Name == chainName {
			return chain, nil
		}
	}
	chain := a.Conn.AddChain(&nftables.Chain{
		Name:     chainName,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	})
	return chain, err
}

func (a *NFTables) Import(wfwFile string) error {
	var restoreBin string
	restoreBin = `iptables-restore`
	return driver.RunCmd(restoreBin, []string{`<`, wfwFile}, nil)
}

func (a *NFTables) Export(wfwFile string) error {
	var saveBin string
	return driver.RunCmd(saveBin, []string{`>`, wfwFile}, nil)
}

func (a *NFTables) Insert(pos int, rule *driver.Rule) error {
	if pos <= 0 {
		pos = 1
	}
	r := &nftables.Rule{}
	a.Conn.InsertRule(r)
	return a.Flush()
}

func (a *NFTables) Append(rule *driver.Rule) error {
	r := &nftables.Rule{}
	a.Conn.AddRule(r)
	return a.Flush()
}

func (a *NFTables) AsWhitelist(tableName, chainName string) error {
	chain, err := a.getChain(tableName, chainName)
	if err != nil {
		return err
	}
	r := &nftables.Rule{
		Table: chain.Table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Verdict{
				// [ immediate reg 0 drop ]
				Kind: expr.VerdictDrop,
			},
		},
	}
	a.Conn.AddRule(r)
	return a.Flush()
}

// Update update rulespec in specified table/chain
func (a *NFTables) Update(pos int, rule *driver.Rule) error {
	r := &nftables.Rule{}
	a.Conn.ReplaceRule(r)
	return a.Flush()
}

func (a *NFTables) Delete(rule *driver.Rule) error {
	r := &nftables.Rule{}
	a.Conn.DelRule(r)
	return a.Flush()
}

func (a *NFTables) Exists(rule *driver.Rule) (bool, error) {
	return false, driver.ErrUnsupported
}

func (a *NFTables) Stats(tableName, chainName string) ([]map[string]string, error) {
	chain, err := a.getChain(tableName, chainName)
	if err != nil {
		return nil, err
	}
	rows, err := a.Conn.GetRules(chain.Table, chain)
	if err != nil {
		return nil, err
	}
	result := make([]map[string]string, len(rows))
	for index, row := range rows {
		result[index] = map[string]string{
			`num`: param.AsString(row.Position),
		}
	}
	return result, nil
}

func (a *NFTables) List(tableName, chainName string) ([]*driver.Rule, error) {
	chain, err := a.getChain(tableName, chainName)
	if err != nil {
		return nil, err
	}
	rows, err := a.Conn.GetRules(chain.Table, chain)
	if err != nil {
		return nil, err
	}
	errs := errorslice.New()
	var rules []*driver.Rule
	var ipVersion string
	switch a.TableFamily {
	case nftables.TableFamilyIPv4:
		ipVersion = `4`
	case nftables.TableFamilyIPv6:
		ipVersion = `6`
	}
	for _, row := range rows {
		rule := &driver.Rule{
			Type:      tableName,
			Direction: chainName,
			IPVersion: ipVersion,
			Number:    row.Position,
		}
		rules = append(rules, rule)
	}
	return rules, errs.ToError()
}
