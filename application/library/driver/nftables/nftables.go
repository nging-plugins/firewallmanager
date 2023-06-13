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
	"github.com/admpub/nftablesutils"
	"github.com/admpub/nftablesutils/biz"
	ruleutils "github.com/admpub/nftablesutils/rule"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/nging-plugins/firewallmanager/application/library/driver"
)

var _ driver.Driver = (*NFTables)(nil)

func New(family nftables.TableFamily) (*NFTables, error) {
	cfg := biz.Config{
		Enabled:       true,
		DefaultPolicy: `accept`,
		TablePrefix:   `nging_`,
		TrustPorts:    []uint16{},
	}
	t := &NFTables{
		TableFamily: family,
		cfg:         &cfg,
		NFTables:    biz.New(family, cfg, nil),
	}
	err := t.Init()
	if err == nil {
		err = t.Do(t.ApplyBase)
	}
	return t, err
}

type NFTables struct {
	TableFamily nftables.TableFamily
	cfg         *biz.Config
	*biz.NFTables
}

func (a *NFTables) ruleFrom(rule *driver.Rule) []expr.Any {
	if len(rule.Type) == 0 {
		//rule.Type = `filter`
	}
	if len(rule.Protocol) == 0 {
		//rule.Protocol = `tcp`
	}
	if len(rule.Direction) == 0 {
		//rule.Direction = `input`
	}
	args := nftablesutils.JoinExprs(nftablesutils.SetProtoTCP())
	if len(rule.Interface) > 0 {
		args = args.Add(nftablesutils.SetIIF(rule.Interface)...) // 只能用于 PREROUTING、INPUT、FORWARD
	} else if len(rule.Outerface) > 0 {
		args = args.Add(nftablesutils.SetOIF(rule.Outerface)...) // 只能用于 FORWARD、OUTPUT、POSTROUTING
	}
	// if len(rule.RemoteIP) > 0 {
	// 	if strings.Contains(rule.RemoteIP, `-`) {
	// 		args = append(args, `-m`, `iprange`)
	// 		args = append(args, `--src-range`, rule.RemoteIP)
	// 	} else {
	// 		args = append(args, `-s`, rule.RemoteIP)
	// 	}
	// } else if len(rule.LocalIP) > 0 {
	// 	if strings.Contains(rule.LocalIP, `-`) {
	// 		args = append(args, `-m`, `iprange`)
	// 		args = append(args, `--dst-range`, rule.LocalIP)
	// 	} else {
	// 		args = append(args, `-d`, rule.LocalIP)
	// 	}
	// }
	// if len(rule.RemotePort) > 0 {
	// 	if strings.Contains(rule.RemotePort, `,`) {
	// 		args = append(args, `-m`, `multiport`)
	// 		args = append(args, `--sports`, rule.RemotePort)
	// 	} else {
	// 		rule.RemotePort = strings.ReplaceAll(rule.RemotePort, `-`, `:`)
	// 		args = append(args, `--sport`, rule.RemotePort) // 支持用“:”指定端口范围，例如 “22:25” 指端口 22-25，或者 “:22” 指端口 0-22 或者 “22:” 指端口 22-65535
	// 	}
	// } else if len(rule.LocalPort) > 0 {
	// 	if strings.Contains(rule.LocalPort, `,`) {
	// 		args = append(args, `-m`, `multiport`)
	// 		args = append(args, `--dports`, rule.LocalPort)
	// 	} else {
	// 		rule.LocalPort = strings.ReplaceAll(rule.LocalPort, `-`, `:`)
	// 		args = args.Add(nftablesutils.DestinationPort(defaultRegister))
	// 		args = args.Add(nftablesutils.SetPortRange(rule.Outerface)...)
	// 		args = append(args, `--dport`, rule.LocalPort)
	// 	}
	// }
	// if len(rule.State) > 0 {
	// 	args = args.Add(nftablesutils.SetPortRange(rule.Outerface)...)
	// 	args = append(args, `-m`, `state`)
	// 	args = append(args, `--state`)
	// 	states := strings.SplitN(rule.State, ` `, 2)
	// 	if len(states) != 2 {
	// 		//args = append(args, TCPFlagALL, rule.State)
	// 	} else {
	// 		args = append(args, states...)
	// 	}
	// }
	switch rule.Action {
	case `accept`:
		args = args.Add(nftablesutils.Accept())
	case `drop`:
		args = args.Add(nftablesutils.Drop())
	case `reject`:
		args = args.Add(nftablesutils.Reject())
	default:
		args = args.Add(nftablesutils.Drop())
	}
	return args
}

func (a *NFTables) Enabled(on bool) error {
	return driver.ErrUnsupported
}

func (a *NFTables) Reset() error {
	return driver.ErrUnsupported
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

func (a *NFTables) NewFilterRuleTarget(chain ...*nftables.Chain) ruleutils.RuleTarget {
	var c *nftables.Chain
	if len(chain) > 0 {
		c = chain[0]
	}
	if c == nil {
		c = a.NFTables.ChainInput()
	}
	return ruleutils.New(a.NFTables.TableFilter(), c)
}

func (a *NFTables) NewNATRuleTarget(chain ...*nftables.Chain) ruleutils.RuleTarget {
	var c *nftables.Chain
	if len(chain) > 0 {
		c = chain[0]
	}
	if c == nil {
		c = a.NFTables.ChainPostrouting()
	}
	return ruleutils.New(a.NFTables.TableNAT(), c)
}

func (a *NFTables) Insert(pos int, rule *driver.Rule) error {
	ruleTarget := a.NewFilterRuleTarget()
	id := binaryutil.BigEndian.PutUint64(uint64(rule.ID))
	exprs := a.ruleFrom(rule)
	ruleData := ruleutils.NewData(id, exprs)
	return a.NFTables.Do(func(conn *nftables.Conn) error {
		_, err := ruleTarget.Insert(conn, ruleData)
		if err != nil {
			return err
		}
		return conn.Flush()
	})
}

func (a *NFTables) Append(rule *driver.Rule) error {
	ruleTarget := a.NewFilterRuleTarget()
	id := binaryutil.BigEndian.PutUint64(uint64(rule.ID))
	exprs := a.ruleFrom(rule)
	ruleData := ruleutils.NewData(id, exprs)
	return a.NFTables.Do(func(conn *nftables.Conn) error {
		_, err := ruleTarget.Add(conn, ruleData)
		if err != nil {
			return err
		}
		return conn.Flush()
	})
}

func (a *NFTables) AsWhitelist(tableName, chainName string) error {
	// a.cfg.DefaultPolicy = `drop`
	// return a.NFTables.Do(func(conn *nftables.Conn) error {
	// 	conn.FlushTable(a.NFTables.TableFilter())
	// 	// reapply
	// 	return conn.Flush()
	// })
	return driver.ErrUnsupported
}

// Update update rulespec in specified table/chain
func (a *NFTables) Update(pos int, rule *driver.Rule) error {
	ruleTarget := a.NewFilterRuleTarget()
	id := binaryutil.BigEndian.PutUint64(uint64(rule.ID))
	exprs := a.ruleFrom(rule)
	ruleData := ruleutils.NewData(id, exprs)
	return a.NFTables.Do(func(conn *nftables.Conn) error {
		_, _, _, err := ruleTarget.Update(conn, []ruleutils.RuleData{ruleData})
		if err != nil {
			return err
		}
		return conn.Flush()
	})
}

func (a *NFTables) Delete(rule *driver.Rule) error {
	ruleTarget := a.NewFilterRuleTarget()
	id := binaryutil.BigEndian.PutUint64(uint64(rule.ID))
	exprs := a.ruleFrom(rule)
	ruleData := ruleutils.NewData(id, exprs)
	return a.NFTables.Do(func(conn *nftables.Conn) error {
		_, err := ruleTarget.Delete(conn, ruleData)
		if err != nil {
			return err
		}
		return conn.Flush()
	})
}

func (a *NFTables) Exists(rule *driver.Rule) (bool, error) {
	ruleTarget := a.NewFilterRuleTarget()
	id := binaryutil.BigEndian.PutUint64(uint64(rule.ID))
	exprs := a.ruleFrom(rule)
	ruleData := ruleutils.NewData(id, exprs)
	var exists bool
	err := a.NFTables.Do(func(conn *nftables.Conn) (err error) {
		exists, err = ruleTarget.Exists(conn, ruleData)
		return
	})
	return exists, err
}

func (a *NFTables) Stats(tableName, chainName string) ([]map[string]string, error) {
	var result []map[string]string
	// ruleTarget := a.NewFilterRuleTarget()
	// err := a.NFTables.Do(func(conn *nftables.Conn) error {
	// 	rules, err := ruleTarget.List(conn)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	for _, rule := range rules {
	// 		result = append(result, map[string]string{
	// 			`id`: string(rule.UserData),
	// 		})
	// 	}
	// 	return err
	// })
	return result, driver.ErrUnsupported
}

func (a *NFTables) List(tableName, chainName string) ([]*driver.Rule, error) {
	var rules []*driver.Rule
	var ipVersion string
	switch a.TableFamily {
	case nftables.TableFamilyIPv4:
		ipVersion = `4`
	case nftables.TableFamilyIPv6:
		ipVersion = `6`
	}
	ruleTarget := a.NewFilterRuleTarget()
	err := a.NFTables.Do(func(conn *nftables.Conn) error {
		rows, err := ruleTarget.List(conn)
		if err != nil {
			return err
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
		return err
	})
	return rules, err
}
