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
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/admpub/nftablesutils"
	"github.com/admpub/nftablesutils/biz"
	ruleutils "github.com/admpub/nftablesutils/rule"
	setutils "github.com/admpub/nftablesutils/set"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/nging-plugins/firewallmanager/application/library/driver"
	"github.com/webx-top/echo/param"
	"golang.org/x/sys/unix"
)

var _ driver.Driver = (*NFTables)(nil)

func New(proto driver.Protocol) (*NFTables, error) {
	var family nftables.TableFamily
	if proto == driver.ProtocolIPv4 {
		family = nftables.TableFamilyIPv4
	} else {
		family = nftables.TableFamilyIPv6
	}
	cfg := biz.Config{
		NetworkNamespace: ``,
		Enabled:          true,
		DefaultPolicy:    `accept`,
		TablePrefix:      `nging_`,
		TrustPorts:       []uint16{},
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

var notNumberRegexp = regexp.MustCompile(`[^\d]+`)

func (a *NFTables) isIPv4() bool {
	return a.TableFamily == nftables.TableFamilyIPv4
}

func (a *NFTables) ruleFrom(c *nftables.Conn, rule *driver.Rule) (args nftablesutils.Exprs, err error) {
	if len(rule.Type) == 0 {
		rule.Type = `filter`
	}
	if len(rule.Protocol) == 0 {
		rule.Protocol = `tcp`
	}
	if len(rule.Direction) == 0 {
		rule.Direction = `input`
	}
	args = nftablesutils.JoinExprs(nftablesutils.SetProtoTCP())
	if len(rule.Interface) > 0 {
		args = args.Add(nftablesutils.SetIIF(rule.Interface)...) // 只能用于 PREROUTING、INPUT、FORWARD
	} else if len(rule.Outerface) > 0 {
		args = args.Add(nftablesutils.SetOIF(rule.Outerface)...) // 只能用于 FORWARD、OUTPUT、POSTROUTING
	}
	if len(rule.RemoteIP) > 0 {
		if strings.Contains(rule.RemoteIP, `-`) {
			var ipSet *nftables.Set
			var elems []nftables.SetElement
			var eErr error
			if a.isIPv4() {
				ipSet = nftablesutils.GetIPv4AddrSet(a.NFTables.TableFilter())
				elems, eErr = setutils.GenerateElementsFromIPv4Address([]string{rule.RemoteIP})
			} else {
				ipSet = nftablesutils.GetIPv6AddrSet(a.NFTables.TableFilter())
				elems, eErr = setutils.GenerateElementsFromIPv6Address([]string{rule.RemoteIP})
			}
			if eErr != nil {
				err = eErr
				return
			}
			err = c.AddSet(ipSet, elems)
			if err != nil {
				return nil, err
			}
			args = args.Add(nftablesutils.SetSAddrSet(ipSet)...)
		} else {
			args = args.Add(nftablesutils.SetCIDRMatcher(nftablesutils.ExprDirectionSource, rule.RemoteIP, false)...)
		}
	} else if len(rule.LocalIP) > 0 {
		if strings.Contains(rule.LocalIP, `-`) {
			var ipSet *nftables.Set
			var elems []nftables.SetElement
			var eErr error
			if a.isIPv4() {
				ipSet = nftablesutils.GetIPv4AddrSet(a.NFTables.TableFilter())
				elems, eErr = setutils.GenerateElementsFromIPv4Address([]string{rule.LocalIP})
			} else {
				ipSet = nftablesutils.GetIPv6AddrSet(a.NFTables.TableFilter())
				elems, eErr = setutils.GenerateElementsFromIPv6Address([]string{rule.LocalIP})
			}
			if eErr != nil {
				err = eErr
				return
			}
			err = c.AddSet(ipSet, elems)
			if err != nil {
				return nil, err
			}
			args = args.Add(nftablesutils.SetSAddrSet(ipSet)...)
		} else {
			args = args.Add(nftablesutils.SetCIDRMatcher(nftablesutils.ExprDirectionDestination, rule.LocalIP, false)...)
		}
	}
	if len(rule.RemotePort) > 0 {
		if strings.Contains(rule.RemotePort, `,`) {
			ports := param.Split(rule.RemotePort, `,`).Unique().Uint16(func(_ int, v uint16) bool {
				return nftablesutils.ValidatePort(v) == nil
			})
			if len(ports) > 0 {
				portSet := nftablesutils.GetPortSet(a.NFTables.TableFilter())
				portsUint16 := make([]uint16, len(ports))
				for k, v := range ports {
					portsUint16[k] = uint16(v)
				}
				elems := nftablesutils.GetPortElems(portsUint16)
				err = c.AddSet(portSet, elems)
				if err != nil {
					return nil, err
				}
				args = args.Add(nftablesutils.SetSPortSet(portSet)...)
			}
		} else {
			ports := param.StringSlice(notNumberRegexp.Split(rule.RemotePort, -1)).Unique().Uint16(func(_ int, v uint16) bool {
				return nftablesutils.ValidatePort(v) == nil
			})

			if len(ports) > 0 {
				portsUint16 := make([]uint16, len(ports))
				for k, v := range ports {
					portsUint16[k] = uint16(v)
				}
				if len(portsUint16) >= 2 {
					err = nftablesutils.ValidatePortRange(portsUint16[0], portsUint16[1])
					if err != nil {
						return
					}
					args = args.Add(nftablesutils.SetSPortRange(portsUint16[0], portsUint16[1])...)
				} else {
					args = args.Add(nftablesutils.SetSPort(portsUint16[0])...)
				}
			}
		}
	} else if len(rule.LocalPort) > 0 {
		if strings.Contains(rule.LocalPort, `,`) {
			ports := param.Split(rule.LocalPort, `,`).Unique().Uint16(func(_ int, v uint16) bool {
				return nftablesutils.ValidatePort(v) == nil
			})
			if len(ports) > 0 {
				portSet := nftablesutils.GetPortSet(a.NFTables.TableFilter())
				portsUint16 := make([]uint16, len(ports))
				for k, v := range ports {
					portsUint16[k] = uint16(v)
				}
				elems := nftablesutils.GetPortElems(portsUint16)
				err = c.AddSet(portSet, elems)
				if err != nil {
					return nil, err
				}
				args = args.Add(nftablesutils.SetDPortSet(portSet)...)
			}
		} else {
			ports := param.StringSlice(notNumberRegexp.Split(rule.LocalPort, -1)).Unique().Uint16(func(_ int, v uint16) bool {
				return nftablesutils.ValidatePort(v) == nil
			})

			if len(ports) > 0 {
				portsUint16 := make([]uint16, len(ports))
				for k, v := range ports {
					portsUint16[k] = uint16(v)
				}
				if len(portsUint16) >= 2 {
					err = nftablesutils.ValidatePortRange(portsUint16[0], portsUint16[1])
					if err != nil {
						return
					}
					args = args.Add(nftablesutils.SetDPortRange(portsUint16[0], portsUint16[1])...)
				} else {
					args = args.Add(nftablesutils.SetDPort(portsUint16[0])...)
				}
			}
		}
	}
	if len(rule.State) > 0 {
		stateSet := nftablesutils.GetConntrackStateSet(a.NFTables.TableFilter())
		states := strings.SplitN(rule.State, ` `, 2) // "target1,target2 allow1,allow2"
		if len(states) != 2 {
			states = strings.Split(rule.State, `,`)
		} else {
			states = strings.Split(states[1], `,`)
		}
		states = param.StringSlice(states).Unique().Filter().String()
		if len(states) == 0 {
			states = []string{nftablesutils.StateNew, nftablesutils.StateEstablished}
		}
		elems := nftablesutils.GetConntrackStateSetElems(states)
		err = c.AddSet(stateSet, elems)
		if err != nil {
			return nil, err
		}
		args = args.Add(nftablesutils.SetConntrackStateSet(stateSet)...)
	}
	switch rule.Action {
	case `accept`, `ACCEPT`:
		args = args.Add(nftablesutils.Accept())
	case `drop`, `DROP`:
		args = args.Add(nftablesutils.Drop())
	case `reject`, `REJECT`:
		args = args.Add(nftablesutils.Reject())
	case `log`, `LOG`:
		args = args.Add(&expr.Log{
			Level: expr.LogLevelAlert,
			Flags: expr.LogFlagsNFLog, //expr.LogFlagsIPOpt | expr.LogFlagsTCPOpt,
			Key:   1 << unix.NFTA_LOG_PREFIX,
			Data:  []byte(`nging_`),
		})
	default:
		args = args.Add(nftablesutils.Drop())
	}
	return args, nil
}

func (a *NFTables) Enabled(on bool) error {
	return driver.ErrUnsupported
}

func (a *NFTables) Reset() error {
	return a.NFTables.Do(func(conn *nftables.Conn) error {
		conn.FlushTable(a.NFTables.TableFilter())
		conn.FlushTable(a.NFTables.TableNAT())
		return conn.Flush()
	})
}

func (a *NFTables) Import(wfwFile string) error {
	var restoreBin string
	restoreBin = `nft`
	return driver.RunCmd(restoreBin, []string{`-f`, wfwFile}, nil)
}

func (a *NFTables) Export(wfwFile string) error {
	os.MkdirAll(filepath.Dir(wfwFile), os.ModePerm)
	f, err := os.Create(wfwFile)
	if err != nil {
		return err
	}
	defer f.Close()
	err = driver.RunCmd(`nft`, []string{`list`, `ruleset`}, f)
	if err != nil {
		return err
	}
	return f.Sync()
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
	return a.NFTables.Do(func(conn *nftables.Conn) error {
		exprs, err := a.ruleFrom(conn, rule)
		if err != nil {
			return err
		}
		id := binaryutil.BigEndian.PutUint64(uint64(rule.ID))
		ruleData := ruleutils.NewData(id, exprs)
		_, err = ruleTarget.Insert(conn, ruleData)
		if err != nil {
			return err
		}
		return conn.Flush()
	})
}

func (a *NFTables) Append(rule *driver.Rule) error {
	ruleTarget := a.NewFilterRuleTarget()
	return a.NFTables.Do(func(conn *nftables.Conn) error {
		exprs, err := a.ruleFrom(conn, rule)
		if err != nil {
			return err
		}
		id := binaryutil.BigEndian.PutUint64(uint64(rule.ID))
		ruleData := ruleutils.NewData(id, exprs)
		_, err = ruleTarget.Add(conn, ruleData)
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
	return a.NFTables.Do(func(conn *nftables.Conn) error {
		exprs, err := a.ruleFrom(conn, rule)
		if err != nil {
			return err
		}
		id := binaryutil.BigEndian.PutUint64(uint64(rule.ID))
		ruleData := ruleutils.NewData(id, exprs)
		_, _, _, err = ruleTarget.Update(conn, []ruleutils.RuleData{ruleData})
		if err != nil {
			return err
		}
		return conn.Flush()
	})
}

func (a *NFTables) Delete(rule *driver.Rule) error {
	ruleTarget := a.NewFilterRuleTarget()
	return a.NFTables.Do(func(conn *nftables.Conn) error {
		exprs, err := a.ruleFrom(conn, rule)
		if err != nil {
			return err
		}
		id := binaryutil.BigEndian.PutUint64(uint64(rule.ID))
		ruleData := ruleutils.NewData(id, exprs)
		_, err = ruleTarget.Delete(conn, ruleData)
		if err != nil {
			return err
		}
		return conn.Flush()
	})
}

func (a *NFTables) Exists(rule *driver.Rule) (bool, error) {
	ruleTarget := a.NewFilterRuleTarget()
	var exists bool
	err := a.NFTables.Do(func(conn *nftables.Conn) (err error) {
		exprs, err := a.ruleFrom(conn, rule)
		if err != nil {
			return err
		}
		id := binaryutil.BigEndian.PutUint64(uint64(rule.ID))
		ruleData := ruleutils.NewData(id, exprs)
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
	if a.isIPv4() {
		ipVersion = `4`
	} else {
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
