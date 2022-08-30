package iptables

import (
	"errors"
	"os/exec"
	"strings"

	"github.com/admpub/go-iptables/iptables"
	parser "github.com/admpub/iptables_parser"
	"github.com/admpub/log"
	"github.com/admpub/packer"
	"github.com/nging-plugins/firewallmanager/application/library/driver"
	"github.com/webx-top/com"
)

func New() (*IPTables, error) {
	t := &IPTables{
		IPProtocol: ProtocolIPv4,
	}
	var err error
	t.IPTables, err = iptables.New(iptables.IPFamily(t.IPProtocol))
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			err = packer.Install(`iptables`)
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
	// if len(rule.Interface) > 0 {
	// 	args = append(args, `-i`, rule.Interface)
	// }
	if len(rule.RemoteIP) > 0 {
		if strings.Contains(rule.RemoteIP, `-`) {
			args = append(args, `-m`, `iprange`)
			args = append(args, `--src-range`, rule.RemoteIP)
		} else {
			args = append(args, `-s`, rule.RemoteIP)
		}
	} else if len(rule.LocalIP) > 0 {
		args = append(args, `-d`, rule.LocalIP)
	}
	if len(rule.RemotePort) > 0 {
		if strings.Contains(rule.RemotePort, `,`) {
			args = append(args, `-m`, `multiport`)
		}
		args = append(args, `--sport`, rule.RemotePort)
	} else if len(rule.LocalPort) > 0 {
		if strings.Contains(rule.LocalPort, `,`) {
			args = append(args, `-m`, `multiport`)
		}
		args = append(args, `--dport`, rule.LocalPort)
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
	return driver.RunCmd(`iptables-restore`, []string{`<`, wfwFile}, nil)
}

func (a *IPTables) Export(wfwFile string) error {
	return driver.RunCmd(`iptables-save`, []string{`>`, wfwFile}, nil)
}

func (a *IPTables) Insert(pos int, rule *driver.Rule) error {
	rulespec := a.RuleFrom(rule)
	table := rule.Type
	chain := rule.Direction
	return a.IPTables.Insert(table, chain, pos, rulespec...)
}

func (a *IPTables) Append(rule *driver.Rule) error {
	rulespec := a.RuleFrom(rule)
	table := rule.Type
	chain := rule.Direction
	return a.IPTables.AppendUnique(table, chain, rulespec...)
}

func (a *IPTables) Delete(rule *driver.Rule) error {
	rulespec := a.RuleFrom(rule)
	table := rule.Type
	chain := rule.Direction
	return a.IPTables.DeleteIfExists(table, chain, rulespec...)
}

func (a *IPTables) Exists(rule *driver.Rule) (bool, error) {
	rulespec := a.RuleFrom(rule)
	table := rule.Type
	chain := rule.Direction
	return a.IPTables.Exists(table, chain, rulespec...)
}

func (a *IPTables) List(table, chain string) ([]*driver.Rule, error) {
	rows, err := a.IPTables.List(table, chain)
	if err != nil {
		return nil, err
	}
	var rules []*driver.Rule
	for _, row := range rows {
		tr, err := parser.NewFromString(row)
		if err != nil {
			log.Errorf("[iptables] failed to parse rule: %s: %v", row, err)
			continue
		}
		com.Dump(tr)
		rule := &driver.Rule{Type: table, Direction: chain}
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
		default:
			log.Debugf("[iptables] something else happend: %v", r)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}
