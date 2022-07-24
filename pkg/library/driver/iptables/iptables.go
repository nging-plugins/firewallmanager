package iptables

import (
	"errors"
	"os/exec"
	"strings"

	"github.com/admpub/go-iptables/iptables"
	"github.com/admpub/packer"
	"github.com/nging-plugins/firewallmanager/pkg/library/driver"
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
	table := rule.Type
	chain := rule.Direction
	rulespec := a.RuleFrom(rule)
	return a.IPTables.Insert(table, chain, pos, rulespec...)
}

func (a *IPTables) Append(rule *driver.Rule) error {
	table := rule.Type
	chain := rule.Direction
	rulespec := a.RuleFrom(rule)
	return a.IPTables.AppendUnique(table, chain, rulespec...)
}

func (a *IPTables) Delete(rule *driver.Rule) error {
	table := rule.Type
	chain := rule.Direction
	rulespec := a.RuleFrom(rule)
	return a.IPTables.DeleteIfExists(table, chain, rulespec...)
}

func (a *IPTables) Exists(rule *driver.Rule) (bool, error) {
	table := rule.Type
	chain := rule.Direction
	rulespec := a.RuleFrom(rule)
	return a.IPTables.Exists(table, chain, rulespec...)
}

func (a *IPTables) List(table, chain string) ([]iptables.Stat, error) {
	return a.IPTables.StructuredStats(table, chain)
}
