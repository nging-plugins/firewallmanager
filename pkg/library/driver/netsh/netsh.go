package netsh

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"

	"github.com/admpub/go-iptables/iptables"
	"github.com/nging-plugins/firewallmanager/pkg/library/driver"
)

func New() (*NetSH, error) {
	t := &NetSH{
		path: `netsh`,
	}
	return t, nil
}

type NetSH struct {
	path string
}

func (a *NetSH) RuleFrom(rule *driver.Rule) []string {
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
	return []string{
		fmt.Sprintf(`name=%q`, rule.Name),
		fmt.Sprintf(`dir=%s`, direction),
		fmt.Sprintf(`action=%s`, action),
		fmt.Sprintf(`protocol=%s`, rule.Protocol),
		fmt.Sprintf(`localport=%s`, rule.LocalPort),
	}
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

func (a *NetSH) Insert(pos int, rule *driver.Rule) error {
	rulespec := []string{`firewall`, `add`, `rule`}
	rulespec = append(rulespec, a.RuleFrom(rule)...)
	return a.run(rulespec, nil)
}

func (a *NetSH) Append(rule *driver.Rule) error {
	rulespec := []string{`firewall`, `add`, `rule`}
	rulespec = append(rulespec, a.RuleFrom(rule)...)
	return a.run(rulespec, nil)
}

func (a *NetSH) Delete(rule *driver.Rule) error {
	rulespec := []string{`firewall`, `delete`, `rule`}
	rulespec = append(rulespec, a.RuleFrom(rule)...)
	return a.run(rulespec, nil)
}

func (a *NetSH) Exists(rule *driver.Rule) (bool, error) {
	return false, driver.ErrUnsupported
}

func (a *NetSH) List(table, chain string) ([]iptables.Stat, error) {
	rulespec := []string{`firewall`, `show`, `rule`}
	rulespec = append(rulespec, `name=all`)
	var stdout bytes.Buffer
	err := a.run(rulespec, &stdout)
	return nil, err
}

func (a *NetSH) run(args []string, stdout io.Writer) error {
	var stderr bytes.Buffer
	cmd := exec.Cmd{
		Path:   a.path,
		Args:   append([]string{`advfirewall`}, args...),
		Stdout: stdout,
		Stderr: &stderr,
	}

	if err := cmd.Run(); err != nil {
		switch e := err.(type) {
		case *exec.ExitError:
			return e
		default:
			return err
		}
	}
	return nil
}
