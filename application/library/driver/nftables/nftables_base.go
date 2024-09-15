package nftables

import (
	"context"
	"fmt"
	"strconv"

	"github.com/admpub/nftablesutils"
	"github.com/admpub/nftablesutils/biz"
	ruleutils "github.com/admpub/nftablesutils/rule"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/nging-plugins/firewallmanager/application/library/cmdutils"
	"github.com/nging-plugins/firewallmanager/application/library/driver"
	"github.com/webx-top/echo/param"
)

// documention: https://wiki.nftables.org/wiki-nftables/index.php/Simple_rule_management
type Base struct {
	TableFamily          nftables.TableFamily
	cfg                  *biz.Config
	bin                  string
	tBlacklistFilter     *nftables.Table
	cBlacklistInput      *nftables.Chain
	filterSetBlacklistIP *nftables.Set
	*biz.NFTables
}

var blacklist = []byte(`blacklist`)

func (a *Base) blacklistRules(c *nftables.Conn) error {
	rules, err := c.GetRules(a.tBlacklistFilter, a.cBlacklistInput)
	if err != nil {
		return err
	}
	if findRuleByID(blacklist, rules, 0) != nil {
		return nil
	}
	exprs := make([]expr.Any, 0, 3)
	if a.isIPv4() {
		exprs = append(exprs, nftablesutils.SetSAddrSet(a.filterSetBlacklistIP)...)
	} else {
		exprs = append(exprs, nftablesutils.SetSAddrIPv6Set(a.filterSetBlacklistIP)...)
	}
	exprs = append(exprs, nftablesutils.Reject())
	rule := &nftables.Rule{
		Table:    a.tBlacklistFilter,
		Chain:    a.cBlacklistInput,
		Exprs:    exprs,
		UserData: blacklist,
	}
	c.AddRule(rule)
	return nil
}

func (a *Base) initBlacklist() {
	a.tBlacklistFilter = a.TableFilter()
	a.cBlacklistInput = a.ChainInput()
	a.filterSetBlacklistIP = a.FilterSetBlacklistIP()
}

func (a *Base) isIPv4() bool {
	return a.TableFamily == nftables.TableFamilyIPv4
}

func (a *Base) ListSets(table, set string, startOffset, limit uint) (rows []cmdutils.RowInfo, hasMore bool, offset uint, err error) {
	//nft --handle list set test_filter trust_ipset
	return cmdutils.RecvCmdOutputs(startOffset, limit, a.bin, []string{`--handle`, `list`, `set`, a.getTableFamilyString(), table, set}, LineParser)
}

func (a *Base) getTableFamilyString() string {
	var family string
	if a.isIPv4() {
		family = `ip`
	} else {
		family = `ip6`
	}
	return family
}

func (a *Base) ListChainRules(table, chain string, startOffset, limit uint) (rows []cmdutils.RowInfo, hasMore bool, offset uint, err error) {
	//nft --handle list chain test_filter input
	return cmdutils.RecvCmdOutputs(startOffset, limit, a.bin, []string{`--handle`, `list`, `chain`, a.getTableFamilyString(), table, chain}, LineParser)
}

func (a *Base) DeleteElementInSet(table, set, element string) (err error) {
	//nft delete element global ipv4_ad { 192.168.1.5 }
	//element = com.AddCSlashes(element, ';')
	err = cmdutils.RunCmd(context.Background(), a.bin, []string{
		`delete`, `element`, a.getTableFamilyString(), table, set, `{ ` + element + ` }`,
	}, nil)
	return
}

// Unban removing ip from backlist.
func (a *Base) Unban(ipAddresses ...string) error {
	if len(ipAddresses) == 0 {
		return a.ClearSet(a.tBlacklistFilter.Name, a.filterSetBlacklistIP.Name)
	}
	var err error
	for _, ipStr := range ipAddresses {
		err = a.DeleteElementInSet(a.tBlacklistFilter.Name, a.filterSetBlacklistIP.Name, ipStr)
		if err != nil {
			break
		}
	}
	return err
}

func (a *Base) DeleteElementInSetByHandleID(table, set string, handleID uint64) (err error) {
	err = cmdutils.RunCmd(context.Background(), a.bin, []string{
		`delete`, `element`, a.getTableFamilyString(), table, set,
		`handle`, strconv.FormatUint(handleID, 10),
	}, nil)
	return
}

func (a *Base) DeleteSet(table, set string) (err error) {
	//nft delete set global myset
	err = cmdutils.RunCmd(context.Background(), a.bin, []string{
		`delete`, `set`, a.getTableFamilyString(), table, set,
	}, nil)
	return
}

func (a *Base) ClearSet(table, set string) (err error) {
	//nft flush set ip nging_dynamic_ip4 set4
	err = cmdutils.RunCmd(context.Background(), a.bin, []string{
		`flush`, `set`, a.getTableFamilyString(), table, set,
	}, nil)
	return
}

func (a *Base) DeleteRuleByHandleID(table, chain string, handleID uint64) (err error) {
	//nft delete rule filter output handle 10
	err = cmdutils.RunCmd(context.Background(), a.bin, []string{
		`delete`, `rule`, a.getTableFamilyString(), table, chain,
		`handle`, strconv.FormatUint(handleID, 10),
	}, nil)
	return
}

func (a *Base) NewRuleTarget(table, chain string) (ruleutils.RuleTarget, error) {
	var t *nftables.Table
	var c *nftables.Chain
	switch table {
	case `filter`, a.TableFilter().Name:
		t = a.TableFilter()
		switch chain {
		case `INPUT`, `input`:
			c = a.ChainInput()
		case `FORWARD`, `forward`:
			c = a.ChainForward()
		case `OUTPUT`, `output`:
			c = a.ChainOutput()
		default:
			return ruleutils.RuleTarget{}, fmt.Errorf(`%w: %s (table=%v)`, driver.ErrUnsupportedChain, chain, table)
		}
	case `nat`, a.TableNAT().Name:
		t = a.TableNAT()
		switch chain {
		case `PREROUTING`, `prerouting`:
			c = a.ChainPrerouting()
		case `POSTROUTING`, `postrouting`:
			c = a.ChainPostrouting()
		default:
			return ruleutils.RuleTarget{}, fmt.Errorf(`%w: %s (table=%v)`, driver.ErrUnsupportedChain, chain, table)
		}
	default:
		return ruleutils.RuleTarget{}, fmt.Errorf(`%w: %s`, driver.ErrUnsupportedTable, table)
	}
	return ruleutils.New(t, c), nil
}

func (a *Base) FindPositionByID(table, chain string, id uint) (uint, error) {
	var position uint
	err := a.NFTables.Do(func(conn *nftables.Conn) (err error) {
		ruleTarget, err := a.NewRuleTarget(table, chain)
		if err != nil {
			return err
		}
		s := strconv.FormatUint(uint64(id), 10)
		ruleData := ruleutils.NewData([]byte(s), nil, 0)
		rule, err := ruleTarget.FindRuleByID(conn, ruleData)
		if err != nil || rule == nil {
			return err
		}
		// If you want to add a rule after the rule with handler number 8, you have to type:
		// % nft add rule filter output position 8 ip daddr 127.0.0.8 drop
		position = param.AsUint(rule.Handle)
		return nil
	})
	return position, err
}
