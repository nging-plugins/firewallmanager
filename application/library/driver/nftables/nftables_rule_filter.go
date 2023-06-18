package nftables

import (
	"github.com/admpub/nftablesutils"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"github.com/nging-plugins/firewallmanager/application/library/driver"
)

func (a *NFTables) ruleFilterFrom(c *nftables.Conn, rule *driver.Rule) (args nftablesutils.Exprs, err error) {
	args, err = a.buildCommonRule(c, rule)
	if err != nil {
		return
	}
	_args, _err := a.buildStateRule(c, rule)
	if _err != nil {
		return nil, _err
	}
	args = args.Add(_args...)
	switch rule.Action {
	case `accept`, `ACCEPT`:
		args = args.Add(nftablesutils.Accept())
	case `drop`, `DROP`:
		args = args.Add(nftablesutils.ExprCounter())
		args = args.Add(nftablesutils.Drop())
	case `reject`, `REJECT`:
		args = args.Add(nftablesutils.ExprCounter())
		args = args.Add(nftablesutils.Reject())
	case `log`, `LOG`:
		args = args.Add(&expr.Log{
			Level: expr.LogLevelAlert,
			Flags: expr.LogFlagsNFLog, //expr.LogFlagsIPOpt | expr.LogFlagsTCPOpt,
			Key:   1 << unix.NFTA_LOG_PREFIX,
			Data:  []byte(`nging_`),
		})
	default:
		args = args.Add(nftablesutils.ExprCounter())
		args = args.Add(nftablesutils.Drop())
	}
	return args, nil
}
