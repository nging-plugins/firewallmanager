// go:build linux

package handler

import (
	"github.com/admpub/nging/v5/application/handler"
	"github.com/admpub/nging/v5/application/library/common"
	"github.com/admpub/nging/v5/application/registry/navigate"
	"github.com/nging-plugins/firewallmanager/application/library/driver"
	"github.com/nging-plugins/firewallmanager/application/library/driver/iptables"
	"github.com/nging-plugins/firewallmanager/application/library/firewall"
	"github.com/webx-top/com"
	"github.com/webx-top/echo"
)

func init() {
	routeRegisters.Register(func(g echo.RouteRegister) {
		subG := g.Group(`/iptables`)
		subG.Route(`GET`, `/index`, ipTablesIndex)
		subG.Route(`GET`, `/delete`, ipTablesDelete)
	})
	LeftNavigate.Children.Add(-1, &navigate.Item{
		Display: true,
		Name:    `IPTables`,
		Action:  `iptables/index`,
	})
}

var ipTablesFieldList = []string{
	`num`, `pkts`, `bytes`, `target`, `prot`, `opt`, `in`, `out`, `source`, `destination`, // original fields
	`options`, // custom fields
}

func ipTablesGetTableAndChain(ctx echo.Context) (ipVer string, table string, chain string, chainList []string) {
	ipVer = ctx.Form(`ipVer`, `4`)
	table = ctx.Form(`table`, iptables.TableFilter)
	chain = ctx.Form(`chain`, iptables.ChainInput)
	if !com.InSlice(table, iptables.TableList) {
		table = iptables.TableFilter
	}
	chainList = iptables.TablesChains[table]
	if !com.InSlice(chain, chainList) {
		chain = chainList[0]
	}
	if ipVer != `4` && ipVer != `6` {
		ipVer = `4`
	}
	return
}

func ipTablesIndex(ctx echo.Context) error {
	ipVer, table, chain, chainList := ipTablesGetTableAndChain(ctx)
	rules, err := firewall.Engine(ipVer).Stats(table, chain)
	if err != nil {
		return err
	}
	ctx.Set(`listData`, rules)
	ctx.Set(`tableList`, firewall.Types.Slice())
	ctx.Set(`chainList`, chainList)
	ctx.Set(`ipVerList`, firewall.IPProtocols.Slice())
	// ctx.Set(`targetList`, iptables.TargetList)
	// ctx.Set(`protocolList`, iptables.ProtocolList)
	ctx.Set(`fieldList`, ipTablesFieldList)
	ctx.Set(`table`, table)
	ctx.Set(`chain`, chain)
	ctx.Set(`ipVer`, ipVer)
	return ctx.Render(`firewall/iptables/index`, common.Err(ctx, err))
}

func ipTablesDelete(ctx echo.Context) error {
	id := ctx.Formx(`id`).Uint64()
	ipVer, table, chain, _ := ipTablesGetTableAndChain(ctx)
	err := firewall.Engine(ipVer).Delete(&driver.Rule{
		Number:    id,
		Type:      table,
		Direction: chain,
	})
	if err == nil {
		handler.SendOk(ctx, ctx.T(`删除成功`))
	} else {
		handler.SendErr(ctx, err)
	}
	return ctx.Redirect(handler.URLFor(`/firewall/iptables/index`) + `?ipVer=` + ipVer + `&table=` + table + `&chain=` + chain)
}
