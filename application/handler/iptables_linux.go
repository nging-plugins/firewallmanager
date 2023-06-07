// go:build linux

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

package handler

import (
	"github.com/webx-top/com"
	"github.com/webx-top/echo"
	
	"github.com/admpub/nging/v5/application/handler"
	"github.com/admpub/nging/v5/application/library/common"
	"github.com/admpub/nging/v5/application/registry/navigate"
	"github.com/nging-plugins/firewallmanager/application/library/cmder"
	"github.com/nging-plugins/firewallmanager/application/library/driver"
	"github.com/nging-plugins/firewallmanager/application/library/driver/iptables"
	"github.com/nging-plugins/firewallmanager/application/library/firewall"
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
	}, &navigate.Item{
		Display: false,
		Name:    `删除IPTables规则`,
		Action:  `iptables/delete`,
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
	ctx.SetFunc(`canDelete`, ipTablesCanDelete)
	return ctx.Render(`firewall/iptables/index`, common.Err(ctx, err))
}

func ipTablesCanDelete(target string) bool {
	return target != cmder.DefaultChainName
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
