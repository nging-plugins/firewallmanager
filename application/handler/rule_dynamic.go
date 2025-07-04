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
	"github.com/coscms/webcore/library/backend"
	"github.com/coscms/webcore/library/common"
	"github.com/nging-plugins/firewallmanager/application/library/cmder"
	"github.com/nging-plugins/firewallmanager/application/library/firewall"
	"github.com/nging-plugins/firewallmanager/application/model"
	"github.com/webx-top/db"
	"github.com/webx-top/echo"
	"github.com/webx-top/echo/code"
)

func ruleDynamicIndex(ctx echo.Context) error {
	m := model.NewRuleDynamic(ctx)
	cond := db.NewCompounds()
	sorts := common.Sorts(ctx, m.NgingFirewallRuleDynamic)
	list, err := m.ListPage(cond, sorts...)
	ctx.Set(`listData`, list)
	ctx.Set(`firewallBackend`, firewall.GetBackend())
	return ctx.Render(`firewall/rule/dynamic`, common.Err(ctx, err))
}

func ruleDynamicAdd(ctx echo.Context) error {
	m := model.NewRuleDynamic(ctx)
	var err error
	if ctx.IsPost() {
		err = firewall.DynamicRuleParseForm(ctx, m.NgingFirewallRuleDynamic)
		if err != nil {
			goto END
		}
		_, err = m.Add()
		if err != nil {
			goto END
		}
		if m.Disabled == `N` {
			wOut, wErr, _ := backend.NoticeWriter(ctx, ctx.T(`防火墙服务`))
			cmder.Get().Restart(wOut, wErr)
		}
		return ctx.Redirect(backend.URLFor(`/firewall/rule/dynamic`))
	} else {
		id := ctx.Formx(`copyId`).Uint()
		if id > 0 {
			err = m.Get(nil, db.Cond{`id`: id})
			if err == nil {
				echo.StructToForm(ctx, m.NgingFirewallRuleDynamic, ``, echo.LowerCaseFirstLetter)
				ctx.Request().Form().Set(`id`, `0`)
				firewall.SetDynamicRuleForm(ctx, m.NgingFirewallRuleDynamic)
			}
		}
	}

END:
	ctx.Set(`activeURL`, `/firewall/rule/dynamic`)
	ctx.Set(`title`, ctx.T(`添加规则`))
	ctx.Set(`sourceList`, firewall.DynamicRuleSources.Slice())
	ctx.Set(`actionList`, firewall.DynamicRuleActions.Slice())
	ctx.Set(`rule`, m.NgingFirewallRuleDynamic)
	return ctx.Render(`firewall/rule/dynamic_edit`, common.Err(ctx, err))
}

func ruleDynamicEdit(ctx echo.Context) error {
	m := model.NewRuleDynamic(ctx)
	id := ctx.Formx(`id`).Uint()
	err := m.Get(nil, `id`, id)
	if err != nil {
		return err
	}
	if ctx.IsPost() {
		oldDisabled := m.Disabled
		err = firewall.DynamicRuleParseForm(ctx, m.NgingFirewallRuleDynamic)
		if err != nil {
			goto END
		}
		m.Id = id
		err = m.Edit(nil, `id`, id)
		if err != nil {
			goto END
		}
		if m.Disabled == `N` {
			if oldDisabled != m.Disabled {
				wOut, wErr, _ := backend.NoticeWriter(ctx, ctx.T(`防火墙服务`))
				cmder.Get().Restart(wOut, wErr)
			}
		} else {
			exists, _ := m.ExistsAvailable()
			if !exists {
				cmder.Stop()
			} else {
				wOut, wErr, _ := backend.NoticeWriter(ctx, ctx.T(`防火墙服务`))
				cmder.Get().Restart(wOut, wErr)
			}
		}
		return ctx.Redirect(backend.URLFor(`/firewall/rule/dynamic`))
	} else if ctx.IsAjax() {
		disabled := ctx.Query(`disabled`)
		if len(disabled) > 0 {
			if !common.IsBoolFlag(disabled) {
				return ctx.NewError(code.InvalidParameter, ``).SetZone(`disabled`)
			}
			data := ctx.Data()
			if m.Disabled == disabled {
				data.SetError(ctx.NewError(code.DataNotChanged, `状态没有改变`))
				return ctx.JSON(data)
			}
			m.Disabled = disabled
			err = m.UpdateField(nil, `disabled`, disabled, db.Cond{`id`: id})
			if err != nil {
				data.SetError(err)
				return ctx.JSON(data)
			}
			if m.Disabled == `Y` {
				exists, _ := m.ExistsAvailable()
				if !exists {
					cmder.Stop()
				} else {
					wOut, wErr, _ := backend.NoticeWriter(ctx, ctx.T(`防火墙服务`))
					cmder.Get().Restart(wOut, wErr)
				}
			} else {
				wOut, wErr, _ := backend.NoticeWriter(ctx, ctx.T(`防火墙服务`))
				cmder.Get().Restart(wOut, wErr)
			}
			if err != nil {
				data.SetError(err)
				return ctx.JSON(data)
			}
			data.SetInfo(ctx.T(`操作成功`))
			return ctx.JSON(data)
		}
	}
	echo.StructToForm(ctx, m.NgingFirewallRuleDynamic, ``, echo.LowerCaseFirstLetter)
	firewall.SetDynamicRuleForm(ctx, m.NgingFirewallRuleDynamic)

END:
	ctx.Set(`activeURL`, `/firewall/rule/dynamic`)
	ctx.Set(`title`, ctx.T(`修改规则`))
	ctx.Set(`sourceList`, firewall.DynamicRuleSources.Slice())
	ctx.Set(`actionList`, firewall.DynamicRuleActions.Slice())
	ctx.Set(`rule`, m.NgingFirewallRuleDynamic)
	return ctx.Render(`firewall/rule/dynamic_edit`, common.Err(ctx, err))
}

func ruleDynamicDelete(ctx echo.Context) error {
	m := model.NewRuleDynamic(ctx)
	id := ctx.Formx(`id`).Uint()
	if id < 1 {
		return ctx.NewError(code.InvalidParameter, `无效参数`).SetZone(`id`)
	}
	err := m.Get(func(r db.Result) db.Result {
		return r.Select(`disabled`)
	}, `id`, id)
	if err != nil {
		return err
	}
	err = m.Delete(nil, `id`, id)
	if err == nil {
		if m.Disabled == common.BoolN {
			wOut, wErr, _ := backend.NoticeWriter(ctx, ctx.T(`防火墙服务`))
			cmder.Get().Restart(wOut, wErr)
		}
		common.SendOk(ctx, ctx.T(`删除成功`))
	} else {
		common.SendErr(ctx, err)
	}
	return ctx.Redirect(backend.URLFor(`/firewall/rule/dynamic`))
}
