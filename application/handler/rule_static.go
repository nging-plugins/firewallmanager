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
	"github.com/webx-top/db"
	"github.com/webx-top/echo"

	"github.com/admpub/nging/v5/application/handler"
	"github.com/admpub/nging/v5/application/library/common"
	"github.com/nging-plugins/firewallmanager/application/library/firewall"
	"github.com/nging-plugins/firewallmanager/application/model"
)

func ruleStaticIndex(ctx echo.Context) error {
	m := model.NewRuleStatic(ctx)
	cond := db.NewCompounds()
	sorts := common.Sorts(ctx, m.NgingFirewallRuleStatic)
	list, err := m.ListPage(cond, sorts...)
	if ctx.Format() == echo.ContentTypeJSON {
		rules, err := firewall.Engine(`4`).List(`filter`, `INPUT`)
		if err != nil {
			return err
		}
		ctx.Set(`rules`, rules)
	}
	ctx.Set(`listData`, list)
	return ctx.Render(`firewall/rule/static`, common.Err(ctx, err))
}

func ruleStaticAdd(ctx echo.Context) error {
	m := model.NewRuleStatic(ctx)
	var err error
	if ctx.IsPost() {
		err = ctx.MustBind(m.NgingFirewallRuleStatic)
		if err != nil {
			goto END
		}
		_, err = m.Add()
		if err != nil {
			goto END
		}
		rule := m.AsRule()
		if rule.IPVersion == `all` {
			err = firewall.Engine(`4`).Insert(m.Position, &rule)
			if err != nil {
				goto END
			}
			err = firewall.Engine(`6`).Insert(m.Position, &rule)
			if err != nil {
				goto END
			}
		} else {
			err = firewall.Engine(rule.IPVersion).Insert(m.Position, &rule)
			if err != nil {
				goto END
			}
		}
		return ctx.Redirect(handler.URLFor(`/firewall/rule/static`))
	} else {
		id := ctx.Formx(`copyId`).Uint()
		if id > 0 {
			err = m.Get(nil, db.Cond{`id`: id})
			if err == nil {
				ctx.Request().Form().Set(`id`, `0`)
			}
		}
	}

END:
	ctx.Set(`activeURL`, `/firewall/rule/static`)
	ctx.Set(`title`, ctx.T(`添加规则`))
	firewall.SetFormData(ctx)
	return ctx.Render(`firewall/rule/static_edit`, common.Err(ctx, err))
}

func ruleStaticEdit(ctx echo.Context) error {
	m := model.NewRuleStatic(ctx)
	id := ctx.Formx(`id`).Uint()
	err := m.Get(nil, `id`, id)
	if err != nil {
		return err
	}
	if ctx.IsPost() {
		err = ctx.MustBind(m.NgingFirewallRuleStatic)
		if err != nil {
			goto END
		}
		m.Id = id
		err = m.Edit(nil, `id`, id)
		if err != nil {
			goto END
		}
		rule := m.AsRule()
		if rule.IPVersion == `all` {
			err = firewall.Engine(`4`).Update(m.Position, &rule)
			if err != nil {
				goto END
			}
			err = firewall.Engine(`6`).Update(m.Position, &rule)
			if err != nil {
				goto END
			}
		} else {
			err = firewall.Engine(rule.IPVersion).Update(m.Position, &rule)
			if err != nil {
				goto END
			}
		}
		return ctx.Redirect(handler.URLFor(`/firewall/rule/static`))
	}
	echo.StructToForm(ctx, m.NgingFirewallRuleStatic, ``, echo.LowerCaseFirstLetter)

END:
	ctx.Set(`activeURL`, `/firewall/rule/static`)
	ctx.Set(`title`, ctx.T(`修改规则`))
	firewall.SetFormData(ctx)
	return ctx.Render(`firewall/rule/static_edit`, common.Err(ctx, err))
}

func ruleStaticDelete(ctx echo.Context) error {
	m := model.NewRuleStatic(ctx)
	id := ctx.Formx(`id`).Uint()
	err := m.Get(nil, `id`, id)
	if err == nil {
		err = m.Delete(nil, `id`, id)
		if err == nil {
			rule := m.AsRule()
			var ipv = `4`
			err = firewall.Engine(ipv).Delete(&rule)
		}
	}
	if err == nil {
		handler.SendOk(ctx, ctx.T(`删除成功`))
	} else {
		handler.SendErr(ctx, err)
	}
	return ctx.Redirect(handler.URLFor(`/firewall/rule/static`))
}
