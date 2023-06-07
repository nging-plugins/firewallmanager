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
	"github.com/admpub/nging/v5/application/library/errorslice"
	"github.com/nging-plugins/firewallmanager/application/library/firewall"
	"github.com/nging-plugins/firewallmanager/application/model"
)

func ruleStaticIndex(ctx echo.Context) error {
	m := model.NewRuleStatic(ctx)
	cond := db.NewCompounds()
	sorts := common.Sorts(ctx, m.NgingFirewallRuleStatic)
	list, err := m.ListPage(cond, sorts...)
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
		err = firewall.Insert(0, &rule)
		if err != nil {
			goto END
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
		old := *m.NgingFirewallRuleStatic
		err = ctx.MustBind(m.NgingFirewallRuleStatic)
		if err != nil {
			goto END
		}
		m.Id = id
		err = m.Edit(nil, `id`, id)
		if err != nil {
			goto END
		}
		oldRule := model.AsRule(&old)
		err = firewall.Delete(&oldRule)
		if err != nil {
			goto END
		}
		rule := m.AsRule()
		err = firewall.Insert(0, &rule)
		if err != nil {
			goto END
		}
		return ctx.Redirect(handler.URLFor(`/firewall/rule/static`))
	} else if ctx.IsAjax() {
		disabled := ctx.Query(`disabled`)
		if len(disabled) > 0 {
			m.Disabled = disabled
			data := ctx.Data()
			err = m.UpdateField(nil, `disabled`, disabled, db.Cond{`id`: id})
			if err != nil {
				data.SetError(err)
				return ctx.JSON(data)
			}
			rule := m.AsRule()
			if m.Disabled == `Y` {
				err = firewall.Delete(&rule)
			} else {
				err = firewall.Update(0, &rule)
			}
			if err != nil {
				data.SetError(err)
				return ctx.JSON(data)
			}
			data.SetInfo(ctx.T(`操作成功`))
			return ctx.JSON(data)
		}
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
			err = firewall.Delete(&rule)
		}
	}
	if err == nil {
		handler.SendOk(ctx, ctx.T(`删除成功`))
	} else {
		handler.SendErr(ctx, err)
	}
	return ctx.Redirect(handler.URLFor(`/firewall/rule/static`))
}

func ruleStaticApply(ctx echo.Context) error {
	errs := errorslice.New()
	m := model.NewRuleStatic(ctx)
	_, err := m.ListByOffset(nil, nil, 0, -1, `disabled`, `Y`)
	if err == nil {
		for _, row := range m.Objects() {
			rule := m.AsRule(row)
			err = firewall.Delete(&rule)
			if err != nil {
				errs.Add(err)
			}
		}
	}
	// err = firewall.Insert(0, &driver.Rule{
	// 	Type:      `filter`,
	// 	Direction: `INPUT`,
	// 	LocalPort: `28181`,
	// 	Action:    `ACCEPT`,
	// 	Protocol:  `tcp`,
	// })
	// if err != nil {
	// 	return err
	// }
	// err = firewall.Insert(0, &driver.Rule{
	// 	Type:      `filter`,
	// 	Direction: `INPUT`,
	// 	LocalPort: `5001:5050`,
	// 	Action:    `ACCEPT`,
	// 	Protocol:  `tcp`,
	// })
	// if err != nil {
	// 	return err
	// }

	// err = firewall.AsWhitelist(`all`, `filter`, `INPUT`)
	// if err != nil {
	// 	return err
	// }
	_, err = m.ListByOffset(nil, func(r db.Result) db.Result {
		return r.OrderBy(`-position`, `-id`)
	}, 0, -1, `disabled`, `N`)
	if err == nil {
		for _, row := range m.Objects() {
			rule := m.AsRule(row)
			err = firewall.Insert(0, &rule)
			if err != nil {
				errs.Add(err)
			}
		}
	}
	if err == nil {
		err = errs.ToError()
	}
	if err == nil {
		handler.SendOk(ctx, ctx.T(`规则应用成功`))
	} else {
		handler.SendErr(ctx, err)
	}
	return ctx.Redirect(handler.URLFor(`/firewall/rule/static`))
}
