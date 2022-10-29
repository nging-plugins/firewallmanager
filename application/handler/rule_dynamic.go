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
	"github.com/admpub/nging/v5/application/handler"
	"github.com/admpub/nging/v5/application/library/common"
	"github.com/nging-plugins/firewallmanager/application/model"
	"github.com/webx-top/echo"
)

func ruleDynamicAdd(ctx echo.Context) error {
	m := model.NewRuleDynamic(ctx)
	var err error
	if ctx.IsPost() {
		err = ctx.MustBind(m.NgingFirewallRuleDynamic)
		if err != nil {
			goto END
		}
		_, err = m.Add()
		if err != nil {
			goto END
		}
		return ctx.Redirect(handler.URLFor(`/firewall/index`))
	}

END:
	ctx.Set(`activeURL`, `/firewall/rule/index`)
	ctx.Set(`title`, ctx.T(`添加规则`))
	return ctx.Render(`firewall/edit_dynamic`, common.Err(ctx, err))
}

func ruleDynamicEdit(ctx echo.Context) error {
	m := model.NewRuleDynamic(ctx)
	id := ctx.Paramx(`id`).Uint()
	err := m.Get(nil, `id`, id)
	if err != nil {
		return err
	}
	if ctx.IsPost() {
		err = ctx.MustBind(m.NgingFirewallRuleDynamic)
		if err != nil {
			goto END
		}
		_, err = m.Add()
		if err != nil {
			goto END
		}
		return ctx.Redirect(handler.URLFor(`/firewall/index`))
	}
	echo.StructToForm(ctx, m.NgingFirewallRuleDynamic, ``, echo.LowerCaseFirstLetter)

END:
	ctx.Set(`activeURL`, `/firewall/rule/index`)
	ctx.Set(`title`, ctx.T(`修改规则`))
	return ctx.Render(`firewall/edit_dynamic`, common.Err(ctx, err))
}

func ruleDynamicDelete(ctx echo.Context) error {
	m := model.NewRuleDynamic(ctx)
	id := ctx.Paramx(`id`).Uint()
	err := m.Delete(nil, `id`, id)
	if err == nil {
		handler.SendOk(ctx, ctx.T(`删除成功`))
	} else {
		handler.SendErr(ctx, err)
	}
	return ctx.Redirect(handler.URLFor(`/firewall/rule/index`))
}
