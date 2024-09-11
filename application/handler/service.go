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
	"os"

	"github.com/webx-top/echo"

	"github.com/coscms/webcore/library/backend"
	"github.com/coscms/webcore/library/config"
	"github.com/coscms/webcore/library/notice"

	"github.com/nging-plugins/firewallmanager/application/library/cmder"
)

func Restart(ctx echo.Context) error {
	wOut, wErr, err := backend.NoticeWriter(ctx, ctx.T(`防火墙动态规则服务`))
	if err != nil {
		return ctx.String(err.Error())
	}
	if err := cmder.Get().Restart(wOut, wErr); err != nil {
		return ctx.String(err.Error())
	}
	return ctx.String(ctx.T(`已经重启防火墙动态规则服务`))
}

func Stop(ctx echo.Context) error {
	if err := cmder.Get().Stop(); err != nil {
		return ctx.String(err.Error())
	}
	return ctx.String(ctx.T(`已经关闭防火墙动态规则服务`))
}

func Log(ctx echo.Context) error {
	on := ctx.Formx(`on`).Bool()
	if on {
		wOut, wErr, err := backend.NoticeWriter(ctx, ctx.T(`防火墙动态规则服务`))
		if err != nil {
			return ctx.String(err.Error())
		}
		err = config.FromCLI().SetLogWriter(cmder.Name, wOut, wErr)
		if err != nil {
			return ctx.String(err.Error())
		}
		return ctx.String(ctx.T(`已经开始直播防火墙动态规则服务状态`))
	}
	err := config.FromCLI().SetLogWriter(cmder.Name, os.Stdout, os.Stderr)
	if err != nil {
		return ctx.String(err.Error())
	}
	user := backend.User(ctx)
	if user == nil {
		return ctx.String(ctx.T(`请先登录`))
	}
	typ := `service:` + ctx.T(`防火墙动态规则服务`)
	notice.CloseMessage(user.Username, typ)
	return ctx.String(ctx.T(`已经停止直播防火墙动态规则服务状态`))
}
