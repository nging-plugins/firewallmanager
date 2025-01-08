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
	"github.com/coscms/webcore/library/navigate"
	"github.com/webx-top/echo"
)

var LeftNavigate = &navigate.Item{
	Display: true,
	Name:    echo.T(`防火墙`),
	Action:  `firewall`,
	Icon:    `shield`,
	Children: &navigate.List{
		{
			Display: true,
			Name:    echo.T(`静态规则`),
			Action:  `rule/static`,
		},
		{
			Display: false,
			Name:    echo.T(`添加静态规则`),
			Action:  `rule/static_add`,
		},
		{
			Display: false,
			Name:    echo.T(`修改静态规则`),
			Action:  `rule/static_edit`,
		},
		{
			Display: false,
			Name:    echo.T(`应用静态规则`),
			Action:  `rule/static_apply`,
		},
		{
			Display: false,
			Name:    echo.T(`临时封IP`),
			Action:  `rule/static_ban`,
		},
		{
			Display: false,
			Name:    echo.T(`删除静态规则`),
			Action:  `rule/static_delete`,
		},
		{
			Display: true,
			Name:    echo.T(`动态规则`),
			Action:  `rule/dynamic`,
		},
		{
			Display: false,
			Name:    echo.T(`添加动态规则`),
			Action:  `rule/dynamic_add`,
		},
		{
			Display: false,
			Name:    echo.T(`修改动态规则`),
			Action:  `rule/dynamic_edit`,
		},
		{
			Display: false,
			Name:    echo.T(`删除动态规则`),
			Action:  `rule/dynamic_delete`,
		},
		{
			Display: false,
			Name:    echo.T(`重启服务`),
			Action:  `service/restart`,
			Icon:    ``,
		},
		{
			Display: false,
			Name:    echo.T(`关闭服务`),
			Action:  `service/stop`,
			Icon:    ``,
		},
		{
			Display: false,
			Name:    echo.T(`查看动态`),
			Action:  `service/log`,
			Icon:    ``,
		},
	},
}
