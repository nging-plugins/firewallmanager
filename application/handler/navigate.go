package handler

import "github.com/admpub/nging/v5/application/registry/navigate"

var LeftNavigate = &navigate.Item{
	Display: true,
	Name:    `防火墙`,
	Action:  `firewall`,
	Icon:    `download`,
	Children: &navigate.List{
		{
			Display: true,
			Name:    `静态规则`,
			Action:  `rule/static/index`,
		},
		{
			Display: false,
			Name:    `添加静态规则`,
			Action:  `rule/static/add`,
		},
		{
			Display: false,
			Name:    `修改静态规则`,
			Action:  `rule/static/edit`,
		},
		{
			Display: false,
			Name:    `删除静态规则`,
			Action:  `rule/static/delete`,
		},
		{
			Display: true,
			Name:    `静态规则`,
			Action:  `rule/dynamic/index`,
		},
		{
			Display: false,
			Name:    `添加动态规则`,
			Action:  `rule/dynamic/add`,
		},
		{
			Display: false,
			Name:    `修改动态规则`,
			Action:  `rule/dynamic/edit`,
		},
		{
			Display: false,
			Name:    `删除动态规则`,
			Action:  `rule/dynamic/delete`,
		},
	},
}