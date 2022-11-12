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
			Action:  `rule/static`,
		},
		{
			Display: false,
			Name:    `添加静态规则`,
			Action:  `rule/static_add`,
		},
		{
			Display: false,
			Name:    `修改静态规则`,
			Action:  `rule/static_edit`,
		},
		{
			Display: false,
			Name:    `删除静态规则`,
			Action:  `rule/static_delete`,
		},
		{
			Display: true,
			Name:    `静态规则`,
			Action:  `rule/dynamic`,
		},
		{
			Display: false,
			Name:    `添加动态规则`,
			Action:  `rule/dynamic_add`,
		},
		{
			Display: false,
			Name:    `修改动态规则`,
			Action:  `rule/dynamic_edit`,
		},
		{
			Display: false,
			Name:    `删除动态规则`,
			Action:  `rule/dynamic_delete`,
		},
	},
}
