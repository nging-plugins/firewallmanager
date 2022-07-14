package handler

import "github.com/admpub/nging/v4/application/registry/navigate"

var LeftNavigate = &navigate.Item{
	Display: true,
	Name:    `防火墙`,
	Action:  `firewall`,
	Icon:    `download`,
	Children: &navigate.List{
		{
			Display: true,
			Name:    `防火墙管理`,
			Action:  `index`,
		},
	},
}
