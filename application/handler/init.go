package handler

import (
	"github.com/webx-top/echo"

	"github.com/admpub/nging/v5/application/library/config/startup"
	"github.com/admpub/nging/v5/application/library/route"
)

func RegisterRoute(r *route.Collection) {
	r.Backend.RegisterToGroup(`/firewall`, registerRoute)
}

func registerRoute(g echo.RouteRegister) {
	g.Route(`GET,POST`, `/rule/static/index`, ruleStaticIndex)
	g.Route(`GET,POST`, `/rule/static/add`, ruleStaticAdd)
	g.Route(`GET,POST`, `/rule/static/edit`, ruleStaticEdit)
	g.Route(`GET,POST`, `/rule/static/delete`, ruleStaticDelete)
	g.Route(`GET,POST`, `/rule/dynamic/index`, ruleDynamicIndex)
	g.Route(`GET,POST`, `/rule/dynamic/add`, ruleDynamicAdd)
	g.Route(`GET,POST`, `/rule/dynamic/edit`, ruleDynamicEdit)
	g.Route(`GET,POST`, `/rule/dynamic/delete`, ruleDynamicDelete)
}

func init() {
	startup.OnAfter(`web.installed`, func() {
	})
	startup.OnAfter(`web`, func() {
	})
}
