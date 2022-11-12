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
	g.Route(`GET,POST`, `/rule/static`, ruleStaticIndex)
	g.Route(`GET,POST`, `/rule/static_add`, ruleStaticAdd)
	g.Route(`GET,POST`, `/rule/static_edit`, ruleStaticEdit)
	g.Route(`GET,POST`, `/rule/static_delete`, ruleStaticDelete)
	g.Route(`GET,POST`, `/rule/dynamic`, ruleDynamicIndex)
	g.Route(`GET,POST`, `/rule/dynamic_add`, ruleDynamicAdd)
	g.Route(`GET,POST`, `/rule/dynamic_edit`, ruleDynamicEdit)
	g.Route(`GET,POST`, `/rule/dynamic_delete`, ruleDynamicDelete)
}

func init() {
	startup.OnAfter(`web.installed`, func() {
	})
	startup.OnAfter(`web`, func() {
	})
}
