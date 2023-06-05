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
	ruleG := g.Group(`/rule`)
	ruleG.Route(`GET,POST`, `/static`, ruleStaticIndex)
	ruleG.Route(`GET,POST`, `/static_add`, ruleStaticAdd)
	ruleG.Route(`GET,POST`, `/static_edit`, ruleStaticEdit)
	ruleG.Route(`GET,POST`, `/static_delete`, ruleStaticDelete)
	ruleG.Route(`GET,POST`, `/dynamic`, ruleDynamicIndex)
	ruleG.Route(`GET,POST`, `/dynamic_add`, ruleDynamicAdd)
	ruleG.Route(`GET,POST`, `/dynamic_edit`, ruleDynamicEdit)
	ruleG.Route(`GET,POST`, `/dynamic_delete`, ruleDynamicDelete)

	serviceG := g.Group(`/service`)
	serviceG.Route(`GET,POST`, `/restart`, Restart)
	serviceG.Route(`GET,POST`, `/stop`, Stop)
	serviceG.Route(`GET,POST`, `/log`, Log)
}

func init() {
	startup.OnAfter(`web.installed`, func() {
	})
	startup.OnAfter(`web`, func() {
	})
}
