package handler

import (
	"github.com/webx-top/echo"

	"github.com/admpub/nging/v4/application/library/config/startup"
	"github.com/admpub/nging/v4/application/library/route"
)

func RegisterRoute(r *route.Collection) {
	r.Backend.RegisterToGroup(`/firewall`, registerRoute)
}

func registerRoute(g echo.RouteRegister) {
	g.Route(`GET,POST`, `/index`, firewall)
}

func init() {
	startup.OnAfter(`web.installed`, func() {
	})
	startup.OnAfter(`web`, func() {
	})
}
