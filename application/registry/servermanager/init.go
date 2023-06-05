package servermanager

import (
	"github.com/admpub/nging/v5/application/registry/dashboard"
	"github.com/nging-plugins/servermanager/application/registry"
)

func init() {
	registry.ServiceControls.Add(-1, &dashboard.Tmplx{
		Tmpl: `firewall/service/buttons`,
	})
}
