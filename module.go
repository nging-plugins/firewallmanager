package firewallmanager

import (
	"github.com/admpub/nging/v4/application/library/module"

	"github.com/nging-plugins/firewallmanager/application/handler"
)

const ID = `firewall`

var Module = module.Module{
	TemplatePath: map[string]string{
		ID: `firewallmanager/template/backend`,
	},
	AssetsPath:  []string{},
	Navigate:    RegisterNavigate,
	Route:       handler.RegisterRoute,
	DBSchemaVer: 0.0000,
}
