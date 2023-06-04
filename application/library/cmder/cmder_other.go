//go:build !linux

package cmder

import (
	"fmt"

	"github.com/nging-plugins/firewallmanager/application/library/firewall"
)

func (c *firewallCmd) Boot() error {
	return fmt.Errorf(`[nging-plugins/firewall]: %w`, firewall.ErrUnsupportedOperatingSystem)
}
