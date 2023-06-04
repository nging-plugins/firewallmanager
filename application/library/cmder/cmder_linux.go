//go:build linux

package cmder

func (c *firewallCmd) Boot() error {
	return c.boot()
}
