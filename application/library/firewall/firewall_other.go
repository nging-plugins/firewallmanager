//go:build !linux && !windows

package firewall

import (
	"errors"

	"github.com/nging-plugins/firewallmanager/application/library/driver"
)

func Engine(ipVersionNumber string) driver.Driver {
	return defaultUnsupportedDriver
}

var ErrUnsupportedOperatingSystem = errors.New(`This feature is not supported in the current operating system`) //此功能在当前操作系统里不支持

var defaultUnsupportedDriver = &unsupportedDriver{}

type unsupportedDriver struct {
}

func (unsupportedDriver) RuleFrom(rule *driver.Rule) []string {
	return nil
}

func (unsupportedDriver) Enabled(on bool) error {
	return ErrUnsupportedOperatingSystem
}

func (unsupportedDriver) Reset() error {
	return ErrUnsupportedOperatingSystem
}

func (unsupportedDriver) Import(wfwFile string) error {
	return ErrUnsupportedOperatingSystem
}

func (unsupportedDriver) Export(wfwFile string) error {
	return ErrUnsupportedOperatingSystem
}

func (unsupportedDriver) Insert(pos int, rule *driver.Rule) error {
	return ErrUnsupportedOperatingSystem
}

func (unsupportedDriver) Append(rule *driver.Rule) error {
	return ErrUnsupportedOperatingSystem
}

func (unsupportedDriver) Update(pos int, rule *driver.Rule) error {
	return ErrUnsupportedOperatingSystem
}

func (unsupportedDriver) Delete(rule *driver.Rule) error {
	return ErrUnsupportedOperatingSystem
}

func (unsupportedDriver) Exists(rule *driver.Rule) (bool, error) {
	return false, ErrUnsupportedOperatingSystem
}

func (unsupportedDriver) List(table, chain string) ([]*driver.Rule, error) {
	return nil, ErrUnsupportedOperatingSystem
}
