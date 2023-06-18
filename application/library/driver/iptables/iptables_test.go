package iptables

import (
	"testing"

	"github.com/admpub/log"
	"github.com/admpub/pp"
	"github.com/nging-plugins/firewallmanager/application/library/driver"
	"github.com/nging-plugins/firewallmanager/application/library/enums"
)

func TestInstall(t *testing.T) {
	a, err := New(driver.ProtocolIPv4, true)
	if err != nil {
		t.Fatal(err)
	}
	_ = a
}

func TestAppend(t *testing.T) {
	a, err := New(driver.ProtocolIPv4, false)
	if err != nil {
		t.Fatal(err)
	}
	err = a.Append(driver.Rule{
		Type:      enums.TableFilter,
		Name:      `testAppend`,
		Direction: enums.ChainInput,
		Protocol:  enums.ProtocolTCP,
		Action:    enums.TargetDrop,
		LocalPort: `14444`,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestList(t *testing.T) {
	defer log.Close()
	a, err := New(driver.ProtocolIPv4, false)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := a.List(enums.TableFilter, enums.ChainInput)
	if err != nil {
		t.Fatal(err)
	}
	pp.Println(rows)
}
