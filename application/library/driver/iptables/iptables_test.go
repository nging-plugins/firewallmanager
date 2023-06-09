package iptables

import (
	"testing"

	"github.com/admpub/log"
	"github.com/admpub/pp"
	"github.com/nging-plugins/firewallmanager/application/library/driver"
)

func TestInstall(t *testing.T) {
	a, err := New(ProtocolIPv4, true)
	if err != nil {
		t.Fatal(err)
	}
	_ = a
}

func TestAppend(t *testing.T) {
	a, err := New(ProtocolIPv4, false)
	if err != nil {
		t.Fatal(err)
	}
	err = a.Append(&driver.Rule{
		Type:      TableFilter,
		Name:      `testAppend`,
		Direction: ChainInput,
		Protocol:  ProtocolTCP,
		Action:    TargetDrop,
		LocalPort: `14444`,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestList(t *testing.T) {
	defer log.Close()
	a, err := New(ProtocolIPv4, false)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := a.List(TableFilter, ChainInput)
	if err != nil {
		t.Fatal(err)
	}
	pp.Println(rows)
}
