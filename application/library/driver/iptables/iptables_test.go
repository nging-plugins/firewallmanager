package iptables

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/nging-plugins/firewallmanager/application/library/driver"
)

func TestInstall(t *testing.T) {
	a, err := New(ProtocolIPv4)
	if err != nil {
		t.Fatal(err)
	}
	_ = a
}

func TestAppend(t *testing.T) {
	a, err := New(ProtocolIPv4)
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
	a, err := New(ProtocolIPv4)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := a.List(TableFilter, ChainInput)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.MarshalIndent(rows, ``, `  `)
	fmt.Println(string(b))
}
