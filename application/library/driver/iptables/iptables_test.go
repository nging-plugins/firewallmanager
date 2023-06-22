package iptables

import (
	"testing"

	"github.com/admpub/log"
	"github.com/admpub/pp"
	"github.com/stretchr/testify/assert"

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
	rule := driver.Rule{
		Type:      enums.TableFilter,
		Name:      `testAppend`,
		Direction: enums.ChainInput,
		Protocol:  enums.ProtocolTCP,
		Action:    enums.TargetDrop,
		LocalPort: `14444`,
	}
	err = a.Append(rule)
	if err != nil {
		t.Fatal(err)
	}
	exists, err := a.Exists(rule)
	assert.NoError(t, err)
	assert.True(t, exists)
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

func TestFindByComment(t *testing.T) {
	defer log.Close()
	a, err := New(driver.ProtocolIPv4, false)
	if err != nil {
		t.Fatal(err)
	}
	nums, err := a.findByComment(enums.TableFilter, enums.ChainInput, CommentPrefix+`2`)
	if err != nil {
		t.Fatal(err)
	}
	pp.Println(nums)
}
