package nftables

import (
	"os/exec"
	"testing"

	"github.com/admpub/log"
	"github.com/admpub/pp"
	"github.com/nging-plugins/firewallmanager/application/library/driver"
	"github.com/nging-plugins/firewallmanager/application/library/enums"
)

func TestMain(m *testing.M) {
	defer log.Close()
	code := m.Run()
	println(code)
	//b, _ := exec.Command(`nft`, `list`, `ruleset`).CombinedOutput()
	b, _ := exec.Command(`nft`, `list`, `table`, `nging_filter`).CombinedOutput()
	println(string(b))
	b, _ = exec.Command(`nft`, `delete`, `table`, `nging_filter`).CombinedOutput()
	println(string(b))
}

func TestFindPositionByID(t *testing.T) {
	a, err := New(driver.ProtocolIPv4)
	if err != nil {
		t.Fatal(err)
	}
	nums, err := a.FindPositionByID(enums.TableFilter, enums.ChainInput, 2)
	if err != nil {
		t.Fatal(err)
	}
	pp.Println(nums)
}

func TestAcceptPorts(t *testing.T) {
	a, err := New(driver.ProtocolIPv4)
	if err != nil {
		t.Fatal(err)
	}
	rule := driver.Rule{
		CustomID:  `test`,
		Name:      `test`,
		Protocol:  enums.ProtocolTCP,
		Type:      enums.TableFilter,
		Direction: enums.ChainInput,
		Action:    enums.TargetAccept,
		LocalPort: `80,443`,
		IPVersion: `4`,
	}
	err = a.Append(rule)
	if err != nil {
		t.Fatal(err)
	}

	rule.CustomID = `test0`
	rule.Name = `test0`
	rule.LocalPort = `800,60003-60005`
	err = a.Append(rule)
	if err != nil {
		t.Fatal(err)
	}

	rule.CustomID = `test1`
	rule.Name = `test1`
	rule.LocalPort = `801`
	err = a.Append(rule)
	if err != nil {
		t.Fatal(err)
	}

	rule.CustomID = `test2`
	rule.Name = `test2`
	rule.LocalPort = `60000-60002`
	err = a.Append(rule)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDropLimit(t *testing.T) {
	a, err := New(driver.ProtocolIPv4)
	if err != nil {
		t.Fatal(err)
	}
	rule := driver.Rule{
		ID:          99999,
		Protocol:    enums.ProtocolTCP,
		Type:        enums.TableFilter,
		Direction:   enums.ChainInput,
		Action:      enums.TargetDrop,
		RateLimit:   `50+/p/s`,
		RateBurst:   60,
		RateExpires: 0,
		LocalPort:   `80,443`,
		IPVersion:   `4`,
	}
	err = a.Append(rule)
	if err != nil {
		t.Fatal(err)
	}
}
