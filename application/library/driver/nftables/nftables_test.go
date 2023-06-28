package nftables

import (
	"testing"

	"github.com/admpub/log"
	"github.com/admpub/pp"
	"github.com/nging-plugins/firewallmanager/application/library/driver"
	"github.com/nging-plugins/firewallmanager/application/library/enums"
)

func TestFindPositionByID(t *testing.T) {
	defer log.Close()
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
