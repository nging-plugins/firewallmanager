package netutils

import (
	"testing"

	"github.com/admpub/pp/ppnocolor"
	"github.com/stretchr/testify/assert"
)

func TestNetInterfaces(t *testing.T) {
	ifaces, err := GetNetInterfaces()
	assert.NoError(t, err)
	for index, iface := range ifaces {
		ppnocolor.Println(index, iface.Name, iface.HardwareAddr.String(), iface.Flags.String())
	}
}
