package iptables

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLineCommentParser(t *testing.T) {
	lp := LineCommentParser([]string{`nging-rule-2`})
	row, err := lp(0, `9    REJECT     tcp  --  anywhere             anywhere             tcp dpt:12345 /* nging-rule-2 */ reject-with icmp-port-unreachable`)
	assert.NoError(t, err)
	assert.NotNil(t, row)
	assert.Equal(t, uint(9), row.Handle.Uint)
}
