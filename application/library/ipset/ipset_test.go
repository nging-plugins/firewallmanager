package ipset

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseInfo(t *testing.T) {
	reader := bytes.NewReader([]byte(`Name: myset6
Type: hash:net
Revision: 1
Header: family inet6 hashsize 1024 maxelem 65536 timeout 60
Size in memory: 1432
References: 0
Number of entries: 2
Members:
2022::1 timeout 9
2022::/32 timeout 59
`))
	info, err := ParseInfo(reader)
	assert.NoError(t, err)
	assert.Equal(t, `myset6`, info.Name)
	assert.Equal(t, 1, info.Revision)
	assert.Equal(t, `family inet6 hashsize 1024 maxelem 65536 timeout 60`, info.Header)
	assert.Equal(t, 1432, info.SizeInMemory)
	assert.Equal(t, 0, info.References)
	assert.Equal(t, 2, info.NumEntries)
	assert.Equal(t, []string{`2022::1 timeout 9`, `2022::/32 timeout 59`}, info.Entries)
}
