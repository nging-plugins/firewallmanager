package cmdutils

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func testLineParser(i uint, t string) (rowInfo RowInfo, err error) {
	fmt.Println(`line:`, i, `text:`, t)
	t = strings.TrimSpace(t)
	if strings.HasSuffix(t, `{`) || t == `}` {
		return
	}
	parts := strings.SplitN(t, `# handle `, 2)
	if len(parts) == 2 {
		parts[0] = strings.TrimSpace(parts[0])
		if strings.HasSuffix(parts[0], `{`) {
			return
		}
		var handleID uint64
		handleID, err = strconv.ParseUint(parts[1], 10, 0)
		if err != nil {
			return
		}
		rowInfo = RowInfo{
			RowNo: i,
			Row:   parts[0],
		}
		rowInfo.Handle.SetValid(uint(handleID))
	}
	return
}

func TestRecvCmdOutputs(t *testing.T) {
	rows, hasMore, offset, err := RecvCmdOutputs(1, 10, `bash`, []string{`./test.sh`}, testLineParser)
	assert.NoError(t, err)
	assert.True(t, hasMore)
	assert.Equal(t, 10, len(rows))
	assert.Equal(t, uint64(12), offset)
}

func TestBits(t *testing.T) {
	for i := 0; i < 10; i++ {
		fmt.Println(i, `->`, 1<<i)
	}
}
