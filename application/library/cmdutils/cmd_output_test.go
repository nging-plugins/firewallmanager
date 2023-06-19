package cmdutils

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func testLineParser(i uint64, t string) (rowInfo *RowInfo, err error) {
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
		handleID, err = strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			return
		}
		rowInfo = &RowInfo{
			RowNo:  i,
			Row:    parts[0],
			Handle: &handleID,
		}
	} else {
		rowInfo = &RowInfo{
			RowNo: i,
			Row:   t,
		}
	}
	return
}

func TestRecvCmdOutputs(t *testing.T) {
	rows, hasMore, err := RecvCmdOutputs(1, 10, `bash`, []string{`./test.sh`}, testLineParser)
	assert.NoError(t, err)
	assert.True(t, hasMore)
	assert.Equal(t, 10, len(rows))
}
