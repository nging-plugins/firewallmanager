package enums

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/webx-top/com"
)

func TestInSlice(t *testing.T) {
	result := com.InSlice(`notExist`, TablesChains[`notExist`])
	assert.False(t, result)
}
