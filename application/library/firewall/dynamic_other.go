//go:build !linux

package firewall

import "github.com/webx-top/echo"

var DynamicRuleBackends = echo.NewKVData()
var DynamicRuleSources = echo.NewKVData()
var DynamicRuleActions = echo.NewKVData()
