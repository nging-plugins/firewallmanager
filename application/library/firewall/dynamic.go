package firewall

import (
	"encoding/json"
	"strings"

	"github.com/admpub/gerberos"
	"github.com/admpub/nging/v5/application/library/common"
	"github.com/nging-plugins/firewallmanager/application/dbschema"
	"github.com/webx-top/echo"
	"github.com/webx-top/echo/code"
	"github.com/webx-top/echo/param"
)

func RegisterDynamicRuleBackend(k string, v string) {
	DynamicRuleBackends.Add(k, v)
}

func RegisterDynamicRuleSource(k string, v string, formElements echo.KVList) {
	DynamicRuleSources.Add(k, v, echo.KVOptHKV(`formElements`, formElements))
}

func RegisterDynamicRuleAction(k string, v string, formElements echo.KVList) {
	DynamicRuleActions.Add(k, v, echo.KVOptHKV(`formElements`, formElements))
}

func DynamicRuleParseForm(c echo.Context, rule *dbschema.NgingFirewallRuleDynamic) error {
	rule.Name = c.Form(`name`)

	// source
	rule.SourceType = c.Form(`sourceType`)
	sourceArgs := c.FormxValues(`sourceArgs`).Filter()
	b, _ := json.Marshal(sourceArgs)
	rule.SourceArgs = string(b)

	// action
	rule.ActionType = c.Form(`actionType`)
	rule.ActionArg = c.Form(`actionArg`)

	// aggregate
	rule.AggregateDuration = c.Form(`aggregateDuration`)
	aggregateRegexp := c.Form(`aggregateRegexp`)
	var aggregateRegexpList []string
	for idx, re := range strings.Split(aggregateRegexp, "\n") {
		re = strings.TrimSpace(re)
		if len(re) == 0 {
			continue
		}
		if !strings.Contains(re, `%id%`) {
			return c.NewError(code.InvalidParameter, `必须在每一行的规则里包含“%%id%%”，在第 %d 行规则中没有找到“%%id%%”，请添加`, idx+1).SetZone(`aggregateRegexp`)
		}
		aggregateRegexpList = append(aggregateRegexpList, re)
	}
	b, _ = json.Marshal(aggregateRegexpList)
	rule.AggregateRegexp = string(b)
	hasAggregate := len(rule.AggregateDuration) > 0 && len(aggregateRegexpList) > 0

	// occurrence
	rule.OccurrenceNum = c.Formx(`occurrenceNum`).Uint()
	rule.OccurrenceDuration = c.Form(`occurrenceDuration`)

	// regexp
	regexp := c.Form(`regexp`)
	var regexpList []string
	for idx, re := range strings.Split(regexp, "\n") {
		re = strings.TrimSpace(re)
		if len(re) == 0 {
			continue
		}
		if !strings.Contains(re, `%ip%`) {
			return c.NewError(code.InvalidParameter, `必须在每一行的规则里包含“%%ip%%”，在第 %d 行规则中没有找到“%%ip%%”，请添加`, idx+1).SetZone(`regexp`)
		}
		if hasAggregate && !strings.Contains(re, `%id%`) {
			return c.NewError(code.InvalidParameter, `在设置“聚合规则”的情况下，必须在同时在每一行的规则里包含“%%id%%”，在第 %d 行规则中没有找到“%%id%%”，请添加`, idx+1).SetZone(`regexp`)
		}
		regexpList = append(regexpList, re)
	}
	b, _ = json.Marshal(regexpList)
	rule.Regexp = string(b)

	// status
	rule.Disabled = c.Form(`disabled`)
	return nil
}

func DynamicRuleFromDB(c echo.Context, row *dbschema.NgingFirewallRuleDynamic) (rule gerberos.Rule, err error) {
	var args []string
	err = json.Unmarshal([]byte(row.SourceArgs), &args)
	if err != nil {
		err = common.JSONBytesParseError(err, []byte(row.SourceArgs))
		return
	}
	rule.Source = []string{row.SourceType}
	rule.Source = append(rule.Source, args...)

	args = []string{}
	err = json.Unmarshal([]byte(row.Regexp), &args)
	if err != nil {
		err = common.JSONBytesParseError(err, []byte(row.Regexp))
		return
	}
	rule.Regexp = args
	rule.Action = []string{row.SourceType}
	if len(row.ActionArg) > 0 {
		rule.Action = append(rule.Action, row.ActionArg)
	}
	rule.Aggregate = []string{}
	if len(row.AggregateDuration) > 0 && len(row.AggregateRegexp) > 0 {
		rule.Aggregate = append(rule.Aggregate, row.AggregateDuration)
		args = []string{}
		err = json.Unmarshal([]byte(row.AggregateRegexp), &args)
		if err != nil {
			err = common.JSONBytesParseError(err, []byte(row.AggregateRegexp))
			return
		}
		rule.Aggregate = append(rule.Aggregate, args...)
	}
	rule.Occurrences = []string{}
	if row.OccurrenceNum > 0 && len(row.OccurrenceDuration) > 0 {
		rule.Occurrences = append(rule.Occurrences, param.AsString(row.OccurrenceNum))
		rule.Occurrences = append(rule.Occurrences, row.OccurrenceDuration)
	}

	return
}
