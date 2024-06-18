/*
   Nging is a toolbox for webmasters
   Copyright (C) 2018-present  Wenhui Shen <swh@admpub.com>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published
   by the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package nftables

import (
	"fmt"
	"strings"
	"time"

	"github.com/admpub/nftablesutils"
	setutils "github.com/admpub/nftablesutils/set"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/webx-top/com"
	"github.com/webx-top/echo/param"

	"github.com/nging-plugins/firewallmanager/application/library/driver"
	"github.com/nging-plugins/firewallmanager/application/library/enums"
)

func (a *NFTables) buildCommonRule(c *nftables.Conn, rule *driver.Rule) (args nftablesutils.Exprs, err error) {
	args = args.Add(a.buildProtoRule(rule)...)
	if com.InSlice(rule.Direction, enums.InputIfaceChainList) && !enums.IsEmptyIface(rule.Interface) {
		args = args.Add(nftablesutils.SetIIF(rule.Interface)...)
	}

	if com.InSlice(`localIp`, enums.ChainParams[rule.Direction]) {
		_args, _err := a.buildLocalIPRule(c, rule)
		if _err != nil {
			return nil, _err
		}
		args = args.Add(_args...)
	}

	if com.InSlice(`localPort`, enums.ChainParams[rule.Direction]) {
		_args, _err := a.buildLocalPortRule(c, rule)
		if _err != nil {
			return nil, _err
		}
		args = args.Add(_args...)
	}

	if com.InSlice(rule.Direction, enums.OutputIfaceChainList) && !enums.IsEmptyIface(rule.Outerface) {
		args = args.Add(nftablesutils.SetOIF(rule.Outerface)...)
	}

	if com.InSlice(`remoteIp`, enums.ChainParams[rule.Direction]) {
		_args, _err := a.buildRemoteIPRule(c, rule)
		if _err != nil {
			return nil, _err
		}
		args = args.Add(_args...)
	}

	if com.InSlice(`remotePort`, enums.ChainParams[rule.Direction]) {
		_args, _err := a.buildRemotePortRule(c, rule)
		if _err != nil {
			return nil, _err
		}
		args = args.Add(_args...)
	}

	return
}

func (a *NFTables) buildProtoRule(rule *driver.Rule) (args nftablesutils.Exprs) {
	switch rule.Protocol {
	case enums.ProtocolTCP:
		args = nftablesutils.JoinExprs(args, nftablesutils.SetProtoTCP())
	case enums.ProtocolUDP:
		args = nftablesutils.JoinExprs(args, nftablesutils.SetProtoUDP())
	case enums.ProtocolICMP:
		if a.base.isIPv4() {
			args = nftablesutils.JoinExprs(args, nftablesutils.SetProtoICMP())
		} else {
			args = nftablesutils.JoinExprs(args, nftablesutils.SetProtoICMPv6())
		}
	default:
		// all
	}
	return
}

func (a *NFTables) buildLocalIPRule(c *nftables.Conn, rule *driver.Rule) (args nftablesutils.Exprs, err error) {
	if enums.IsEmptyIP(rule.LocalIP) {
		return
	}
	var neq bool
	if strings.HasPrefix(rule.LocalIP, `!`) {
		neq = true
		rule.LocalIP = strings.TrimPrefix(rule.LocalIP, `!`)
	}
	if strings.ContainsAny(rule.LocalIP, `-,`) {
		var ipSet *nftables.Set
		var elems []nftables.SetElement
		var eErr error
		ips := param.Split(rule.LocalIP, `,`).Unique().Filter().String()
		if a.base.isIPv4() {
			ipSet = nftablesutils.GetIPv4AddrSet(a.base.TableFilter())
			elems, eErr = setutils.GenerateElementsFromIPv4Address(ips)
		} else {
			ipSet = nftablesutils.GetIPv6AddrSet(a.base.TableFilter())
			elems, eErr = setutils.GenerateElementsFromIPv6Address(ips)
		}
		if eErr != nil {
			err = eErr
			return
		}
		ipSet.Interval = true
		err = c.AddSet(ipSet, elems)
		if err != nil {
			return nil, err
		}
		args = args.Add(nftablesutils.SetDAddrSet(ipSet, !neq)...)
	} else {
		exprs, err := nftablesutils.SetCIDRMatcher(nftablesutils.ExprDirectionDestination, rule.LocalIP, false, !neq)
		if err != nil {
			return nil, err
		}
		args = args.Add(exprs...)
	}
	return
}

func (a *NFTables) buildRemoteIPRule(c *nftables.Conn, rule *driver.Rule) (args nftablesutils.Exprs, err error) {
	if enums.IsEmptyIP(rule.RemoteIP) {
		return
	}
	var neq bool
	if strings.HasPrefix(rule.RemoteIP, `!`) {
		neq = true
		rule.RemoteIP = strings.TrimPrefix(rule.RemoteIP, `!`)
	}
	if strings.ContainsAny(rule.RemoteIP, `-,`) {
		var ipSet *nftables.Set
		var elems []nftables.SetElement
		var eErr error
		ips := param.Split(rule.RemoteIP, `,`).Unique().Filter().String()
		if a.base.isIPv4() {
			ipSet = nftablesutils.GetIPv4AddrSet(a.base.TableFilter())
			elems, eErr = setutils.GenerateElementsFromIPv4Address(ips)
		} else {
			ipSet = nftablesutils.GetIPv6AddrSet(a.base.TableFilter())
			elems, eErr = setutils.GenerateElementsFromIPv6Address(ips)
		}
		if eErr != nil {
			err = eErr
			return
		}
		ipSet.Interval = true
		err = c.AddSet(ipSet, elems)
		if err != nil {
			return nil, err
		}
		args = args.Add(nftablesutils.SetSAddrSet(ipSet, !neq)...)
	} else {
		exprs, err := nftablesutils.SetCIDRMatcher(nftablesutils.ExprDirectionSource, rule.RemoteIP, false, !neq)
		if err != nil {
			return nil, err
		}
		args = args.Add(exprs...)
	}
	return
}

func (a *NFTables) parsePorts(c *nftables.Conn, portCfg string, source bool, neq bool) (nftablesutils.Exprs, error) {
	ports := param.Split(portCfg, `,`).Unique().Filter().String()
	var exprs nftablesutils.Exprs
	var portList []uint16
	var portRange [][2]uint16
	for _, port := range ports {
		if !strings.Contains(port, `-`) {
			portN := param.AsUint16(port)
			err := nftablesutils.ValidatePort(portN)
			if err != nil {
				return nil, fmt.Errorf(`%w: %s`, err, portCfg)
			}
			portList = append(portList, portN)
			continue
		}
		parts := strings.SplitN(port, `-`, 2)
		portsUint16 := [2]uint16{}
		for k, v := range parts {
			portsUint16[k] = param.AsUint16(v)
		}
		err := nftablesutils.ValidatePortRange(portsUint16[0], portsUint16[1])
		if err != nil {
			return nil, fmt.Errorf(`%w: %s`, err, portCfg)
		}
		portRange = append(portRange, portsUint16)
	}
	if len(portRange) == 0 && len(portList) == 1 {
		if source {
			exprs = exprs.Add(nftablesutils.SetSPort(portList[0], !neq)...)
		} else {
			exprs = exprs.Add(nftablesutils.SetDPort(portList[0], !neq)...)
		}
		return exprs, nil
	}
	if !neq {
		if len(portRange) == 1 && len(portList) == 0 {
			if source {
				exprs = exprs.Add(nftablesutils.SetSPortRange(portRange[0][0], portRange[0][1])...)
			} else {
				exprs = exprs.Add(nftablesutils.SetDPortRange(portRange[0][0], portRange[0][1])...)
			}
			return exprs, nil
		}
	}
	portSet := nftablesutils.GetPortSet(a.base.TableFilter())
	portSet.Interval = true
	elems, err := setutils.GenerateElementsFromPort(ports)
	if err != nil {
		return nil, fmt.Errorf(`%w: %s`, err, portCfg)
	}
	err = c.AddSet(portSet, elems)
	if err != nil {
		return nil, fmt.Errorf(`%w: %s`, err, portCfg)
	}
	if source {
		exprs = exprs.Add(nftablesutils.SetSPortSet(portSet, !neq)...)
	} else {
		exprs = exprs.Add(nftablesutils.SetDPortSet(portSet, !neq)...)
	}
	return exprs, nil
}

func (a *NFTables) buildLocalPortRule(c *nftables.Conn, rule *driver.Rule) (args nftablesutils.Exprs, err error) {
	if enums.IsEmptyPort(rule.LocalPort) {
		return
	}
	var neq bool
	if strings.HasPrefix(rule.LocalPort, `!`) {
		neq = true
		rule.LocalPort = strings.TrimPrefix(rule.LocalPort, `!`)
	}
	return a.parsePorts(c, rule.LocalPort, false, neq)
}

func (a *NFTables) buildRemotePortRule(c *nftables.Conn, rule *driver.Rule) (args nftablesutils.Exprs, err error) {
	if enums.IsEmptyPort(rule.RemotePort) {
		return
	}
	var neq bool
	if strings.HasPrefix(rule.RemotePort, `!`) {
		neq = true
		rule.RemotePort = strings.TrimPrefix(rule.RemotePort, `!`)
	}
	return a.parsePorts(c, rule.RemotePort, true, neq)
}

func (a *NFTables) buildStateRule(c *nftables.Conn, rule *driver.Rule) (args nftablesutils.Exprs, err error) {
	if len(rule.State) == 0 {
		return
	}
	stateSet := nftablesutils.GetConntrackStateSet(a.base.TableFilter())
	states := strings.Split(rule.State, `,`)
	states = param.StringSlice(states).Unique().Filter().String()
	if len(states) == 0 {
		states = []string{nftablesutils.StateNew, nftablesutils.StateEstablished}
	} else {
		for index, state := range states {
			states[index] = strings.ToLower(state)
		}
	}
	elems := nftablesutils.GetConntrackStateSetElems(states)
	err = c.AddSet(stateSet, elems)
	if err != nil {
		return nil, err
	}
	args = args.Add(nftablesutils.SetConntrackStateSet(stateSet)...)
	return
}

func (a *NFTables) buildConnLimitRule(_ *nftables.Conn, rule *driver.Rule) (args nftablesutils.Exprs, err error) {
	if len(rule.ConnLimit) == 0 {
		return
	}
	var m *expr.Connlimit
	m, err = nftablesutils.ParseConnLimit(rule.ConnLimit)
	if err != nil {
		return
	}
	args = args.Add(m)
	return
}

func (a *NFTables) buildLimitRule(c *nftables.Conn, rule *driver.Rule) (args nftablesutils.Exprs, err error) {
	if len(rule.RateLimit) == 0 {
		setName := rule.GenLimitSetName()
		existSet, existErr := c.GetSetByName(a.base.TableFilter(), setName)
		if existErr != nil {
			return
		}
		c.DelSet(existSet)
		return
	}
	var exp *expr.Limit
	exp, err = nftablesutils.ParseLimits(rule.RateLimit, uint32(rule.RateBurst))
	if err != nil {
		return
	}
	args = args.Add(exp)
	return
}

func (a *NFTables) buildLimitRuleWithTimeout(c *nftables.Conn, rule *driver.Rule) (args nftablesutils.Exprs, err error) {
	setName := rule.GenLimitSetName()
	if len(rule.RateLimit) == 0 {
		existSet, existErr := c.GetSetByName(a.base.TableFilter(), setName)
		if existErr != nil {
			return
		}
		c.DelSet(existSet)
		return
	}
	var set *nftables.Set
	if a.base.isIPv4() {
		set = nftablesutils.GetIPv4AddrSet(a.base.TableFilter())
	} else {
		set = nftablesutils.GetIPv6AddrSet(a.base.TableFilter())
	}
	set.Anonymous = false
	set.Constant = false
	set.Dynamic = true
	set.HasTimeout = true
	if rule.RateExpires > 0 {
		set.Timeout = time.Duration(rule.RateExpires) * time.Second
	} else {
		set.Timeout = 86400 * time.Second
	}
	set.Name = setName

	var existSet *nftables.Set
	existSet, err = c.GetSetByName(a.base.TableFilter(), set.Name)
	if err == nil {
		if existSet.Timeout != set.Timeout {
			c.DelSet(existSet)
		} else {
			goto END
		}
	}
	err = c.AddSet(set, []nftables.SetElement{})
	if err != nil {
		return
	}

END:
	var exprs []expr.Any
	exprs, err = nftablesutils.SetDynamicLimitSet(set, rule.RateLimit, uint32(rule.RateBurst))
	if err != nil {
		return
	}
	args = args.Add(exprs...)
	return
}
