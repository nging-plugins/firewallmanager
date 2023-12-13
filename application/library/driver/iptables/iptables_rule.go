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

package iptables

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/nging-plugins/firewallmanager/application/library/driver"
	"github.com/nging-plugins/firewallmanager/application/library/enums"
	"github.com/webx-top/com"
	"github.com/webx-top/echo/param"
)

func appendArgs(to *[]string, from []string) {
	if len(from) == 0 {
		return
	}
	*to = append(*to, from...)
}

func (a *IPTables) buildCommonRule(rule *driver.Rule) (args []string, err error) {
	args, err = a.buildProtoRule(rule)
	if err != nil {
		return
	}
	if com.InSlice(rule.Direction, enums.InputIfaceChainList) && !enums.IsEmptyIface(rule.Interface) {
		args = append(args, `-i`, rule.Interface)
	}

	if com.InSlice(`localIp`, enums.ChainParams[rule.Direction]) {
		_args, _err := a.buildLocalIPRule(rule)
		if _err != nil {
			err = _err
			return
		}
		appendArgs(&args, _args)
	}

	if com.InSlice(`localPort`, enums.ChainParams[rule.Direction]) {
		_args, _err := a.buildLocalPortRule(rule)
		if _err != nil {
			err = _err
			return
		}
		appendArgs(&args, _args)
	}

	if com.InSlice(rule.Direction, enums.OutputIfaceChainList) && !enums.IsEmptyIface(rule.Outerface) {
		args = append(args, `-o`, rule.Outerface)
	}

	if com.InSlice(`remoteIp`, enums.ChainParams[rule.Direction]) {
		_args, _err := a.buildRemoteIPRule(rule)
		if _err != nil {
			err = _err
			return
		}
		appendArgs(&args, _args)
	}

	if com.InSlice(`remotePort`, enums.ChainParams[rule.Direction]) {
		_args, _err := a.buildRemotePortRule(rule)
		if _err != nil {
			err = _err
			return
		}
		appendArgs(&args, _args)
	}
	cmt := &ModuleComment{
		Comment: CommentPrefix + rule.IDString(),
	}
	args = append(args, cmt.Args()...)
	return
}

func (a *IPTables) buildProtoRule(rule *driver.Rule) (args []string, err error) {
	args = []string{
		`-p`, rule.Protocol,
	}
	return
}

func (a *IPTables) buildLocalIPRule(rule *driver.Rule) (args []string, err error) {
	if enums.IsEmptyIP(rule.LocalIP) {
		return
	}
	var neq bool
	if strings.HasPrefix(rule.LocalIP, `!`) {
		neq = true
		rule.LocalIP = strings.TrimPrefix(rule.LocalIP, `!`)
	}
	if strings.ContainsAny(rule.LocalIP, `-,`) {
		ips := param.Split(rule.LocalIP, `,`).Unique().Filter().String()
		for _, ip := range ips {
			if strings.Contains(ip, `-`) {
				args = append(args, `-m`, `iprange`)
				if neq {
					args = append(args, `!`)
				}
				args = append(args, `--dst-range`, ip)
			} else {
				if neq {
					args = append(args, `!`)
				}
				args = append(args, `-d`, ip)
			}
		}
	} else {
		if neq {
			args = append(args, `!`)
		}
		args = append(args, `-d`, rule.LocalIP)
	}
	return
}

func (a *IPTables) buildRemoteIPRule(rule *driver.Rule) (args []string, err error) {
	if enums.IsEmptyIP(rule.RemoteIP) {
		return
	}
	var neq bool
	if strings.HasPrefix(rule.RemoteIP, `!`) {
		neq = true
		rule.RemoteIP = strings.TrimPrefix(rule.RemoteIP, `!`)
	}
	if strings.ContainsAny(rule.RemoteIP, `-,`) {
		ips := param.Split(rule.RemoteIP, `,`).Unique().Filter().String()
		for _, ip := range ips {
			if strings.Contains(ip, `-`) {
				args = append(args, `-m`, `iprange`)
				if neq {
					args = append(args, `!`)
				}
				args = append(args, `--src-range`, ip)
			} else {
				if neq {
					args = append(args, `!`)
				}
				args = append(args, `-s`, ip)
			}
		}
	} else {
		if neq {
			args = append(args, `!`)
		}
		args = append(args, `-s`, rule.RemoteIP)
	}
	return
}

func (a *IPTables) parsePorts(portCfg string, source bool, neq bool) (args []string, err error) {
	var portKey string
	var portsKey string
	if source {
		portKey = `sport`
		portsKey = `sports`
	} else {
		portKey = `dport`
		portsKey = `dports`
	}
	if strings.ContainsAny(portCfg, `-,`) {
		ports := param.Split(portCfg, `,`).Unique().Filter().String()
		for index, port := range ports {
			port = strings.ReplaceAll(port, `-`, `:`)
			ports[index] = port
		}
		switch {
		case len(ports) > 1:
			args = append(args, `-m`, `multiport`)
			if neq {
				args = append(args, `!`)
			}
			args = append(args, `--`+portsKey, strings.Join(ports, `,`))
		case len(ports) == 1:
			if neq {
				args = append(args, `!`)
			}
			args = append(args, `--`+portKey, ports[0])
		}
	} else {
		if neq {
			args = append(args, `!`)
		}
		args = append(args, `--`+portKey, portCfg) // 支持用“:”指定端口范围，例如 “22:25” 指端口 22-25，或者 “:22” 指端口 0-22 或者 “22:” 指端口 22-65535
	}
	return
}

func (a *IPTables) buildLocalPortRule(rule *driver.Rule) (args []string, err error) {
	if enums.IsEmptyPort(rule.LocalPort) {
		return
	}
	var neq bool
	if strings.HasPrefix(rule.LocalPort, `!`) {
		neq = true
		rule.LocalPort = strings.TrimPrefix(rule.LocalPort, `!`)
	}
	return a.parsePorts(rule.LocalPort, false, neq)
}

func (a *IPTables) buildRemotePortRule(rule *driver.Rule) (args []string, err error) {
	if enums.IsEmptyPort(rule.RemotePort) {
		return
	}
	var neq bool
	if strings.HasPrefix(rule.RemotePort, `!`) {
		neq = true
		rule.RemotePort = strings.TrimPrefix(rule.RemotePort, `!`)
	}
	return a.parsePorts(rule.RemotePort, true, neq)
}

func (a *IPTables) buildStateRule(rule *driver.Rule) (args []string, err error) {
	if len(rule.State) == 0 {
		return
	}
	args = append(args, `-m`, `state`)
	args = append(args, `--state`, rule.State)
	return
}

func (a *IPTables) buildConnLimitRule(rule *driver.Rule) (args []string, err error) {
	if len(rule.ConnLimit) == 0 {
		return
	}
	var m *ModuleConnLimit
	m, err = ParseConnLimit(rule.ConnLimit)
	if err != nil {
		return
	}
	args = append(args, m.Args()...)
	return
}

func (a *IPTables) buildLimitRule(rule *driver.Rule) (args []string, err error) {
	if len(rule.RateLimit) == 0 {
		return
	}
	var m *ModuleLimit
	m, err = ParseLimits(rule.RateLimit, rule.RateBurst)
	if err != nil {
		return
	}
	args = append(args, m.Args()...)
	return
}

func (a *IPTables) buildHashLimitRule(rule *driver.Rule) (args []string, err error) {
	if len(rule.RateLimit) == 0 {
		return
	}
	var m *ModuleHashLimit
	m, err = ParseHashLimits(rule.RateLimit, rule.RateBurst)
	if err != nil {
		return
	}
	m.Name = rule.GenLimitSetName()
	if rule.RateExpires > 0 {
		m.ExpireMs = rule.RateExpires * 1000
	}
	var mask string
	m.Mode = HashLimitModeSrcIP
	switch m.Mode {
	case HashLimitModeSrcIP:
		if len(rule.RemoteIP) > 0 {
			parts := strings.SplitN(rule.RemoteIP, `/`, 2)
			if len(parts) == 2 {
				mask = parts[1]
			}
		}
	case HashLimitModeDstIP:
		if len(rule.LocalIP) > 0 {
			parts := strings.SplitN(rule.LocalIP, `/`, 2)
			if len(parts) == 2 {
				mask = parts[1]
			}
		}
	}
	if len(mask) > 0 {
		var i uint64
		i, err = strconv.ParseUint(mask, 10, 16)
		if err != nil {
			err = fmt.Errorf(`failed to parse mask number (%v): %v`, mask, err)
			return
		}
		m.Mask = uint16(i)
	}
	args = append(args, m.Args()...)
	return
}
