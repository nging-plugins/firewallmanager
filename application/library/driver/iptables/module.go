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
	"strings"

	"github.com/webx-top/echo/param"
)

var ModuleList = []string{`comment`, `string`, `time`, `connlimit`, `limit`}

type ModuleComment struct {
	Comment string // 注释
}

func (m *ModuleComment) Strings() []string {
	var rs []string
	if len(m.Comment) > 0 {
		rs = append(rs, `--comment`, m.Comment)
	}
	return rs
}

func (m *ModuleComment) ModuleStrings() []string {
	return []string{`-m`, `comment`}
}

func (m *ModuleComment) String() string {
	return strings.Join(m.ModuleStrings(), ` `) + ` ` + strings.Join(m.Strings(), ` `)
}

type ModuleString struct {
	Find string // 指定需要匹配的字符串。
	Algo string // 指定对应的匹配算法，可用算法为bm、kmp，此选项为必选项。
}

func (m *ModuleString) Strings() []string {
	var rs []string
	if len(m.Find) > 0 {
		rs = append(rs, `--string`, m.Find)
	}
	if len(m.Algo) == 0 {
		m.Algo = `bm`
	}
	rs = append(rs, `--algo`, m.Algo)
	return rs
}

func (m *ModuleString) ModuleStrings() []string {
	return []string{`-m`, `string`}
}

func (m *ModuleString) String() string {
	return strings.Join(m.ModuleStrings(), ` `) + ` ` + strings.Join(m.Strings(), ` `)
}

type ModuleTime struct {
	Date      [2]string // 2006-01-02
	Time      [2]string // 15:04:05
	Weekdays  []uint    // 1-7
	Monthdays []uint    // 1-28/30/31
	KernelTZ  bool      // KernelTZ 为 false 的情况下，以上参数时间的时区为 UTC。否则为本地机器时区。
}

func joinUint(vals []uint, sep string) string {
	r := make([]string, len(vals))
	for i, v := range vals {
		r[i] = param.AsString(v)
	}
	return strings.Join(r, sep)
}

func (m *ModuleTime) Strings() []string {
	var rs []string
	if len(m.Date[0]) > 0 {
		rs = append(rs, `--datestart`, m.Date[0])
	}
	if len(m.Date[1]) > 0 {
		rs = append(rs, `--datestop`, m.Date[1])
	}
	if len(m.Time[0]) > 0 {
		rs = append(rs, `--timestart`, m.Time[0])
	}
	if len(m.Time[1]) > 0 {
		rs = append(rs, `--timestop`, m.Time[1])
	}
	if len(m.Monthdays) > 0 {
		rs = append(rs, `--monthdays`, joinUint(m.Monthdays, `,`))
	}
	if len(m.Weekdays) > 0 {
		rs = append(rs, `--weekdays`, joinUint(m.Weekdays, `,`))
	}
	if m.KernelTZ {
		rs = append(rs, `--kerneltz`)
	}
	return rs
}

func (m *ModuleTime) ModuleStrings() []string {
	return []string{`-m`, `time`}
}

func (m *ModuleTime) String() string {
	return strings.Join(m.ModuleStrings(), ` `) + ` ` + strings.Join(m.Strings(), ` `)
}

type ModuleConnLimit struct {
	ConnLimitAbove uint // 单独使用此选项时，表示限制每个IP的链接数量。
	ConnLimitMask  uint // 此选项不能单独使用，在使用–connlimit-above选项时，配合此选项，则可以针对”某类IP段内的一定数量的IP”进行连接数量的限制。例如 24 或 27。
}

func (m *ModuleConnLimit) Strings() []string {
	var rs []string
	if m.ConnLimitAbove > 0 {
		rs = append(rs, `--connlimit-above`, param.AsString(m.ConnLimitAbove))
		if m.ConnLimitMask > 0 {
			rs = append(rs, `--connlimit-mask`, param.AsString(m.ConnLimitMask))
		}
	}
	return rs
}

func (m *ModuleConnLimit) ModuleStrings() []string {
	return []string{`-m`, `connlimit`}
}

func (m *ModuleConnLimit) String() string {
	return strings.Join(m.ModuleStrings(), ` `) + ` ` + strings.Join(m.Strings(), ` `)
}

type ModuleLimit struct {
	Limit      uint   // 指定令牌桶中生成新令牌的频率
	Unit       string // 时间单位 second、minute、hour、day
	LimitBurst uint   // 指定令牌桶中令牌的最大数量
}

func (m *ModuleLimit) Strings() []string {
	var rs []string
	if m.LimitBurst > 0 {
		rs = append(rs, `--limit-burst`, param.AsString(m.LimitBurst))
	}
	if m.LimitBurst > 0 && len(m.Unit) > 0 {
		rs = append(rs, `--limit`, param.AsString(m.Limit)+`/`+m.Unit)
	}
	return rs
}

func (m *ModuleLimit) ModuleStrings() []string {
	return []string{`-m`, `limit`}
}

func (m *ModuleLimit) String() string {
	return strings.Join(m.ModuleStrings(), ` `) + ` ` + strings.Join(m.Strings(), ` `)
}