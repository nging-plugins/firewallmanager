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

package driver

type Rule struct {
	ID        uint   `json:"id,omitempty" xml:"id,omitempty"`
	Number    uint64 `json:"num,omitempty" xml:"num,omitempty"`
	Type      string `json:"type" xml:"type"` // filter / nat / etc.
	Name      string `json:"name" xml:"name"`
	Direction string `json:"direction" xml:"direction"` // INPUT / OUTPUT / etc.
	Action    string `json:"action" xml:"action"`       // ACCEPT / DROP / etc.
	Protocol  string `json:"protocol" xml:"protocol"`   // tcp / udp / etc.

	// interface 网口
	Interface string `json:"interface" xml:"interface"` // 网络入口网络接口
	Outerface string `json:"outerface" xml:"outerface"` // 网络出口网络接口

	// state
	State string `json:"state" xml:"state"`

	// IP or Port
	RemoteIP   string `json:"remoteIP" xml:"remoteIP"`
	LocalIP    string `json:"localIP" xml:"localIP"`
	RemotePort string `json:"remotePort" xml:"remotePort"` // 支持指定范围
	LocalPort  string `json:"localPort" xml:"localPort"`   // 支持指定范围
	IPVersion  string `json:"ipVersion"  xml:"ipVersion"`  // 4 or 6
}
