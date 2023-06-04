package driver

type Rule struct {
	Type      string `json:"type" xml:"type"` // filter / nat / etc.
	Name      string `json:"name" xml:"name"`
	Direction string `json:"direction" xml:"direction"` // INPUT / OUTPUT / etc.
	Action    string `json:"action" xml:"action"`       // ACCEPT / DROP / etc.
	Protocol  string `json:"protocol" xml:"protocol"`   // tcp / udp / etc.

	// IP or Port
	RemoteIP   string `json:"remoteIP" xml:"remoteIP"`
	LocalIP    string `json:"localIP" xml:"localIP"`
	RemotePort string `json:"remotePort" xml:"remotePort"` // 支持指定范围
	LocalPort  string `json:"localPort" xml:"localPort"`   // 支持指定范围
	IPVersion  string `json:"ipVersion"  xml:"ipVersion"`  // 4 or 6
}
