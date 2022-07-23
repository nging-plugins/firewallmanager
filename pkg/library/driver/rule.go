package driver

type Rule struct {
	Type      string `json:"type" xml:"type"`
	Name      string `json:"name" xml:"name"`
	Direction string `json:"direction" xml:"direction"`
	Action    string `json:"action" xml:"action"`
	Protocol  string `json:"protocol" xml:"protocol"`

	// IP or Port
	RemoteIP   string `json:"remoteIP" xml:"remoteIP"`
	LocalIP    string `json:"localIP" xml:"localIP"`
	RemotePort string `json:"remotePort" xml:"remotePort"`
	LocalPort  string `json:"localPort" xml:"localPort"`
}
