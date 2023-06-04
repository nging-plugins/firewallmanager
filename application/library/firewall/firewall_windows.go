//go:build windows

package firewall

var engine driver.Driver
var engonce sync.Once

func initEngine() {
	var err error
	engine, err = netsh.New()
	if err != nil {
		panic(err)
	}
}

func Engine(_ string) driver.Driver {
	engonce.Do(initEngine)
	return engine
}
