package config

import (
	"github.com/admpub/nging/v4/application/library/config"
	"github.com/admpub/nging/v4/application/library/config/extend"
)

func init() {
	extend.Register(`firewall`, func() interface{} {
		return &Config{}
	})
}

func Get() *Config {
	cfg, _ := config.MustGetConfig().Extend.Get(`firewall`).(*Config)
	if cfg == nil {
		cfg = &Config{}
	}
	return cfg
}

type Config struct {
	BackendType string `json:"backendType"`
}
