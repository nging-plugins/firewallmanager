package cmder

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/admpub/gerberos"
	"github.com/admpub/log"
	"github.com/admpub/once"
	"github.com/webx-top/com"
	"github.com/webx-top/echo"
	"github.com/webx-top/echo/defaults"
	"github.com/webx-top/echo/param"

	"github.com/admpub/nging/v5/application/library/config"
	"github.com/admpub/nging/v5/application/library/config/cmder"
	"github.com/admpub/nging/v5/application/library/config/extend"

	firewallConfig "github.com/nging-plugins/firewallmanager/application/library/config"
	"github.com/nging-plugins/firewallmanager/application/library/firewall"
	"github.com/nging-plugins/firewallmanager/application/model"
)

const Name = `firewall`
const DefaultPidFile = `firewall.pid`

func init() {
	cmder.Register(Name, New())
	config.DefaultStartup += "," + Name
	extend.Register(Name, func() interface{} {
		return &firewallConfig.Config{}
	})
}

func Initer() interface{} {
	return &firewallConfig.Config{}
}

func Get() cmder.Cmder {
	return cmder.Get(Name)
}

func GetFirewallConfig() *firewallConfig.Config {
	cm := cmder.Get(Name).(*firewallCmd)
	return cm.FirewallConfig()
}

func StartOnce(writer ...io.Writer) {
	if config.FromCLI().IsRunning(Name) {
		return
	}
	Get().Start(writer...)
}

func Stop() {
	if !config.FromCLI().IsRunning(Name) {
		return
	}
	Get().Stop()
}

func New() cmder.Cmder {
	return &firewallCmd{
		CLIConfig: config.FromCLI(),
		once:      once.Once{},
	}
}

type firewallCmd struct {
	CLIConfig      *config.CLIConfig
	firewallConfig *firewallConfig.Config
	pidFile        string
	once           once.Once
}

func (c *firewallCmd) PidFile() string {
	c.FirewallConfig()
	return c.pidFile
}

func (c *firewallCmd) boot() error {
	cfg := c.FirewallConfig()
	err := com.WritePidFile(c.pidFile)
	if err != nil {
		log.Error(err.Error())
	}

	gerberosCfg := &gerberos.Configuration{
		Verbose:      cfg.Verbose,
		Backend:      cfg.Backend,
		SaveFilePath: cfg.SaveFilePath,
		Rules:        map[string]*gerberos.Rule{},
	}
	if len(gerberosCfg.Backend) == 0 {
		backends := firewall.DynamicRuleBackends.Slice()
		if len(backends) > 0 {
			gerberosCfg.Backend = backends[0].K
		}
	}

	ctx := defaults.NewMockContext()
	ruleM := model.NewRuleDynamic(ctx)
	_, err = ruleM.ListByOffset(nil, nil, 0, -1, `disabled`, `N`)
	if err != nil {
		return err
	}

	for _, row := range ruleM.Objects() {
		rule, err := firewall.DynamicRuleFromDB(ctx, row)
		if err != nil {
			log.Error(err.Error())
		} else {
			gerberosCfg.Rules[param.AsString(row.Id)] = &rule
		}
	}
	echo.Dump(gerberosCfg)

	// Runner
	rn := gerberos.NewRunner(gerberosCfg)
	if err := rn.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize runner: %s", err)
	}
	defer func() {
		if err := rn.Finalize(); err != nil {
			log.Fatalf("failed to finalize runner: %s", err)
		}
	}()
	rn.Run(true)
	return err
}

func (c *firewallCmd) getConfig() *config.Config {
	if config.FromFile() == nil {
		c.CLIConfig.ParseConfig()
	}
	return config.FromFile()
}

func (c *firewallCmd) parseConfig() {
	c.firewallConfig, _ = c.getConfig().Extend.Get(Name).(*firewallConfig.Config)
	if c.firewallConfig == nil {
		c.firewallConfig = &firewallConfig.Config{}
	}
	pidFile := filepath.Join(echo.Wd(), `data/pid/`+Name)
	err := com.MkdirAll(pidFile, os.ModePerm)
	if err != nil {
		log.Error(err)
	}
	pidFile = filepath.Join(pidFile, DefaultPidFile)
	c.pidFile = pidFile
}

func (c *firewallCmd) FirewallConfig() *firewallConfig.Config {
	c.once.Do(c.parseConfig)
	return c.firewallConfig
}

func (c *firewallCmd) StopHistory(_ ...string) error {
	if c.getConfig() == nil {
		return nil
	}
	return com.CloseProcessFromPidFile(c.PidFile())
}

func (c *firewallCmd) Start(writer ...io.Writer) error {
	err := c.StopHistory()
	if err != nil {
		log.Error(err.Error())
	}
	ctx := defaults.NewMockContext()
	ruleM := model.NewRuleDynamic(ctx)
	exists, err := ruleM.ExistsAvailable()
	if err != nil {
		log.Error(err.Error())
	}
	if !exists { // 没有有效用户时无需启动
		return nil
	}
	params := []string{os.Args[0], `--config`, c.CLIConfig.Conf, `--type`, Name}
	cmd := com.RunCmdWithWriter(params, writer...)
	c.CLIConfig.CmdSet(Name, cmd)
	return nil
}

func (c *firewallCmd) Stop() error {
	c.CLIConfig.CmdSendSignal(Name, syscall.SIGINT)
	time.Sleep(time.Second)
	return c.CLIConfig.CmdStop(Name)
}

func (c *firewallCmd) Reload() error {
	err := c.Stop()
	if err != nil {
		log.Error(err)
	}
	err = c.StopHistory()
	if err != nil {
		log.Error(err.Error())
	}
	c.once.Reset()
	return c.Start()
}

func (c *firewallCmd) Restart(writer ...io.Writer) error {
	err := c.Stop()
	if err != nil {
		log.Error(err)
	}
	return c.Start(writer...)
}
