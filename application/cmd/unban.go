package cmd

import (
	"fmt"

	"github.com/coscms/webcore/cmd"
	"github.com/nging-plugins/firewallmanager/application/library/firewall"
	"github.com/spf13/cobra"
)

var unbanCmd = &cobra.Command{
	Use:   "unban",
	Short: "clear banned ip",
	Long:  `Usage ./webx unban or ./webx unban dynamic`,
	RunE:  unbanRunE,
}

func unbanRunE(cmd *cobra.Command, args []string) error {
	var onlyDynamic bool
	if len(args) > 0 && args[0] == `dynamic` {
		onlyDynamic = true
	}
	var err error
	if !onlyDynamic {
		err = firewall.Unban(`4`)
		if err != nil {
			fmt.Println(err)
		}
		err = firewall.Unban(`6`)
		if err != nil {
			fmt.Println(err)
		}
	}
	err = firewall.UnbanDynamic(`4`)
	if err != nil {
		fmt.Println(err)
	}
	err = firewall.UnbanDynamic(`6`)
	if err != nil {
		fmt.Println(err)
	}
	return err
}

func init() {
	cmd.Add(unbanCmd)
}
