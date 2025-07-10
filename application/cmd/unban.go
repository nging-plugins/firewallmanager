package cmd

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/coscms/webcore/cmd"
	"github.com/nging-plugins/firewallmanager/application/library/firewall"
	"github.com/spf13/cobra"
)

var unbanCmd = &cobra.Command{
	Use:     "unban",
	Short:   "clear banned ip",
	Long:    `Usage ./webx unban or ./webx unban dynamic`,
	RunE:    unbanRunE,
	Example: `./webx unban <ip1> <ip2>... or ./webx unban dynamic <ip1> <ip2>...`,
}

func unbanRunE(cmd *cobra.Command, args []string) error {
	var onlyDynamic bool
	var ipv4 []string
	var ipv6 []string
	var inputIPs []string
	length := len(args)
	if length > 0 {
		if args[0] == `dynamic` {
			onlyDynamic = true
			if length > 1 {
				inputIPs = args[1:]
			}
		} else {
			inputIPs = args
		}
	}
	for _, ip := range inputIPs {
		for _, v := range strings.Split(ip, `,`) {
			v = strings.TrimSpace(v)
			if len(v) == 0 {
				continue
			}
			bv := net.ParseIP(ip)
			if bv == nil {
				continue
			}
			if bv.To4() != nil {
				ipv4 = append(ipv4, v)
			} else {
				ipv6 = append(ipv6, v)
			}
		}
	}

	var err error
	hasIPv4 := len(ipv4) > 0
	hasIPv6 := len(ipv6) > 0
	if len(inputIPs) > 0 && !hasIPv4 && !hasIPv6 {
		err = errors.New(`please enter valid IP address`)
		return err
	}
	hasInputIP := hasIPv4 || hasIPv6

	if !onlyDynamic {
		if !hasInputIP || hasIPv4 {
			err = firewall.Unban(`4`, ipv4...)
			if err != nil {
				fmt.Println(err)
			}
		}
		if !hasInputIP || hasIPv6 {
			err = firewall.Unban(`6`, ipv6...)
			if err != nil {
				fmt.Println(err)
			}
		}
	}

	if !hasInputIP || hasIPv4 {
		err = firewall.UnbanDynamic(`4`, ipv4...)
		if err != nil {
			fmt.Println(err)
		}
	}

	if !hasInputIP || hasIPv6 {
		err = firewall.UnbanDynamic(`6`, ipv6...)
		if err != nil {
			fmt.Println(err)
		}
	}
	return err
}

func init() {
	cmd.Add(unbanCmd)
}
