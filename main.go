package main

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"net"
)

func start(cmd *cobra.Command, args []string) error {
	host := cmd.Flag("host").Value.String()
	port := cmd.Flag("port").Value.String()
	domain := args[0]
	client := new(dns.Client)
	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	resp, _, err := client.Exchange(message, net.JoinHostPort(host, port))
	if err != nil {
		return err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return errors.New(fmt.Sprintf("invalid answer name %s after CNAME query for %s", domain, domain))
	}
	for _, answer := range resp.Answer {
		fmt.Println(answer.String())
	}
	return nil
}

func initCommand() *cobra.Command {
	return &cobra.Command{
		Use:          "yxdns -s [SERVER] [DOMAIN]",
		SilenceUsage: true,
		Example:      "yxdns -s 192.168.1.2 xxx.yyy.zzz",
		Short:        "yxdns is a dns client that can specify a DNS server.",
		PreRunE:      cobra.ExactArgs(1),
		RunE:         start,
	}
}

func setupRootCmd(cmd *cobra.Command) {
	cmd.PersistentFlags().StringP("host", "H", "223.5.5.5", "DNS server eg. 223.5.5.5")
	cmd.PersistentFlags().StringP("port", "p", "53", "DNS server eg. 53")
}

func main() {
	cmd := initCommand()
	setupRootCmd(cmd)
	cmd.Execute()
}
