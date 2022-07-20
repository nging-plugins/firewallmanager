package iptables

import (
	"github.com/admpub/go-iptables/iptables"
)

func New() *IPTables {
	return &IPTables{
		IPProtocol: ProtocolIPv4,
		IPTables:   iptables.New(),
	}
}

type IPTables struct {
	IPProtocol iptables.Protocol
	*iptables.IPTables
}

func (a *IPTables) Insert(table, chain string, pos int, rulespec ...string) error {
	return a.IPTables.Insert(table, chain, pos, rulespec...)
}

func (a *IPTables) Append(table, chain string, rulespec ...string) error {
	return a.IPTables.AppendUnique(table, chain, rulespec...)
}

func (a *IPTables) Delete(table, chain string, rulespec ...string) error {
	return a.IPTables.DeleteIfExists(table, chain, rulespec...)
}

func (a *IPTables) Exists(table, chain string, rulespec ...string) (bool, error) {
	return a.IPTables.Exists(table, chain, rulespec...)
}

func (a *IPTables) List(table, chain string) ([]iptables.Stat, error) {
	return a.IPTables.StructuredStats(table, chain)
}
