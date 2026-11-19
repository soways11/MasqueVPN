//go:build linux

package netsetup

import (
	"fmt"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

const tunnelFilterTable = "masquevpn_ingress"

// FilterTunnel ограничивает доступ с серверного TUN к самому серверу и
// сетям за ним. Фильтр работает независимо от NAT.
func FilterTunnel(iface string, gateways, allow []netip.Prefix, allowPeers bool) (func() error, error) {
	name := tunnelFilterTable
	if iface != "masquevpn0" {
		// У каждого TUN своя таблица. Кодируем имя интерфейса, чтобы
		// в имени таблицы были только допустимые символы.
		name = fmt.Sprintf("%s_%x", name, iface)
	}
	c, err := nftables.New()
	if err != nil {
		return nil, err
	}
	tables, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return nil, err
	}
	for _, table := range tables {
		if table.Name == name {
			c.DelTable(table)
			break
		}
	}
	table := c.AddTable(&nftables.Table{Name: name, Family: nftables.TableFamilyINet})
	addTunnelFilterRules(c, table, iface, gateways, allow, allowPeers)
	if err := c.Flush(); err != nil {
		return nil, fmt.Errorf("nftables: %w", err)
	}
	return func() error {
		c.DelTable(table)
		return c.Flush()
	}, nil
}

func addTunnelFilterRules(c *nftables.Conn, table *nftables.Table, iface string, gateways, allow []netip.Prefix, allowPeers bool) {
	input := c.AddChain(&nftables.Chain{
		Name: "input", Table: table, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityFilter,
	})
	forward := c.AddChain(&nftables.Chain{
		Name: "forward", Table: table, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter,
	})
	rule := func(chain *nftables.Chain, verdict expr.VerdictKind, match ...expr.Any) {
		expressions := []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(iface)},
		}
		expressions = append(expressions, match...)
		expressions = append(expressions, &expr.Verdict{Kind: verdict})
		c.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: expressions})
	}

	// Пакеты между клиентами уже проверены политикой CONNECT-IP. Повторяем
	// решение по выходному интерфейсу и после возможного DNAT.
	peerVerdict := expr.VerdictDrop
	if allowPeers {
		peerVerdict = expr.VerdictAccept
	}
	rule(forward, peerVerdict,
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(iface)},
	)
	for _, prefix := range allow {
		if dest := daddrMatch(prefix); dest != nil {
			rule(input, expr.VerdictAccept, dest...)
			rule(forward, expr.VerdictAccept, dest...)
		}
	}

	// Оставляем ping адреса шлюза для диагностики. Остальной доступ к
	// локальным службам сервера требует явного исключения.
	for _, gateway := range gateways {
		addr := gateway.Addr()
		dest := daddrMatch(netip.PrefixFrom(addr, addr.BitLen()))
		if dest == nil {
			continue
		}
		protocol, echo := byte(unix.IPPROTO_ICMP), byte(8)
		if addr.Is6() {
			protocol, echo = unix.IPPROTO_ICMPV6, 128
		}
		rule(input, expr.VerdictAccept, append(dest,
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protocol}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Len: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{echo}},
		)...)
	}
	rule(input, expr.VerdictDrop)

	for _, prefix := range restrictedTunnelDestinations {
		if dest := daddrMatch(prefix); dest != nil {
			rule(forward, expr.VerdictDrop, dest...)
		}
	}
	if global := daddrMatch(netip.MustParsePrefix("2000::/3")); global != nil {
		rule(forward, expr.VerdictAccept, global...)
		rule(forward, expr.VerdictDrop,
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV6}},
		)
	}
}

var restrictedTunnelDestinations = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("168.63.129.16/32"), // адрес платформы Azure
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/3"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
}
