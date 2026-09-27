//go:build linux

package netsetup

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// NAT выпускает трафик клиентов туннеля в интернет от имени сервера
// (masquerade) через nf_tables — напрямую по netlink, без утилиты nft.
//
// Создаётся отдельная таблица inet (по умолчанию «masquevpn»), которую Up
// пересоздаёт, а Down удаляет целиком: чужие правила не затрагиваются.
//
//	postrouting (nat):  ip  saddr <пул v4> oifname != <tun> masquerade
//	                    ip6 saddr <пул v6> oifname != <tun> masquerade
//	forward (filter):   oifname <tun> tcp flags syn → maxseg size set rt mtu
//
// Второе правило (MSS clamping) подрезает MSS в SYN-ACK от внешних хостов под
// MTU туннеля: тогда крупные TCP-сегменты вниз по туннелю не появляются вовсе,
// а не отбиваются ICMP. ICMP при этом остаётся страховкой для всего остального
// (UDP, хосты, игнорирующие MSS).
type NAT struct {
	// Table — имя таблицы nf_tables; по умолчанию «masquevpn».
	Table string
	// TunIface — имя TUN-интерфейса сервера.
	TunIface string
	// Sources — пулы адресов клиентов.
	Sources []netip.Prefix
	// OutIface — если задан, маскарадинг только при выходе через него.
	// Пусто — через любой интерфейс, кроме TUN.
	OutIface string
	// NoMSSClamp отключает подрезку MSS.
	NoMSSClamp bool
	// NoIPv6 — не маскарадить IPv6.
	//
	// Маскарадинг IPv6 (NAT66) — не то, как IPv6 задуман: обычно хостер
	// выдаёт маршрутизируемый префикс, и клиентам раздаются адреса из него,
	// без трансляции. Если префикс маршрутизирован на сервер, NAT66 надо
	// выключить, иначе он ломает сквозную адресацию без всякой пользы.
	NoIPv6 bool
}

// legacyNATTable — имя таблицы до переименования проекта. Сервер,
// обновлённый поверх прежней версии, иначе оставил бы её рядом с новой:
// два маскарадинга одних и тех же адресов и путаница при разборе правил.
const legacyNATTable = "govpn"

func (n *NAT) tableName() string {
	if n.Table == "" {
		return "masquevpn"
	}
	return n.Table
}

// ifname кодирует имя интерфейса так, как его сравнивает ядро: IFNAMSIZ байт
// с нулевым хвостом.
func ifname(s string) []byte {
	b := make([]byte, unix.IFNAMSIZ)
	copy(b, s)
	return b
}

// Up создаёт (пересоздаёт) таблицу с правилами NAT.
func (n *NAT) Up() error {
	if n.TunIface == "" {
		return fmt.Errorf("netsetup: NAT: не задан TunIface")
	}
	if len(n.Sources) == 0 {
		return fmt.Errorf("netsetup: NAT: не заданы Sources")
	}
	_ = n.Down()

	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("netsetup: nftables: %w", err)
	}
	t := c.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: n.tableName()})
	post := c.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    t,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})
	for _, src := range n.Sources {
		src = src.Masked()
		var proto byte = unix.NFPROTO_IPV4
		var off, l uint32 = 12, 4 // ip saddr
		if src.Addr().Is6() {
			if !IPv6Available() || n.NoIPv6 {
				continue
			}
			proto, off, l = unix.NFPROTO_IPV6, 8, 16 // ip6 saddr
		}
		mask := net.CIDRMask(src.Bits(), src.Addr().BitLen())
		exprs := []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: off, Len: l},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: l, Mask: mask, Xor: make([]byte, l)},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: src.Addr().AsSlice()},
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		}
		if n.OutIface != "" {
			exprs = append(exprs, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(n.OutIface)})
		} else {
			exprs = append(exprs, &expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: ifname(n.TunIface)})
		}
		exprs = append(exprs, &expr.Masq{})
		c.AddRule(&nftables.Rule{Table: t, Chain: post, Exprs: exprs})
	}

	if !n.NoMSSClamp {
		fwd := c.AddChain(&nftables.Chain{
			Name:     "forward",
			Table:    t,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookForward,
			Priority: nftables.ChainPriorityMangle,
		})
		c.AddRule(&nftables.Rule{Table: t, Chain: fwd, Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(n.TunIface)},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
			// tcp flags & syn != 0
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 13, Len: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1, Mask: []byte{0x02}, Xor: []byte{0}},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0}},
			// tcp option maxseg size set rt mtu (ядро только уменьшает MSS)
			&expr.Rt{Register: 1, Key: expr.RtTCPMSS},
			&expr.Byteorder{SourceRegister: 1, DestRegister: 1, Op: expr.ByteorderHton, Len: 2, Size: 2},
			&expr.Exthdr{SourceRegister: 1, Type: 2, Offset: 2, Len: 2, Op: expr.ExthdrOpTcpopt},
		}})
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("netsetup: nftables: %w", err)
	}
	return nil
}

// Down удаляет таблицу NAT, если она есть.
func (n *NAT) Down() error {
	c, err := nftables.New()
	if err != nil {
		return err
	}
	tables, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return err
	}
	found := false
	for _, t := range tables {
		// Таблица прежнего имени снимается вместе с нынешней — только если
		// имя не задано явно (явное — чужая настройка, её не трогаем).
		if t.Name == n.tableName() || (n.Table == "" && t.Name == legacyNATTable) {
			c.DelTable(t)
			found = true
		}
	}
	if !found {
		return nil
	}
	return c.Flush()
}
