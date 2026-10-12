//go:build linux

package netsetup

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Аварийное отключение на Linux (nftables).
//
// # Что делает
//
// Пока туннель поднят, наружу нельзя ничего, кроме того, что мы явно
// разрешили: сам туннель, помеченный сокет клиента, петля, уже установленные
// соединения, локальные подсети и адреса из kill_switch_allow. Всё остальное
// ядро роняет. Так трафик не утечёт мимо туннеля даже там, где таблица
// маршрутов бессильна (сокет, привязанный к физическому адаптеру).
//
// # Как устроено
//
// Отдельная таблица `inet masquevpn_ks` с цепочкой output и политикой drop —
// тем же способом, что NAT сервера (nat_linux.go): своя таблица, чужие правила
// не трогаем. Пропускающие правила:
//
//   - oifname lo                — петля;
//   - oifname <tun>             — трафик в туннель (там уже зашифровано);
//   - meta mark <fwmark>        — помеченный сокет клиента. QUIC к серверу и
//                                 запросы DNS-прикрытия идут ИМЕННО с этой
//                                 меткой (SO_MARK, см. MarkSocket), поэтому
//                                 отдельно разрешать адрес сервера и резолверы
//                                 не требуется — метка их покрывает;
//   - daddr канальных адресов (broadcast, multicast, link-local), локальных
//     подсетей и kill_switch_allow.
//
// Исключений по состоянию соединения (ct state established) здесь нет
// сознательно — через них наружу уходил поток, открытый до подключения
// туннеля; разбор в addRules.
//
// # Двойная служба: перехват и аварийное отключение
//
// Эта же таблица закрывает единственную лазейку полного туннеля, которую не
// закрыть маршрутами: сокет, привязанный к физическому интерфейсу
// (SO_BINDTODEVICE), ядро отправляет на этот интерфейс само, не спрашивая
// таблицы маршрутизации (см. fulltunnel_linux.go, «Чего маршрутизация не
// может»). Поэтому клиент поднимает таблицу при полном туннеле ВСЕГДА, а флаг
// kill_switch решает другое: что будет ПОСЛЕ краха клиента (см. «Fail-open»).
//
// # Fail-open
//
// Правила nftables переживают смерть процесса. Чтобы упавший клиент не запер
// машину без сети, снятие берут на себя Cleanup при старте, команда
// `vpnclient -cleanup` и сторож (watchdog_linux.go). Режим «упал клиент —
// трафик закрыт» включается отдельным флагом kill_switch_fail_closed: тогда
// сторож не запускается и таблица остаётся до следующего запуска.

const (
	killSwitchTable = "masquevpn_ks"
	killSwitchChain = "output"
)

// KillSwitch держит параметры поднятой блокировки. В отличие от Windows (где
// блокировку держит открытый дескриптор WFP), правила nftables живут сами по
// себе, поэтому объект хранит лишь то, что нужно пересобрать правила в Reapply.
type KillSwitch struct {
	iface string
	mark  uint32
}

// KillSwitchArm поднимает блокировку: таблицу с политикой drop и разрешающими
// правилами. iface — туннельный интерфейс, mark — метка сокета клиента (та же,
// что у полного туннеля), allow — дополнительные разрешённые адреса/подсети
// (kill_switch_allow).
func KillSwitchArm(iface string, mark uint32, allow []netip.Prefix) (*KillSwitch, error) {
	if iface == "" {
		return nil, fmt.Errorf("netsetup: kill switch: не задан интерфейс")
	}
	// На всякий случай снимаем остатки прошлого запуска, чтобы не городить
	// вторую таблицу поверх.
	if _, err := removeKillSwitchTable(); err != nil {
		return nil, err
	}
	k := &KillSwitch{iface: iface, mark: mark}

	c, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("netsetup: nftables: %w", err)
	}
	t := c.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: killSwitchTable})
	drop := nftables.ChainPolicyDrop
	ch := c.AddChain(&nftables.Chain{
		Name:     killSwitchChain,
		Table:    t,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &drop,
	})
	k.addRules(c, t, ch, allow)
	if err := c.Flush(); err != nil {
		_, _ = removeKillSwitchTable()
		return nil, fmt.Errorf("netsetup: kill switch: %w", err)
	}
	return k, nil
}

// Reapply атомарно заменяет разрешающие правила, не снимая блокировку:
// очистка цепочки и новые правила уходят в ОДНОЙ транзакции nftables, поэтому
// промежутка «политика drop без разрешений» не бывает. Политика цепочки (drop)
// при очистке сохраняется.
func (k *KillSwitch) Reapply(allow []netip.Prefix) error {
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("netsetup: nftables: %w", err)
	}
	t := &nftables.Table{Family: nftables.TableFamilyINet, Name: killSwitchTable}
	ch := &nftables.Chain{Name: killSwitchChain, Table: t}
	c.FlushChain(ch)
	k.addRules(c, t, ch, allow)
	if err := c.Flush(); err != nil {
		return fmt.Errorf("netsetup: kill switch reapply: %w", err)
	}
	return nil
}

// Disarm снимает блокировку.
func (k *KillSwitch) Disarm() error {
	_, err := removeKillSwitchTable()
	return err
}

// addRules наполняет цепочку разрешающими правилами. Статические (петля,
// туннель, метка, established) пересобираются при каждом вызове, поэтому Reapply
// после FlushChain восстанавливает и их.
func (k *KillSwitch) addRules(c *nftables.Conn, t *nftables.Table, ch *nftables.Chain, allow []netip.Prefix) {
	accept := func(exprs ...expr.Any) {
		exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})
		c.AddRule(&nftables.Rule{Table: t, Chain: ch, Exprs: exprs})
	}

	// Петля.
	accept(
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname("lo")},
	)
	// Трафик в туннель.
	accept(
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(k.iface)},
	)
	// Помеченный сокет клиента (QUIC к серверу и DNS-прикрытие).
	accept(
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(k.mark)},
	)
	// Исключения по состоянию соединения (ct state established,related)
	// здесь НЕТ, и это решение, а не упущение.
	//
	// Правило «established — можно» пропускало наружу поток, открытый ДО
	// подключения туннеля: он продолжал идти мимо туннеля открытым текстом,
	// пока весь остальной трафик уже перехвачен. Ровно эта дырка известна на
	// Windows (WFP ALE_AUTH_CONNECT не видит уже открытых соединений), и на
	// Linux она была такой же: сквозной тест TestNothingEscapesTunnel ловит
	// её на соединении, привязанном к физическому интерфейсу.
	//
	// Сузить правило до «ответы по входящим соединениям» (ct direction
	// reply) не выходит, и это стоит знать: conntrack в этом пространстве
	// имён начинает следить за потоками ВМЕСТЕ с нашей таблицей — до неё
	// отслеживать было некому. Для давно открытого соединения он создаёт
	// запись по первому увиденному пакету, а это ответ сервера, то есть
	// «входящий»: наши собственные подтверждения оказываются в направлении
	// reply и правило их пропускает. Проверено тем же тестом — утечка
	// оставалась.
	//
	// Плата: пока туннель поднят, машина не отвечает наружу по соединениям,
	// которые начали СНАРУЖЕ на её физический адрес (служба, открытая в
	// интернет, сессия SSH извне). Под полным туннелем это и значит
	// «весь трафик через туннель»; в локальной сети всё работает — её
	// подсети разрешены ниже.
	//
	// Канальные адреса — широковещательные, multicast и link-local. За
	// пределы сегмента они не уходят, то есть утечкой быть не могут, а без
	// них ломается нужное: продление аренды DHCP (255.255.255.255), поиск
	// соседей IPv6 и mDNS. На Windows тот же список (см. localPrefixes).
	for _, p := range append(append(linkScopePrefixes(), localSubnets(k.iface)...), allow...) {
		if m := daddrMatch(p); m != nil {
			accept(m...)
		}
	}
}

// daddrMatch собирает выражения «адрес назначения в подсети p». Повторяет приём
// из nat_linux.go (там saddr), только смещение поля — назначения.
func daddrMatch(p netip.Prefix) []expr.Any {
	p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()).Masked()
	var proto byte = unix.NFPROTO_IPV4
	var off, l uint32 = 16, 4 // ip daddr
	if p.Addr().Is6() {
		if !IPv6Available() {
			return nil
		}
		proto, off, l = unix.NFPROTO_IPV6, 24, 16 // ip6 daddr
	}
	mask := net.CIDRMask(p.Bits(), p.Addr().BitLen())
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: off, Len: l},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: l, Mask: mask, Xor: make([]byte, l)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: p.Addr().AsSlice()},
	}
}

// linkScopePrefixes — адреса, которые не уходят за пределы канала:
// широковещательные, multicast и link-local. Разрешены потому, что утечкой
// быть не могут, а без них ломается продление аренды DHCP, поиск соседей
// IPv6 и mDNS. Список повторяет Windows (killswitch_windows.go,
// localPrefixes).
func linkScopePrefixes() []netip.Prefix {
	out := []netip.Prefix{
		netip.MustParsePrefix("255.255.255.255/32"), // широковещательный
		netip.MustParsePrefix("224.0.0.0/4"),        // multicast
		netip.MustParsePrefix("169.254.0.0/16"),     // link-local
	}
	if IPv6Available() {
		out = append(out,
			netip.MustParsePrefix("fe80::/10"), // link-local
			netip.MustParsePrefix("ff00::/8"),  // multicast
		)
	}
	return out
}

// localSubnets — напрямую подключённые подсети всех интерфейсов, кроме
// туннельного и петли: локальная сеть должна остаться доступной под
// блокировкой, как и на Windows. Ошибку перечисления считаем «подсетей нет» —
// блокировка от этого лишь строже.
func localSubnets(tun string) []netip.Prefix {
	links, err := netlink.LinkList()
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, ln := range links {
		name := ln.Attrs().Name
		if name == tun || name == "lo" {
			continue
		}
		fams := []int{netlink.FAMILY_V4}
		if IPv6Available() {
			fams = append(fams, netlink.FAMILY_V6)
		}
		for _, fam := range fams {
			addrs, err := netlink.AddrList(ln, fam)
			if err != nil {
				continue
			}
			for _, a := range addrs {
				if a.IPNet == nil {
					continue
				}
				ip, ok := netip.AddrFromSlice(a.IPNet.IP)
				if !ok {
					continue
				}
				ones, _ := a.IPNet.Mask.Size()
				out = append(out, netip.PrefixFrom(ip.Unmap(), ones).Masked())
			}
		}
	}
	return out
}

// removeKillSwitchTable удаляет таблицу блокировки, если она есть. Сообщает,
// нашлась ли она. Безвредна, когда снимать нечего.
func removeKillSwitchTable() (bool, error) {
	c, err := nftables.New()
	if err != nil {
		return false, err
	}
	tables, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return false, err
	}
	found := false
	for _, t := range tables {
		if t.Name == killSwitchTable {
			c.DelTable(t)
			found = true
		}
	}
	if !found {
		return false, nil
	}
	if err := c.Flush(); err != nil {
		return false, err
	}
	return true, nil
}
