//go:build linux

package netsetup

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// FullTunnel заворачивает весь трафик устройства в туннель, не ломая путь до
// самого VPN-сервера.
//
// # Как это устроено
//
// Главная ловушка полного туннеля — петля: если маршрут по умолчанию ведёт в
// TUN, то и QUIC-пакеты к серверу уйдут в TUN. Классическое решение —
// отдельный маршрут /32 до сервера через старый шлюз — ломается при смене сети
// и при нескольких адресах сервера. Мы делаем, как wg-quick:
//
//	правило P:   lookup main suppress_prefixlength 0
//	               — все маршруты основной таблицы, КРОМЕ маршрута по умолчанию
//	                 (локальная сеть и явные маршруты продолжают работать)
//	правило P+1: not fwmark M lookup T
//	               — всё немаркированное идёт в таблицу T
//	таблица T:   default dev <tun>
//
// Сокет QUIC помечается меткой M (SO_MARK, см. MarkSocket): его пакеты второе
// правило пропускает, и они идут по обычному маршруту по умолчанию. Смена
// сети или шлюза ничего не ломает — метка не привязана к адресам.
type FullTunnel struct {
	// Iface — имя TUN-интерфейса.
	Iface string
	// Table — номер таблицы маршрутизации; по умолчанию DefaultTable.
	Table int
	// FwMark — метка сокета туннеля; по умолчанию DefaultFwMark.
	FwMark uint32
	// Priority — приоритет первого правила; по умолчанию DefaultRulePriority.
	Priority int
	// IPv6 — заворачивать и IPv6. Если IPv6 в ядре выключен, игнорируется.
	IPv6 bool
}

// Значения по умолчанию для FullTunnel.
const (
	DefaultTable        = 7443
	DefaultFwMark       = 0x7443
	DefaultRulePriority = 7440
)

func (ft *FullTunnel) defaults() {
	if ft.Table == 0 {
		ft.Table = DefaultTable
	}
	if ft.FwMark == 0 {
		ft.FwMark = DefaultFwMark
	}
	if ft.Priority == 0 {
		ft.Priority = DefaultRulePriority
	}
}

func (ft *FullTunnel) families() []int {
	fams := []int{netlink.FAMILY_V4}
	if ft.IPv6 && IPv6Available() {
		fams = append(fams, netlink.FAMILY_V6)
	}
	return fams
}

func (ft *FullTunnel) rules(fam int) []*netlink.Rule {
	suppress := netlink.NewRule()
	suppress.Family = fam
	suppress.Priority = ft.Priority
	suppress.Table = unix.RT_TABLE_MAIN
	suppress.SuppressPrefixlen = 0

	notMarked := netlink.NewRule()
	notMarked.Family = fam
	notMarked.Priority = ft.Priority + 1
	notMarked.Table = ft.Table
	notMarked.Mark = ft.FwMark
	mask := uint32(0xffffffff)
	notMarked.Mask = &mask
	notMarked.Invert = true
	return []*netlink.Rule{suppress, notMarked}
}

// Up включает полный туннель. Остатки прошлого запуска (например, после
// аварийного завершения) предварительно удаляются.
func (ft *FullTunnel) Up() error {
	ft.defaults()
	link, err := netlink.LinkByName(ft.Iface)
	if err != nil {
		return fmt.Errorf("netsetup: интерфейс %q: %w", ft.Iface, err)
	}
	_ = ft.Down()

	// Без src_valid_mark обратная проверка источника (rp_filter) не учитывает
	// метку, и ответы сервера на помеченный сокет могут отбрасываться.
	if err := SetSysctl("net.ipv4.conf.all.src_valid_mark", "1"); err != nil {
		return err
	}
	for _, fam := range ft.families() {
		dst := &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
		if fam == netlink.FAMILY_V6 {
			dst = &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
		}
		r := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       dst,
			Table:     ft.Table,
			Scope:     netlink.SCOPE_LINK,
			Family:    fam,
		}
		if err := netlink.RouteReplace(r); err != nil {
			_ = ft.Down()
			return fmt.Errorf("netsetup: маршрут по умолчанию в таблице %d: %w", ft.Table, err)
		}
		for _, rule := range ft.rules(fam) {
			if err := netlink.RuleAdd(rule); err != nil {
				_ = ft.Down()
				return fmt.Errorf("netsetup: правило %d: %w", rule.Priority, err)
			}
		}
	}
	return nil
}

// Down снимает правила и маршруты полного туннеля. Отсутствующие не считаются
// ошибкой. Маршруты таблицы T исчезнут и сами при удалении интерфейса.
func (ft *FullTunnel) Down() error {
	ft.defaults()
	var errs []error
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		if fam == netlink.FAMILY_V6 && !IPv6Available() {
			continue
		}
		for _, rule := range ft.rules(fam) {
			// Удаляем все копии: после нескольких аварийных запусков их может
			// оказаться больше одной.
			for i := 0; i < 16; i++ {
				err := netlink.RuleDel(rule)
				if err != nil {
					if !errors.Is(err, unix.ENOENT) {
						errs = append(errs, err)
					}
					break
				}
			}
		}
		routes, err := netlink.RouteListFiltered(fam, &netlink.Route{Table: ft.Table}, netlink.RT_FILTER_TABLE)
		if err == nil {
			for i := range routes {
				_ = netlink.RouteDel(&routes[i])
			}
		}
	}
	return errors.Join(errs...)
}

// MarkSocket помечает сокет меткой mark (SO_MARK) — пакеты такого сокета
// идут мимо туннеля. Требует CAP_NET_ADMIN.
func MarkSocket(c syscall.RawConn, mark uint32) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
	})
	if err != nil {
		return err
	}
	if serr != nil {
		return fmt.Errorf("netsetup: SO_MARK: %w", serr)
	}
	return nil
}
