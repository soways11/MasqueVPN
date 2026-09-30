//go:build linux

// Package netsetup — системная настройка сети для туннеля: адреса, MTU,
// маршруты, правила маршрутизации, форвардинг и NAT.
//
// Всё делается напрямую через netlink (rtnetlink и nf_tables), без вызова
// внешних `ip`, `iptables` или `nft`: в целевых окружениях этих утилит может
// не быть, а зависеть от PATH клиент не должен.
package netsetup

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// IPv6Available сообщает, включён ли IPv6 в ядре. В некоторых контейнерах и на
// части VPS он выключен целиком (нет даже /proc/sys/net/ipv6).
func IPv6Available() bool {
	_, err := os.Stat("/proc/sys/net/ipv6")
	return err == nil
}

// ConfigureInterface задаёт MTU, поднимает интерфейс и назначает адреса.
// Уже назначенные адреса не считаются ошибкой.
func ConfigureInterface(name string, mtu int, addrs []netip.Prefix) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("netsetup: интерфейс %q: %w", name, err)
	}
	if mtu > 0 {
		if err := netlink.LinkSetMTU(link, mtu); err != nil {
			return fmt.Errorf("netsetup: MTU %d на %q: %w", mtu, name, err)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("netsetup: поднять %q: %w", name, err)
	}
	for _, p := range addrs {
		if err := addrReplace(link, p); err != nil {
			return err
		}
	}
	return nil
}

// ReplaceAddresses меняет адреса интерфейса: добавляет новые, затем удаляет
// те старые, которых нет среди новых. Порядок «сначала добавить» важен: пока
// идёт замена, у интерфейса всегда есть рабочий адрес.
func ReplaceAddresses(name string, old, new []netip.Prefix) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("netsetup: интерфейс %q: %w", name, err)
	}
	keep := map[netip.Prefix]bool{}
	for _, p := range new {
		if err := addrReplace(link, p); err != nil {
			return err
		}
		keep[p] = true
	}
	var errs []error
	for _, p := range old {
		if keep[p] {
			continue
		}
		err := netlink.AddrDel(link, &netlink.Addr{IPNet: ipNet(p)})
		if err != nil && !errors.Is(err, unix.EADDRNOTAVAIL) {
			errs = append(errs, fmt.Errorf("netsetup: удалить %s: %w", p, err))
		}
	}
	return errors.Join(errs...)
}

func addrReplace(link netlink.Link, p netip.Prefix) error {
	if p.Addr().Is6() && !IPv6Available() {
		return fmt.Errorf("netsetup: %s: %w", p, ErrNoIPv6)
	}
	a := &netlink.Addr{IPNet: ipNet(p)}
	if p.Addr().Is6() {
		// Без NODAD адрес несколько секунд висит в состоянии tentative,
		// и первые пакеты с него ядро не отправляет.
		a.Flags = unix.IFA_F_NODAD
	}
	if err := netlink.AddrReplace(link, a); err != nil {
		return fmt.Errorf("netsetup: адрес %s на %q: %w", p, link.Attrs().Name, err)
	}
	return nil
}

// ErrNoIPv6 — в ядре выключен IPv6.
var ErrNoIPv6 = errors.New("IPv6 выключен в ядре")

func ipNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

// SetSysctl записывает значение в /proc/sys (ключ через точки, как у sysctl).
func SetSysctl(key, value string) error {
	path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
		return fmt.Errorf("netsetup: sysctl %s=%s: %w", key, value, err)
	}
	return nil
}

// EnableForwarding включает маршрутизацию пакетов между интерфейсами.
// IPv6 включается, только если он есть в ядре.
func EnableForwarding() error {
	if err := SetSysctl("net.ipv4.ip_forward", "1"); err != nil {
		return err
	}
	if IPv6Available() {
		if err := SetSysctl("net.ipv6.conf.all.forwarding", "1"); err != nil {
			return err
		}
	}
	return nil
}

// DefaultRouteInterface возвращает имя интерфейса маршрута по умолчанию для
// семейства адресов (4 или 6) — туда сервер выпускает трафик клиентов.
func DefaultRouteInterface(family int) (string, error) {
	dst := net.IPv4(1, 1, 1, 1) // адрес не важен: нужен любой внешний
	if family == 6 {
		dst = net.ParseIP("2606:4700::1111")
	}
	routes, err := netlink.RouteGet(dst)
	if err != nil {
		return "", fmt.Errorf("netsetup: маршрут по умолчанию (IPv%d): %w", family, err)
	}
	for _, r := range routes {
		if r.LinkIndex == 0 {
			continue
		}
		link, err := netlink.LinkByIndex(r.LinkIndex)
		if err != nil {
			return "", err
		}
		return link.Attrs().Name, nil
	}
	return "", fmt.Errorf("netsetup: нет маршрута по умолчанию (IPv%d)", family)
}

func linkByName(name string) (netlink.Link, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("netsetup: интерфейс %q: %w", name, err)
	}
	return link, nil
}

func routeReplace(link netlink.Link, p netip.Prefix) error {
	return netlink.RouteReplace(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       ipNet(p),
		Scope:     netlink.SCOPE_LINK,
	})
}

// KillSwitchOff снимает аварийную блокировку (nftables), если она осталась.
// Оставлено для совместимости с прежним именем команды; -cleanup зовёт полную
// уборку (Cleanup), которая делает то же и вдобавок восстанавливает DNS.
func KillSwitchOff() error {
	_, err := removeKillSwitchTable()
	return err
}

// CleanupReport — см. реализацию для Windows.
type CleanupReport struct {
	KillSwitch bool
	NRPT       bool
	Routes     int
	// DNS — возвращён оригинал /etc/resolv.conf, который подменил упавший
	// клиент.
	DNS bool
	// KillSwitchUnchecked — таблицу блокировки проверить не удалось: нет прав
	// на nftables (запуск не от root). Снять root-таблицу без прав всё равно
	// нельзя, поэтому это не ошибка уборки, а оговорка в отчёте.
	KillSwitchUnchecked bool
}

func (r CleanupReport) Empty() bool { return !r.DNS && !r.KillSwitch }

func (r CleanupReport) String() string {
	var s string
	switch {
	case r.Empty():
		s = "следов прошлого запуска нет"
	case r.KillSwitch && r.DNS:
		s = "убрано: аварийная блокировка снята и DNS восстановлен (" + ResolvConf + ")"
	case r.KillSwitch:
		s = "убрано: аварийная блокировка снята"
	default:
		s = "убрано: DNS восстановлен (" + ResolvConf + ")"
	}
	if r.KillSwitchUnchecked {
		s += "; аварийная блокировка не проверена — нет прав на nftables (нужен root)"
	}
	return s
}

// removeKillSwitch — снятие блокировки для Cleanup; подменяется в тестах.
var removeKillSwitch = removeKillSwitchTable

// Cleanup убирает то, что на Linux переживает упавший клиент.
//
// Маршруты и правила живут на туннельном интерфейсе и в своей таблице:
// интерфейс исчезает вместе с процессом, а с ним и маршруты. А вот DNS —
// нет: SetDNS переименовывает /etc/resolv.conf в резервную копию и кладёт
// свой. Упал клиент — система так и живёт с DNS туннеля, пока клиент не
// запустят снова. Служба (masquevpn-client.service) зовёт уборку после
// остановки, чтобы не ждать этого.
//
// Чужой resolv.conf не трогаем: если рядом лежит давняя резервная копия, а
// файл уже не наш (систему с тех пор перенастроили), вернуть копию значило
// бы затереть настройку, сделанную после. Об этом — ошибкой, руками.
func Cleanup() (CleanupReport, error) {
	var rep CleanupReport

	// Сначала аварийная блокировка: это самое опасное, что переживает клиента
	// (машина без сети). Но её ошибка не останавливает уборку: DNS
	// возвращается в любом случае, а ошибки сообщаются вместе.
	var ksErr error
	if removed, err := removeKillSwitch(); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, os.ErrPermission) {
			rep.KillSwitchUnchecked = true
		} else {
			ksErr = fmt.Errorf("netsetup: снятие аварийной блокировки: %w", err)
		}
	} else if removed {
		rep.KillSwitch = true
	}
	dnsErr := restoreDNS(&rep)
	return rep, errors.Join(ksErr, dnsErr)
}

// restoreDNS возвращает resolv.conf, подменённый упавшим клиентом.
func restoreDNS(rep *CleanupReport) error {
	backup := existingBackup()
	if backup == "" {
		return nil // подменённого DNS нет: клиент вышел штатно или не запускался
	}
	if b, err := os.ReadFile(ResolvConf); err == nil && !ownResolvConf(b) {
		return fmt.Errorf("netsetup: рядом с %s лежит %s, но сам %s уже не от клиента — "+
			"не трогаю, чтобы не затереть более новую настройку; сравните файлы и уберите лишний руками",
			ResolvConf, backup, ResolvConf)
	}
	if err := os.Rename(backup, ResolvConf); err != nil {
		return fmt.Errorf("netsetup: восстановление %s: %w", ResolvConf, err)
	}
	rep.DNS = true
	return nil
}
