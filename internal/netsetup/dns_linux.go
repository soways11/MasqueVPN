//go:build linux

package netsetup

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
)

// ResolvConf — путь к resolv.conf (переменная ради тестов).
var ResolvConf = "/etc/resolv.conf"

// SystemdResolvConf — файл, куда systemd-resolved кладёт НАСТОЯЩИЕ адреса
// вышестоящих резолверов. В самом resolv.conf при нём стоит заглушка
// 127.0.0.53, по которой снаружи ничего не видно.
var SystemdResolvConf = "/run/systemd/resolve/resolv.conf"

// dnsMarker — по этой строке узнаётся resolv.conf, написанный нами.
const dnsMarker = "# Сгенерировано masquevpn"

// legacyDNSMarker и legacyBackupSuffix — то же у версии до переименования
// проекта. Клиент, упавший до обновления, оставил файл с прежней меткой и
// копию с прежним суффиксом: их тоже надо узнавать и возвращать, иначе
// система так и жила бы с DNS туннеля.
const (
	legacyDNSMarker    = "# Сгенерировано govpn"
	backupSuffix       = ".masquevpn-backup"
	legacyBackupSuffix = ".govpn-backup"
)

// ownResolvConf сообщает, наш ли это resolv.conf (любой из версий).
func ownResolvConf(b []byte) bool {
	s := string(b)
	return strings.Contains(s, dnsMarker) || strings.Contains(s, legacyDNSMarker)
}

// existingBackup — резервная копия resolv.conf, если она есть: нынешняя
// или оставленная прежней версией. Пусто — копии нет.
func existingBackup() string {
	for _, p := range []string{ResolvConf + backupSuffix, ResolvConf + legacyBackupSuffix} {
		if _, err := os.Lstat(p); err == nil {
			return p
		}
	}
	return ""
}

// SystemResolvers возвращает адреса резолверов, которыми система пользуется
// без туннеля, — к ним идёт фоновое прикрытие DNS (internal/dnscover).
//
// Локальные заглушки (127.0.0.53 от systemd-resolved и прочий loopback)
// отбрасываются: запрос к ним ушёл бы дальше по обычной маршрутизации, то
// есть внутрь туннеля, и снаружи не появилось бы ничего. Вместо заглушки
// берутся вышестоящие резолверы из файла systemd-resolved.
//
// Функция не зависит от того, подменён ли уже resolv.conf: свой файл она
// узнаёт по метке и читает резервную копию.
func SystemResolvers() ([]netip.Addr, error) {
	path := ResolvConf
	if b, err := os.ReadFile(path); err == nil && ownResolvConf(b) {
		if bk := existingBackup(); bk != "" {
			path = bk
		}
	}
	addrs, err := nameservers(path)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		// Остались одни заглушки — спрашиваем systemd-resolved.
		if up, err := nameservers(SystemdResolvConf); err == nil {
			addrs = up
		}
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("netsetup: в %s нет внешних резолверов (одни локальные заглушки)", path)
	}
	return addrs, nil
}

// nameservers читает строки nameserver, пропуская локальные заглушки.
func nameservers(path string) ([]netip.Addr, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		rest, ok := strings.CutPrefix(line, "nameserver")
		if !ok {
			continue
		}
		rest = strings.TrimSpace(rest)
		if rest == "" {
			continue
		}
		// У IPv6-адреса в resolv.conf может быть зона: fe80::1%eth0.
		if i := strings.Index(rest, "%"); i >= 0 {
			rest = rest[:i]
		}
		a, err := netip.ParseAddr(rest)
		if err != nil || a.IsLoopback() || a.IsUnspecified() {
			continue
		}
		out = append(out, a)
	}
	return out, nil
}

// SetDNS подменяет системные DNS-серверы на время работы туннеля и
// возвращает функцию восстановления.
//
// Исходный файл (часто это символическая ссылка systemd-resolved)
// переименовывается, а не переписывается: восстановление — обратное
// переименование, и файл возвращается в точности таким, каким был.
// Если процесс упал, резервная копия остаётся рядом (*.masquevpn-backup), и
// следующий запуск восстановит её перед подменой.
func SetDNS(servers []netip.Addr) (restore func() error, err error) {
	backup := ResolvConf + backupSuffix
	if old := existingBackup(); old != "" {
		// Хвост аварийного завершения (в том числе прежней версии):
		// сначала вернуть оригинал.
		if err := os.Rename(old, ResolvConf); err != nil {
			return nil, fmt.Errorf("netsetup: восстановление %s: %w", ResolvConf, err)
		}
	}
	if err := os.Rename(ResolvConf, backup); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("netsetup: резервная копия %s: %w", ResolvConf, err)
	}
	var b strings.Builder
	b.WriteString(dnsMarker + " на время работы туннеля; оригинал: " + backup + "\n")
	for _, s := range servers {
		b.WriteString("nameserver " + s.String() + "\n")
	}
	if err := os.WriteFile(ResolvConf, []byte(b.String()), 0o644); err != nil {
		_ = os.Rename(backup, ResolvConf)
		return nil, fmt.Errorf("netsetup: запись %s: %w", ResolvConf, err)
	}
	return func() error {
		if _, err := os.Lstat(backup); err != nil {
			return os.Remove(ResolvConf)
		}
		return os.Rename(backup, ResolvConf)
	}, nil
}

// AddRoutes направляет сети через интерфейс (раздельный туннель).
func AddRoutes(iface string, prefixes []netip.Prefix) error {
	link, err := linkByName(iface)
	if err != nil {
		return err
	}
	for _, p := range prefixes {
		if p.Addr().Is6() && !IPv6Available() {
			continue
		}
		if err := routeReplace(link, p); err != nil {
			return fmt.Errorf("netsetup: маршрут %s: %w", p, err)
		}
	}
	return nil
}
