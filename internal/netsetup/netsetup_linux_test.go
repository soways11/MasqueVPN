//go:build linux

package netsetup_test

import (
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/vishvananda/netlink"

	"github.com/soways11/masquevpn/internal/netnstest"
	"github.com/soways11/masquevpn/internal/netsetup"
	"github.com/soways11/masquevpn/internal/tun"
)

func TestMain(m *testing.M) { netnstest.Main(m) }

func addrsOf(t *testing.T, name string) []netip.Prefix {
	t.Helper()
	link, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	list, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	var out []netip.Prefix
	for _, a := range list {
		ip, _ := netip.AddrFromSlice(a.IP.To4())
		ones, _ := a.Mask.Size()
		out = append(out, netip.PrefixFrom(ip, ones))
	}
	return out
}

// uplink создаёт «физический» интерфейс с маршрутом по умолчанию —
// то, что у клиента было до включения туннеля.
func uplink(t *testing.T) {
	t.Helper()
	// dummy-интерфейсы есть не во всех ядрах (в песочнице их нет), TUN — везде.
	up, err := tun.Open("uplink0", 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { up.Close() })
	if err := netsetup.ConfigureInterface("uplink0", 1500, []netip.Prefix{netip.MustParsePrefix("192.168.50.2/24")}); err != nil {
		t.Fatal(err)
	}
	d, err := netlink.LinkByName("uplink0")
	if err != nil {
		t.Fatal(err)
	}
	gw := net.IPv4(192, 168, 50, 1)
	if err := netlink.RouteAdd(&netlink.Route{Gw: gw, LinkIndex: d.Attrs().Index}); err != nil {
		t.Fatal(err)
	}
}

func routeDev(t *testing.T, dst string, mark uint32) string {
	t.Helper()
	rs, err := netlink.RouteGetWithOptions(net.ParseIP(dst), &netlink.RouteGetOptions{Mark: mark})
	if err != nil {
		t.Fatalf("route get %s mark %#x: %v", dst, mark, err)
	}
	l, err := netlink.LinkByIndex(rs[0].LinkIndex)
	if err != nil {
		t.Fatal(err)
	}
	return l.Attrs().Name
}

func TestReplaceAddresses(t *testing.T) {
	netnstest.Require(t)
	dev, err := tun.Open("gvaddr0", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	a := netip.MustParsePrefix("10.66.0.5/32")
	b := netip.MustParsePrefix("10.66.0.9/32")
	if err := netsetup.ConfigureInterface("gvaddr0", 1280, []netip.Prefix{a}); err != nil {
		t.Fatal(err)
	}
	// Повторная настройка тем же адресом — не ошибка (переподключение).
	if err := netsetup.ConfigureInterface("gvaddr0", 1280, []netip.Prefix{a}); err != nil {
		t.Fatal(err)
	}
	if got := addrsOf(t, "gvaddr0"); !slices.Equal(got, []netip.Prefix{a}) {
		t.Fatalf("addrs = %v", got)
	}
	if err := netsetup.ReplaceAddresses("gvaddr0", []netip.Prefix{a}, []netip.Prefix{b}); err != nil {
		t.Fatal(err)
	}
	if got := addrsOf(t, "gvaddr0"); !slices.Equal(got, []netip.Prefix{b}) {
		t.Fatalf("после смены addrs = %v", got)
	}
	// Удаление уже отсутствующего адреса не считается ошибкой.
	if err := netsetup.ReplaceAddresses("gvaddr0", []netip.Prefix{a}, []netip.Prefix{b}); err != nil {
		t.Fatal(err)
	}
}

// TestFullTunnelRouting проверяет решение маршрутизации ядра:
// обычный трафик — в TUN, помеченный сокет туннеля — мимо, локальная сеть — мимо.
func TestFullTunnelRouting(t *testing.T) {
	netnstest.Require(t)
	uplink(t)
	dev, err := tun.Open("gvfull0", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	if err := netsetup.ConfigureInterface("gvfull0", 1280, []netip.Prefix{netip.MustParsePrefix("10.66.0.2/32")}); err != nil {
		t.Fatal(err)
	}
	if got := routeDev(t, "8.8.8.8", 0); got != "uplink0" {
		t.Fatalf("до туннеля: %s", got)
	}

	ft := &netsetup.FullTunnel{Iface: "gvfull0", IPv6: true}
	if err := ft.Up(); err != nil {
		t.Fatal(err)
	}
	// Повторный Up (перезапуск после аварии) не плодит правила.
	if err := ft.Up(); err != nil {
		t.Fatal(err)
	}
	rules, _ := netlink.RuleList(netlink.FAMILY_V4)
	ours := 0
	for _, r := range rules {
		if r.Priority == netsetup.DefaultRulePriority || r.Priority == netsetup.DefaultRulePriority+1 {
			ours++
		}
	}
	if ours != 2 {
		t.Fatalf("правил туннеля: %d, want 2", ours)
	}

	if got := routeDev(t, "8.8.8.8", 0); got != "gvfull0" {
		t.Fatalf("обычный трафик идёт через %s, а не через туннель", got)
	}
	if got := routeDev(t, "8.8.8.8", netsetup.DefaultFwMark); got != "uplink0" {
		t.Fatalf("помеченный трафик идёт через %s — будет петля", got)
	}
	if got := routeDev(t, "192.168.50.77", 0); got != "uplink0" {
		t.Fatalf("локальная сеть ушла в туннель (%s)", got)
	}

	if err := ft.Down(); err != nil {
		t.Fatal(err)
	}
	if got := routeDev(t, "8.8.8.8", 0); got != "uplink0" {
		t.Fatalf("после Down: %s", got)
	}
}

// TestMarkSocket — метка реально ставится на сокет.
func TestMarkSocket(t *testing.T) {
	netnstest.Require(t)
	c, err := net.ListenUDP("udp4", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rc, _ := c.SyscallConn()
	if err := netsetup.MarkSocket(rc, 0x7443); err != nil {
		t.Fatal(err)
	}
}

func TestNATTable(t *testing.T) {
	netnstest.Require(t)
	// Таблица от версии до переименования: Up обязан её снять, иначе на
	// обновлённом сервере работали бы два маскарадинга сразу.
	lc, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	lc.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: "govpn"})
	if err := lc.Flush(); err != nil {
		t.Fatal(err)
	}
	n := &netsetup.NAT{TunIface: "gvsrv0", Sources: []netip.Prefix{netip.MustParsePrefix("10.66.0.1/24")}}
	for i := 0; i < 2; i++ { // Up идемпотентен
		if err := n.Up(); err != nil {
			t.Fatal(err)
		}
	}
	c, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	tables, _ := c.ListTablesOfFamily(nftables.TableFamilyINet)
	var tbl *nftables.Table
	for _, x := range tables {
		if x.Name == "masquevpn" {
			tbl = x
		}
		if x.Name == "govpn" {
			t.Fatal("таблица прежнего имени (govpn) осталась после Up")
		}
	}
	if tbl == nil {
		t.Fatal("таблица masquevpn не создана")
	}
	chains, _ := c.ListChainsOfTableFamily(nftables.TableFamilyINet)
	total := 0
	for _, ch := range chains {
		if ch.Table.Name != "masquevpn" {
			continue
		}
		rs, err := c.GetRules(tbl, ch)
		if err != nil {
			t.Fatal(err)
		}
		total += len(rs)
	}
	if total != 2 { // masquerade + MSS clamp
		t.Fatalf("правил: %d, want 2", total)
	}
	if err := n.Down(); err != nil {
		t.Fatal(err)
	}
	tables, _ = c.ListTablesOfFamily(nftables.TableFamilyINet)
	for _, x := range tables {
		if x.Name == "masquevpn" {
			t.Fatal("таблица осталась после Down")
		}
	}
}

func TestSetDNSRestoresSymlink(t *testing.T) {
	dir := t.TempDir()
	target := dir + "/stub-resolv.conf"
	os.WriteFile(target, []byte("nameserver 127.0.0.53\n"), 0o644)
	netsetup.ResolvConf = dir + "/resolv.conf"
	defer func() { netsetup.ResolvConf = "/etc/resolv.conf" }()
	if err := os.Symlink(target, netsetup.ResolvConf); err != nil {
		t.Fatal(err)
	}
	restore, err := netsetup.SetDNS([]netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2606:4700::1111")})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(netsetup.ResolvConf)
	if !strings.Contains(string(b), "nameserver 1.1.1.1\n") || !strings.Contains(string(b), "nameserver 2606:4700::1111\n") {
		t.Fatalf("resolv.conf:\n%s", b)
	}
	if b, _ := os.ReadFile(target); string(b) != "nameserver 127.0.0.53\n" {
		t.Fatal("подмена испортила файл, на который указывала ссылка")
	}

	// Аварийное завершение: restore не вызван, запуск повторяется.
	restore2, err := netsetup.SetDNS([]netip.Addr{netip.MustParseAddr("9.9.9.9")})
	if err != nil {
		t.Fatal(err)
	}
	_ = restore
	if err := restore2(); err != nil {
		t.Fatal(err)
	}
	if l, err := os.Readlink(netsetup.ResolvConf); err != nil || l != target {
		t.Fatalf("после восстановления resolv.conf не ссылка на оригинал: %q %v", l, err)
	}
}

func TestAddRoutes(t *testing.T) {
	netnstest.Require(t)
	dev, err := tun.Open("gvsplit0", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	if err := netsetup.ConfigureInterface("gvsplit0", 1280, []netip.Prefix{netip.MustParsePrefix("10.66.0.3/32")}); err != nil {
		t.Fatal(err)
	}
	if err := netsetup.AddRoutes("gvsplit0", []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}); err != nil {
		t.Fatal(err)
	}
	if got := routeDev(t, "192.0.2.55", 0); got != "gvsplit0" {
		t.Fatalf("сеть идёт через %s", got)
	}
}

// TestSystemResolvers — адреса для прикрытия DNS берутся те, которыми
// система пользуется БЕЗ туннеля; локальные заглушки не годятся.
func TestSystemResolvers(t *testing.T) {
	dir := t.TempDir()
	netsetup.ResolvConf = dir + "/resolv.conf"
	netsetup.SystemdResolvConf = dir + "/systemd-resolv.conf"
	defer func() {
		netsetup.ResolvConf = "/etc/resolv.conf"
		netsetup.SystemdResolvConf = "/run/systemd/resolve/resolv.conf"
	}()

	// Обычный случай: резолверы провайдера, комментарии и зоны игнорируются.
	os.WriteFile(netsetup.ResolvConf, []byte(
		"# комментарий\nsearch lan\nnameserver 192.168.1.1\nnameserver 2001:4860:4860::8888%eth0\n"), 0o644)
	got, err := netsetup.SystemResolvers()
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Addr{netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("2001:4860:4860::8888")}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}

	// systemd-resolved: в resolv.conf заглушка, настоящие адреса — в его файле.
	os.WriteFile(netsetup.ResolvConf, []byte("nameserver 127.0.0.53\noptions edns0\n"), 0o644)
	os.WriteFile(netsetup.SystemdResolvConf, []byte("nameserver 192.0.2.53\n"), 0o644)
	got, err = netsetup.SystemResolvers()
	if err != nil || !slices.Equal(got, []netip.Addr{netip.MustParseAddr("192.0.2.53")}) {
		t.Fatalf("заглушка не обойдена: %v %v", got, err)
	}

	// Одни заглушки и никакого systemd — честная ошибка, а не пустой список.
	os.Remove(netsetup.SystemdResolvConf)
	if got, err := netsetup.SystemResolvers(); err == nil {
		t.Fatalf("вернулись адреса %v, ожидалась ошибка", got)
	}

	// После подмены resolv.conf читается резервная копия: порядок вызовов
	// не должен влиять на результат.
	os.WriteFile(netsetup.ResolvConf, []byte("nameserver 192.168.1.1\n"), 0o644)
	restore, err := netsetup.SetDNS([]netip.Addr{netip.MustParseAddr("10.0.0.53")})
	if err != nil {
		t.Fatal(err)
	}
	defer restore()
	got, err = netsetup.SystemResolvers()
	if err != nil || !slices.Equal(got, []netip.Addr{netip.MustParseAddr("192.168.1.1")}) {
		t.Fatalf("после подмены: %v %v", got, err)
	}
}
