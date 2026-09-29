package core

import (
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/soways11/masquevpn/internal/client"
	"github.com/soways11/masquevpn/internal/config"
)

// Здесь проверяется то, что можно проверить без сервера: порядок вызовов,
// отказы и построение описания сети. Работа туннеля целиком проверяется на
// стенде из трёх netns (test/e2e, TestAndroidCoreOnStand) — там ядро
// вызывается ровно так, как его вызывает VpnService.

func testConfig(extra string) string {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	s := `{"server":"vpn.example.test:443","auth_key":"` + key + `"`
	if extra != "" {
		s += "," + extra
	}
	return s + "}"
}

// recorder — приложение: запоминает состояния и строки журнала.
type recorder struct {
	mu      sync.Mutex
	states  []string
	logs    []string
	rebinds []string
}

func (r *recorder) OnState(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.states = append(r.states, s)
}

func (r *recorder) OnLog(level, msg string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.logs = append(r.logs, level+": "+msg)
}

func (r *recorder) OnRebind(j string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rebinds = append(r.rebinds, j)
}

func (r *recorder) seen(s string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, v := range r.states {
		if v == s {
			return true
		}
	}
	return false
}

type okProtector struct{ calls int }

func (p *okProtector) Protect(int) bool { p.calls++; return true }

func TestBadConfigFails(t *testing.T) {
	tn := NewTunnel()
	rec := &recorder{}
	if _, err := tn.Connect(`{"это не конфигурация"`, &okProtector{}, rec); err == nil {
		t.Fatal("битая конфигурация принята")
	}
	if tn.State() != StateError {
		t.Fatalf("состояние %q, ожидалось %q", tn.State(), StateError)
	}
	if !rec.seen(StateConnecting) || !rec.seen(StateError) {
		t.Fatalf("приложение не получило смену состояний: %v", rec.states)
	}
	// После ошибки можно пробовать снова — иначе приложение пришлось бы
	// перезапускать после первой же опечатки в конфигурации.
	if _, err := tn.Connect(`{"опять битая"`, &okProtector{}, rec); err == nil {
		t.Fatal("вторая попытка не состоялась")
	}
}

// Полный туннель без защиты сокета — это туннель, замкнутый сам на себя:
// пакеты QUIC пойдут в тот же интерфейс, который они обслуживают. Молчать
// об этом нельзя, потому что снаружи это выглядит как «просто не работает».
func TestFullTunnelRequiresProtector(t *testing.T) {
	tn := NewTunnel()
	rec := &recorder{}
	_, err := tn.Connect(testConfig(`"full_tunnel":true`), nil, rec)
	if err == nil {
		t.Fatal("полный туннель принят без Protector")
	}
	if !strings.Contains(err.Error(), "Protector") {
		t.Fatalf("ошибка не объясняет причину: %v", err)
	}
}

func TestWrongOrderRejected(t *testing.T) {
	tn := NewTunnel()
	if err := tn.Attach(3); err == nil {
		t.Fatal("Attach прошёл без Connect")
	}
	if err := tn.Rebind(3); err == nil {
		t.Fatal("Rebind прошёл без запущенного туннеля")
	}
	// Stop на неподнятом туннеле — не ошибка: приложение может позвать его
	// из обработчика «пользователь передумал» в любой момент.
	tn.Stop()
	if tn.State() != StateStopped {
		t.Fatalf("после Stop состояние %q", tn.State())
	}
}

func TestStatsAndNetworkJSONAlwaysValid(t *testing.T) {
	tn := NewTunnel()
	for _, s := range []string{tn.StatsJSON(), tn.NetworkJSON()} {
		if !strings.HasPrefix(s, "{") {
			t.Fatalf("не JSON: %q", s)
		}
	}
}

// ---------- описание сети ----------

func parseCfg(t *testing.T, extra string) *config.Client {
	t.Helper()
	c, err := config.ParseClient([]byte(testConfig(extra)))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func has(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func TestNetworkFullTunnelIPv4Only(t *testing.T) {
	cfg := parseCfg(t, `"full_tunnel":true,"ipv6":false,"tun":{"mtu":1280}`)
	addrs := []netip.Prefix{
		netip.MustParsePrefix("10.66.0.2/32"),
		netip.MustParsePrefix("fd66::2/128"),
	}
	nw := networkFor(cfg, addrs, netip.MustParseAddr("203.0.113.5"))

	if !has(nw.Addresses, "10.66.0.2/32") {
		t.Fatalf("адреса %v", nw.Addresses)
	}
	if has(nw.Addresses, "fd66::2/128") {
		t.Fatal("адрес IPv6 отдан системе, хотя IPv6 выключен в конфигурации")
	}
	if !has(nw.Routes, "0.0.0.0/0") {
		t.Fatalf("маршруты %v", nw.Routes)
	}
	// Главное: без адреса IPv6 маршрут ::/0 отдавать нельзя — система
	// заберёт весь IPv6-трафик в интерфейс, из которого он не уйдёт.
	if has(nw.Routes, "::/0") {
		t.Fatal("маршрут ::/0 без адреса IPv6 — это чёрная дыра для всего IPv6")
	}
	if !has(nw.Bypass, "203.0.113.5") {
		t.Fatalf("адрес сервера не попал в исключения: %v", nw.Bypass)
	}
	if nw.MTU != 1280 {
		t.Fatalf("MTU %d", nw.MTU)
	}
}

func TestNetworkFullTunnelDualStack(t *testing.T) {
	cfg := parseCfg(t, `"full_tunnel":true,"ipv6":true,"dns":["1.1.1.1","2606:4700:4700::1111"]`)
	addrs := []netip.Prefix{
		netip.MustParsePrefix("10.66.0.2/32"),
		netip.MustParsePrefix("fd66::2/128"),
	}
	nw := networkFor(cfg, addrs, netip.Addr{})

	if !has(nw.Addresses, "fd66::2/128") {
		t.Fatalf("адрес IPv6 потерян: %v", nw.Addresses)
	}
	if !has(nw.Routes, "::/0") {
		t.Fatalf("при живом адресе IPv6 маршрут ::/0 обязателен: %v", nw.Routes)
	}
	if !has(nw.DNS, "2606:4700:4700::1111") {
		t.Fatalf("DNS IPv6 потерян: %v", nw.DNS)
	}
}

// Резолвер IPv6 при выключенном IPv6 — верный способ получить неработающий
// DNS внутри туннеля: система примет адрес, а ходить по нему будет некуда.
func TestNetworkDropsIPv6DNSWithoutIPv6(t *testing.T) {
	cfg := parseCfg(t, `"full_tunnel":true,"ipv6":false,"dns":["1.1.1.1","2606:4700:4700::1111"]`)
	nw := networkFor(cfg, []netip.Prefix{netip.MustParsePrefix("10.66.0.2/32")}, netip.Addr{})
	if !has(nw.DNS, "1.1.1.1") {
		t.Fatalf("DNS IPv4 потерян: %v", nw.DNS)
	}
	if has(nw.DNS, "2606:4700:4700::1111") {
		t.Fatalf("резолвер IPv6 отдан системе при выключенном IPv6: %v", nw.DNS)
	}
}

func TestNetworkSplitTunnelUsesConfiguredRoutes(t *testing.T) {
	cfg := parseCfg(t, `"full_tunnel":false,"routes":["198.51.100.0/24","192.0.2.0/24"]`)
	nw := networkFor(cfg, []netip.Prefix{netip.MustParsePrefix("10.66.0.2/32")}, netip.Addr{})
	if has(nw.Routes, "0.0.0.0/0") {
		t.Fatalf("раздельный туннель забрал весь трафик: %v", nw.Routes)
	}
	for _, want := range []string{"198.51.100.0/24", "192.0.2.0/24"} {
		if !has(nw.Routes, want) {
			t.Fatalf("маршрут %s потерян: %v", want, nw.Routes)
		}
	}
}

func TestProtectorFailureIsAnError(t *testing.T) {
	// Protector, который отказал, должен приводить к ошибке, а не к
	// молчаливому продолжению: незащищённый сокет — это неработающий туннель.
	fn := protectFunc(refusing{})
	err := fn(fakeRawConn{})
	if err == nil {
		t.Fatal("отказ защиты сокета проглочен")
	}
	if !strings.Contains(err.Error(), "защит") {
		t.Fatalf("ошибка непонятна: %v", err)
	}
}

type refusing struct{}

func (refusing) Protect(int) bool { return false }

// fakeRawConn — syscall.RawConn, который просто зовёт переданную функцию.
type fakeRawConn struct{}

func (fakeRawConn) Control(f func(uintptr)) error { f(7); return nil }
func (fakeRawConn) Read(func(uintptr) bool) error { return nil }
func (fakeRawConn) Write(func(uintptr) bool) error {
	return nil
}

// Строки для экрана есть всегда — и до подключения тоже: экран не должен
// показывать пустые плитки, пока туннель не поднят.
func TestStatsTextsBeforeConnect(t *testing.T) {
	var st map[string]any
	if err := json.Unmarshal([]byte(NewTunnel().StatsJSON()), &st); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"rate_in_text": "0 бит/с", "rate_out_text": "0 бит/с",
		"bytes_in_text": "0 Б", "bytes_out_text": "0 Б",
		"session_text": "00:00",
	}
	for k, v := range want {
		if st[k] != v {
			t.Errorf("%s = %v, ожидалось %q — формат разошёлся с окнами Windows и Linux", k, st[k], v)
		}
	}
}

// Псевдоним устройства доходит до дозвона. Без него телефон всё равно
// работал бы одновременно с ноутбуком, но при каждом перезапуске получал
// бы новый адрес — соединения внутри туннеля рвались бы на ровном месте.
func TestDeviceIDReachesDialer(t *testing.T) {
	tn := NewTunnel()
	tn.SetDeviceID("  телефон-7f3a  ")
	cfg := parseCfg(t, "")
	opt, err := tn.dialOptions(cfg, &okProtector{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if opt.DeviceID != "телефон-7f3a" {
		t.Fatalf("до дозвона дошёл псевдоним %q", opt.DeviceID)
	}
	if opt.Protect == nil {
		t.Fatal("защита сокета потерялась по дороге")
	}
}

// Чем телефон разрешает имя сервера: сначала резолверы сети от системы
// (из dns_cover.servers), затем DNS из конфигурации; IPv4 вперёд, без
// повторов и без заглушек вроде [::1]. Пустой список вернул бы ту самую
// ошибку первого запуска — «lookup … on [::1]:53: connection refused».
func TestBootstrapResolvers(t *testing.T) {
	cfg, err := config.ParseClient([]byte(`{
		"server": "vpn.example.test:443",
		"auth_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"dns_cover": {"servers": ["[2001:db8::53]:53", "192.0.2.53:53", "[::1]:53", "192.0.2.53"]}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	got := bootstrapResolvers(cfg)
	var s []string
	for _, ap := range got {
		s = append(s, ap.String())
	}
	want := "192.0.2.53:53 1.1.1.1:53 [2001:db8::53]:53 [2606:4700:4700::1111]:53"
	if strings.Join(s, " ") != want {
		t.Fatalf("резолверы:\n  %s\nожидалось:\n  %s", strings.Join(s, " "), want)
	}

	// Без резолверов от системы остаётся DNS конфигурации — не пусто.
	bare, err := config.ParseClient([]byte(`{"server": "vpn.example.test:443",
		"auth_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(bootstrapResolvers(bare)) == 0 {
		t.Fatal("без dns_cover список пуст — имя сервера на телефоне не разрешится")
	}
}

// TestStateDirKeepsPorts — с каталогом приложения удачный порт помнится в
// файле (переживает перезапуск телефона), без него — до конца процесса.
func TestStateDirKeepsPorts(t *testing.T) {
	cfg := parseCfg(t, "")

	tn := NewTunnel()
	opt, err := tn.dialOptions(cfg, &okProtector{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if opt.Ports != processPorts {
		t.Fatal("без каталога порт не помнится даже в процессе")
	}

	dir := t.TempDir()
	tn.SetStateDir(" " + dir + " ")
	opt, err = tn.dialOptions(cfg, &okProtector{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	opt.Ports.Remember("vpn.example.com", "2053")
	if _, err := os.Stat(filepath.Join(dir, client.PortsFile)); err != nil {
		t.Fatalf("порт не записан в каталог приложения: %v", err)
	}
	tn2 := NewTunnel()
	tn2.SetStateDir(dir)
	again, err := tn2.dialOptions(cfg, &okProtector{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if again.Ports.Port("vpn.example.com") != "2053" {
		t.Fatal("после «перезапуска» порт не прочитан")
	}
}
