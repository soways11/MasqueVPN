package config

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var key = base64.StdEncoding.EncodeToString(make([]byte, 32))

func TestClientDefaults(t *testing.T) {
	c, err := ParseClient([]byte(`{"server":"vpn.example.com:443","auth_key":"` + key + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !*c.FullTunnel || !*c.IPv6 || !*c.Rotation.KeepAddress {
		t.Fatal("умолчания: полный туннель, IPv6 и сохранение адреса должны быть включены")
	}
	if c.TUN.Name != "masquevpn0" || c.TUN.MTU != 1280 {
		t.Fatalf("tun = %+v", c.TUN)
	}
	if c.Host() != "vpn.example.com" {
		t.Fatalf("SNI = %q", c.Host())
	}
}

// Опечатка в имени поля — ошибка, а не молчаливое значение по умолчанию.
func TestUnknownFieldRejected(t *testing.T) {
	_, err := ParseClient([]byte(`{"server":"a:443","auth_key":"` + key + `","ful_tunnel":false}`))
	if err == nil || !strings.Contains(err.Error(), "ful_tunnel") {
		t.Fatalf("err = %v", err)
	}
}

func TestClientValidation(t *testing.T) {
	for name, js := range map[string]string{
		"без порта":     `{"server":"a","auth_key":"` + key + `"}`,
		"короткий ключ": `{"server":"a:1","auth_key":"` + base64.StdEncoding.EncodeToString(make([]byte, 8)) + `"}`,
		"транспорт":     `{"server":"a:1","auth_key":"` + key + `","transport":"tcp"}`,
		"shaping":       `{"server":"a:1","auth_key":"` + key + `","shaping":"fast"}`,
		"пустой сплит":  `{"server":"a:1","auth_key":"` + key + `","full_tunnel":false}`,
		"плохой dns":    `{"server":"a:1","auth_key":"` + key + `","dns":["x"]}`,
		"длинное имя":   `{"server":"a:1","auth_key":"` + key + `","tun":{"name":"very-long-interface-name"}}`,
		"длительность":  `{"server":"a:1","auth_key":"` + key + `","rotation":{"every":30}}`,
	} {
		if _, err := ParseClient([]byte(js)); err == nil {
			t.Errorf("%s: ошибка не обнаружена", name)
		}
	}
}

func TestDurationAndKeyFile(t *testing.T) {
	dir := t.TempDir()
	kf := filepath.Join(dir, "key")
	os.WriteFile(kf, []byte(base64.RawURLEncoding.EncodeToString(make([]byte, 40))+"\n"), 0o600)
	// Путь — через json.Marshal: в Windows в нём обратные слэши, а в JSON
	// это начало escape-последовательности.
	keyRef, _ := json.Marshal("file:" + kf)
	c, err := ParseClient([]byte(`{"server":"a:1","auth_key":` + string(keyRef) + `,"rotation":{"every":"30m"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Rotation.Every.D() != 30*time.Minute {
		t.Fatalf("every = %v", c.Rotation.Every.D())
	}
	if b, err := c.AuthKey.Bytes(); err != nil || len(b) != 40 {
		t.Fatalf("ключ из файла: %v %d", err, len(b))
	}
}

func TestServerConfig(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "s.json")
	os.WriteFile(p, []byte(`{"cert_file":"c","key_file":"k","auth_key":"`+key+`","pool6":"fd66::/64"}`), 0o600)
	c, err := LoadServer(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":443" || !*c.WebTransport {
		t.Fatalf("умолчания: %+v", c)
	}
	pools, _ := c.Pools()
	if len(pools) != 1 || !pools[0].Addr().Is6() {
		t.Fatalf("pools = %v (при заданном pool6 IPv4-пул по умолчанию не добавляется)", pools)
	}
	os.WriteFile(p, []byte(`{"cert_file":"c","key_file":"k","auth_key":"`+key+`","pool4":"fd66::/64"}`), 0o600)
	if _, err := LoadServer(p); err == nil {
		t.Fatal("IPv6-сеть в pool4 принята")
	}
}

func TestProfilesResolve(t *testing.T) {
	for _, n := range []string{"", "none", "chrome", "cloud-gaming-up", "cloud-gaming-down"} {
		if _, err := ShapingProfile(n); err != nil {
			t.Errorf("%q: %v", n, err)
		}
	}
	if p, _ := Protocol(""); p != "webtransport" {
		t.Fatalf("протокол по умолчанию %q", p)
	}
}

func TestDNSCoverConfig(t *testing.T) {
	base := `{"server":"a:443","auth_key":"` + key + `"`
	// По умолчанию при полном туннеле прикрытие включено.
	c, err := ParseClient([]byte(base + `}`))
	if err != nil || !c.DNSCoverEnabled() {
		t.Fatalf("прикрытие DNS выключено по умолчанию: %v", err)
	}
	// При раздельном туннеле прикрывать нечего: DNS и так идёт мимо туннеля.
	c, err = ParseClient([]byte(base + `,"full_tunnel":false,"routes":["10.0.0.0/8"]}`))
	if err != nil || c.DNSCoverEnabled() {
		t.Fatalf("раздельный туннель: %v", err)
	}
	// Явное выключение.
	c, err = ParseClient([]byte(base + `,"dns_cover":{"disabled":true}}`))
	if err != nil || c.DNSCoverEnabled() {
		t.Fatalf("dns_cover.disabled не сработал: %v", err)
	}
	// Резолверы: с портом и без.
	c, err = ParseClient([]byte(base + `,"dns_cover":{"servers":["192.0.2.1","192.0.2.2:5353"],"mean_interval":"10s"}}`))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := c.DNSCoverServers()
	if err != nil || len(srv) != 2 || srv[0].Port() != 53 || srv[1].Port() != 5353 {
		t.Fatalf("servers = %v, err = %v", srv, err)
	}
	if c.DNSCover.MeanInterval.D() != 10*time.Second {
		t.Fatalf("mean_interval = %v", c.DNSCover.MeanInterval.D())
	}
	if _, err := ParseClient([]byte(base + `,"dns_cover":{"servers":["не адрес"]}}`)); err == nil {
		t.Fatal("некорректный резолвер принят")
	}
}

func TestPackingConfig(t *testing.T) {
	base := `{"server":"a:443","auth_key":"` + key + `"`
	// По умолчанию кадрирование включено с окном агрегации.
	c, err := ParseClient([]byte(base + `}`))
	if err != nil {
		t.Fatal(err)
	}
	opt, err := c.Packing.Options()
	if err != nil || opt == nil || opt.Window != DefaultAggregationWindow || opt.Pace != nil {
		t.Fatalf("умолчания: %+v %v", opt, err)
	}
	// Выключение.
	c, _ = ParseClient([]byte(base + `,"packing":{"disabled":true}}`))
	if opt, _ := c.Packing.Options(); opt != nil {
		t.Fatal("disabled не сработал")
	}
	// Профиль расписания и переопределения.
	c, err = ParseClient([]byte(base + `,"packing":{"window":"1ms","pace":"cloud-gaming-up","pace_interval":"20ms","burst":4096}}`))
	if err != nil {
		t.Fatal(err)
	}
	opt, err = c.Packing.Options()
	if err != nil || opt.Window != time.Millisecond || opt.Pace == nil {
		t.Fatalf("профиль: %+v %v", opt, err)
	}
	if opt.Pace.Interval == nil || opt.Pace.Size == nil || !opt.Pace.Idle {
		t.Fatalf("расписание не заполнено: %+v", opt.Pace)
	}
	if _, err := ParseClient([]byte(base + `,"packing":{"pace":"турбо"}}`)); err == nil {
		t.Fatal("неизвестный профиль принят")
	}
}

func TestServerTCPAndFallback(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "s.json")
	base := `{"cert_file":"c","key_file":"k","auth_key":"` + key + `"`

	// TCP по умолчанию включён и слушает тот же порт, что и QUIC.
	os.WriteFile(p, []byte(base+`,"listen":"0.0.0.0:8443"}`), 0o600)
	c, err := LoadServer(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.TCPAddr(); got != "0.0.0.0:8443" {
		t.Fatalf("TCPAddr = %q", got)
	}
	// Выключение и отдельный адрес.
	os.WriteFile(p, []byte(base+`,"tcp":{"disabled":true}}`), 0o600)
	if c, _ := LoadServer(p); c.TCPAddr() != "" {
		t.Fatal("tcp.disabled не сработал")
	}
	os.WriteFile(p, []byte(base+`,"tcp":{"listen":"127.0.0.1:8444"}}`), 0o600)
	if c, _ := LoadServer(p); c.TCPAddr() != "127.0.0.1:8444" {
		t.Fatal("tcp.listen не применился")
	}
	// Мусор в адресе прокси и в адресе слушателя — ошибка конфигурации.
	os.WriteFile(p, []byte(base+`,"fallback_proxy":"не адрес"}`), 0o600)
	if _, err := LoadServer(p); err == nil {
		t.Fatal("некорректный fallback_proxy принят")
	}
	os.WriteFile(p, []byte(base+`,"tcp":{"listen":"без-порта"}}`), 0o600)
	if _, err := LoadServer(p); err == nil {
		t.Fatal("некорректный tcp.listen принят")
	}
	// NAT66 выключается явно.
	os.WriteFile(p, []byte(base+`,"nat":{"no_ipv6":true}}`), 0o600)
	if c, _ := LoadServer(p); !c.NAT.NoIPv6 {
		t.Fatal("nat.no_ipv6 не прочитан")
	}
}

// TestServerACMEValidation — ACME нельзя включить в конфигурации, где проверку
// владения доменом пройти нечем: она приходит на TCP/443.
func TestServerACMEValidation(t *testing.T) {
	base := func() *Server {
		return &Server{
			Listen:  ":443",
			AuthKey: Key(strings.Repeat("A", 44)),
			ACME:    ACME{Domains: []string{"vpn.example.com"}},
		}
	}
	// Сертификата из файлов нет — и это нормально: его выпустит ACME.
	c := base()
	c.Defaults()
	if err := c.Validate(); err != nil {
		t.Fatalf("конфигурация с одним только ACME отвергнута: %v", err)
	}
	if c.ACME.CacheDir != DefaultACMECache {
		t.Fatalf("каталог кэша не подставлен: %q", c.ACME.CacheDir)
	}

	// Без TCP-слушателя проверка не пройдёт.
	c = base()
	c.TCP.Disabled = true
	c.Defaults()
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "tls-alpn-01") {
		t.Fatalf("выключенный TCP при ACME пропущен: %v", err)
	}

	// И на чужом порту тоже: удостоверяющий центр ходит только на 443.
	c = base()
	c.TCP.Listen = ":8443"
	c.Defaults()
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "443") {
		t.Fatalf("TCP на 8443 при ACME пропущен: %v", err)
	}

	// Ни ACME, ни файлов — сказать об этом надо прямо.
	c = &Server{Listen: ":443", AuthKey: Key(strings.Repeat("A", 44))}
	c.Defaults()
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "acme.domains") {
		t.Fatalf("конфигурация без сертификата пропущена: %v", err)
	}
}
