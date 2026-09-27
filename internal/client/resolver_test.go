package client

import (
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/soways11/masquevpn/internal/config"
)

func testClientConfig() *config.Client {
	c := &config.Client{
		Server:    "example.test:443",
		AuthKey:   config.Key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
		Transport: "quic",
	}
	return c
}

// Выбор резолвера — не деталь реализации, а то, работает ли клиент на чужой
// машине вообще.
//
// Встроенный в Go резолвер собирает DNS-серверы со ВСЕХ сетевых адаптеров и
// опрашивает их по порядку. Стоит остаться отключённому виртуальному
// адаптеру — от VirtualBox, WSL, другого VPN-клиента, — и первый же запрос
// уходит в никуда и истекает по таймауту. Пользователь видит «сервер не
// найден», хотя браузер на той же машине открывает тот же домен мгновенно.
// Системный резолвер этого не делает: он знает порядок адаптеров, NRPT,
// hosts и DoH.
//
// Поэтому системный — по умолчанию, а встроенный включается ровно тогда,
// когда без него нельзя: его сокет нужно увести мимо туннеля, и своё Dial
// уважает только он.
func TestSystemResolverUnlessSocketMustBeProtected(t *testing.T) {
	d, err := NewDialer(testClientConfig(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if d.resolver.PreferGo {
		t.Error("без защиты сокета выбран встроенный резолвер: на машине с " +
			"отключённым виртуальным адаптером имя сервера не разрешится")
	}
	if d.resolver.Dial != nil {
		t.Error("без защиты сокета задан свой Dial")
	}
}

func TestProtectedResolverUsesOwnDial(t *testing.T) {
	called := false
	d, err := NewDialer(testClientConfig(), Options{
		Protect: func(syscall.RawConn) error { called = true; return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !d.resolver.PreferGo {
		t.Error("при защите сокета нужен встроенный резолвер: системный не " +
			"даст пометить сокет, и запрос уйдёт в туннель, которого ещё нет")
	}
	if d.resolver.Dial == nil {
		t.Fatal("при защите сокета не задан свой Dial — сокет не будет помечен")
	}
	_ = called
}

// Адрес вместо имени не должен вообще доходить до резолвера, и при этом
// обязан попасть в ServerIP: по нему платформы уводят трафик туннеля мимо
// туннеля.
func TestLiteralAddressSkipsResolution(t *testing.T) {
	cfg := testClientConfig()
	cfg.Server = "192.0.2.10:443"
	cfg.ServerName = "example.test"
	d, err := NewDialer(cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	addr, err := d.resolve(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if addr != "192.0.2.10:443" {
		t.Fatalf("получен адрес %q", addr)
	}
	if got := d.ServerIP().String(); got != "192.0.2.10" {
		t.Fatalf("ServerIP = %q — полный туннель завернёт сам себя", got)
	}
	// Маскировка при этом остаётся доменной: в SNI и :authority идёт имя.
	if got := d.authority(); got != "example.test" {
		t.Fatalf("authority = %q, ожидалось имя из server_name", got)
	}
}

// fakeDNS — UDP-резолвер на 127.0.0.1, отвечающий на A-запрос адресом ip и
// считающий запросы. Настоящий DNS-формат, а не заглушка на уровне Go:
// проверяется ровно тот путь, которым пойдёт запрос на телефоне.
func fakeDNS(t *testing.T, ip netip.Addr) (netip.AddrPort, *atomic.Int32) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	var hits atomic.Int32
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			hits.Add(1)
			var p dnsmessage.Parser
			h, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true})
			b.EnableCompression()
			_ = b.StartQuestions()
			_ = b.Question(q)
			_ = b.StartAnswers()
			if q.Type == dnsmessage.TypeA {
				_ = b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60},
					dnsmessage.AResource{A: ip.As4()})
			}
			out, err := b.Finish()
			if err == nil {
				pc.WriteTo(out, from)
			}
		}
	}()
	return netip.MustParseAddrPort(pc.LocalAddr().String()), &hits
}

// На Android у Go нет своего списка резолверов (нет /etc/resolv.conf), и он
// идёт в [::1]:53 — «connection refused», что и случилось на первом живом
// запуске. С Resolvers запрос обязан уйти на заданные серверы, и сокет его
// при этом защищается (иначе при переподключении он ушёл бы в туннель).
func TestProtectedResolverUsesGivenServers(t *testing.T) {
	want := netip.MustParseAddr("203.0.113.7")
	dead := netip.MustParseAddrPort("127.0.0.1:9") // никто не слушает
	live, hits := fakeDNS(t, want)

	var protected atomic.Int32
	d, err := NewDialer(testClientConfig(), Options{
		Protect:   func(syscall.RawConn) error { protected.Add(1); return nil },
		Resolvers: []netip.AddrPort{dead, live},
	})
	if err != nil {
		t.Fatal(err)
	}
	addr, err := d.resolve(t.Context())
	if err != nil {
		t.Fatalf("имя не разрешилось через заданные резолверы: %v", err)
	}
	if addr != "203.0.113.7:443" {
		t.Fatalf("получен адрес %q", addr)
	}
	if hits.Load() == 0 {
		t.Fatal("заданный резолвер не получил ни одного запроса")
	}
	if protected.Load() == 0 {
		t.Fatal("сокет запроса к резолверу не защищён")
	}
}

// Первый резолвер молчит (недоступен, пакеты теряются) — через
// perServerTimeout спрашивается следующий, и имя находится. И наоборот:
// когда первый отвечает, до запасного дело не доходит вовсе — запасной
// (1.1.1.1 из конфигурации) не должен получать лишних запросов, тем более
// половину из них, как было при раздаче запросов по кругу.
func TestResolversAskedInOrder(t *testing.T) {
	want := netip.MustParseAddr("203.0.113.8")
	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	silentAddr := netip.MustParseAddrPort(silent.LocalAddr().String())
	live, liveHits := fakeDNS(t, want)
	spare, spareHits := fakeDNS(t, netip.MustParseAddr("198.51.100.99"))

	protect := func(syscall.RawConn) error { return nil }

	d, err := NewDialer(testClientConfig(), Options{Protect: protect, Resolvers: []netip.AddrPort{silentAddr, live}})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	addr, err := d.resolve(t.Context())
	if err != nil {
		t.Fatalf("молчащий первый резолвер не пропущен: %v", err)
	}
	if addr != "203.0.113.8:443" {
		t.Fatalf("адрес %q", addr)
	}
	if el := time.Since(start); el > perServerTimeout+2*time.Second {
		t.Fatalf("разрешение заняло %v — молчащий резолвер держал слишком долго", el)
	}
	if liveHits.Load() == 0 {
		t.Fatal("второй резолвер не спросили")
	}

	d2, err := NewDialer(testClientConfig(), Options{Protect: protect, Resolvers: []netip.AddrPort{live, spare}})
	if err != nil {
		t.Fatal(err)
	}
	addr, err = d2.resolve(t.Context())
	if err != nil || addr != "203.0.113.8:443" {
		t.Fatalf("адрес %q, ошибка %v — ответил не первый резолвер", addr, err)
	}
	if n := spareHits.Load(); n != 0 {
		t.Fatalf("запасной резолвер получил %d запросов при живом первом", n)
	}
}
