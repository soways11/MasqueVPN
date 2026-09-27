package tunnel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/soways11/masquevpn/internal/masque"
	"github.com/soways11/masquevpn/internal/tun"
)

// memDevice — TUN в памяти: in — то, что «ядро» отдаёт на чтение,
// out — то, что записано в интерфейс.
type memDevice struct {
	in   chan []byte
	out  chan []byte
	once sync.Once
	done chan struct{}
}

func newMemDevice() *memDevice {
	return &memDevice{in: make(chan []byte, 64), out: make(chan []byte, 64), done: make(chan struct{})}
}

func (d *memDevice) Name() string { return "mem0" }
func (d *memDevice) MTU() int     { return 1500 }
func (d *memDevice) Read(b []byte) (int, error) {
	select {
	case p := <-d.in:
		return copy(b, p), nil
	case <-d.done:
		return 0, tun.ErrClosed
	}
}
func (d *memDevice) Write(b []byte) (int, error) {
	select {
	case <-d.done:
		return 0, tun.ErrClosed
	default:
	}
	p := append([]byte(nil), b...)
	select {
	case d.out <- p:
	case <-d.done:
		return 0, tun.ErrClosed
	}
	return len(b), nil
}
func (d *memDevice) Close() error { d.once.Do(func() { close(d.done) }); return nil }

func (d *memDevice) expect(t *testing.T, what string, match func([]byte) bool) []byte {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case p := <-d.out:
			if match(p) {
				return p
			}
		case <-deadline:
			t.Fatalf("не дождались: %s", what)
		}
	}
}

func ipv4(src, dst netip.Addr, proto byte, payload []byte) []byte {
	b := make([]byte, 20+len(payload))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	b[6] = 0x40 // DF
	b[8], b[9] = 64, proto
	s, d := src.As4(), dst.As4()
	copy(b[12:], s[:])
	copy(b[16:], d[:])
	copy(b[20:], payload)
	return b
}

func src4(p []byte) netip.Addr { return netip.AddrFrom4([4]byte(p[12:16])) }
func dst4(p []byte) netip.Addr { return netip.AddrFrom4([4]byte(p[16:20])) }

type testServer struct {
	addr      string
	clientTLS *tls.Config
	dev       *memDevice
	router    *Router
	pool      *masque.IPPool
}

func startServer(t *testing.T, tweak ...func(*masque.ServerConfig)) *testServer {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(cert)

	dev := newMemDevice()
	router := NewRouter(dev, RouterOptions{})
	pool, _ := masque.NewIPPool(netip.MustParsePrefix("10.66.0.0/24"))
	scfg := masque.ServerConfig{
		Pool:            pool,
		OnSession:       router.Serve,
		OnAddressChange: router.AddressChanged,
	}
	for _, f := range tweak {
		f(&scfg)
	}
	h, err := masque.NewHandler(scfg)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := masque.NewHTTP3Server("", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	}, h)
	go srv.Serve(pc)
	ctx, cancel := context.WithCancel(context.Background())
	go router.Run(ctx)
	t.Cleanup(func() { cancel(); srv.Close(); pc.Close() })
	return &testServer{addr: pc.LocalAddr().String(), clientTLS: &tls.Config{RootCAs: roots, ServerName: "localhost"},
		dev: dev, router: router, pool: pool}
}

func (s *testServer) dial(t *testing.T) *masque.Conn { return s.dialAs(t, nil) }

// dialAs — дозвон с заданными заголовками: так подключается клиент с токеном.
func (s *testServer) dialAs(t *testing.T, hdr http.Header) *masque.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := masque.Dial(ctx, masque.ClientConfig{Addr: s.addr, TLSConfig: s.clientTLS,
		Authority: "localhost", Header: hdr})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.WaitForAddress(ctx); err != nil {
		t.Fatal(err)
	}
	for len(c.Routes()) == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	return c
}

// client поднимает насос клиента поверх memDevice.
func (s *testServer) client(t *testing.T) (*memDevice, *masque.Conn, *Counters) {
	return s.clientAs(t, nil)
}

func (s *testServer) clientAs(t *testing.T, hdr http.Header) (*memDevice, *masque.Conn, *Counters) {
	t.Helper()
	c := s.dialAs(t, hdr)
	dev := newMemDevice()
	cnt := new(Counters)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- RunClient(ctx, dev, c, ClientOptions{Counters: cnt}) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("RunClient не завершился после отмены")
		}
	})
	// Сервер регистрирует сессию асинхронно.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := s.router.Lookup(c.AssignedPrefixes()[0].Addr()); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("сессия не зарегистрирована в маршрутизаторе")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return dev, c, cnt
}

var internet = netip.MustParseAddr("198.51.100.10")

// TestRoundTripThroughRouter — пакет из TUN клиента выходит из TUN сервера,
// ответ из TUN сервера доходит до TUN именно своего клиента.
func TestRoundTripThroughRouter(t *testing.T) {
	s := startServer(t)
	devA, a, _ := s.client(t)
	devB, b, _ := s.client(t)
	addrA := a.AssignedPrefixes()[0].Addr()
	addrB := b.AssignedPrefixes()[0].Addr()

	devA.in <- ipv4(addrA, internet, 17, []byte("from-a"))
	devB.in <- ipv4(addrB, internet, 17, []byte("from-b"))
	for i := 0; i < 2; i++ {
		s.dev.expect(t, "пакеты клиентов на сервере", func(p []byte) bool {
			return dst4(p) == internet && (src4(p) == addrA || src4(p) == addrB)
		})
	}

	s.dev.in <- ipv4(internet, addrB, 17, []byte("to-b"))
	s.dev.in <- ipv4(internet, addrA, 17, []byte("to-a"))
	pa := devA.expect(t, "ответ клиенту A", func(p []byte) bool { return true })
	pb := devB.expect(t, "ответ клиенту B", func(p []byte) bool { return true })
	if string(pa[20:]) != "to-a" || string(pb[20:]) != "to-b" {
		t.Fatalf("пакеты перепутаны: A=%q B=%q", pa[20:], pb[20:])
	}

	// Пакет на неизвестный адрес не уходит никому.
	s.dev.in <- ipv4(internet, netip.MustParseAddr("10.66.0.200"), 17, []byte("nobody"))
	deadline := time.Now().Add(2 * time.Second)
	for s.router.Counters().NoRoute.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if s.router.Counters().NoRoute.Load() != 1 {
		t.Fatal("пакет без сессии не посчитан")
	}
}

// isICMPTooBig4 — ICMPv4 тип 3 код 4, адресованный to.
func isICMPTooBig4(to netip.Addr) func([]byte) bool {
	return func(p []byte) bool {
		return p[0]>>4 == 4 && p[9] == 1 && dst4(p) == to && p[20] == 3 && p[21] == 4
	}
}

// waitCounter ждёт значения счётчика. Пакет попадает в TUN раньше, чем
// увеличивается счётчик (считаем только успешную запись), поэтому проверять
// его сразу после появления пакета — гонка, которая всплывает под нагрузкой.
func waitCounter(t *testing.T, c *atomic.Uint64, want uint64, what string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		got := c.Load()
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("счётчик %s = %d, ожидалось %d", what, got, want)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestClientICMPFeedback — крупный пакет из TUN клиента превращается в ICMP,
// записанный обратно в TUN клиента: ядро отправителя узнаёт MTU.
func TestClientICMPFeedback(t *testing.T) {
	s := startServer(t)
	dev, c, cnt := s.client(t)
	me := c.AssignedPrefixes()[0].Addr()
	dev.in <- ipv4(me, internet, 6, make([]byte, 1600))
	p := dev.expect(t, "ICMP Fragmentation Needed", isICMPTooBig4(me))
	mtu := int(binary.BigEndian.Uint16(p[26:28]))
	if mtu < 1280 || mtu > 1500 {
		t.Fatalf("MTU в ICMP = %d", mtu)
	}
	waitCounter(t, &cnt.ICMP, 1, "ICMP клиента")
	// Пакет в пределах MTU проходит.
	dev.in <- ipv4(me, internet, 6, make([]byte, mtu-20))
	s.dev.expect(t, "пакет размером MTU на сервере", func(p []byte) bool { return len(p) == mtu })
}

// TestServerICMPFeedback — то же в обратную сторону: крупный пакет из
// интернета к клиенту даёт ICMP в TUN сервера, адресованный внешнему хосту.
func TestServerICMPFeedback(t *testing.T) {
	s := startServer(t)
	_, c, _ := s.client(t)
	me := c.AssignedPrefixes()[0].Addr()
	s.dev.in <- ipv4(internet, me, 6, make([]byte, 1600))
	p := s.dev.expect(t, "ICMP к внешнему отправителю", isICMPTooBig4(internet))
	if src4(p[28:]) != internet || dst4(p[28:]) != me {
		t.Fatal("во вложенной копии не исходный пакет")
	}
	waitCounter(t, &s.router.Counters().ICMP, 1, "ICMP сервера")
}

// TestRouterFollowsAddressChange — клиент попросил другой адрес
// (ADDRESS_REQUEST), таблица маршрутизатора обязана последовать за ним.
func TestRouterFollowsAddressChange(t *testing.T) {
	s := startServer(t)
	dev, c, _ := s.client(t)
	old := c.AssignedPrefixes()[0].Addr()
	want := netip.MustParsePrefix("10.66.0.77/32")
	if err := c.RequestAddresses(want); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if got, ok := s.router.Lookup(want.Addr()); ok && got != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("маршрутизатор не узнал о новом адресе")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, ok := s.router.Lookup(old); ok {
		t.Fatal("старый адрес остался в таблице")
	}
	s.dev.in <- ipv4(internet, want.Addr(), 17, []byte("new-addr"))
	p := dev.expect(t, "пакет на новый адрес", func([]byte) bool { return true })
	if string(p[20:]) != "new-addr" {
		t.Fatalf("got %q", p[20:])
	}
}

// TestSessionEndUnregisters — закрытая сессия пропадает из таблицы.
func TestSessionEndUnregisters(t *testing.T) {
	s := startServer(t)
	c := s.dial(t)
	a := c.AssignedPrefixes()[0].Addr()
	deadline := time.Now().Add(5 * time.Second)
	for s.router.Sessions() != 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	c.Close()
	for s.router.Sessions() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if _, ok := s.router.Lookup(a); ok || s.router.Sessions() != 0 {
		t.Fatal("сессия не снята с маршрутизатора")
	}
}

// TestRunClientEndsOnSessionClose — оборвалась сессия — насос завершается
// с ошибкой, а не висит.
func TestRunClientEndsOnSessionClose(t *testing.T) {
	s := startServer(t)
	c := s.dial(t)
	dev := newMemDevice()
	done := make(chan error, 1)
	go func() { done <- RunClient(context.Background(), dev, c, ClientOptions{}) }()
	time.Sleep(100 * time.Millisecond)
	c.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("ожидалась ошибка")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunClient не завершился")
	}
}
