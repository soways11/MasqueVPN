//go:build utls

package utlsquic

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	uquic "github.com/refraction-networking/uquic"
	"github.com/soways11/masquevpn/internal/auth"
	"github.com/soways11/masquevpn/internal/masque"
)

func ipv4(src, dst netip.Addr, payload []byte) []byte {
	b := make([]byte, 20+len(payload))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	b[8], b[9] = 64, 17
	s, d := src.As4(), dst.As4()
	copy(b[12:], s[:])
	copy(b[16:], d[:])
	copy(b[20:], payload)
	return b
}

type env struct {
	addr string
	pool *x509.CertPool
	ipp  *masque.IPPool
}

// startServer поднимает НАШ обычный сервер на quic-go — клиент на uTLS должен
// работать с ним без единой доработки серверной стороны.
func startServer(t *testing.T, cfg masque.ServerConfig) *env {
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
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	if cfg.Pool == nil {
		p, err := masque.NewIPPool(netip.MustParsePrefix("10.8.0.0/24"))
		if err != nil {
			t.Fatal(err)
		}
		cfg.Pool = p
	}
	h, err := masque.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := masque.NewHTTP3Server("", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	}, h, masque.WithWebTransportSettings())
	go func() { _ = srv.Serve(pc) }()
	t.Cleanup(func() { _ = srv.Close(); _ = pc.Close() })
	return &env{addr: pc.LocalAddr().String(), pool: pool, ipp: cfg.Pool}
}

// startServerWT — сервер, объявляющий SETTINGS WebTransport.
func startServerWT(t *testing.T, cfg masque.ServerConfig) *env {
	t.Helper()
	e := startServer(t, cfg)
	return e
}

func echoSession(ctx context.Context, c *masque.Conn, _ netip.Prefix) {
	buf := make([]byte, 2000)
	for {
		n, err := c.ReadPacket(buf)
		if err != nil {
			return
		}
		var t [4]byte
		copy(t[:], buf[12:16])
		copy(buf[12:16], buf[16:20])
		copy(buf[16:20], t[:])
		_ = c.WritePacket(buf[:n])
	}
}

func dial(t *testing.T, e *env, mod ...func(*Config)) (*masque.Conn, error) {
	t.Helper()
	cfg := Config{Addr: e.addr, ServerName: "localhost", RootCAs: e.pool, Authority: "localhost"}
	for _, m := range mod {
		m(&cfg)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return Dial(ctx, cfg)
}

func readWithTimeout(c *masque.Conn, buf []byte, d time.Duration) (int, error) {
	type res struct {
		n   int
		err error
	}
	ch := make(chan res, 1)
	go func() { n, err := c.ReadPacket(buf); ch <- res{n, err} }()
	select {
	case r := <-ch:
		return r.n, r.err
	case <-time.After(d):
		return 0, context.DeadlineExceeded
	}
}

// Главный тест: полноценная CONNECT-IP сессия через uTLS-транспорт с отпечатком
// Chrome против нашего обычного quic-go сервера.
func TestConnectIPOverUTLS(t *testing.T) {
	e := startServer(t, masque.ServerConfig{OnSession: echoSession})
	c, err := dial(t, e)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	prefixes, err := c.WaitForAddress(ctx)
	if err != nil {
		t.Fatalf("адрес не выдан: %v", err)
	}
	if len(prefixes) != 1 || prefixes[0].String() != "10.8.0.2/32" {
		t.Fatalf("выдан адрес %v", prefixes)
	}
	// ROUTE_ADVERTISEMENT доходит следом.
	deadline := time.Now().Add(5 * time.Second)
	for len(c.Routes()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if len(c.Routes()) == 0 {
		t.Fatal("маршруты не получены")
	}

	src := prefixes[0].Addr()
	dst := netip.MustParseAddr("1.1.1.1")
	buf := make([]byte, 2000)
	for _, size := range []int{0, 64, 512, 1000} {
		payload := bytes.Repeat([]byte{byte(size)}, size)
		if err := c.WritePacket(ipv4(src, dst, payload)); err != nil {
			t.Fatalf("размер %d: %v", size, err)
		}
		n, err := readWithTimeout(c, buf, 10*time.Second)
		if err != nil {
			t.Fatalf("размер %d: эхо не пришло: %v", size, err)
		}
		if !bytes.Equal(buf[20:n], payload) {
			t.Fatalf("размер %d: нагрузка искажена", size)
		}
	}
	if st := c.Stats(); st.PacketsIn != 4 || st.PacketsOut != 4 {
		t.Fatalf("счётчики: %+v", st)
	}
}

// Ядро (капсулы, политика, паддинг, cover) работает поверх uTLS-транспорта
// без изменений — проверяем паддинг и политику адресов.
func TestShapingAndPolicyOverUTLS(t *testing.T) {
	e := startServer(t, masque.ServerConfig{OnSession: echoSession})
	shaping := &masque.Shaping{Pad: func(int) int { return 512 }}
	c, err := dial(t, e, func(cfg *Config) { cfg.Shaping = shaping })
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	prefixes, err := c.WaitForAddress(ctx)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(c.Routes()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	src := prefixes[0].Addr()

	// Паддинг: сервер обрежет его по длине из IP-заголовка.
	orig := ipv4(src, netip.MustParseAddr("1.1.1.1"), []byte("pad"))
	if err := c.WritePacket(orig); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2000)
	n, err := readWithTimeout(c, buf, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(orig) {
		t.Fatalf("вернулось %d байт вместо %d — паддинг не обрезан", n, len(orig))
	}

	// Политика адресов действует и здесь.
	bad := ipv4(netip.MustParseAddr("10.8.0.99"), netip.MustParseAddr("1.1.1.1"), nil)
	if err := c.WritePacket(bad); !errors.Is(err, masque.ErrPacketRejected) {
		t.Fatalf("чужой src принят: %v", err)
	}
}

// Аутентификация и Fallback работают через uTLS-транспорт так же.
func TestAuthOverUTLS(t *testing.T) {
	authr, err := auth.New([]byte("0123456789abcdef0123456789abcdef"), auth.Options{})
	if err != nil {
		t.Fatal(err)
	}
	e := startServer(t, masque.ServerConfig{
		Authorize: authr.Authorize,
		Fallback:  http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) }),
	})

	hdr, _ := authr.Header()
	c, err := dial(t, e, func(cfg *Config) { cfg.Header = hdr })
	if err != nil {
		t.Fatalf("валидный токен отклонён: %v", err)
	}
	c.Close()

	// Без токена — 404, как у обычного веб-сервера без такого маршрута.
	var re *masque.ResponseError
	_, err = dial(t, e, func(cfg *Config) { cfg.Protocol = masque.ProtocolWebTransport })
	if !errors.As(err, &re) || re.StatusCode != http.StatusNotFound {
		t.Fatalf("без токена ожидался 404, получено: %v", err)
	}
	// С меткой connect-ip — 501, как на метку, которой WebTransport-сервер
	// не знает (masque/probe.go).
	_, err = dial(t, e, func(cfg *Config) { cfg.Protocol = masque.ProtocolConnectIP })
	if !errors.As(err, &re) || re.StatusCode != http.StatusNotImplemented {
		t.Fatalf("connect-ip без токена: ожидался 501, получено: %v", err)
	}
}

func TestParrots(t *testing.T) {
	if !Available() {
		t.Fatal("Available() должен быть true в utls-сборке")
	}
	e := startServer(t, masque.ServerConfig{})
	for _, p := range Parrots() {
		t.Run(p, func(t *testing.T) {
			c, err := dial(t, e, func(cfg *Config) { cfg.Parrot = p })
			if err != nil {
				t.Fatalf("профиль %s: %v", p, err)
			}
			defer c.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := c.WaitForAddress(ctx); err != nil {
				t.Fatalf("профиль %s: адрес не выдан: %v", p, err)
			}
		})
	}
	if _, err := dial(t, e, func(cfg *Config) { cfg.Parrot = "нет-такого" }); err == nil {
		t.Fatal("неизвестный профиль должен отклоняться")
	}
}

// TestCapsuleWriteOverUTLS проверяет путь «клиент → сервер» для капсул:
// они обязаны уходить внутри HTTP/3 DATA-фреймов, иначе сервер не разберёт
// поток и сессия развалится.
func TestCapsuleWriteOverUTLS(t *testing.T) {
	e := startServer(t, masque.ServerConfig{OnSession: echoSession})
	c, err := dial(t, e)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	prefixes, err := c.WaitForAddress(ctx)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(c.Routes()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	// Отправляем капсулу ADDRESS_REQUEST — это единственный путь, где клиент
	// пишет в поток сам.
	if err := c.RequestAddresses(netip.Prefix{}); err != nil {
		t.Fatalf("отправка капсулы: %v", err)
	}
	time.Sleep(300 * time.Millisecond)

	// Сессия должна выжить: если обрамление сломано, сервер закроет поток.
	select {
	case <-c.Done():
		t.Fatalf("сессия закрылась после отправки капсулы: %v", c.Err())
	default:
	}

	// И трафик продолжает ходить.
	src := prefixes[0].Addr()
	if err := c.WritePacket(ipv4(src, netip.MustParseAddr("1.1.1.1"), []byte("after-capsule"))); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2000)
	n, err := readWithTimeout(c, buf, 10*time.Second)
	if err != nil {
		t.Fatalf("после капсулы трафик встал: %v", err)
	}
	if !bytes.Equal(buf[20:n], []byte("after-capsule")) {
		t.Fatalf("нагрузка искажена: %q", buf[20:n])
	}
}

// TestWebTransportOverUTLS — обе маскировки вместе: рукопожатие как у Chrome
// (uTLS) и семантика как у WebTransport. Это закрывает и отпечаток, и поведение.
func TestWebTransportOverUTLS(t *testing.T) {
	var seenProto atomic.Value
	e := startServerWT(t, masque.ServerConfig{
		OnSession: echoSession,
		Authorize: func(r *http.Request) bool { seenProto.Store(r.Proto); return true },
	})
	c, err := dial(t, e, func(cfg *Config) { cfg.Protocol = masque.ProtocolWebTransport })
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	prefixes, err := c.WaitForAddress(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if p, _ := seenProto.Load().(string); p != masque.ProtocolWebTransport {
		t.Fatalf(":protocol = %q, ожидалось webtransport", p)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(c.Routes()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	// Туннель работает под обеими масками сразу.
	if err := c.WritePacket(ipv4(prefixes[0].Addr(), netip.MustParseAddr("1.1.1.1"), []byte("both"))); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2000)
	n, err := readWithTimeout(c, buf, 10*time.Second)
	if err != nil {
		t.Fatalf("трафик под двойной маскировкой встал: %v", err)
	}
	if !bytes.Equal(buf[20:n], []byte("both")) {
		t.Fatalf("нагрузка искажена: %q", buf[20:n])
	}
}

func TestUnknownProtocolRejected(t *testing.T) {
	e := startServer(t, masque.ServerConfig{})
	if _, err := dial(t, e, func(cfg *Config) { cfg.Protocol = "нет-такого" }); err == nil {
		t.Fatal("неизвестная метка :protocol принята")
	}
}

// TestCustomSpecHook — путь для отпечатка, снятого с настоящего браузера:
// встроенные профили устаревают, и подставить свой должно быть можно без
// правки кода библиотеки.
func TestCustomSpecHook(t *testing.T) {
	e := startServer(t, masque.ServerConfig{})

	// Берём встроенный профиль и подставляем его как «свой» — проверяем сам
	// механизм подстановки, а не конкретные значения отпечатка.
	spec, err := uquic.QUICID2Spec(uquic.QUICChrome_115_IPv4)
	if err != nil {
		t.Fatal(err)
	}
	c, err := dial(t, e, func(cfg *Config) { cfg.CustomSpec = &spec })
	if err != nil {
		t.Fatalf("подставленный профиль не сработал: %v", err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := c.WaitForAddress(ctx); err != nil {
		t.Fatalf("сессия не установилась: %v", err)
	}
}

func TestCustomSpecValidation(t *testing.T) {
	e := startServer(t, masque.ServerConfig{})

	// Неверный тип — внятная ошибка, а не паника.
	if _, err := dial(t, e, func(cfg *Config) { cfg.CustomSpec = "не спек" }); err == nil {
		t.Fatal("CustomSpec неверного типа принят")
	}
	// Спек без ClientHelloSpec отвергается: uquic на таком паникует.
	if _, err := dial(t, e, func(cfg *Config) { cfg.CustomSpec = &uquic.QUICSpec{} }); err == nil {
		t.Fatal("CustomSpec без ClientHelloSpec принят")
	}
}

// TestCoverBrowsingOverUTLS — прикрытие потоками должно работать и здесь.
// Раньше оно было только в quic-go пути, то есть мера против «одного вечного
// потока» отсутствовала ровно там, где маскировка и нужна больше всего.
func TestCoverBrowsingOverUTLS(t *testing.T) {
	var hits atomic.Int64
	var paths sync.Map
	e := startServer(t, masque.ServerConfig{
		OnSession: echoSession,
		Fallback: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				hits.Add(1)
				paths.Store(r.URL.Path, true)
				w.Header().Set("Content-Type", "text/html")
				_, _ = w.Write(bytes.Repeat([]byte("<p>cover</p>"), 100))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}),
	})

	c, err := dial(t, e, func(cfg *Config) {
		cfg.CoverBrowsing = &masque.CoverBrowsing{
			Paths: []string{"/", "/style.css", "/app.js"},
			Next:  func() time.Duration { return 20 * time.Millisecond },
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := c.WaitForAddress(ctx); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for hits.Load() < 5 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := hits.Load(); got < 5 {
		t.Fatalf("сервер получил лишь %d фоновых запросов, ожидалось >=5", got)
	}
	if got := c.CoverRequests(); got < 5 {
		t.Fatalf("клиент насчитал %d запросов", got)
	}
	n := 0
	paths.Range(func(_, _ any) bool { n++; return true })
	if n < 2 {
		t.Fatalf("запрошено путей: %d — прикрытие однообразно", n)
	}
	t.Logf("фоновых запросов: %d, уникальных путей: %d", hits.Load(), n)

	// Основной туннель при этом продолжает работать.
	deadline = time.Now().Add(5 * time.Second)
	for len(c.Routes()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	src := c.AssignedPrefixes()[0].Addr()
	if err := c.WritePacket(ipv4(src, netip.MustParseAddr("1.1.1.1"), []byte("tunnel"))); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2000)
	nn, err := readWithTimeout(c, buf, 10*time.Second)
	if err != nil {
		t.Fatalf("туннель встал из-за прикрытия: %v", err)
	}
	if !bytes.Equal(buf[20:nn], []byte("tunnel")) {
		t.Fatalf("нагрузка искажена: %q", buf[20:nn])
	}
}
