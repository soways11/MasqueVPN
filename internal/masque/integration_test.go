package masque

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

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/soways11/masquevpn/internal/auth"
	"github.com/soways11/masquevpn/internal/fingerprint"
)

// ---------- вспомогательные функции ----------

func buildIPv4(src, dst netip.Addr, proto uint8, payload []byte) []byte {
	b := make([]byte, 20+len(payload))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	b[8] = 64
	b[9] = proto
	s, d := src.As4(), dst.As4()
	copy(b[12:], s[:])
	copy(b[16:], d[:])
	copy(b[20:], payload)
	return b
}

func buildIPv6(src, dst netip.Addr, proto uint8, payload []byte) []byte {
	b := make([]byte, 40+len(payload))
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:], uint16(len(payload)))
	b[6] = proto
	b[7] = 64
	s, d := src.As16(), dst.As16()
	copy(b[8:], s[:])
	copy(b[24:], d[:])
	copy(b[40:], payload)
	return b
}

// swapAddrs меняет местами src и dst (эхо-ответ «из интернета»), для обоих семейств.
func swapAddrs(p []byte) {
	if len(p) == 0 {
		return
	}
	switch p[0] >> 4 {
	case 4:
		if len(p) < 20 {
			return
		}
		var tmp [4]byte
		copy(tmp[:], p[12:16])
		copy(p[12:16], p[16:20])
		copy(p[16:20], tmp[:])
	case 6:
		if len(p) < 40 {
			return
		}
		var tmp [16]byte
		copy(tmp[:], p[8:24])
		copy(p[8:24], p[24:40])
		copy(p[24:40], tmp[:])
	}
}

func testTLS(t *testing.T) (server, client *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	server = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	client = &tls.Config{RootCAs: pool, ServerName: "localhost"}
	return
}

type testEnv struct {
	addr   string
	client *tls.Config
	pool   *IPPool
}

func startServer(t *testing.T, cfg ServerConfig, opts ...HTTP3Option) *testEnv {
	t.Helper()
	if cfg.Pool == nil {
		p, err := NewIPPool(netip.MustParsePrefix("10.8.0.0/24"))
		if err != nil {
			t.Fatal(err)
		}
		cfg.Pool = p
	}
	h, err := NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	stls, ctls := testTLS(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := NewHTTP3Server("", stls, h, opts...)
	go func() { _ = srv.Serve(pc) }()
	t.Cleanup(func() { _ = srv.Close(); _ = pc.Close() })
	return &testEnv{addr: pc.LocalAddr().String(), client: ctls, pool: cfg.Pool}
}

// startServerWT — как startServer, но сервер объявляет SETTINGS WebTransport.
func startServerWT(t *testing.T, cfg ServerConfig) *testEnv {
	t.Helper()
	if cfg.Pool == nil {
		p, err := NewIPPool(netip.MustParsePrefix("10.8.0.0/24"))
		if err != nil {
			t.Fatal(err)
		}
		cfg.Pool = p
	}
	h, err := NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	stls, ctls := testTLS(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := NewHTTP3Server("", stls, h, WithWebTransportSettings())
	go func() { _ = srv.Serve(pc) }()
	t.Cleanup(func() { _ = srv.Close(); _ = pc.Close() })
	return &testEnv{addr: pc.LocalAddr().String(), client: ctls, pool: cfg.Pool}
}

func (e *testEnv) dial(t *testing.T, mod ...func(*ClientConfig)) (*Conn, error) {
	t.Helper()
	cfg := ClientConfig{Addr: e.addr, TLSConfig: e.client, Authority: "localhost"}
	for _, m := range mod {
		m(&cfg)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return Dial(ctx, cfg)
}

func mustDial(t *testing.T, e *testEnv) *Conn {
	t.Helper()
	c, err := e.dial(t)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.WaitForAddress(ctx); err != nil {
		t.Fatal(err)
	}
	waitRoutes(t, c)
	return c
}

// waitRoutes дожидается ROUTE_ADVERTISEMENT: без маршрутов WritePacket
// отклонит пакет по политике.
func waitRoutes(t *testing.T, c *Conn) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(c.Routes()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if len(c.Routes()) == 0 {
		t.Fatal("маршруты не получены")
	}
}

func readWithTimeout(c *Conn, buf []byte, d time.Duration) (int, error) {
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

// echoSession отражает пакеты обратно, меняя src/dst местами.
func echoSession(ctx context.Context, c *Conn, _ netip.Prefix) {
	buf := make([]byte, 2000)
	for {
		n, err := c.ReadPacket(buf)
		if err != nil {
			return
		}
		swapAddrs(buf[:n])
		_ = c.WritePacket(buf[:n])
	}
}

// ---------- тесты ----------

func TestHandshakeAssignsAddressAndRoutes(t *testing.T) {
	env := startServer(t, ServerConfig{})
	c := mustDial(t, env)

	got := c.AssignedPrefixes()
	if len(got) != 1 || got[0].String() != "10.8.0.2/32" {
		t.Fatalf("assigned %v", got)
	}
	routes := c.Routes()
	full := FullRoutes()
	if len(routes) != 2 || routes[0] != full[0] || routes[1] != full[1] {
		t.Fatalf("routes %v", routes)
	}
	if env.pool.InUse() != 1 {
		t.Fatalf("pool in use %d", env.pool.InUse())
	}

	// Второй клиент получает другой адрес.
	c2 := mustDial(t, env)
	if c2.AssignedPrefixes()[0].String() != "10.8.0.3/32" {
		t.Fatalf("second client got %v", c2.AssignedPrefixes())
	}
}

func TestPacketRoundTrip(t *testing.T) {
	env := startServer(t, ServerConfig{OnSession: echoSession})
	c := mustDial(t, env)
	src := c.AssignedPrefixes()[0].Addr()
	dst := netip.MustParseAddr("1.1.1.1")

	// ADDRESS_REQUEST посреди сессии не должен её ломать.
	if err := c.RequestAddresses(netip.Prefix{}); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 2000)
	sizes := []int{0, 1, 64, 512, 1000, 1150}
	const perSize = 50
	for _, sz := range sizes {
		for i := 0; i < perSize; i++ {
			payload := bytes.Repeat([]byte{byte(i)}, sz)
			if err := c.WritePacket(buildIPv4(src, dst, 17, payload)); err != nil {
				t.Fatalf("size %d: %v", sz, err)
			}
			n, err := readWithTimeout(c, buf, 5*time.Second)
			if err != nil {
				t.Fatalf("size %d #%d: %v", sz, i, err)
			}
			info, _ := parsePacket(buf[:n])
			if info.Src != dst || info.Dst != src || !bytes.Equal(buf[20:n], payload) {
				t.Fatalf("size %d: bad echo %+v", sz, info)
			}
		}
	}
	st := c.Stats()
	want := uint64(len(sizes) * perSize)
	if st.PacketsOut != want || st.PacketsIn != want || st.DroppedIn != 0 {
		t.Fatalf("stats %+v, want %d in/out", st, want)
	}
}

func TestServerDropsSpoofedAndForeignDatagrams(t *testing.T) {
	var got atomic.Int64
	var gotSrc atomic.Value
	serverConn := make(chan *Conn, 1)
	env := startServer(t, ServerConfig{OnSession: func(ctx context.Context, c *Conn, _ netip.Prefix) {
		serverConn <- c
		buf := make([]byte, 2000)
		for {
			n, err := c.ReadPacket(buf)
			if err != nil {
				return
			}
			info, _ := parsePacket(buf[:n])
			gotSrc.Store(info.Src)
			got.Add(1)
		}
	}})
	c := mustDial(t, env)
	sc := <-serverConn
	own := c.AssignedPrefixes()[0].Addr()
	dst := netip.MustParseAddr("8.8.8.8")

	// Обходим клиентскую проверку и шлём мусор напрямую в поток.
	raw := func(b []byte) {
		if err := c.str.SendDatagram(b); err != nil {
			t.Fatal(err)
		}
	}
	raw(appendIPDatagram(nil, buildIPv4(netip.MustParseAddr("10.8.0.99"), dst, 17, nil), 0)) // чужой src
	raw(appendIPDatagram(nil, buildIPv4(netip.MustParseAddr("9.9.9.9"), dst, 6, nil), 0))    // src из интернета
	raw(append([]byte{0x05}, buildIPv4(own, dst, 17, nil)...))                               // неизвестный Context ID
	raw(appendIPDatagram(nil, []byte{0x45, 0x00}, 0))                                        // обрезанный пакет
	raw(appendIPDatagram(nil, buildIPv6(netip.MustParseAddr("fd00::1"), netip.MustParseAddr("2001:db8::1"), 17, nil), 0))
	// И один валидный.
	if err := c.WritePacket(buildIPv4(own, dst, 17, []byte("ok"))); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for (got.Load() < 1 || sc.Stats().DroppedIn < 5) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond) // даём шанс «лишним» пакетам дойти, если бы они проходили
	if got.Load() != 1 {
		t.Fatalf("server accepted %d packets, want 1", got.Load())
	}
	if gotSrc.Load().(netip.Addr) != own {
		t.Fatalf("accepted src %v", gotSrc.Load())
	}
	if d := sc.Stats().DroppedIn; d != 5 {
		t.Fatalf("server dropped %d, want 5", d)
	}
}

func TestClientDropsForeignDestination(t *testing.T) {
	serverConn := make(chan *Conn, 1)
	env := startServer(t, ServerConfig{OnSession: func(ctx context.Context, c *Conn, _ netip.Prefix) {
		serverConn <- c
		<-ctx.Done()
	}})
	c := mustDial(t, env)
	sc := <-serverConn
	own := c.AssignedPrefixes()[0].Addr()
	from := netip.MustParseAddr("1.1.1.1")

	// Сервер тоже не даст отправить пакет на чужой адрес.
	if err := sc.WritePacket(buildIPv4(from, netip.MustParseAddr("10.8.0.50"), 17, nil)); !errors.Is(err, ErrPacketRejected) {
		t.Fatalf("server write to foreign dst: %v", err)
	}
	// Обходим серверную проверку.
	_ = sc.str.SendDatagram(appendIPDatagram(nil, buildIPv4(from, netip.MustParseAddr("10.8.0.50"), 17, nil), 0))
	_ = sc.WritePacket(buildIPv4(from, own, 17, []byte("mine")))

	buf := make([]byte, 2000)
	n, err := readWithTimeout(c, buf, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[20:n], []byte("mine")) {
		t.Fatalf("got %q", buf[20:n])
	}
	if d := c.Stats().DroppedIn; d != 1 {
		t.Fatalf("client dropped %d, want 1", d)
	}
}

func TestClientRejectsOutOfPolicyWrite(t *testing.T) {
	env := startServer(t, ServerConfig{
		Routes: []IPRoute{{Start: netip.MustParseAddr("10.0.0.0"), End: netip.MustParseAddr("10.255.255.255")}},
	})
	c := mustDial(t, env)
	own := c.AssignedPrefixes()[0].Addr()

	cases := map[string][]byte{
		"foreign src":    buildIPv4(netip.MustParseAddr("192.168.1.5"), netip.MustParseAddr("10.1.1.1"), 17, nil),
		"dst not routed": buildIPv4(own, netip.MustParseAddr("8.8.8.8"), 17, nil),
		"ipv6 no route":  buildIPv6(netip.MustParseAddr("fd00::2"), netip.MustParseAddr("2001:db8::1"), 17, nil),
		"garbage":        {0xff, 0xff},
	}
	for name, p := range cases {
		if err := c.WritePacket(p); !errors.Is(err, ErrPacketRejected) {
			t.Errorf("%s: want ErrPacketRejected, got %v", name, err)
		}
	}
	if err := c.WritePacket(buildIPv4(own, netip.MustParseAddr("10.1.1.1"), 17, nil)); err != nil {
		t.Fatalf("routed packet rejected: %v", err)
	}
	if st := c.Stats(); st.RejectedOut != uint64(len(cases)) || st.PacketsOut != 1 {
		t.Fatalf("stats %+v", st)
	}
}

func TestNonConnectIPRequestsGoToFallback(t *testing.T) {
	var authCalls atomic.Int64
	env := startServer(t, ServerConfig{
		Authorize: func(r *http.Request) bool {
			authCalls.Add(1)
			return r.Header.Get("Authorization") == "Bearer good"
		},
		Fallback: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("<html>not found</html>"))
		}),
	})

	// Обычный GET — это просто веб-сервер.
	tr := &http3.Transport{TLSClientConfig: env.client}
	defer tr.Close()
	rsp, err := (&http.Client{Transport: tr}).Get("https://localhost" + env.addr[len("127.0.0.1"):] + DefaultPath)
	if err != nil {
		t.Fatal(err)
	}
	rsp.Body.Close()
	if rsp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET status %d", rsp.StatusCode)
	}

	var re *ResponseError
	wt := func(c *ClientConfig) { c.Protocol = ProtocolWebTransport }
	// Неверный путь.
	_, err = env.dial(t, wt, func(c *ClientConfig) { c.Path = "/other/"; c.Header = http.Header{"Authorization": {"Bearer good"}} })
	if !errors.As(err, &re) || re.StatusCode != http.StatusNotFound {
		t.Fatalf("wrong path: %v", err)
	}
	// Не авторизован — ответ такой же, как на неизвестный путь.
	_, err = env.dial(t, wt, func(c *ClientConfig) { c.Header = http.Header{"Authorization": {"Bearer bad"}} })
	if !errors.As(err, &re) || re.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorized: %v", err)
	}
	// С меткой connect-ip и путь, и токен дают ответ на чужую метку.
	for _, c := range []func(*ClientConfig){
		func(c *ClientConfig) { c.Path = "/other/"; c.Header = http.Header{"Authorization": {"Bearer good"}} },
		func(c *ClientConfig) { c.Header = http.Header{"Authorization": {"Bearer bad"}} },
	} {
		_, err = env.dial(t, c)
		if !errors.As(err, &re) || re.StatusCode != http.StatusNotImplemented {
			t.Fatalf("connect-ip постороннего: %v", err)
		}
	}
	if env.pool.InUse() != 0 {
		t.Fatal("address allocated for rejected request")
	}
	// Авторизован.
	c, err := env.dial(t, func(c *ClientConfig) { c.Header = http.Header{"Authorization": {"Bearer good"}} })
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	// Неверный путь до Authorize не доходит: проверок три — чужой токен с
	// каждой из меток и свой.
	if authCalls.Load() != 3 {
		t.Fatalf("authorize called %d times", authCalls.Load())
	}
}

func TestPoolExhaustionAndRelease(t *testing.T) {
	pool, _ := NewIPPool(netip.MustParsePrefix("10.9.0.0/30")) // ровно один клиентский адрес
	env := startServer(t, ServerConfig{Pool: pool})

	c1 := mustDial(t, env)
	var re *ResponseError
	if _, err := env.dial(t); !errors.As(err, &re) || re.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("second client: %v", err)
	}
	c1.Close()

	deadline := time.Now().Add(5 * time.Second)
	for pool.InUse() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if pool.InUse() != 0 {
		t.Fatal("address not released after client close")
	}
	c2 := mustDial(t, env)
	if c2.AssignedPrefixes()[0].String() != "10.9.0.2/32" {
		t.Fatalf("got %v", c2.AssignedPrefixes())
	}
}

func TestServerCloseTerminatesClient(t *testing.T) {
	env := startServer(t, ServerConfig{OnSession: func(ctx context.Context, c *Conn, _ netip.Prefix) {
		time.Sleep(200 * time.Millisecond) // сессия живёт 200 мс
	}})
	c := mustDial(t, env)
	buf := make([]byte, 100)
	start := time.Now()
	_, err := readWithTimeout(c, buf, 5*time.Second)
	if !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("want ErrSessionClosed, got %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("close took too long")
	}
	if err := c.WritePacket(buildIPv4(c.AssignedPrefixes()[0].Addr(), netip.MustParseAddr("1.1.1.1"), 17, nil)); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("write after close: %v", err)
	}
}

func TestClientCloseEndsServerSession(t *testing.T) {
	ended := make(chan struct{})
	env := startServer(t, ServerConfig{OnSession: func(ctx context.Context, c *Conn, _ netip.Prefix) {
		<-ctx.Done()
		close(ended)
	}})
	c := mustDial(t, env)
	c.Close()
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("server session did not end")
	}
}

func TestFingerprintProfileAndDialerSeam(t *testing.T) {
	env := startServer(t, ServerConfig{})

	var dialerUsed atomic.Bool
	prof := fingerprint.Chrome()
	c, err := env.dial(t, func(cfg *ClientConfig) {
		cfg.QUICConfig = prof.QUICConfig()
		cfg.TLSConfig = prof.TLSConfig(env.client)
		cfg.Dialer = func(ctx context.Context, addr string, tlsConf *tls.Config, qc *quic.Config) (*quic.Conn, error) {
			dialerUsed.Store(true)
			// Проверяем, что профиль реально долетел до транспорта.
			if qc.InitialPacketSize != 1200 || !qc.EnableDatagrams {
				t.Errorf("профиль не применён к quic.Config: %+v", qc)
			}
			return quic.DialAddr(ctx, addr, tlsConf, qc)
		}
	})
	if err != nil {
		t.Fatalf("рукопожатие с профилем Chrome не прошло: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	if !dialerUsed.Load() {
		t.Fatal("подключаемый Dialer не был вызван")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.WaitForAddress(ctx); err != nil {
		t.Fatalf("сессия не установилась с профилем Chrome: %v", err)
	}
}

func TestHMACAuthEndToEnd(t *testing.T) {
	authr, err := auth.New([]byte("0123456789abcdef0123456789abcdef"), auth.Options{})
	if err != nil {
		t.Fatal(err)
	}
	env := startServer(t, ServerConfig{
		Authorize: authr.Authorize,
		Fallback:  http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) }),
	})

	// Валидный токен — сессия открывается.
	hdr, _ := authr.Header()
	c, err := env.dial(t, func(cfg *ClientConfig) { cfg.Header = hdr })
	if err != nil {
		t.Fatalf("валидный токен отклонён: %v", err)
	}
	c.Close()

	// Повтор того же токена — отказ, неотличимый от неизвестного пути (404).
	var re *ResponseError
	wt := func(cfg *ClientConfig) { cfg.Protocol = ProtocolWebTransport }
	_, err = env.dial(t, wt, func(cfg *ClientConfig) { cfg.Header = cloneHeader(hdr) })
	if !errors.As(err, &re) || re.StatusCode != http.StatusNotFound {
		t.Fatalf("повтор токена: %v", err)
	}
	// Без токена — тот же 404.
	_, err = env.dial(t, wt)
	if !errors.As(err, &re) || re.StatusCode != http.StatusNotFound {
		t.Fatalf("без токена: %v", err)
	}
	// С меткой connect-ip посторонний получает 501, как на любую метку,
	// которой WebTransport-сервер не знает (см. probe.go).
	_, err = env.dial(t, func(cfg *ClientConfig) { cfg.Header = cloneHeader(hdr) })
	if !errors.As(err, &re) || re.StatusCode != http.StatusNotImplemented {
		t.Fatalf("повтор токена с connect-ip: %v", err)
	}
	if env.pool.InUse() != 0 {
		t.Fatal("адрес выделен для неавторизованного запроса")
	}
}

func cloneHeader(h http.Header) http.Header {
	c := http.Header{}
	for k, v := range h {
		c[k] = append([]string(nil), v...)
	}
	return c
}

func TestPaddingRoundTripAndTrim(t *testing.T) {
	// Клиент паддит всё до 512 байт; эхо-сервер отражает то, что прочитал.
	shaping := &Shaping{Pad: func(int) int { return 512 }}
	env := startServer(t, ServerConfig{OnSession: echoSession})
	c, err := env.dial(t, func(cfg *ClientConfig) { cfg.Shaping = shaping })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.WaitForAddress(ctx); err != nil {
		t.Fatal(err)
	}
	waitRoutes(t, c)
	src := c.AssignedPrefixes()[0].Addr()
	dst := netip.MustParseAddr("1.1.1.1")

	orig := buildIPv4(src, dst, 17, []byte("hi")) // 22 байт
	if err := c.WritePacket(orig); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2000)
	n, err := readWithTimeout(c, buf, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// Сервер обрезал паддинг: длина как у исходного пакета, не 512.
	if n != len(orig) {
		t.Fatalf("получено %d байт, ожидалось %d (паддинг не обрезан)", n, len(orig))
	}
	if !bytes.Equal(buf[20:n], []byte("hi")) {
		t.Fatalf("нагрузка искажена: %q", buf[20:n])
	}
}

func TestCoverTrafficDroppedButCounted(t *testing.T) {
	serverConn := make(chan *Conn, 1)
	env := startServer(t, ServerConfig{OnSession: func(ctx context.Context, c *Conn, _ netip.Prefix) {
		serverConn <- c
		buf := make([]byte, 2000)
		for {
			if _, err := c.ReadPacket(buf); err != nil {
				return
			}
		}
	}})
	shaping := &Shaping{Cover: &CoverConfig{
		Next: func() time.Duration { return 30 * time.Millisecond },
		Size: func() int { return 300 },
	}}
	c, err := env.dial(t, func(cfg *ClientConfig) { cfg.Shaping = shaping })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	sc := <-serverConn

	deadline := time.Now().Add(5 * time.Second)
	for sc.Stats().CoverIn < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	st := sc.Stats()
	if st.CoverIn < 3 {
		t.Fatalf("сервер принял cover-датаграмм: %d, ожидалось >=3", st.CoverIn)
	}
	// Cover-трафик не считается реальными пакетами и не попадает в приложение.
	if st.PacketsIn != 0 || st.DroppedIn != 0 {
		t.Fatalf("cover повлиял на счётчики реальных пакетов: %+v", st)
	}
	if c.Stats().CoverOut < 3 {
		t.Fatalf("клиент отправил cover: %d, ожидалось >=3", c.Stats().CoverOut)
	}
}

func TestOversizedPacket(t *testing.T) {
	env := startServer(t, ServerConfig{})
	c := mustDial(t, env)
	big := buildIPv4(c.AssignedPrefixes()[0].Addr(), netip.MustParseAddr("1.1.1.1"), 17, make([]byte, 3000))
	if err := c.WritePacket(big); err == nil {
		t.Fatal("3000-byte packet sent in a QUIC datagram")
	}
}

// ---------- пункт 5: маскировка семантики протокола ----------

// TestWebTransportDisguise — сессия предъявляется как WebTransport: метка
// :protocol и SETTINGS согласованы. Именно это убирает главную улику —
// «датаграммы на HTTP/3, которых у обычного сайта не бывает».
func TestWebTransportDisguise(t *testing.T) {
	var seenProto atomic.Value
	env := startServerWT(t, ServerConfig{
		OnSession: echoSession,
		Authorize: func(r *http.Request) bool { seenProto.Store(r.Proto); return true },
	})

	c, err := env.dial(t, func(cfg *ClientConfig) { cfg.Protocol = ProtocolWebTransport })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.WaitForAddress(ctx); err != nil {
		t.Fatal(err)
	}
	waitRoutes(t, c)

	// Сервер увидел именно метку webtransport.
	if p, _ := seenProto.Load().(string); p != ProtocolWebTransport {
		t.Fatalf(":protocol на сервере = %q, ожидалось %q", p, ProtocolWebTransport)
	}
	// Туннель под маскировкой работает как обычно.
	src := c.AssignedPrefixes()[0].Addr()
	if err := c.WritePacket(buildIPv4(src, netip.MustParseAddr("1.1.1.1"), 17, []byte("wt"))); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2000)
	n, err := readWithTimeout(c, buf, 5*time.Second)
	if err != nil {
		t.Fatalf("под маскировкой трафик встал: %v", err)
	}
	if !bytes.Equal(buf[20:n], []byte("wt")) {
		t.Fatalf("нагрузка искажена: %q", buf[20:n])
	}
}

// TestWebTransportSettingsAdvertised — SETTINGS сервера должны содержать
// идентификаторы WebTransport, иначе метка :protocol не согласуется с ними
// и маскировка рассыпается при активном зондировании.
func TestWebTransportSettingsAdvertised(t *testing.T) {
	env := startServerWT(t, ServerConfig{})
	tr := &http3.Transport{TLSClientConfig: env.client, EnableDatagrams: true}
	defer tr.Close()
	tlsConf := env.client.Clone()
	tlsConf.NextProtos = []string{http3.NextProtoH3} // при ручном DialAddr ALPN ставим сами
	qc, err := quic.DialAddr(context.Background(), env.addr, tlsConf,
		&quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer qc.CloseWithError(0, "")
	cc := tr.NewClientConn(qc)
	select {
	case <-cc.ReceivedSettings():
	case <-time.After(5 * time.Second):
		t.Fatal("SETTINGS не получены")
	}
	other := cc.Settings().Other
	t.Logf("SETTINGS сервера (прочие): %v", other)
	if !IsWebTransportCapable(other) {
		t.Fatalf("сервер не объявил поддержку WebTransport: %v", other)
	}
}

// TestCoverBrowsingOpensStreams — прикрытие потоками: клиент фоном ходит
// GET-запросами к сайту-прикрытию, так что сессия перестаёт быть «один поток,
// живущий часами, и только датаграммы».
func TestCoverBrowsingOpensStreams(t *testing.T) {
	var hits atomic.Int64
	var paths sync.Map
	env := startServer(t, ServerConfig{
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

	c, err := env.dial(t, func(cfg *ClientConfig) {
		cfg.CoverBrowsing = &CoverBrowsing{
			Paths: []string{"/", "/style.css", "/app.js"},
			Next:  func() time.Duration { return 20 * time.Millisecond },
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.WaitForAddress(ctx); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for hits.Load() < 5 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := hits.Load(); got < 5 {
		t.Fatalf("сервер получил лишь %d фоновых запросов, ожидалось >=5", got)
	}
	if got := c.CoverRequests(); got < 5 {
		t.Fatalf("клиент насчитал %d фоновых запросов, ожидалось >=5", got)
	}
	// Запрашивается не один и тот же путь. Ждём разнообразия, а не смотрим
	// один снимок: путь выбирается случайно, и пять запросов подряд иногда
	// честно приходятся на один — тест мигал раз в сотню прогонов.
	countPaths := func() int {
		n := 0
		paths.Range(func(_, _ any) bool { n++; return true })
		return n
	}
	n := countPaths()
	for deadline := time.Now().Add(5 * time.Second); n < 2 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
		n = countPaths()
	}
	if n < 2 {
		t.Fatalf("запрошено путей: %d за %d запросов — прикрытие однообразно", n, hits.Load())
	}
	t.Logf("фоновых запросов: %d, уникальных путей: %d", hits.Load(), n)
}

// ---------- 2.3: лимиты ресурсов ----------

func TestMaxSessionsLimit(t *testing.T) {
	env := startServer(t, ServerConfig{Limits: &Limits{MaxSessions: 2}})

	c1 := mustDial(t, env)
	c2 := mustDial(t, env)
	_ = c1
	_ = c2

	var re *ResponseError
	if _, err := env.dial(t); !errors.As(err, &re) || re.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("третья сессия: ожидался 503, получено %v", err)
	}
	// Адрес из пула на отказ не потрачен.
	if env.pool.InUse() != 2 {
		t.Fatalf("занято адресов %d, ожидалось 2", env.pool.InUse())
	}

	// После закрытия место освобождается.
	c1.Close()
	deadline := time.Now().Add(5 * time.Second)
	for env.pool.InUse() != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := env.dial(t); err != nil {
		t.Fatalf("после освобождения места сессия не открылась: %v", err)
	}
}

func TestMaxSessionsPerIPLimit(t *testing.T) {
	// Все клиенты в тесте идут с 127.0.0.1, поэтому лимит на адрес их и ограничит.
	env := startServer(t, ServerConfig{Limits: &Limits{MaxSessionsPerIP: 1}})
	c1 := mustDial(t, env)
	defer c1.Close()

	var re *ResponseError
	if _, err := env.dial(t); !errors.As(err, &re) || re.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("вторая сессия с того же адреса: ожидался 503, получено %v", err)
	}
}

func TestIdleTimeoutClosesSession(t *testing.T) {
	env := startServer(t, ServerConfig{
		OnSession: echoSession,
		Limits:    &Limits{IdleTimeout: 1200 * time.Millisecond},
	})
	c := mustDial(t, env)

	// Пока трафик идёт — сессия живёт.
	src := c.AssignedPrefixes()[0].Addr()
	dst := netip.MustParseAddr("1.1.1.1")
	buf := make([]byte, 2000)
	for i := 0; i < 3; i++ {
		if err := c.WritePacket(buildIPv4(src, dst, 17, []byte("keep"))); err != nil {
			t.Fatal(err)
		}
		if _, err := readWithTimeout(c, buf, 3*time.Second); err != nil {
			t.Fatalf("итерация %d: %v", i, err)
		}
		time.Sleep(600 * time.Millisecond)
	}
	select {
	case <-c.Done():
		t.Fatal("сессия закрыта, хотя трафик шёл")
	default:
	}

	// Замолкаем — сессия должна закрыться по простою.
	select {
	case <-c.Done():
	case <-time.After(6 * time.Second):
		t.Fatal("сессия не закрылась по простою")
	}
}

func TestAddressRequestFloodRejected(t *testing.T) {
	env := startServer(t, ServerConfig{Limits: &Limits{MaxAddressRequests: 3}})
	c := mustDial(t, env)

	for i := 0; i < 10; i++ {
		if err := c.RequestAddresses(netip.Prefix{}); err != nil {
			break // поток уже закрыт сервером
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case <-c.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("сервер не закрыл сессию при потоке ADDRESS_REQUEST")
	}
}

// TestPreferredAddressHonored — сервер обязан выдать запрошенный адрес, если он
// свободен. Это то, ради чего в RFC 9484 есть ADDRESS_REQUEST: клиент может
// вернуть себе прежний адрес и не потерять соединения внутри туннеля.
func TestPreferredAddressHonored(t *testing.T) {
	env := startServer(t, ServerConfig{})
	c := mustDial(t, env)
	first := c.AssignedPrefixes()[0]
	if first.Addr().String() != "10.8.0.2" {
		t.Fatalf("первый адрес %v", first)
	}

	want := netip.MustParsePrefix("10.8.0.77/32")
	if err := c.RequestAddresses(want); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got := c.AssignedPrefixes(); len(got) == 1 && got[0] == want {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	got := c.AssignedPrefixes()
	if len(got) != 1 || got[0] != want {
		t.Fatalf("выдан адрес %v, запрашивался %v", got, want)
	}
	// Прежний адрес вернулся в пул, новый занят — утечки нет.
	if env.pool.InUse() != 1 {
		t.Fatalf("занято адресов %d, ожидался 1", env.pool.InUse())
	}
	// Новым адресом можно пользоваться: политика обновилась.
	if err := c.WritePacket(buildIPv4(want.Addr(), netip.MustParseAddr("1.1.1.1"), 17, nil)); err != nil {
		t.Fatalf("пакет с новым адресом отклонён: %v", err)
	}
	// А старым — уже нельзя.
	if err := c.WritePacket(buildIPv4(first.Addr(), netip.MustParseAddr("1.1.1.1"), 17, nil)); !errors.Is(err, ErrPacketRejected) {
		t.Fatalf("пакет со старым адресом принят: %v", err)
	}
}

func TestPreferredAddressBusyFallsBack(t *testing.T) {
	env := startServer(t, ServerConfig{})
	c1 := mustDial(t, env) // займёт 10.8.0.2
	c2 := mustDial(t, env) // займёт 10.8.0.3

	// c2 просит адрес, который держит c1 — должен остаться при своём.
	if err := c2.RequestAddresses(c1.AssignedPrefixes()[0]); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if got := c2.AssignedPrefixes(); len(got) != 1 || got[0].Addr().String() != "10.8.0.3" {
		t.Fatalf("адрес c2 = %v, ожидался 10.8.0.3", got)
	}
	if got := c1.AssignedPrefixes(); len(got) != 1 || got[0].Addr().String() != "10.8.0.2" {
		t.Fatalf("адрес c1 изменился: %v", got)
	}
	if env.pool.InUse() != 2 {
		t.Fatalf("занято адресов %d, ожидалось 2", env.pool.InUse())
	}
}

// ---------- исправления группы 1 ----------

// TestOversizedPacketReturnsICMP — вместо молчаливой пропажи пакета отправитель
// внутри туннеля должен получить ICMP с размером. Это лечит «чёрную дыру MTU»:
// раньше TCP устанавливал соединение и вис на первой большой передаче.
func TestOversizedPacketReturnsICMP(t *testing.T) {
	env := startServer(t, ServerConfig{})
	c := mustDial(t, env)
	src := c.AssignedPrefixes()[0].Addr()
	dst := netip.MustParseAddr("1.1.1.1")

	big := buildIPv4(src, dst, 6, make([]byte, 3000))
	err := c.WritePacket(big)
	if err == nil {
		t.Fatal("пакет 3000 байт отправлен")
	}
	tooLarge, ok := AsPacketTooLarge(err)
	if !ok {
		t.Fatalf("ожидался PacketTooLargeError, получено: %v", err)
	}
	if tooLarge.MaxSize <= 0 || tooLarge.MaxSize > 1500 {
		t.Fatalf("предельный размер %d выглядит неправдоподобно", tooLarge.MaxSize)
	}
	if tooLarge.ICMP == nil {
		t.Fatal("ICMP для отправителя не построен — отправитель не узнает о размере")
	}

	// ICMP адресован отправителю исходного пакета и несёт нужный MTU.
	info, err := parsePacket(tooLarge.ICMP)
	if err != nil {
		t.Fatalf("ICMP неразбираем: %v", err)
	}
	if info.Dst != src {
		t.Fatalf("ICMP адресован %v, а не отправителю %v", info.Dst, src)
	}
	body := tooLarge.ICMP[20:]
	if got := int(binary.BigEndian.Uint16(body[6:8])); got != tooLarge.MaxSize {
		t.Fatalf("MTU в ICMP=%d, а в ошибке=%d", got, tooLarge.MaxSize)
	}

	// Предельный размер теперь известен и доступен слою TUN.
	if c.MaxPacketSize() != tooLarge.MaxSize {
		t.Fatalf("MaxPacketSize()=%d, ожидалось %d", c.MaxPacketSize(), tooLarge.MaxSize)
	}
	if st := c.Stats(); st.TooLargeOut != 1 {
		t.Fatalf("счётчик TooLargeOut=%d", st.TooLargeOut)
	}

	// Пакет с запасом по размеру по-прежнему уходит. Точную границу не проверяем:
	// оценка MTU у quic-go уточняется по ходу и может меняться между вызовами.
	if err := c.WritePacket(buildIPv4(src, dst, 6, make([]byte, tooLarge.MaxSize-120))); err != nil {
		t.Fatalf("пакет с запасом по размеру отклонён: %v", err)
	}
}

// TestDualStack — клиент должен получать адреса обоих семейств, иначе половина
// трафика уходит мимо туннеля.
func TestDualStack(t *testing.T) {
	v4, err := NewIPPool(netip.MustParsePrefix("10.8.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	v6, err := NewIPPool(netip.MustParsePrefix("fd00:8::/64"))
	if err != nil {
		t.Fatal(err)
	}
	env := startServer(t, ServerConfig{Pools: []*IPPool{v4, v6}, OnSession: echoSession})
	c := mustDial(t, env)

	got := c.AssignedPrefixes()
	if len(got) != 2 {
		t.Fatalf("выдано адресов: %d, ожидалось 2 — %v", len(got), got)
	}
	var has4, has6 bool
	for _, p := range got {
		if p.Addr().Is4() {
			has4 = true
		} else {
			has6 = true
		}
	}
	if !has4 || !has6 {
		t.Fatalf("нет обоих семейств: %v", got)
	}
	t.Logf("выданы адреса: %v", got)

	// Трафик ходит по обоим семействам.
	buf := make([]byte, 2000)
	for _, tc := range []struct {
		name      string
		pkt       []byte
		payloadAt int
	}{
		{"IPv4", buildIPv4(got[0].Addr(), netip.MustParseAddr("1.1.1.1"), 17, []byte("v4")), 20},
		{"IPv6", buildIPv6(got[1].Addr(), netip.MustParseAddr("2001:db8::1"), 17, []byte("v6")), 40},
	} {
		if err := c.WritePacket(tc.pkt); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		n, err := readWithTimeout(c, buf, 5*time.Second)
		if err != nil {
			t.Fatalf("%s: эхо не пришло: %v", tc.name, err)
		}
		t.Logf("%s: получено %d байт", tc.name, n)
	}

	// Оба пула заняты ровно по одному адресу.
	if v4.InUse() != 1 || v6.InUse() != 1 {
		t.Fatalf("занято в пулах: v4=%d v6=%d", v4.InUse(), v6.InUse())
	}
}

func TestDualStackRejectsDuplicateFamily(t *testing.T) {
	a, _ := NewIPPool(netip.MustParsePrefix("10.8.0.0/24"))
	b, _ := NewIPPool(netip.MustParsePrefix("10.9.0.0/24"))
	if _, err := NewHandler(ServerConfig{Pools: []*IPPool{a, b}}); err == nil {
		t.Fatal("два пула IPv4 приняты — адреса одного семейства перетрут друг друга")
	}
}

// TestClientIsolation — сервер не должен пропускать пакет одного клиента на
// туннельный адрес другого. Маршруты по умолчанию — весь интернет, а он включает
// и нашу туннельную сеть, поэтому без отдельной проверки сосед достижим.
//
// Проверяем именно СЕРВЕРНУЮ сторону: клиент не доверенный, и граница проходит
// там. Клиент о чужих туннельных адресах не знает и такой пакет отправит.
func TestClientIsolation(t *testing.T) {
	serverConns := make(chan *Conn, 4)
	received := make(chan netip.Addr, 8)
	env := startServer(t, ServerConfig{OnSession: func(ctx context.Context, c *Conn, _ netip.Prefix) {
		serverConns <- c
		buf := make([]byte, 2000)
		for {
			n, err := c.ReadPacket(buf)
			if err != nil {
				return
			}
			info, _ := parsePacket(buf[:n])
			received <- info.Dst
		}
	}})

	c1 := mustDial(t, env)
	c2 := mustDial(t, env)
	sc1 := <-serverConns
	own := c1.AssignedPrefixes()[0].Addr()
	neighbour := c2.AssignedPrefixes()[0].Addr()

	// Клиент отправляет — он о запрете не знает.
	if err := c1.WritePacket(buildIPv4(own, neighbour, 17, []byte("сосед"))); err != nil {
		t.Fatalf("клиент не смог отправить: %v", err)
	}
	// Затем — заведомо разрешённый пакет наружу, как маркер очерёдности.
	if err := c1.WritePacket(buildIPv4(own, netip.MustParseAddr("1.1.1.1"), 17, []byte("наружу"))); err != nil {
		t.Fatal(err)
	}

	// До приложения должен дойти только второй.
	select {
	case dst := <-received:
		if dst == neighbour {
			t.Fatal("сервер пропустил пакет, адресованный соседу по туннелю")
		}
		if dst.String() != "1.1.1.1" {
			t.Fatalf("получен неожиданный пакет на %v", dst)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("сервер не получил разрешённый пакет")
	}
	// И пакет соседу учтён как отброшенный.
	deadline := time.Now().Add(3 * time.Second)
	for sc1.Stats().DroppedIn == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if sc1.Stats().DroppedIn != 1 {
		t.Fatalf("отброшено на сервере: %d, ожидался ровно 1", sc1.Stats().DroppedIn)
	}
}

func TestClientToClientCanBeAllowed(t *testing.T) {
	received := make(chan netip.Addr, 4)
	env := startServer(t, ServerConfig{
		AllowClientToClient: true,
		OnSession: func(ctx context.Context, c *Conn, _ netip.Prefix) {
			buf := make([]byte, 2000)
			for {
				n, err := c.ReadPacket(buf)
				if err != nil {
					return
				}
				info, _ := parsePacket(buf[:n])
				received <- info.Dst
			}
		},
	})
	c1 := mustDial(t, env)
	c2 := mustDial(t, env)
	neighbour := c2.AssignedPrefixes()[0].Addr()
	if err := c1.WritePacket(buildIPv4(c1.AssignedPrefixes()[0].Addr(), neighbour, 17, nil)); err != nil {
		t.Fatal(err)
	}
	select {
	case dst := <-received:
		if dst != neighbour {
			t.Fatalf("получен пакет на %v, ожидался %v", dst, neighbour)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("при AllowClientToClient пакет соседу не дошёл")
	}
}

// TestPaddingBucketAbovePathIsClamped — «ведро» паддинга крупнее, чем
// помещается в датаграмму, не должно превращать проходимые пакеты в ICMP.
// Раньше пакет 1100 байт с ведром 1500 получал PacketTooLargeError, а в ICMP
// уходил размер, уменьшенный на паддинг, — отправитель резал пакеты зря.
func TestPaddingBucketAbovePathIsClamped(t *testing.T) {
	env := startServer(t, ServerConfig{OnSession: echoSession})
	shaping := &Shaping{Pad: func(n int) int {
		if n <= 1500 {
			return 1500
		}
		return n
	}}
	c, err := env.dial(t, func(cfg *ClientConfig) { cfg.Shaping = shaping })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.WaitForAddress(ctx); err != nil {
		t.Fatal(err)
	}
	waitRoutes(t, c)
	src := c.AssignedPrefixes()[0].Addr()
	dst := netip.MustParseAddr("1.1.1.1")

	buf := make([]byte, 2000)
	for i := 0; i < 3; i++ { // первый раз — выяснение потолка, дальше — сразу
		pkt := buildIPv4(src, dst, 17, make([]byte, 1100))
		if err := c.WritePacket(pkt); err != nil {
			t.Fatalf("попытка %d: пакет 1120 байт не отправлен: %v", i, err)
		}
		n, err := readWithTimeout(c, buf, 5*time.Second)
		if err != nil || n != len(pkt) {
			t.Fatalf("попытка %d: эхо n=%d err=%v", i, n, err)
		}
	}
	if st := c.Stats(); st.TooLargeOut != 0 {
		t.Fatalf("TooLargeOut=%d: проходимый пакет посчитан слишком большим", st.TooLargeOut)
	}
	// А по-настоящему большой пакет по-прежнему даёт ICMP с честным потолком —
	// без вычета паддинга.
	err = c.WritePacket(buildIPv4(src, dst, 17, make([]byte, 3000)))
	tl, ok := AsPacketTooLarge(err)
	if !ok {
		t.Fatalf("ожидался PacketTooLargeError: %v", err)
	}
	if tl.MaxSize < 1280 {
		t.Fatalf("потолок %d < 1280: в туннель не поместится IPv6-пакет минимального MTU", tl.MaxSize)
	}
}

// TestCapacityFitsIPv6MinimumMTU — ёмкость датаграммы по умолчанию должна
// вмещать IPv6-пакет 1280 байт в ОБЕ стороны, иначе IPv6 в туннеле не работает
// (стеки игнорируют Packet Too Big ниже 1280).
func TestCapacityFitsIPv6MinimumMTU(t *testing.T) {
	env := startServer(t, ServerConfig{OnSession: echoSession})
	c := mustDial(t, env)
	src := c.AssignedPrefixes()[0].Addr()
	pkt := buildIPv4(src, netip.MustParseAddr("1.1.1.1"), 17, make([]byte, 1280-20))
	if err := c.WritePacket(pkt); err != nil {
		t.Fatalf("клиент→сервер, 1280 байт: %v", err)
	}
	buf := make([]byte, 2000)
	n, err := readWithTimeout(c, buf, 5*time.Second)
	if err != nil || n != 1280 {
		t.Fatalf("сервер→клиент, 1280 байт: n=%d err=%v", n, err)
	}
}

// TestDatagramCapacityIsHonest — отчёт о потолке обязан быть честным: пакет
// ровно в DatagramCapacity() доходит, на байт больше — отклоняется с ICMP.
// Любое расхождение — чёрная дыра: транспорт примет датаграмму и молча
// выбросит её при упаковке. Проверяется на всей полосе вокруг потолка и с
// любым паддингом.
func TestDatagramCapacityIsHonest(t *testing.T) {
	env := startServer(t, ServerConfig{OnSession: echoSession})
	for _, pad := range []int{0, 1330, 1340, 1500} {
		pad := pad
		c, err := env.dial(t, func(cfg *ClientConfig) {
			if pad > 0 {
				cfg.Shaping = &Shaping{Pad: func(int) int { return pad }}
			}
		})
		if err != nil {
			t.Fatal(err)
		}
		waitRoutes(t, c)
		src := c.AssignedPrefixes()[0].Addr()
		dst := netip.MustParseAddr("1.1.1.1")
		buf := make([]byte, 20000)
		// Первый обмен — чтобы прошёл первый ACK (после него quic-go меняет оценку).
		c.WritePacket(buildIPv4(src, dst, 17, []byte("warmup")))
		readWithTimeout(c, buf, 2*time.Second)
		time.Sleep(3 * capacityTTL / 2)

		capIP := c.DatagramCapacity()
		if capIP < 1280 {
			t.Fatalf("pad=%d: потолок %d < 1280", pad, capIP)
		}
		for size := capIP - 30; size <= capIP; size++ {
			pkt := buildIPv4(src, dst, 17, make([]byte, size-20))
			if err := c.WritePacket(pkt); err != nil {
				t.Fatalf("pad=%d size=%d (потолок %d): %v", pad, size, capIP, err)
			}
			n, err := readWithTimeout(c, buf, 2*time.Second)
			if err != nil || n != size {
				t.Fatalf("pad=%d size=%d (потолок %d): принят транспортом, но потерян — чёрная дыра (n=%d err=%v)",
					pad, size, capIP, n, err)
			}
		}
		err = c.WritePacket(buildIPv4(src, dst, 17, make([]byte, capIP+1-20)))
		tl, ok := AsPacketTooLarge(err)
		if !ok || tl.MaxSize != capIP || tl.ICMP == nil {
			t.Fatalf("pad=%d: пакет потолок+1: err=%v", pad, err)
		}
		c.Close()
	}
}

// TestIsolationLetsGatewayThrough — изоляция закрывает соседей, но не сам
// сервер: адрес шлюза туннеля (ping шлюза, будущий DNS на нём) доступен.
func TestIsolationLetsGatewayThrough(t *testing.T) {
	received := make(chan netip.Addr, 8)
	env := startServer(t, ServerConfig{OnSession: func(ctx context.Context, c *Conn, _ netip.Prefix) {
		buf := make([]byte, 2000)
		for {
			n, err := c.ReadPacket(buf)
			if err != nil {
				return
			}
			info, _ := parsePacket(buf[:n])
			received <- info.Dst
		}
	}})
	c := mustDial(t, env)
	own := c.AssignedPrefixes()[0].Addr()
	gw := env.pool.Gateway()
	if err := c.WritePacket(buildIPv4(own, gw, 1, make([]byte, 8))); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-received:
		if got != gw {
			t.Fatalf("дошёл пакет на %v", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("пакет на шлюз отброшен изоляцией")
	}
}

// TestJitterDoesNotBlockWriter — джиттер задерживает пакет, но не насос:
// 30 мелких пакетов с задержкой 20 мс ставятся в очередь мгновенно (при
// блокирующем сне это заняло бы 0,6 с), приходят все, по порядку и не позже
// заданного максимума.
func TestJitterDoesNotBlockWriter(t *testing.T) {
	env := startServer(t, ServerConfig{OnSession: echoSession})
	const jitter = 20 * time.Millisecond
	c, err := env.dial(t, func(cfg *ClientConfig) {
		cfg.Shaping = &Shaping{Delay: func(n int) time.Duration {
			if n <= 128 {
				return jitter
			}
			return 0
		}}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	waitRoutes(t, c)
	src := c.AssignedPrefixes()[0].Addr()
	dst := netip.MustParseAddr("1.1.1.1")

	// Залп короче 32: столько датаграмм quic-go держит на поток HTTP/3, более
	// длинный залп эхо-сервер может частично потерять (см. recvLoop).
	const n = 30
	// Читаем параллельно, как насос.
	got := make(chan []uint32, 1)
	go func() {
		buf := make([]byte, 2000)
		var seq []uint32
		for len(seq) < n {
			k, err := readWithTimeout(c, buf, 5*time.Second)
			if err != nil {
				break
			}
			seq = append(seq, binary.BigEndian.Uint32(buf[20:k]))
		}
		got <- seq
	}()
	begin := time.Now()
	for i := 0; i < n; i++ {
		p := buildIPv4(src, dst, 17, binary.BigEndian.AppendUint32(nil, uint32(i)))
		if err := c.WritePacket(p); err != nil {
			t.Fatal(err)
		}
	}
	queued := time.Since(begin)
	if queued > n*jitter/2 {
		t.Fatalf("%d пакетов ставились %v — джиттер блокирует насос", n, queued)
	}
	seq := <-got
	if len(seq) != n {
		t.Fatalf("получено %d из %d", len(seq), n)
	}
	for i, v := range seq {
		if v != uint32(i) {
			t.Fatalf("порядок нарушен: на месте %d пришёл %d", i, v)
		}
	}
	total := time.Since(begin)
	if total < jitter {
		t.Fatalf("пакеты пришли за %v — задержки не было", total)
	}
	t.Logf("поставлено в очередь за %v, доставлено за %v", queued, total)
}

// waitFraming дожидается согласования кадров (капсула от другой стороны).
func waitFraming(t *testing.T, c *Conn) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !c.FramingActive() {
		if time.Now().After(deadline) {
			t.Fatal("кадры не согласованы")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestFramingAggregatesBurst — главный тест C2: залп мелких пакетов уезжает
// в НЕСКОЛЬКИХ датаграммах, а не в пятидесяти. Снаружи поток датаграмм
// перестаёт повторять поток IP-пакетов.
//
// Побочно проверяется и потеря на залпах: раньше залп длиннее 32 датаграмм
// частично выбрасывался очередью quic-go, теперь столько датаграмм просто
// не образуется.
func TestFramingAggregatesBurst(t *testing.T) {
	packing := &Packing{Window: 3 * time.Millisecond}
	env := startServer(t, ServerConfig{OnSession: echoSession, Packing: packing})
	c, err := env.dial(t, func(cfg *ClientConfig) { cfg.Packing = packing })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.WaitForAddress(ctx); err != nil {
		t.Fatal(err)
	}
	waitRoutes(t, c)
	waitFraming(t, c)

	src := c.AssignedPrefixes()[0].Addr()
	dst := netip.MustParseAddr("1.1.1.1")
	const n = 50

	got := make(chan int, 1)
	go func() {
		buf := make([]byte, 2000)
		k := 0
		for k < n {
			if _, err := readWithTimeout(c, buf, 3*time.Second); err != nil {
				break
			}
			k++
		}
		got <- k
	}()
	for i := 0; i < n; i++ {
		if err := c.WritePacket(buildIPv4(src, dst, 17, binary.BigEndian.AppendUint32(nil, uint32(i)))); err != nil {
			t.Fatal(err)
		}
	}
	if k := <-got; k != n {
		t.Fatalf("вернулось %d пакетов из %d", k, n)
	}

	st := c.Stats()
	if st.DatagramsOut == 0 || st.DatagramsOut > n/3 {
		t.Fatalf("на %d пакетов ушло %d датаграмм — агрегации нет", n, st.DatagramsOut)
	}
	if st.PacketsOut != n {
		t.Fatalf("отправлено пакетов: %d", st.PacketsOut)
	}
	t.Logf("%d пакетов уехали в %d датаграммах (в пачках: %d)", st.PacketsOut, st.DatagramsOut, st.PackedOut)
}

// TestFramingFragmentsLargePackets — пакет крупнее датаграммы больше не
// отбивается ICMP, а режется на куски и собирается обратно. Это снимает
// жёсткую привязку MTU туннеля к размеру QUIC-пакета.
func TestFramingFragmentsLargePackets(t *testing.T) {
	packing := &Packing{}
	// Крупные пакеты возвращаются тем же путём, поэтому эхо-обработчику нужен
	// буфер под самый большой пакет, а серверной сессии — согласованные кадры.
	serverConns := make(chan *Conn, 1)
	env := startServer(t, ServerConfig{Packing: packing, OnSession: func(ctx context.Context, c *Conn, _ netip.Prefix) {
		serverConns <- c
		buf := make([]byte, 70000)
		for {
			n, err := c.ReadPacket(buf)
			if err != nil {
				return
			}
			swapAddrs(buf[:n])
			_ = c.WritePacket(buf[:n])
		}
	}})
	c, err := env.dial(t, func(cfg *ClientConfig) { cfg.Packing = packing })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.WaitForAddress(ctx); err != nil {
		t.Fatal(err)
	}
	waitRoutes(t, c)
	waitFraming(t, c)
	// И на сервере тоже: пока он не получил нашу капсулу, он отвечает
	// по-старому и крупный пакет вернуть не сможет.
	waitFraming(t, <-serverConns)

	src := c.AssignedPrefixes()[0].Addr()
	dst := netip.MustParseAddr("1.1.1.1")
	for _, size := range []int{1500, 4000, 9000} {
		pkt := buildIPv4(src, dst, 17, make([]byte, size-20))
		for i := range pkt[20:] {
			pkt[20+i] = byte(i)
		}
		if err := c.WritePacket(pkt); err != nil {
			t.Fatalf("пакет %d байт: %v", size, err)
		}
		buf := make([]byte, 70000)
		n, err := readWithTimeout(c, buf, 5*time.Second)
		if err != nil {
			t.Fatalf("пакет %d байт не вернулся: %v", size, err)
		}
		if n != size || !bytes.Equal(buf[20:n], pkt[20:]) {
			t.Fatalf("пакет %d байт вернулся искажённым (%d байт)", size, n)
		}
	}
	st := c.Stats()
	if st.FragmentsOut == 0 || st.TooLargeOut != 0 {
		t.Fatalf("кусков отправлено %d, отказов по размеру %d", st.FragmentsOut, st.TooLargeOut)
	}
	t.Logf("три крупных пакета уехали %d кусками", st.FragmentsOut)
}

// TestFramingFallsBackToOldFormat — со старым сервером (кадры не
// поддерживает) клиент обязан работать по-прежнему: Context ID 0 и ICMP
// на слишком крупный пакет.
func TestFramingFallsBackToOldFormat(t *testing.T) {
	env := startServer(t, ServerConfig{OnSession: echoSession}) // без Packing
	c, err := env.dial(t, func(cfg *ClientConfig) { cfg.Packing = &Packing{} })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.WaitForAddress(ctx); err != nil {
		t.Fatal(err)
	}
	waitRoutes(t, c)
	time.Sleep(200 * time.Millisecond) // капсула согласования не придёт
	if c.FramingActive() {
		t.Fatal("кадры включились без подтверждения другой стороны")
	}

	src := c.AssignedPrefixes()[0].Addr()
	dst := netip.MustParseAddr("1.1.1.1")
	if err := c.WritePacket(buildIPv4(src, dst, 17, []byte("hi"))); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2000)
	if n, err := readWithTimeout(c, buf, 5*time.Second); err != nil || n != 22 {
		t.Fatalf("эхо: n=%d err=%v", n, err)
	}
	err = c.WritePacket(buildIPv4(src, dst, 17, make([]byte, 3000)))
	if _, ok := AsPacketTooLarge(err); !ok {
		t.Fatalf("без кадров крупный пакет должен давать ICMP, получено: %v", err)
	}
}

// TestServerTransportParametersFollowProfile — отпечаток серверной стороны
// (C1): клиент видит от нас те транспортные параметры, которые заданы
// профилем, а не умолчания quic-go.
//
// Параметры снимаются так же, как их видит любой клиент, — из события
// qlog о принятых параметрах.
func TestServerTransportParametersFollowProfile(t *testing.T) {
	profile := fingerprint.CDNLike()
	withProfile := startServer(t, ServerConfig{}, WithQUICConfig(profile.QUICConfig()))
	stock := startServer(t, ServerConfig{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, err := fingerprint.CaptureParams(ctx, withProfile.addr, "localhost", true)
	if err != nil {
		t.Fatal(err)
	}
	base, err := fingerprint.CaptureParams(ctx, stock.addr, "localhost", true)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("профиль:   %+v", got)
	t.Logf("умолчания: %+v", base)

	if got.MaxIdleTimeout != time.Duration(profile.MaxIdleTimeoutMS)*time.Millisecond {
		t.Fatalf("время простоя %v, профиль требует %d мс", got.MaxIdleTimeout, profile.MaxIdleTimeoutMS)
	}
	if got.InitialMaxData != profile.InitialMaxData {
		t.Fatalf("initial_max_data %d, профиль требует %d", got.InitialMaxData, profile.InitialMaxData)
	}
	if got.InitialMaxStreamDataBidiRemote != profile.InitialMaxStreamData {
		t.Fatalf("окно потока %d, профиль требует %d", got.InitialMaxStreamDataBidiRemote, profile.InitialMaxStreamData)
	}
	if got.MaxBidiStreams != profile.MaxBidiStreams || got.MaxUniStreams != profile.MaxUniStreams {
		t.Fatalf("лимиты потоков %d/%d, профиль требует %d/%d",
			got.MaxBidiStreams, got.MaxUniStreams, profile.MaxBidiStreams, profile.MaxUniStreams)
	}
	if got.MaxDatagramFrameSize == 0 {
		t.Fatal("датаграммы не объявлены — CONNECT-IP не заработает")
	}

	// Разница со стоковым сервером должна быть видна: иначе профиль ничего
	// не меняет.
	same := got.InitialMaxData == base.InitialMaxData &&
		got.InitialMaxStreamDataBidiRemote == base.InitialMaxStreamDataBidiRemote &&
		got.MaxBidiStreams == base.MaxBidiStreams
	if same {
		t.Fatal("параметры совпали с умолчаниями quic-go — профиль не применился")
	}

	// А это — честный остаток C1: поля, которые quic-go наружу не отдаёт.
	// Если они когда-нибудь станут настраиваемыми, тест об этом скажет.
	if got.ActiveConnectionIDLimit != base.ActiveConnectionIDLimit ||
		got.AckDelayExponent != base.AckDelayExponent ||
		got.MaxAckDelay != base.MaxAckDelay ||
		got.MaxUDPPayloadSize != base.MaxUDPPayloadSize {
		t.Logf("ВНИМАНИЕ: часть «ненастраиваемых» параметров всё же разошлась — стоит пересмотреть профиль")
	}
}

// TestUnknownCapsuleFloodClosesSession — неизвестные капсулы положено
// игнорировать (RFC 9297), но не бесконечно: поток мусора занимает
// процессор сервера, а у честной стороны таких капсул не бывает вовсе.
func TestUnknownCapsuleFloodClosesSession(t *testing.T) {
	env := startServer(t, ServerConfig{
		OnSession: echoSession,
		Limits:    &Limits{MaxUnknownCapsules: 8},
	})
	c := mustDial(t, env)
	for i := 0; i < 64; i++ {
		if err := c.writeCapsule(http3.CapsuleType(0x5555), []byte{byte(i)}); err != nil {
			break
		}
	}
	select {
	case <-c.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("сервер стерпел поток неизвестных капсул")
	}

	// А в пределах потолка всё по-прежнему игнорируется: сессия жива.
	env2 := startServer(t, ServerConfig{OnSession: echoSession, Limits: &Limits{MaxUnknownCapsules: 64}})
	c2 := mustDial(t, env2)
	for i := 0; i < 8; i++ {
		if err := c2.writeCapsule(http3.CapsuleType(0x5555), []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	src := c2.AssignedPrefixes()[0].Addr()
	if err := c2.WritePacket(buildIPv4(src, netip.MustParseAddr("1.1.1.1"), 17, []byte("жив"))); err != nil {
		t.Fatalf("сессия закрылась от нескольких неизвестных капсул: %v", err)
	}
	buf := make([]byte, 2000)
	if _, err := readWithTimeout(c2, buf, 5*time.Second); err != nil {
		t.Fatalf("эхо не вернулось: %v", err)
	}
}

// TestTLSSessionResumption — второе подключение возобновляет TLS-сессию по
// билету, как это делает браузер. Клиент, который каждый раз проводит
// полное рукопожатие, этим и выделяется — особенно на фоне ротации
// соединений, где подключений много.
func TestTLSSessionResumption(t *testing.T) {
	env := startServer(t, ServerConfig{OnSession: echoSession})
	env.client.ClientSessionCache = tls.NewLRUClientSessionCache(4)

	first := mustDial(t, env)
	if first.Resumed() {
		t.Fatal("первое подключение не может быть возобновлением")
	}
	// Билет приходит сразу после рукопожатия — даём ему долететь.
	time.Sleep(300 * time.Millisecond)
	first.Close()

	second := mustDial(t, env)
	if !second.Resumed() {
		t.Fatal("второе подключение не возобновило сессию — кэш билетов не работает")
	}
	t.Logf("возобновление: %v, ранние данные: %v", second.Resumed(), second.Used0RTT())
}
