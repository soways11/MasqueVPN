package session

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
	"math"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/soways11/masquevpn/internal/masque"
)

// --- тестовый MASQUE-сервер поверх публичного API пакета masque ---

func buildIPv4(src, dst netip.Addr, payload []byte) []byte {
	b := make([]byte, 20+len(payload))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	b[8] = 64
	b[9] = 17
	s, d := src.As4(), dst.As4()
	copy(b[12:], s[:])
	copy(b[16:], d[:])
	copy(b[20:], payload)
	return b
}

func swap(p []byte) {
	var tmp [4]byte
	copy(tmp[:], p[12:16])
	copy(p[12:16], p[16:20])
	copy(p[16:20], tmp[:])
}

type env struct {
	addr   string
	client *tls.Config
}

func startEnv(t *testing.T, onConn ...func(*masque.Conn)) *env {
	t.Helper()
	return startEnvWith(t, nil, onConn...)
}

// startEnvWith — то же, но сервер можно заставить молчать: пока silent
// взведён, он читает пакеты и ничего не отвечает (путь при этом жив).
func startEnvWith(t *testing.T, silent *atomic.Bool, onConn ...func(*masque.Conn)) *env {
	t.Helper()
	return startEnvOpts(t, envOpts{silent: silent}, onConn...)
}

type envOpts struct {
	silent *atomic.Bool
	// identified — сервер опознаёт клиента, как боевой (auth): адрес
	// закрепляется за клиентом и устройством и возвращается ему сразу, даже
	// пока старая сессия ещё не закрыта.
	identified bool
}

func startEnvOpts(t *testing.T, o envOpts, onConn ...func(*masque.Conn)) *env {
	t.Helper()
	silent := o.silent
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	ipPool, err := masque.NewIPPool(netip.MustParsePrefix("10.8.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	var identify func(*http.Request) (string, string, bool)
	if o.identified {
		identify = func(*http.Request) (string, string, bool) { return "c1", "d1", true }
	}
	h, err := masque.NewHandler(masque.ServerConfig{
		Pool:     ipPool,
		Identify: identify,
		OnSession: func(ctx context.Context, c *masque.Conn, _ netip.Prefix) {
			for _, f := range onConn {
				f(c)
			}
			buf := make([]byte, 2000)
			for {
				n, err := c.ReadPacket(buf)
				if err != nil {
					return
				}
				if silent != nil && silent.Load() {
					continue
				}
				swap(buf[:n])
				_ = c.WritePacket(buf[:n])
			}
		},
	})
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
	go func() { _ = srv.Serve(pc) }()
	t.Cleanup(func() { _ = srv.Close(); _ = pc.Close() })
	return &env{addr: pc.LocalAddr().String(), client: &tls.Config{RootCAs: pool, ServerName: "localhost"}}
}

func (e *env) dialFunc() DialFunc { return e.dialTo(func() string { return e.addr }) }

// dialTo — дозвон по адресу, который выбирается при каждом дозвоне.
func (e *env) dialTo(addr func() string) DialFunc {
	return func(ctx context.Context) (*masque.Conn, error) {
		c, err := masque.Dial(ctx, masque.ClientConfig{Addr: addr(), TLSConfig: e.client, Authority: "localhost"})
		if err != nil {
			return nil, err
		}
		if _, err := c.WaitForAddress(ctx); err != nil {
			c.Close()
			return nil, err
		}
		// Ждём ROUTE_ADVERTISEMENT, иначе WritePacket отклонит по политике.
		deadline := time.Now().Add(3 * time.Second)
		for len(c.Routes()) == 0 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		return c, nil
	}
}

func echo(t *testing.T, s *Session, src netip.Addr) {
	t.Helper()
	if err := s.WritePacket(buildIPv4(src, netip.MustParseAddr("1.1.1.1"), []byte("ping"))); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2000)
	type res struct {
		n   int
		err error
	}
	ch := make(chan res, 1)
	go func() { n, err := s.ReadPacket(buf); ch <- res{n, err} }()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("read: %v", r.err)
		}
		if string(buf[20:r.n]) != "ping" {
			t.Fatalf("bad echo %q", buf[20:r.n])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("нет эха")
	}
}

func TestManualRotationKeepsTrafficAndChangesConn(t *testing.T) {
	e := startEnv(t)
	var rotEvents atomic.Int64
	var oldP, newP atomic.Value
	s, err := Open(context.Background(), Config{
		Dial: e.dialFunc(),
		OnRotate: func(o, n []netip.Prefix) {
			oldP.Store(o)
			newP.Store(n)
			rotEvents.Add(1)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	first := s.Prefixes()
	echo(t, s, first[0].Addr())

	if err := s.Rotate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.Rotations() != 1 || rotEvents.Load() != 1 {
		t.Fatalf("rotations=%d events=%d", s.Rotations(), rotEvents.Load())
	}
	second := s.Prefixes()
	if first[0] == second[0] {
		t.Fatalf("адрес не изменился при ротации: %v", first)
	}
	// Трафик продолжает ходить через новое соединение.
	echo(t, s, second[0].Addr())

	oldPrefixes := oldP.Load().([]netip.Prefix)
	newPrefixes := newP.Load().([]netip.Prefix)
	if oldPrefixes[0] != first[0] || newPrefixes[0] != second[0] {
		t.Fatalf("OnRotate передал неверные адреса: %v -> %v", oldPrefixes, newPrefixes)
	}
}

func TestAutoRotationByTime(t *testing.T) {
	e := startEnv(t)
	s, err := Open(context.Background(), Config{
		Dial:  e.dialFunc(),
		Every: 150 * time.Millisecond,
		Grace: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	deadline := time.Now().Add(5 * time.Second)
	for s.Rotations() < 2 && time.Now().Before(deadline) {
		// Держим трафик, чтобы убедиться, что ротация ему не мешает.
		echo(t, s, s.Prefixes()[0].Addr())
		time.Sleep(60 * time.Millisecond)
	}
	if s.Rotations() < 2 {
		t.Fatalf("автоматических ротаций: %d, ожидалось >=2", s.Rotations())
	}
	// После нескольких ротаций трафик всё ещё работает.
	echo(t, s, s.Prefixes()[0].Addr())
}

func TestCloseStopsEverything(t *testing.T) {
	e := startEnv(t)
	s, err := Open(context.Background(), Config{Dial: e.dialFunc(), Every: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	echo(t, s, s.Prefixes()[0].Addr())
	done := make(chan error, 1)
	go func() { done <- s.Close() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close завис")
	}
	buf := make([]byte, 100)
	if _, err := s.ReadPacket(buf); err != ErrClosed {
		t.Fatalf("после Close ждём ErrClosed, получили %v", err)
	}
}

// TestKeepAddressAcrossRotation — при ротации адрес должен сохраняться, иначе
// каждая ротация рвёт все соединения внутри туннеля: мера против долгоживущих
// соединений ломала бы пользователю работу.
func TestKeepAddressAcrossRotation(t *testing.T) {
	e := startEnv(t)
	rotated := make(chan []netip.Prefix, 4)
	s, err := Open(context.Background(), Config{
		Dial:        e.dialFunc(),
		Grace:       100 * time.Millisecond,
		KeepAddress: true,
		OnRotate:    func(o, n []netip.Prefix) { rotated <- n },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	before := s.Prefixes()
	echo(t, s, before[0].Addr())

	if err := s.Rotate(context.Background()); err != nil {
		t.Fatal(err)
	}

	// OnRotate при KeepAddress вызывается ПОСЛЕ обмена адресами — дожидаемся его.
	var reported []netip.Prefix
	select {
	case reported = <-rotated:
	case <-time.After(10 * time.Second):
		t.Fatal("OnRotate не вызван")
	}

	after := s.Prefixes()
	t.Logf("адрес до ротации: %v, после: %v, в OnRotate: %v", before, after, reported)
	if !slices.Equal(after, before) {
		t.Fatalf("адрес не сохранён: было %v, стало %v", before, after)
	}
	// OnRotate сообщает итоговый адрес, а не промежуточный.
	if !slices.Equal(reported, before) {
		t.Fatalf("OnRotate сообщил %v, ожидался итоговый %v", reported, before)
	}
	// И трафик ходит по сохранённому адресу.
	echo(t, s, after[0].Addr())
}

// Без KeepAddress поведение прежнее: адрес меняется, OnRotate вызывается сразу.
func TestRotationWithoutKeepAddressChangesAddress(t *testing.T) {
	e := startEnv(t)
	s, err := Open(context.Background(), Config{Dial: e.dialFunc(), Grace: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	before := s.Prefixes()
	if err := s.Rotate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if slices.Equal(s.Prefixes(), before) {
		t.Fatal("без KeepAddress адрес неожиданно сохранился")
	}
}

// TestReconnectAfterServerDrop — сервер оборвал сессию (перезапуск, закрытие
// по простою): клиент обязан переподключиться сам, вернуть прежний адрес и
// продолжить работу через тот же объект Session.
func TestReconnectAfterServerDrop(t *testing.T) {
	conns := make(chan *masque.Conn, 8)
	e := startEnv(t, func(c *masque.Conn) { conns <- c })
	var attempts atomic.Int32
	rotated := make(chan []netip.Prefix, 4)
	s, err := Open(context.Background(), Config{
		Dial:        e.dialFunc(),
		Reconnect:   true,
		KeepAddress: true,
		OnReconnect: func(int, error) { attempts.Add(1) },
		OnRotate:    func(_, n []netip.Prefix) { rotated <- n },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	before := s.Prefixes()
	echo(t, s, before[0].Addr())

	(<-conns).Close() // сервер рвёт сессию

	select {
	case n := <-rotated:
		if !slices.Equal(n, before) {
			t.Fatalf("после переподключения адрес %v, ожидался прежний %v", n, before)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("клиент не переподключился")
	}
	if s.Reconnects() != 1 || attempts.Load() < 1 {
		t.Fatalf("reconnects=%d attempts=%d", s.Reconnects(), attempts.Load())
	}
	echo(t, s, before[0].Addr())
}

// Без Reconnect обрыв остаётся обрывом (прежнее поведение).
func TestNoReconnectByDefault(t *testing.T) {
	conns := make(chan *masque.Conn, 8)
	e := startEnv(t, func(c *masque.Conn) { conns <- c })
	s, err := Open(context.Background(), Config{Dial: e.dialFunc()})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	(<-conns).Close()
	time.Sleep(time.Second)
	if s.Reconnects() != 0 {
		t.Fatal("переподключение без Reconnect")
	}
}

// TestKeepAddressRotationHasNoGap — во время ротации с KeepAddress интерфейс
// ещё работает от прежнего адреса, а у нового соединения временный. Пакеты с
// прежним адресом не должны теряться: они идут через старое соединение.
func TestKeepAddressRotationHasNoGap(t *testing.T) {
	e := startEnv(t)
	s, err := Open(context.Background(), Config{
		Dial:        e.dialFunc(),
		Grace:       500 * time.Millisecond,
		KeepAddress: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	addr := s.Prefixes()[0].Addr()
	if err := s.Rotate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if slices.Equal(s.Current().AssignedPrefixes(), s.Prefixes()) && s.Prefixes()[0].Addr() == addr {
		t.Skip("новое соединение сразу получило прежний адрес — окна нет")
	}
	// Окно Grace: прежний адрес всё ещё должен работать.
	pkt := buildIPv4(addr, netip.MustParseAddr("1.1.1.1"), []byte("in-grace"))
	if err := s.WritePacket(pkt); err != nil {
		t.Fatalf("пакет с прежним адресом во время ротации отвергнут: %v", err)
	}
	buf := make([]byte, 2000)
	done := make(chan int, 1)
	go func() { n, _ := s.ReadPacket(buf); done <- n }()
	select {
	case n := <-done:
		if string(buf[20:n]) != "in-grace" {
			t.Fatalf("got %q", buf[20:n])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ответ не получен")
	}
}

// TestAutoRotatePeriodIsAccurate — фактический период ротации близок к
// заданному. Раньше срок проверялся по тикеру, который шёл своей фазой:
// тик почти всегда приходил чуть раньше срока, отбраковывался, и ротация
// уезжала на следующий — заданные 30 минут превращались в час.
func TestAutoRotatePeriodIsAccurate(t *testing.T) {
	e := startEnv(t)
	const every = 150 * time.Millisecond
	// Дозвон никогда не мгновенный — именно на этом прежняя схема и теряла
	// каждый второй тик.
	slowDial := func(ctx context.Context) (*masque.Conn, error) {
		time.Sleep(30 * time.Millisecond)
		return e.dialFunc()(ctx)
	}
	var mu sync.Mutex
	var at []time.Time
	s, err := Open(context.Background(), Config{
		Dial:     slowDial,
		Every:    every,
		Grace:    20 * time.Millisecond,
		OnRotate: func([]netip.Prefix, []netip.Prefix) { mu.Lock(); at = append(at, time.Now()); mu.Unlock() },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	time.Sleep(1500 * time.Millisecond)

	mu.Lock()
	got := append([]time.Time(nil), at...)
	mu.Unlock()
	if len(got) < 3 {
		t.Fatalf("ротаций всего %d — не из чего считать период", len(got))
	}
	avg := got[len(got)-1].Sub(got[0]) / time.Duration(len(got)-1)
	t.Logf("%d ротаций, средний период %v при заданных %v", len(got), avg.Round(time.Millisecond), every)
	if avg > every*8/5 {
		t.Fatalf("средний период %v при заданных %v — срок уезжает", avg, every)
	}
}

// TestRotationPeriodIsJittered — сроки ротации не повторяются.
//
// Ровно периодическая ротация — метроном, и самый заметный из всех:
// рукопожатие QUIC наблюдатель узнаёт в открытую, так что «новое соединение
// к тому же адресу ровно каждые N минут» видно без всякой расшифровки.
func TestRotationPeriodIsJittered(t *testing.T) {
	e := startEnv(t)
	const every = 120 * time.Millisecond
	var mu sync.Mutex
	var at []time.Time
	s, err := Open(context.Background(), Config{
		Dial:     e.dialFunc(),
		Every:    every,
		Grace:    10 * time.Millisecond,
		OnRotate: func([]netip.Prefix, []netip.Prefix) { mu.Lock(); at = append(at, time.Now()); mu.Unlock() },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	time.Sleep(2 * time.Second)

	mu.Lock()
	got := append([]time.Time(nil), at...)
	mu.Unlock()
	if len(got) < 6 {
		t.Fatalf("ротаций всего %d — не из чего считать разброс", len(got))
	}
	var gaps []float64
	var sum float64
	for i := 1; i < len(got); i++ {
		g := got[i].Sub(got[i-1]).Seconds() * 1000
		gaps = append(gaps, g)
		sum += g
	}
	mean := sum / float64(len(gaps))
	var dev float64
	for _, g := range gaps {
		dev += (g - mean) * (g - mean)
	}
	cv := math.Sqrt(dev/float64(len(gaps))) / mean
	t.Logf("%d ротаций, средний период %.0f мс при заданных %v, разброс %.2f, интервалы %.0f",
		len(got), mean, every, cv, gaps)

	// Разброс есть: без него коэффициент вариации был бы околонулевым.
	if cv < 0.05 {
		t.Fatalf("коэффициент вариации %.3f — ротация идёт метрономом", cv)
	}
	// И при этом средний период не уехал от заданного.
	if mean < 0.6*float64(every/time.Millisecond) || mean > 1.6*float64(every/time.Millisecond) {
		t.Fatalf("средний период %.0f мс при заданных %v", mean, every)
	}
}

// Запись в оборванное соединение не должна быть смертельной ошибкой, пока
// включено переподключение.
//
// Насос туннеля считает ошибку записи поводом завершить клиента. Значит,
// сервер, закрывший сессию — отзыв доступа, исчерпанная квота, перезапуск, —
// убивал бы клиент вместо переподключения: вернуть его мог бы только человек
// руками. Нашлось сквозным тестом отзыва, а не рассуждением.
func TestWriteAfterDropIsNotFatal(t *testing.T) {
	conns := make(chan *masque.Conn, 8)
	e := startEnv(t, func(c *masque.Conn) { conns <- c })
	// Переподключение задерживаем: на петле оно происходит мгновенно, и окна,
	// в котором соединение уже мертво, а нового ещё нет, просто не было бы —
	// то есть тест проверял бы не то, ради чего написан.
	dial := e.dialFunc()
	var refuse atomic.Bool
	s, err := Open(context.Background(), Config{
		Dial: func(ctx context.Context) (*masque.Conn, error) {
			if refuse.Load() {
				return nil, errors.New("сервер недоступен")
			}
			return dial(ctx)
		},
		Reconnect: true, KeepAddress: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	addr := s.Prefixes()[0].Addr()

	refuse.Store(true)
	(<-conns).Close() // сервер закрыл сессию
	time.AfterFunc(700*time.Millisecond, func() { refuse.Store(false) })

	// Пишем, пока соединение мертво: пакеты теряются, но ошибки нет.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		err := s.WritePacket(buildIPv4(addr, netip.MustParseAddr("198.51.100.7"), []byte("x")))
		if err != nil {
			t.Fatalf("запись в оборванное соединение вернула ошибку %v — насос туннеля "+
				"на ней завершит клиент, вместо того чтобы дождаться переподключения", err)
		}
		if s.Reconnects() > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if s.Reconnects() == 0 {
		t.Fatal("переподключения не случилось")
	}
	if s.Dropped() == 0 {
		t.Fatal("потерянные пакеты не посчитаны — потеря должна быть видна в счётчиках")
	}
	// После восстановления связь снова работает. Ищем именно свой ответ:
	// в очереди ещё лежат пакеты, отражённые сервером в цикле выше.
	echoMarked(t, s, s.Prefixes()[0].Addr(), "снова-на-связи")
}

// Без переподключения обрыв остаётся ошибкой: молчать о нём нельзя, иначе
// клиент будет бесконечно писать в никуда и считать, что всё хорошо.
func TestWriteAfterDropIsFatalWithoutReconnect(t *testing.T) {
	conns := make(chan *masque.Conn, 8)
	e := startEnv(t, func(c *masque.Conn) { conns <- c })
	s, err := Open(context.Background(), Config{Dial: e.dialFunc()})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	addr := s.Prefixes()[0].Addr()
	(<-conns).Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := s.WritePacket(buildIPv4(addr, netip.MustParseAddr("198.51.100.7"), []byte("x"))); err != nil {
			return // ожидаемо
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("обрыв без переподключения не дал ошибки")
}

// echoMarked шлёт пакет с меткой и ждёт именно его отражения, пропуская
// всё, что уже лежит в очереди.
func echoMarked(t *testing.T, s *Session, src netip.Addr, mark string) {
	t.Helper()
	if err := s.WritePacket(buildIPv4(src, netip.MustParseAddr("1.1.1.1"), []byte(mark))); err != nil {
		t.Fatal(err)
	}
	type res struct {
		p   []byte
		err error
	}
	ch := make(chan res, 64)
	go func() {
		for {
			buf := make([]byte, 2000)
			n, err := s.ReadPacket(buf)
			if err != nil {
				ch <- res{nil, err}
				return
			}
			ch <- res{buf[:n], nil}
		}
	}()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case r := <-ch:
			if r.err != nil {
				t.Fatalf("чтение после восстановления: %v", r.err)
			}
			if bytes.Contains(r.p, []byte(mark)) {
				return
			}
		case <-deadline:
			t.Fatal("после восстановления свой пакет не вернулся")
		}
	}
}

// TestStatsSurviveRotation — счётчики сессии не обнуляются при ротации.
//
// Их показывает окно клиента как «принято/отправлено за сессию». Живут они
// в *masque.Conn, а ротация заменяет соединение новым — без переноса итогов
// расход трафика падал бы до нуля посреди работы, и человек решил бы, что
// соединение переустановилось.
func TestStatsSurviveRotation(t *testing.T) {
	e := startEnv(t)
	s, err := Open(context.Background(), Config{Dial: e.dialFunc()})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	first := s.Prefixes()
	echo(t, s, first[0].Addr())

	before := s.Stats()
	if before.BytesIn == 0 || before.BytesOut == 0 {
		t.Fatalf("до ротации счётчики пусты: %+v", before)
	}

	if err := s.Rotate(context.Background()); err != nil {
		t.Fatal(err)
	}
	after := s.Stats()
	if after.BytesIn < before.BytesIn || after.BytesOut < before.BytesOut {
		t.Errorf("ротация обнулила счётчики: было %d/%d, стало %d/%d",
			before.BytesIn, before.BytesOut, after.BytesIn, after.BytesOut)
	}

	// И трафик после ротации продолжает прибавляться к прежнему итогу.
	second := s.Prefixes()
	echo(t, s, second[0].Addr())
	grown := s.Stats()
	if grown.BytesIn <= after.BytesIn || grown.BytesOut <= after.BytesOut {
		t.Errorf("после ротации счётчики не растут: %d/%d → %d/%d",
			after.BytesIn, after.BytesOut, grown.BytesIn, grown.BytesOut)
	}
}

// relay — UDP-посредник между клиентом и сервером, которого можно
// «перерезать»: пакеты начинают молча пропадать в обе стороны. Так выглядит
// порт, который начали резать посреди сессии.
type relay struct {
	addr    string
	blocked atomic.Bool
}

func newRelay(t *testing.T, target string) *relay {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	up, err := net.Dial("udp", target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close(); up.Close() })
	r := &relay{addr: pc.LocalAddr().String()}
	var client atomic.Value
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if r.blocked.Load() {
				continue
			}
			client.Store(from)
			_, _ = up.Write(buf[:n])
		}
	}()
	go func() {
		buf := make([]byte, 65536)
		for {
			n, err := up.Read(buf)
			if err != nil {
				return
			}
			to, _ := client.Load().(net.Addr)
			if r.blocked.Load() || to == nil {
				continue
			}
			_, _ = pc.WriteTo(buf[:n], to)
		}
	}()
	return r
}

// sendLoop шлёт пакеты в туннель, пока не закроется stop: сторож следит
// только за путём, по которому что-то отправляют.
func sendLoop(s *Session, src netip.Addr, stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		case <-time.After(50 * time.Millisecond):
		}
		_ = s.WritePacket(buildIPv4(src, netip.MustParseAddr("1.1.1.1"), []byte("load")))
	}
}

// TestStallSwitchesPath — путь начали резать посреди сессии: пакеты
// пропадают молча. Сторож замечает это за секунды (а не по таймауту
// простоя QUIC), рвёт соединение, клиент переподключается другим путём и
// получает прежний адрес — соединения внутри туннеля не рвутся.
func TestStallSwitchesPath(t *testing.T) {
	e := startEnvOpts(t, envOpts{identified: true})
	r := newRelay(t, e.addr)
	var direct atomic.Bool // «следующий порт»
	stalled := make(chan struct{}, 4)
	rotated := make(chan []netip.Prefix, 4)
	s, err := Open(context.Background(), Config{
		Dial: e.dialTo(func() string {
			if direct.Load() {
				return e.addr
			}
			return r.addr
		}),
		Reconnect:    true,
		KeepAddress:  true,
		StallAfter:   600 * time.Millisecond,
		ProbeTimeout: 600 * time.Millisecond,
		OnStall: func() {
			direct.Store(true)
			stalled <- struct{}{}
		},
		OnRotate: func(_, n []netip.Prefix) { rotated <- n },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	before := s.Prefixes()
	echo(t, s, before[0].Addr())

	r.blocked.Store(true)
	start := time.Now()
	stop := make(chan struct{})
	defer close(stop)
	go sendLoop(s, before[0].Addr(), stop)

	select {
	case <-stalled:
	case <-time.After(10 * time.Second):
		t.Fatal("сторож не заметил мёртвый путь")
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("мёртвый путь замечен через %v — это уже не быстрее таймаута простоя", took)
	}
	select {
	case n := <-rotated:
		if !slices.Equal(n, before) {
			t.Fatalf("после переключения адрес %v, ожидался прежний %v", n, before)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("клиент не переподключился другим путём")
	}
	if s.Stalls() != 1 {
		t.Fatalf("сторож сработал %d раз", s.Stalls())
	}
	echo(t, s, before[0].Addr())
}

// TestSilentServerIsNotStall — сервер просто молчит (односторонний поток),
// а путь жив: проверка связи отвечает, и соединение не рвётся. Иначе
// любая выгрузка без ответов вызывала бы переподключения.
func TestSilentServerIsNotStall(t *testing.T) {
	var silent atomic.Bool
	e := startEnvWith(t, &silent)
	s, err := Open(context.Background(), Config{
		Dial:         e.dialFunc(),
		Reconnect:    true,
		StallAfter:   300 * time.Millisecond,
		ProbeTimeout: 2 * time.Second,
		OnStall:      func() { t.Error("живой путь признан мёртвым") },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	src := s.Prefixes()[0].Addr()
	echo(t, s, src)
	silent.Store(true)
	stop := make(chan struct{})
	go sendLoop(s, src, stop)
	time.Sleep(2500 * time.Millisecond)
	close(stop)
	if s.Stalls() != 0 || s.Reconnects() != 0 {
		t.Fatalf("stalls=%d reconnects=%d при живом пути", s.Stalls(), s.Reconnects())
	}
	silent.Store(false)
	echo(t, s, src)
}
