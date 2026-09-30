package masque

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// Политика по клиентам на настоящем QUIC: отказ, лимит сессий, учёт трафика и
// отзыв доступа у уже подключённого.

// testPolicy — политика, которой можно управлять из теста.
type testPolicy struct {
	mu       sync.Mutex
	deny     map[string]error
	maxLive  int
	rate     int
	accounts map[string]int64
	admits   int
}

func newTestPolicy() *testPolicy {
	return &testPolicy{deny: map[string]error{}, accounts: map[string]int64{}}
}

func (p *testPolicy) Admit(id string, live int) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.admits++
	if err, ok := p.deny[id]; ok {
		return err
	}
	if p.maxLive > 0 && live >= p.maxLive {
		return errTooMany
	}
	return nil
}

func (p *testPolicy) RateLimit(string) (int, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rate, 0
}

func (p *testPolicy) Account(id string, n int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.accounts[id] += n
}

func (p *testPolicy) accounted(id string) int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.accounts[id]
}

func (p *testPolicy) denyClient(id string, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.deny[id] = err
}

type policyError string

func (e policyError) Error() string { return string(e) }

const errTooMany = policyError("слишком много сессий")

// startServerH — как startServer, но отдаёт ещё и сам Handler: отзыв доступа
// делается через него.
func startServerH(t *testing.T, cfg ServerConfig) (*testEnv, *Handler) {
	t.Helper()
	if cfg.Pool == nil {
		p, err := NewIPPool(netip.MustParsePrefix("10.8.0.0/24"))
		if err != nil {
			t.Fatal(err)
		}
		cfg.Pool = p
	}
	// Идентификация по заголовку: сам токен здесь не важен, важна политика.
	if cfg.Identify == nil {
		cfg.Identify = func(r *http.Request) (string, string, bool) {
			id := r.Header.Get("X-Client")
			return id, r.Header.Get("X-Device"), id != ""
		}
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
	return &testEnv{addr: pc.LocalAddr().String(), client: ctls, pool: cfg.Pool}, h
}

func waitAddr(t *testing.T, c *Conn) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := c.WaitForAddress(ctx)
	return err
}

func dialAs(t *testing.T, e *testEnv, id string) (*Conn, error) {
	t.Helper()
	return e.dial(t, func(c *ClientConfig) {
		c.Header = http.Header{"X-Client": []string{id}}
	})
}

// Отказ по политике не должен расходовать адрес из пула: иначе шквал отказов
// выест пул, и законные клиенты останутся без адресов.
func TestPolicyDenyKeepsPool(t *testing.T) {
	pol := newTestPolicy()
	env, _ := startServerH(t, ServerConfig{Policy: pol})
	pol.denyClient("плохой", policyError("нельзя"))

	if c, err := dialAs(t, env, "плохой"); err == nil {
		c.Close()
		t.Fatal("клиент прошёл, хотя политика отказала")
	}
	if n := env.pool.InUse(); n != 0 {
		t.Fatalf("после отказа занято %d адресов, ожидалось 0", n)
	}

	// А законный клиент проходит — то есть отказ адресный, а не общий.
	c, err := dialAs(t, env, "хороший")
	if err != nil {
		t.Fatalf("законный клиент не прошёл: %v", err)
	}
	defer c.Close()
	if err := waitAddr(t, c); err != nil {
		t.Fatal(err)
	}
}

// Лимит сессий на клиента: без него он обходится открытием второй сессии —
// и полоса, и адреса умножаются на число сессий.
func TestPolicyPerClientSessionLimit(t *testing.T) {
	pol := newTestPolicy()
	pol.maxLive = 2
	env, h := startServerH(t, ServerConfig{Policy: pol})

	var live []*Conn
	for i := 0; i < 2; i++ {
		c, err := dialAs(t, env, "клиент")
		if err != nil {
			t.Fatalf("сессия %d не открылась: %v", i+1, err)
		}
		if err := waitAddr(t, c); err != nil {
			t.Fatal(err)
		}
		live = append(live, c)
	}
	defer func() {
		for _, c := range live {
			c.Close()
		}
	}()

	if n := h.LiveSessions("клиент"); n != 2 {
		t.Fatalf("сервер видит %d живых сессий, ожидалось 2", n)
	}
	if c, err := dialAs(t, env, "клиент"); err == nil {
		c.Close()
		t.Fatal("третья сессия открылась при лимите 2")
	}
	// Другому клиенту лимит первого не мешает.
	other, err := dialAs(t, env, "другой")
	if err != nil {
		t.Fatalf("другой клиент не прошёл: %v", err)
	}
	other.Close()
}

// Учёт трафика: без него квоты считать не на чем.
func TestPolicyAccountsTraffic(t *testing.T) {
	pol := newTestPolicy()
	env, _ := startServerH(t, ServerConfig{
		Policy:       pol,
		AccountEvery: 50 * time.Millisecond,
		OnSession: func(ctx context.Context, c *Conn, _ netip.Prefix) {
			buf := make([]byte, 1500)
			for {
				n, err := c.ReadPacket(buf)
				if err != nil {
					return
				}
				swapAddrs(buf[:n])
				_ = c.WritePacket(buf[:n])
			}
		},
	})
	c, err := dialAs(t, env, "клиент")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := waitAddr(t, c); err != nil {
		t.Fatal(err)
	}
	// Адрес и маршруты приходят разными капсулами: дождавшись адреса, можно
	// успеть отправить пакет раньше маршрутов, и его отвергнет собственная
	// проверка клиента (ErrPacketRejected). Под нагрузкой (-race, весь
	// набор разом) так и случалось.
	for deadline := time.Now().Add(3 * time.Second); len(c.Routes()) == 0; {
		if time.Now().After(deadline) {
			t.Fatal("маршруты от сервера не пришли")
		}
		time.Sleep(5 * time.Millisecond)
	}
	src := c.AssignedPrefixes()[0].Addr()

	const packets = 20
	pkt := buildIPv4(src, netip.MustParseAddr("198.51.100.7"), 17, make([]byte, 200))
	for i := 0; i < packets; i++ {
		if err := c.WritePacket(pkt); err != nil {
			t.Fatal(err)
		}
	}
	buf := make([]byte, 1500)
	for i := 0; i < packets; i++ {
		if _, err := c.ReadPacket(buf); err != nil {
			break
		}
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if pol.accounted("клиент") >= int64(packets*len(pkt)) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("учтено %d байт, ожидалось не меньше %d", pol.accounted("клиент"), packets*len(pkt))
}

// Отзыв доступа у УЖЕ подключённого. Токен проверяется один раз, при открытии
// сессии, поэтому без закрытия живых сессий отзыв не работал бы до следующего
// переподключения — а его может не случиться неделями.
func TestCloseClientRevokesLiveSessions(t *testing.T) {
	pol := newTestPolicy()
	env, h := startServerH(t, ServerConfig{Policy: pol})

	var conns []*Conn
	for i := 0; i < 2; i++ {
		c, err := dialAs(t, env, "уходящий")
		if err != nil {
			t.Fatal(err)
		}
		if err := waitAddr(t, c); err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	keep, err := dialAs(t, env, "остающийся")
	if err != nil {
		t.Fatal(err)
	}
	defer keep.Close()
	if err := waitAddr(t, keep); err != nil {
		t.Fatal(err)
	}

	if n := h.CloseClient("уходящий"); n != 2 {
		t.Fatalf("закрыто %d сессий, ожидалось 2", n)
	}
	for i, c := range conns {
		select {
		case <-c.Done():
		case <-time.After(3 * time.Second):
			t.Fatalf("сессия %d не закрылась после отзыва", i+1)
		}
	}
	// Чужая сессия жива: отзыв адресный.
	select {
	case <-keep.Done():
		t.Fatal("закрыта сессия клиента, которого не отзывали")
	default:
	}

	// Адрес отозванного возвращается в пул сразу, а не через TTL аренды:
	// он не вернётся, а адрес всё это время числился бы занятым.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		h.CloseClient("уходящий") // аренду отпускает закрывающаяся сессия, не мгновенно
		if env.pool.InUse() == 1 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("после отзыва занято %d адресов, ожидался 1 (оставшегося клиента)", env.pool.InUse())
}
