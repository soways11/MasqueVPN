package dnscover

import (
	"context"
	"encoding/binary"
	"math"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// разобранный запрос, как его видит наблюдатель на стороне резолвера.
type seen struct {
	id       uint16
	name     string
	qtype    uint16
	rd       bool
	edns     bool
	srcPort  int
	received time.Time
}

// fakeResolver — UDP-сервер, который разбирает запросы и отвечает пустым
// ответом, как настоящий резолвер.
type fakeResolver struct {
	addr netip.AddrPort
	mu   sync.Mutex
	got  []seen
}

func startResolver(t *testing.T) *fakeResolver {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	r := &fakeResolver{addr: pc.LocalAddr().(*net.UDPAddr).AddrPort()}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			q, err := parseQuery(buf[:n])
			if err != nil {
				continue
			}
			q.srcPort = int(from.Port())
			q.received = time.Now()
			r.mu.Lock()
			r.got = append(r.got, q)
			r.mu.Unlock()
			// Ответ: тот же заголовок с флагом QR и без записей.
			rsp := append([]byte(nil), buf[:n]...)
			rsp[2] |= 0x80
			pc.WriteToUDPAddrPort(rsp, from)
		}
	}()
	return r
}

func (r *fakeResolver) seen() []seen {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]seen(nil), r.got...)
}

// parseQuery разбирает запрос так же, как это сделал бы наблюдатель.
func parseQuery(b []byte) (seen, error) {
	var q seen
	if len(b) < 12 {
		return q, errShort
	}
	q.id = binary.BigEndian.Uint16(b)
	flags := binary.BigEndian.Uint16(b[2:])
	q.rd = flags&0x0100 != 0
	if binary.BigEndian.Uint16(b[4:]) != 1 {
		return q, errShort
	}
	q.edns = binary.BigEndian.Uint16(b[10:]) == 1
	p := 12
	var labels []string
	for {
		if p >= len(b) {
			return q, errShort
		}
		l := int(b[p])
		p++
		if l == 0 {
			break
		}
		if p+l > len(b) {
			return q, errShort
		}
		labels = append(labels, string(b[p:p+l]))
		p += l
	}
	if p+4 > len(b) {
		return q, errShort
	}
	q.name = strings.Join(labels, ".")
	q.qtype = binary.BigEndian.Uint16(b[p:])
	return q, nil
}

var errShort = net.UnknownNetworkError("короткий или битый запрос")

func run(t *testing.T, cfg Config, want int) *Cover {
	t.Helper()
	cfg.allowLoopback = true // поддельный резолвер живёт на 127.0.0.1
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)
	deadline := time.After(10 * time.Second)
	for {
		if int(c.Stats().Queries) >= want {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("за 10 с отправлено %d запросов из %d", c.Stats().Queries, want)
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	time.Sleep(50 * time.Millisecond) // дать долететь последним
	return c
}

// TestQueriesLookLikeAStubResolver — главный тест: то, что уходит на провод,
// должно выглядеть как работа обычного стаб-резолвера.
func TestQueriesLookLikeAStubResolver(t *testing.T) {
	r := startResolver(t)
	domains := []string{"www.example.com", "cdn.example.net", "example.org"}
	c := run(t, Config{
		Servers: []netip.AddrPort{r.addr},
		Domains: domains,
		Next:    func() time.Duration { return time.Millisecond },
	}, 60)
	got := r.seen()
	if len(got) < 50 {
		t.Fatalf("резолвер увидел %d запросов", len(got))
	}

	ids := map[uint16]int{}
	ports := map[int]int{}
	types := map[uint16]int{}
	byID := map[uint16]bool{}
	for _, q := range got {
		if !slices.Contains(domains, q.name) {
			t.Fatalf("спрошено имя не из списка: %q (случайные поддомены — признак DNS-туннеля)", q.name)
		}
		if !q.rd {
			t.Fatal("нет флага рекурсии — стаб-резолверы его ставят всегда")
		}
		if !q.edns {
			t.Fatal("нет OPT-записи EDNS0 — современные резолверы её шлют")
		}
		ids[q.id]++
		ports[q.srcPort]++
		types[q.qtype]++
		byID[q.id] = true
	}
	if types[typeA] == 0 || types[typeAAAA] == 0 {
		t.Fatalf("нет пары A/AAAA: %v", types)
	}
	// A и AAAA идут группой, поэтому их примерно поровну.
	if d := math.Abs(float64(types[typeA] - types[typeAAAA])); d > 2 {
		t.Fatalf("A=%d, AAAA=%d — стаб спрашивает их парой", types[typeA], types[typeAAAA])
	}
	if types[typeHTTPS] == 0 {
		t.Fatal("ни одного запроса HTTPS RR — их шлют современные браузеры")
	}
	if len(ids) < len(got)*9/10 {
		t.Fatalf("идентификаторов %d на %d запросов — они должны быть случайными", len(ids), len(got))
	}
	// Порт на группу свой: так делает glibc, открывая сокет на каждый поиск.
	if len(ports) < int(c.Stats().Groups)*9/10 {
		t.Fatalf("портов %d на %d групп — сокет переиспользуется", len(ports), c.Stats().Groups)
	}
	if st := c.Stats(); st.Answers == 0 || st.Errors != 0 {
		t.Fatalf("счётчики: %+v (ответы должны вычитываться)", st)
	}
}

// TestNamesCycleBeforeRepeat — одно и то же имя не спрашивается подряд:
// у резолвера есть кэш, повтор через секунды выглядел бы неправдоподобно.
func TestNamesCycleBeforeRepeat(t *testing.T) {
	r := startResolver(t)
	domains := []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com"}
	run(t, Config{
		Servers: []netip.AddrPort{r.addr},
		Domains: domains,
		Next:    func() time.Duration { return time.Millisecond },
	}, 40)

	var order []string
	for _, q := range r.seen() {
		if q.qtype == typeA { // по одному имени на группу
			order = append(order, q.name)
		}
	}
	if len(order) < 8 {
		t.Fatalf("групп мало: %d", len(order))
	}
	for i := 1; i < len(order); i++ {
		if order[i] == order[i-1] {
			t.Fatalf("имя %q спрошено дважды подряд: %v", order[i], order)
		}
	}
	// В каждом полном проходе списка встречаются все имена.
	for i := 0; i+len(domains) <= len(order); i += len(domains) {
		window := order[i : i+len(domains)]
		for _, d := range domains {
			if !slices.Contains(window, d) {
				t.Fatalf("в проходе %v нет имени %q — список обходится не целиком", window, d)
			}
		}
	}
}

// TestIntervalsArePoisson — интервалы по умолчанию случайные, а не метроном.
// Постоянный период сам по себе признак (см. cover-трафик в obfuscation).
func TestIntervalsArePoisson(t *testing.T) {
	const n = 500
	mean := DefaultMeanInterval
	vals := make([]float64, n)
	uniq := map[time.Duration]bool{}
	var sum float64
	for i := range vals {
		d := expInterval(mean)
		if d <= 0 || d > 5*mean {
			t.Fatalf("интервал вне границ: %v", d)
		}
		vals[i] = float64(d)
		uniq[d] = true
		sum += vals[i]
	}
	avg := sum / n
	var varsum float64
	for _, v := range vals {
		varsum += (v - avg) * (v - avg)
	}
	cv := math.Sqrt(varsum/n) / avg
	if cv < 0.6 {
		t.Fatalf("коэффициент вариации %.2f — интервалы слишком ровные", cv)
	}
	if len(uniq) < n*9/10 {
		t.Fatalf("уникальных значений %d из %d", len(uniq), n)
	}
	if avg < float64(mean)/2 || avg > float64(mean)*2 {
		t.Fatalf("среднее %v далеко от заданного %v", time.Duration(avg), mean)
	}
}

// TestSocketIsProtected — каждый сокет проходит через Protect: иначе запросы
// уйдут В туннель, и снаружи по-прежнему не будет ни одного DNS-запроса.
func TestSocketIsProtected(t *testing.T) {
	r := startResolver(t)
	var mu sync.Mutex
	protected := 0
	c, err := New(Config{
		Servers:       []netip.AddrPort{r.addr},
		Domains:       []string{"www.example.com"},
		allowLoopback: true,
		Protect: func(syscall.RawConn) error {
			mu.Lock()
			defer mu.Unlock()
			protected++
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := c.QueryOnce(context.Background(), "www.example.com"); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if protected != 3 {
		t.Fatalf("Protect вызван %d раз из 3", protected)
	}
}

// TestLoopbackResolverRejected — заглушка systemd-resolved не годится:
// запрос к 127.0.0.53 уйдёт дальше по обычной маршрутизации, то есть внутрь
// туннеля, и снаружи не появится ничего.
func TestLoopbackResolverRejected(t *testing.T) {
	_, err := New(Config{Servers: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.53:53")}})
	if err == nil {
		t.Fatal("локальная заглушка принята как резолвер")
	}
}

func TestConfigValidation(t *testing.T) {
	ok := netip.MustParseAddrPort("192.0.2.1:53")
	if _, err := New(Config{}); err == nil {
		t.Fatal("пустой список резолверов принят")
	}
	if _, err := New(Config{Servers: []netip.AddrPort{ok}, Domains: []string{"пусто..точки"}}); err == nil {
		t.Fatal("некорректное имя принято")
	}
	if _, err := New(Config{Servers: []netip.AddrPort{ok}, Domains: []string{strings.Repeat("a", 64) + ".com"}}); err == nil {
		t.Fatal("метка длиннее 63 байт принята")
	}
	// Порт по умолчанию проставляется.
	c, err := New(Config{Servers: []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), 0)}})
	if err != nil {
		t.Fatal(err)
	}
	if c.cfg.Servers[0].Port() != 53 {
		t.Fatalf("порт %d", c.cfg.Servers[0].Port())
	}
}
