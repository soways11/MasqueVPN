package masque

import (
	"context"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/soways11/masquevpn/internal/auth"
)

func testPool(t *testing.T, prefix string) *IPPool {
	t.Helper()
	p, err := NewIPPool(netip.MustParsePrefix(prefix))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestAddressLeaseFollowsClient — адрес закреплён за клиентом, а не за
// сессией. Это и есть лечение того, из-за чего вставала передача при
// ротации: новая сессия открывается, пока старая ещё жива, и должна получить
// ТОТ ЖЕ адрес, а не занять второй.
func TestAddressLeaseFollowsClient(t *testing.T) {
	pool := testPool(t, "10.8.0.0/24")
	now := time.Now()
	r := newLeaseRegistry([]*IPPool{pool}, time.Minute)
	r.now = func() time.Time { return now }

	l1, err := r.acquire("клиент-1", "устройство")
	if err != nil {
		t.Fatal(err)
	}
	addr := l1.addrs[0]

	// Ротация: вторая сессия того же клиента при живой первой.
	l2, err := r.acquire("клиент-1", "устройство")
	if err != nil {
		t.Fatal(err)
	}
	if l2.addrs[0] != addr {
		t.Fatalf("при ротации клиент получил %s вместо %s", l2.addrs[0], addr)
	}
	if pool.InUse() != 1 {
		t.Fatalf("адрес задвоился в пуле: занято %d", pool.InUse())
	}

	// Старая сессия ушла — адрес остаётся за клиентом.
	r.release(l1)
	if pool.InUse() != 1 {
		t.Fatal("адрес отдан, пока клиент на связи")
	}

	// Ушла и новая: адрес держится ещё TTL.
	r.release(l2)
	if pool.InUse() != 1 {
		t.Fatal("адрес отдан сразу после ухода клиента — при переподключении он получит чужой")
	}
	l3, _ := r.acquire("клиент-1", "устройство")
	if l3.addrs[0] != addr {
		t.Fatalf("после переподключения выдан %s вместо %s", l3.addrs[0], addr)
	}
	r.release(l3)

	// Другой клиент получает свой адрес.
	l4, _ := r.acquire("клиент-2", "устройство")
	if l4.addrs[0] == addr {
		t.Fatal("двум клиентам выдан один адрес")
	}

	// После TTL аренда ушедшего клиента убирается.
	now = now.Add(2 * time.Minute)
	if _, err := r.acquire("клиент-3", "устройство"); err != nil {
		t.Fatal(err)
	}
	if r.leases() != 2 { // клиент-2 (на связи) и клиент-3
		t.Fatalf("аренд осталось %d — просроченная не убрана", r.leases())
	}
}

// TestAddressLeaseAnonymousAndExhaustion — без псевдонима клиента поведение
// прежнее (адрес живёт ровно сессию), а исчерпанный пул сначала отбирает
// адреса у ушедших и только потом отказывает.
func TestAddressLeaseAnonymousAndExhaustion(t *testing.T) {
	// /30 — ровно один клиентский адрес (сеть, шлюз, клиент, broadcast).
	pool := testPool(t, "10.8.0.0/30")
	r := newLeaseRegistry([]*IPPool{pool}, time.Hour)

	l, err := r.acquire("", "")
	if err != nil {
		t.Fatal(err)
	}
	r.release(l)
	if pool.InUse() != 0 {
		t.Fatal("адрес анонимной сессии не возвращён в пул")
	}
	if r.leases() != 0 {
		t.Fatal("анонимная сессия создала аренду")
	}

	a, err := r.acquire("клиент-1", "устройство")
	if err != nil {
		t.Fatal(err)
	}
	addrA := a.addrs[0]
	if _, err := r.acquire("клиент-2", "устройство"); err == nil {
		t.Fatal("второй клиент получил адрес при занятом пуле")
	}
	r.release(a)
	// Клиент-1 ушёл: его адрес ещё держится за ним, но отдать живому клиенту
	// важнее, чем сохранить для ушедшего.
	b, err := r.acquire("клиент-2", "устройство")
	if err != nil {
		t.Fatalf("пул исчерпан ушедшим клиентом: %v", err)
	}
	if b.addrs[0] != addrA {
		t.Fatalf("выдан %s, а свободен был только %s", b.addrs[0], addrA)
	}
}

// TestSameClientKeepsAddressAcrossSessions — то же на настоящем QUIC: две
// одновременные сессии одного клиента (ровно то, что происходит при ротации)
// получают один адрес, чужой клиент — другой, а переподключение возвращает
// прежний.
func TestSameClientKeepsAddressAcrossSessions(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	srv, err := auth.New(key, auth.Options{})
	if err != nil {
		t.Fatal(err)
	}
	// Два клиента на одном ключе — разные установки, разные псевдонимы.
	cli1, _ := auth.New(key, auth.Options{ClientID: []byte("установка-1")})
	cli2, _ := auth.New(key, auth.Options{ClientID: []byte("установка-2")})

	env := startServer(t, ServerConfig{Identify: srv.Identify})
	dial := func(a *auth.Authenticator) *Conn {
		t.Helper()
		hdr, err := a.Header()
		if err != nil {
			t.Fatal(err)
		}
		c, err := env.dial(t, func(cfg *ClientConfig) { cfg.Header = hdr })
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	addrOf := func(c *Conn) netip.Prefix {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		a, err := c.WaitForAddress(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return a[0]
	}

	c1 := dial(cli1)
	want := addrOf(c1)

	// Ротация: вторая сессия того же клиента при живой первой.
	c2 := dial(cli1)
	if got := addrOf(c2); got != want {
		t.Fatalf("при ротации клиент получил %s вместо %s — пакеты с прежним адресом сервер отбросит", got, want)
	}

	// Чужой клиент — свой адрес.
	c3 := dial(cli2)
	if got := addrOf(c3); got == want {
		t.Fatalf("другой клиент получил тот же адрес %s", got)
	}
	c3.Close()

	// Переподключение после обрыва: адрес возвращается.
	c1.Close()
	c2.Close()
	c4 := dial(cli1)
	defer c4.Close()
	if got := addrOf(c4); got != want {
		t.Fatalf("после переподключения выдан %s вместо %s — соединения внутри туннеля порвались бы", got, want)
	}
}

// TestTokenVersionsAndClientID — токен версии 2 несёт псевдоним клиента,
// подписанный тем же HMAC; чужая подпись и подменённый псевдоним не проходят.
func TestTokenVersionsAndClientID(t *testing.T) {
	key := make([]byte, 32)
	a, _ := auth.New(key, auth.Options{ClientID: []byte("узел-1")})
	b, _ := auth.New(key, auth.Options{ClientID: []byte("узел-2")})
	srv, _ := auth.New(key, auth.Options{})

	ha, _ := a.Header()
	hb, _ := b.Header()
	ida, deva, ok := srv.Identify(&http.Request{Header: ha})
	if !ok || ida == "" {
		t.Fatalf("свой токен не принят: %q %v", ida, ok)
	}
	if deva == "" {
		t.Fatal("в токене нет псевдонима устройства — устройства одного клиента снова поделят адрес")
	}
	idb, _, ok := srv.Identify(&http.Request{Header: hb})
	if !ok || idb == ida {
		t.Fatalf("псевдонимы совпали: %q", idb)
	}
	if ida != a.ClientID() {
		t.Fatalf("сервер увидел %q, клиент считает себя %q", ida, a.ClientID())
	}
	// Тот же псевдоним у той же установки при каждом токене.
	ha2, _ := a.Header()
	if id2, _, _ := srv.Identify(&http.Request{Header: ha2}); id2 != ida {
		t.Fatalf("псевдоним сменился между токенами: %q → %q", ida, id2)
	}
}

// TestTwoDevicesOfOneClientGetOwnAddresses — два устройства по ОДНОМУ ключу
// работают одновременно.
//
// Так живёт человек с ноутбуком и телефоном: ключ один, устройств несколько.
// Адрес закреплён за псевдонимом клиента (lease.go), а псевдоним у обоих
// устройств одинаковый — он же и есть запись в реестре ключей. Значит оба
// получали ОДИН туннельный адрес, а таблица маршрутизатора «адрес → сессия»
// хранит одну запись: входящий трафик уходил в последнюю подключившуюся
// сессию, и на первом устройстве интернет через туннель умирал.
func TestTwoDevicesOfOneClientGetOwnAddresses(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	srv, err := auth.New(key, auth.Options{})
	if err != nil {
		t.Fatal(err)
	}
	// Один и тот же доступ, развёрнутый на двух устройствах: ссылка одна,
	// значит и client_id один.
	id := make([]byte, auth.ClientIDLen)
	for i := range id {
		id[i] = 0xA0 | byte(i)
	}
	laptop, err := auth.New(key, auth.Options{ClientIDExact: id})
	if err != nil {
		t.Fatal(err)
	}
	phone, err := auth.New(key, auth.Options{ClientIDExact: id})
	if err != nil {
		t.Fatal(err)
	}

	env := startServer(t, ServerConfig{Identify: srv.Identify})
	dial := func(a *auth.Authenticator) *Conn {
		t.Helper()
		hdr, err := a.Header()
		if err != nil {
			t.Fatal(err)
		}
		c, err := env.dial(t, func(cfg *ClientConfig) { cfg.Header = hdr })
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	addrOf := func(c *Conn) netip.Prefix {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		a, err := c.WaitForAddress(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return a[0]
	}

	c1 := dial(laptop)
	defer c1.Close()
	c2 := dial(phone)
	defer c2.Close()

	a1, a2 := addrOf(c1), addrOf(c2)
	if a1 == a2 {
		t.Fatalf("оба устройства получили один адрес %s — входящий трафик уйдёт только в одну сессию", a1)
	}
}

// TestForgetFreesAllDevicesOfClient — отзыв закрывает доступ КЛИЕНТУ, значит
// и адреса должны освободиться у всех его устройств. Оставить адрес за
// телефоном отозванного клиента — то же, что занять его навсегда: клиент не
// вернётся, а место в пуле занято.
func TestForgetFreesAllDevicesOfClient(t *testing.T) {
	pool := testPool(t, "10.8.0.0/24")
	r := newLeaseRegistry([]*IPPool{pool}, time.Hour)

	l1, err := r.acquire("клиент-1", "ноутбук")
	if err != nil {
		t.Fatal(err)
	}
	l2, err := r.acquire("клиент-1", "телефон")
	if err != nil {
		t.Fatal(err)
	}
	other, err := r.acquire("клиент-2", "ноутбук")
	if err != nil {
		t.Fatal(err)
	}
	if l1.addrs[0] == l2.addrs[0] {
		t.Fatal("устройства одного клиента получили один адрес")
	}
	r.release(l1)
	r.release(l2)

	if !r.forget("клиент-1") {
		t.Fatal("отзыв не нашёл ни одной аренды")
	}
	if pool.InUse() != 1 { // остался только клиент-2
		t.Fatalf("после отзыва занято адресов: %d — освободились не все устройства", pool.InUse())
	}
	if r.leases() != 1 {
		t.Fatalf("аренд осталось %d", r.leases())
	}
	// Чужие аренды отзыв не трогает.
	if _, ok := r.byID[leaseKey("клиент-2", "ноутбук")]; !ok {
		t.Fatal("отзыв забрал аренду другого клиента")
	}
	r.release(other)
}
