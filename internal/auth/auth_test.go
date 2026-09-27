package auth

import (
	"net/http"
	"testing"
	"time"
)

func newTestAuth(t *testing.T, opts Options) (*Authenticator, *fakeClock) {
	t.Helper()
	a, err := New([]byte("0123456789abcdef0123456789abcdef"), opts)
	if err != nil {
		t.Fatal(err)
	}
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	a.now = clk.now
	return a, clk
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time      { return c.t }
func (c *fakeClock) add(d time.Duration) { c.t = c.t.Add(d) }

func TestValidTokenAccepted(t *testing.T) {
	a, _ := newTestAuth(t, Options{})
	h, err := a.Header()
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{Header: h}
	if !a.Authorize(r) {
		t.Fatal("валидный токен отклонён")
	}
}

func TestMissingOrGarbageRejected(t *testing.T) {
	a, _ := newTestAuth(t, Options{})
	cases := map[string]http.Header{
		"нет заголовка":  {},
		"пустой":         {"Authorization": {""}},
		"без Bearer":     {"Authorization": {"abcdef"}},
		"мусор base64":   {"Authorization": {"Bearer !!!!"}},
		"короткий токен": {"Authorization": {"Bearer AAAA"}},
	}
	for name, h := range cases {
		if a.Authorize(&http.Request{Header: h}) {
			t.Errorf("%s: принято, ожидался отказ", name)
		}
	}
}

func TestWrongKeyRejected(t *testing.T) {
	a, clk := newTestAuth(t, Options{})
	h, _ := a.Header()

	// Другой ключ — та же схема.
	b, _ := New([]byte("ffffffffffffffffffffffffffffffff"), Options{})
	b.now = clk.now
	if b.Authorize(&http.Request{Header: h}) {
		t.Fatal("токен принят на чужом ключе")
	}
}

func TestExpiryWindow(t *testing.T) {
	a, clk := newTestAuth(t, Options{Skew: 30 * time.Second})
	h, _ := a.Header()

	clk.add(20 * time.Second) // в окне
	if !a.Authorize(&http.Request{Header: cloneHeader(h)}) {
		t.Fatal("токен в окне отклонён")
	}
	clk.add(20 * time.Second) // теперь 40с > 30с
	if a.Authorize(&http.Request{Header: cloneHeader(h)}) {
		t.Fatal("протухший токен принят")
	}
}

func TestReplayRejected(t *testing.T) {
	a, _ := newTestAuth(t, Options{})
	h, _ := a.Header()
	if !a.Authorize(&http.Request{Header: cloneHeader(h)}) {
		t.Fatal("первый раз должен пройти")
	}
	if a.Authorize(&http.Request{Header: cloneHeader(h)}) {
		t.Fatal("повтор того же токена принят")
	}
}

func TestReplayCacheEviction(t *testing.T) {
	c := newReplayCache(time.Minute, 0)
	base := time.Unix(0, 0)
	if !c.checkAndStore("a", base) {
		t.Fatal()
	}
	if c.checkAndStore("a", base.Add(time.Second)) {
		t.Fatal("повтор в пределах ttl")
	}
	// После ttl запись вычищается, тот же nonce снова свеж.
	if !c.checkAndStore("a", base.Add(3*time.Minute)) {
		t.Fatal("nonce не вычищен после ttl")
	}
	if len(c.seen) > 2 {
		t.Fatalf("кэш не убирается: %d записей", len(c.seen))
	}
}

func TestCustomHeaderNoBearer(t *testing.T) {
	a, _ := newTestAuth(t, Options{Header: "X-Api-Key"})
	if a.HeaderName() != "X-Api-Key" {
		t.Fatal(a.HeaderName())
	}
	h, _ := a.Header()
	if v := h.Get("X-Api-Key"); v == "" || len(v) > 3 && v[:3] == "Bea" {
		t.Fatalf("нестандартный заголовок не должен нести Bearer: %q", v)
	}
	if !a.Authorize(&http.Request{Header: h}) {
		t.Fatal("свой заголовок не принят")
	}
}

func TestShortKeyRejected(t *testing.T) {
	if _, err := New([]byte("short"), Options{}); err == nil {
		t.Fatal("короткий ключ принят")
	}
}

func cloneHeader(h http.Header) http.Header {
	c := http.Header{}
	for k, v := range h {
		c[k] = append([]string(nil), v...)
	}
	return c
}

// TestReplayCacheBounded — кэш не должен расти неограниченно: иначе поток
// подключений выедает память сервера.
func TestReplayCacheBounded(t *testing.T) {
	const max = 100
	c := newReplayCache(time.Minute, max)
	base := time.Unix(0, 0)

	for i := 0; i < max; i++ {
		if !c.checkAndStore(string(rune(i))+"-nonce", base) {
			t.Fatalf("запись %d отклонена до достижения потолка", i)
		}
	}
	if len(c.seen) != max {
		t.Fatalf("в кэше %d записей, ожидалось %d", len(c.seen), max)
	}
	// Потолок достигнут, срок ни у кого не вышел — новая запись отклоняется.
	if c.checkAndStore("overflow", base) {
		t.Fatal("кэш принял запись сверх потолка")
	}
	if len(c.seen) > max {
		t.Fatalf("кэш вырос за потолок: %d", len(c.seen))
	}
	// После истечения срока место освобождается.
	if !c.checkAndStore("later", base.Add(3*time.Minute)) {
		t.Fatal("после истечения срока запись не принята")
	}
	if len(c.seen) > max {
		t.Fatalf("кэш вырос за потолок после уборки: %d", len(c.seen))
	}
}

func TestReplayCacheBoundConfigurable(t *testing.T) {
	a, err := New([]byte("0123456789abcdef0123456789abcdef"), Options{MaxReplayEntries: 2})
	if err != nil {
		t.Fatal(err)
	}
	if a.replay.max != 2 {
		t.Fatalf("потолок кэша %d, ожидался 2", a.replay.max)
	}
	def, _ := New([]byte("0123456789abcdef0123456789abcdef"), Options{})
	if def.replay.max != defaultMaxReplayEntries {
		t.Fatalf("потолок по умолчанию %d", def.replay.max)
	}
}
