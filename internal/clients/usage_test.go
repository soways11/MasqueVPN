package clients

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// fakeStore — реестр из одного-двух клиентов, без файла.
type fakeStore map[string]Client

func (s fakeStore) Lookup(id string) (Client, bool) { c, ok := s[id]; return c, ok }
func (s fakeStore) Snapshot() []Client {
	out := make([]Client, 0, len(s))
	for _, c := range s {
		out = append(out, c)
	}
	return out
}

func TestAccountAndPeriodRollover(t *testing.T) {
	const id = "00112233aabbccdd"
	store := fakeStore{id: {ID: id, Quota: 1000, Period: "month"}}
	a, err := NewAccountant("", store)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 20, 12, 0, 0, 0, time.UTC)
	a.now = func() time.Time { return now }

	a.Account(id, 400)
	a.Account(id, 300)
	if u := a.Usage(id); u.Bytes != 700 || u.Total != 700 {
		t.Fatalf("после 700 байт: за период %d, всего %d", u.Bytes, u.Total)
	}

	// Новый месяц: расход за период обнуляется, всего — нет.
	now = time.Date(2026, 2, 1, 0, 0, 1, 0, time.UTC)
	u := a.Usage(id)
	if u.Bytes != 0 {
		t.Fatalf("после смены месяца за период %d, ожидался 0", u.Bytes)
	}
	if u.Total != 700 {
		t.Fatalf("всего %d, ожидалось 700 — период не должен сбрасывать общий счётчик", u.Total)
	}
	a.Account(id, 50)
	if u := a.Usage(id); u.Bytes != 50 || u.Total != 750 {
		t.Fatalf("новый период: за период %d, всего %d", u.Bytes, u.Total)
	}
}

func TestAdmit(t *testing.T) {
	const (
		ok       = "00112233aabbccd1"
		off      = "00112233aabbccd2"
		limited  = "00112233aabbccd3"
		quotaed  = "00112233aabbccd4"
		nobody   = "00112233aabbccd9"
		oneKByte = 1000
	)
	store := fakeStore{
		ok:      {ID: ok},
		off:     {ID: off, Disabled: true},
		limited: {ID: limited, MaxSessions: 2},
		quotaed: {ID: quotaed, Quota: oneKByte, Period: "month"},
	}
	a, err := NewAccountant("", store)
	if err != nil {
		t.Fatal(err)
	}

	if err := a.Admit(ok, 5); err != nil {
		t.Fatalf("обычного клиента не пустили: %v", err)
	}

	var eUnknown *ErrUnknown
	if err := a.Admit(nobody, 0); !errors.As(err, &eUnknown) {
		t.Fatalf("неизвестный клиент: %v", err)
	}
	var eDisabled *ErrDisabled
	if err := a.Admit(off, 0); !errors.As(err, &eDisabled) {
		t.Fatalf("выключенный клиент: %v", err)
	}

	if err := a.Admit(limited, 1); err != nil {
		t.Fatalf("вторая сессия при лимите 2: %v", err)
	}
	var eSessions *ErrTooManySessions
	if err := a.Admit(limited, 2); !errors.As(err, &eSessions) {
		t.Fatalf("третья сессия при лимите 2: %v", err)
	}

	a.Account(quotaed, oneKByte-1)
	if err := a.Admit(quotaed, 0); err != nil {
		t.Fatalf("до исчерпания квоты не пустили: %v", err)
	}
	a.Account(quotaed, 1)
	var eQuota *ErrQuota
	if err := a.Admit(quotaed, 0); !errors.As(err, &eQuota) {
		t.Fatalf("после исчерпания квоты: %v", err)
	}
	// Квота считается за период: новый месяц открывает доступ снова.
	a.now = func() time.Time { return time.Now().AddDate(0, 2, 0) }
	if err := a.Admit(quotaed, 0); err != nil {
		t.Fatalf("в новом периоде квота не сбросилась: %v", err)
	}
}

func TestOverQuotaListsOnlyExceeded(t *testing.T) {
	const a1, a2, a3 = "00112233aabbccd1", "00112233aabbccd2", "00112233aabbccd3"
	store := fakeStore{
		a1: {ID: a1, Quota: 100},
		a2: {ID: a2, Quota: 100},
		a3: {ID: a3}, // без квоты
	}
	a, err := NewAccountant("", store)
	if err != nil {
		t.Fatal(err)
	}
	a.Account(a1, 150)
	a.Account(a2, 50)
	a.Account(a3, 10_000)

	over := a.OverQuota()
	if len(over) != 1 || over[0] != a1 {
		t.Fatalf("за квоту вышли %v, ожидался только %s", over, a1)
	}
}

// Квота без сохранения на диск — не квота: перезапуск сервера обнулял бы её.
func TestUsageSurvivesRestart(t *testing.T) {
	const id = "00112233aabbccdd"
	store := fakeStore{id: {ID: id, Quota: 1000, Period: "month"}}
	path := filepath.Join(t.TempDir(), "usage.json")

	a, err := NewAccountant(path, store)
	if err != nil {
		t.Fatal(err)
	}
	a.StartedSession(id)
	a.Account(id, 900)
	if err := a.Save(); err != nil {
		t.Fatal(err)
	}

	b, err := NewAccountant(path, store)
	if err != nil {
		t.Fatal(err)
	}
	u := b.Usage(id)
	if u.Bytes != 900 || u.Total != 900 || u.Sessions != 1 {
		t.Fatalf("после перезапуска: за период %d, всего %d, сессий %d", u.Bytes, u.Total, u.Sessions)
	}
	b.Account(id, 200)
	var eQuota *ErrQuota
	if err := b.Admit(id, 0); !errors.As(err, &eQuota) {
		t.Fatalf("квота не сработала после перезапуска: %v", err)
	}
}

func TestRateLimitPerClient(t *testing.T) {
	const fast, slow = "00112233aabbccd1", "00112233aabbccd2"
	store := fakeStore{
		fast: {ID: fast},
		slow: {ID: slow, MaxBytesPerSecond: 1234},
	}
	a, err := NewAccountant("", store)
	if err != nil {
		t.Fatal(err)
	}
	if bps, _ := a.RateLimit(fast); bps != 0 {
		t.Fatalf("клиенту без персонального потолка выдан %d", bps)
	}
	if bps, _ := a.RateLimit(slow); bps != 1234 {
		t.Fatalf("персональный потолок %d, ожидался 1234", bps)
	}
}
