//go:build utls

package client

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/soways11/masquevpn/internal/masque"
	"github.com/soways11/masquevpn/internal/utlsquic"
)

// fpScript подменяет попытку дозвона и смотрит, каким профилем она идёт
// (d.activeParrot). Профиль из blocked «молчит» на всех портах (как блокировка
// на проводе), из fail — отвечает ошибкой сервера, остальные — успех.
type fpScript struct {
	d       *Dialer
	mu      sync.Mutex
	blocked map[string]bool
	fail    map[string]error
	tried   []string // профиль каждой попытки, по порядку
}

func (s *fpScript) attempt(_ context.Context, ip, port string, last bool) (*masque.Conn, error) {
	fp, _ := s.d.activeParrot.Load().(string)
	s.mu.Lock()
	s.tried = append(s.tried, fp)
	s.mu.Unlock()
	if s.blocked[fp] {
		return nil, timeoutErr{}
	}
	if e := s.fail[fp]; e != nil {
		return nil, e
	}
	return nil, nil
}

// distinct — профили в порядке первого появления.
func (s *fpScript) distinct() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	seen := map[string]bool{}
	for _, fp := range s.tried {
		if !seen[fp] {
			out = append(out, fp)
			seen[fp] = true
		}
	}
	return out
}

func fpDialer(t *testing.T, s *fpScript, opt Options, pool ...string) *Dialer {
	t.Helper()
	cfg := testClientConfig()
	cfg.Server = "192.0.2.10:8443"
	cfg.ServerName = "example.test"
	cfg.Transport = "utls"
	cfg.FingerprintPool = pool
	d, err := NewDialer(cfg, opt)
	if err != nil {
		t.Fatal(err)
	}
	s.d = d
	d.attempt = s.attempt
	return d
}

// TestFingerprintFallback — профиль, с которым молчат все порты, выпадает из
// пула, и клиент подключается следующим; удачный запоминается, а неудачный
// уходит на кулдаун.
func TestFingerprintFallback(t *testing.T) {
	mem := MemFingerprintMemory()
	s := &fpScript{blocked: map[string]bool{"chrome-153": true}}
	d := fpDialer(t, s, Options{Fingerprints: mem}, "chrome-153", "firefox-116")

	if _, err := d.Dial(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := s.distinct(); strings.Join(got, ",") != "chrome-153,firefox-116" {
		t.Fatalf("перебор профилей: %v", got)
	}
	if mem.Good("192.0.2.10") != "firefox-116" {
		t.Fatalf("удачный профиль не запомнен: %q", mem.Good("192.0.2.10"))
	}
	now := time.Now()
	if mem.Enabled("192.0.2.10", "chrome-153", now) {
		t.Fatal("заблокированный профиль не ушёл на кулдаун")
	}
	if !mem.Enabled("192.0.2.10", "firefox-116", now) {
		t.Fatal("удачный профиль оказался на кулдауне")
	}
	// Кулдаун конечен: по истечении профиль снова доступен.
	if !mem.Enabled("192.0.2.10", "chrome-153", now.Add(fpCooldownBase+time.Second)) {
		t.Fatal("профиль не вернулся в пул после кулдауна")
	}
}

// TestFingerprintRememberedAcrossRestarts — удачный профиль переживает
// перезапуск: новый дозвонщик начинает с него.
func TestFingerprintRememberedAcrossRestarts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", FingerprintsFile)
	mem := FileFingerprintMemory(path)
	s := &fpScript{blocked: map[string]bool{"chrome-153": true}}
	fpDialer(t, s, Options{Fingerprints: mem}, "chrome-153", "firefox-116").Dial(t.Context())
	if mem.Good("192.0.2.10") != "firefox-116" {
		t.Fatalf("удачный профиль не записан: %q", mem.Good("192.0.2.10"))
	}

	// «Перезапуск»: новая память из того же файла, ничего не заблокировано.
	s2 := &fpScript{}
	d2 := fpDialer(t, s2, Options{Fingerprints: FileFingerprintMemory(path)}, "chrome-153", "firefox-116")
	if _, err := d2.Dial(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := s2.distinct(); len(got) != 1 || got[0] != "firefox-116" {
		t.Fatalf("после перезапуска начал не с запомненного профиля: %v", got)
	}
}

// TestFingerprintFallbackStopsOnServerAnswer — сервер ответил (404, битый
// серт): другой профиль этого не исправит, ошибка возвращается сразу, второй
// профиль не пробуется.
func TestFingerprintFallbackStopsOnServerAnswer(t *testing.T) {
	for name, e := range map[string]error{
		"ответ HTTP": &masque.ResponseError{StatusCode: http.StatusForbidden},
		"сертификат": errors.New("tls: failed to verify certificate"),
	} {
		mem := MemFingerprintMemory()
		s := &fpScript{fail: map[string]error{"chrome-153": e}}
		d := fpDialer(t, s, Options{Fingerprints: mem}, "chrome-153", "firefox-116")
		if _, err := d.Dial(t.Context()); err == nil {
			t.Fatalf("%s: ошибка потерялась", name)
		}
		if got := s.distinct(); len(got) != 1 || got[0] != "chrome-153" {
			t.Fatalf("%s: после ответа сервера перебирались профили: %v", name, got)
		}
		if !mem.Enabled("192.0.2.10", "chrome-153", time.Now()) {
			t.Fatalf("%s: профиль ушёл на кулдаун из-за ответа сервера, а не молчания", name)
		}
	}
}

// TestFingerprintAllOnCooldown — когда на кулдауне разом все, клиент не
// залипает: пробует весь пул по порядку.
func TestFingerprintAllOnCooldown(t *testing.T) {
	mem := MemFingerprintMemory()
	now := time.Now()
	mem.Penalize("192.0.2.10", "chrome-153", now)
	mem.Penalize("192.0.2.10", "firefox-116", now)

	s := &fpScript{} // ничего не блокируем — первый же профиль подключится
	d := fpDialer(t, s, Options{Fingerprints: mem}, "chrome-153", "firefox-116")
	if _, err := d.Dial(t.Context()); err != nil {
		t.Fatalf("клиент залип при всех профилях на кулдауне: %v", err)
	}
	if got := s.distinct(); len(got) == 0 {
		t.Fatal("не попробовал ни одного профиля")
	}
}

// TestFingerprintPoolWithoutMemory — пул работает и без файла памяти (nil):
// просто без запоминания между запусками.
func TestFingerprintPoolWithoutMemory(t *testing.T) {
	s := &fpScript{blocked: map[string]bool{"chrome-153": true}}
	d := fpDialer(t, s, Options{}, "chrome-153", "firefox-116")
	if _, err := d.Dial(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := s.distinct(); strings.Join(got, ",") != "chrome-153,firefox-116" {
		t.Fatalf("без памяти fallback не сработал: %v", got)
	}
}

// TestDefaultPoolWhenUnset — при transport=utls и без явных
// parrot/fingerprint_file/fingerprint_pool клиент использует пул по умолчанию
// (Chromium + Firefox) с выбором по здоровью.
func TestDefaultPoolWhenUnset(t *testing.T) {
	cfg := testClientConfig()
	cfg.Server = "192.0.2.10:8443"
	cfg.ServerName = "example.test"
	cfg.Transport = "utls" // parrot / fingerprint_file / fingerprint_pool не заданы
	d, err := NewDialer(cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(d.pool, utlsquic.DefaultPool) {
		t.Fatalf("дефолтный пул не применился: %v (ожидался %v)", d.pool, utlsquic.DefaultPool)
	}
	// И он рабочий: первый профиль молчит — уходим на второй.
	s := &fpScript{blocked: map[string]bool{utlsquic.DefaultPool[0]: true}}
	s.d = d
	d.attempt = s.attempt
	if _, err := d.Dial(t.Context()); err != nil {
		t.Fatal(err)
	}
	got := s.distinct()
	if len(got) < 2 || got[0] != utlsquic.DefaultPool[0] || got[1] != utlsquic.DefaultPool[1] {
		t.Fatalf("fallback дефолтного пула не сработал: %v", got)
	}
}

// TestExplicitParrotDisablesPool — явный parrot отключает дефолтный пул
// (пользователь намеренно закрепил один профиль).
func TestExplicitParrotDisablesPool(t *testing.T) {
	cfg := testClientConfig()
	cfg.Transport = "utls"
	cfg.Parrot = "chrome-153"
	d, err := NewDialer(cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(d.pool) != 0 {
		t.Fatalf("явный parrot не отключил дефолтный пул: %v", d.pool)
	}
}

// TestCooldownBackoff — кулдаун растёт при повторных неудачах и не превышает
// потолок.
func TestCooldownBackoff(t *testing.T) {
	if cooldownFor(1) != fpCooldownBase {
		t.Fatalf("первая неудача: %v", cooldownFor(1))
	}
	if cooldownFor(2) != 2*fpCooldownBase {
		t.Fatalf("вторая неудача: %v", cooldownFor(2))
	}
	if cooldownFor(100) != fpCooldownMax {
		t.Fatalf("потолок кулдауна: %v", cooldownFor(100))
	}
}
