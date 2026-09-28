package client

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/soways11/masquevpn/internal/masque"
	"github.com/soways11/masquevpn/internal/utlsquic"
)

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "timeout: no recent network activity" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return false }

// portScript подменяет попытку дозвона: на портах из silent — таймаут, на
// портах из fail — указанная ошибка, на остальных — успех. Записывает, в
// каком порядке и с каким признаком «последний» шли попытки.
type portScript struct {
	mu     sync.Mutex
	silent map[string]bool
	fail   map[string]error
	tried  []string
	lasts  []bool
}

func (p *portScript) attempt(_ context.Context, ip, port string, last bool) (*masque.Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if ip != "192.0.2.10" {
		return nil, errors.New("не тот адрес: " + ip)
	}
	p.tried = append(p.tried, port)
	p.lasts = append(p.lasts, last)
	if p.silent[port] {
		return nil, timeoutErr{}
	}
	if err := p.fail[port]; err != nil {
		return nil, err
	}
	return nil, nil
}

func (p *portScript) reset() {
	p.mu.Lock()
	p.tried, p.lasts = nil, nil
	p.mu.Unlock()
}

func portDialer(t *testing.T, server string, s *portScript) *Dialer {
	t.Helper()
	cfg := testClientConfig()
	cfg.Server = server
	cfg.ServerName = "example.test"
	d, err := NewDialer(cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	d.attempt = s.attempt
	return d
}

// TestPortFallback — основной порт молчит, клиент уходит на следующий и
// запоминает его: следующий дозвон (переподключение, ротация) начинается с
// ответившего, а не бьётся заново в закрытый.
func TestPortFallback(t *testing.T) {
	s := &portScript{silent: map[string]bool{"8443": true}}
	d := portDialer(t, "192.0.2.10:8443,2053,2083", s)

	if _, err := d.Dial(t.Context()); err != nil {
		t.Fatal(err)
	}
	if strings.Join(s.tried, ",") != "8443,2053" {
		t.Fatalf("попытки: %v", s.tried)
	}
	s.reset()
	if _, err := d.Dial(t.Context()); err != nil {
		t.Fatal(err)
	}
	if strings.Join(s.tried, ",") != "2053" {
		t.Fatalf("второй дозвон начался не с ответившего порта: %v", s.tried)
	}
	// Ответивший порт закрыли — идём дальше по кругу и возвращаемся к началу.
	s.silent = map[string]bool{"2053": true, "2083": true}
	s.reset()
	if _, err := d.Dial(t.Context()); err != nil {
		t.Fatal(err)
	}
	if strings.Join(s.tried, ",") != "2053,2083,8443" {
		t.Fatalf("перебор по кругу: %v", s.tried)
	}
}

// TestAllPortsSilent — ни один порт не ответил: ошибка говорит, что
// случилось, человеческим языком и помещается в окно (две строки по 50).
func TestAllPortsSilent(t *testing.T) {
	s := &portScript{silent: map[string]bool{"8443": true, "2053": true, "2083": true}}
	d := portDialer(t, "192.0.2.10:8443,2053,2083", s)
	_, err := d.Dial(t.Context())
	var pe *PortsError
	if !errors.As(err, &pe) {
		t.Fatalf("ошибка %T %v", err, err)
	}
	if strings.Join(pe.Ports, ",") != "8443,2053,2083" {
		t.Fatalf("в ошибке порты %v", pe.Ports)
	}
	msg := "подключение: " + err.Error()
	if !strings.Contains(msg, "8443, 2053, 2083") || !strings.Contains(msg, "закрыты по пути") {
		t.Fatalf("текст: %q", msg)
	}
	if n := len([]rune(msg)); n > 100 {
		t.Fatalf("текст длиной %d не помещается в окно: %q", n, msg)
	}
	var te timeoutErr
	if !errors.As(err, &te) {
		t.Fatal("исходная ошибка потеряна")
	}
	// Предел на попытку — у всех, кроме последней: последней отдаётся
	// весь оставшийся срок.
	if len(s.lasts) != 3 || s.lasts[0] || s.lasts[1] || !s.lasts[2] {
		t.Fatalf("признак последней попытки: %v", s.lasts)
	}

	// Один порт — та же понятная ошибка, в единственном числе.
	s1 := &portScript{silent: map[string]bool{"8443": true}}
	_, err = portDialer(t, "192.0.2.10:8443", s1).Dial(t.Context())
	if err == nil || err.Error() != "порт 8443 не отвечает: закрыт по пути или сервер выключен" {
		t.Fatalf("один порт: %v", err)
	}
}

// TestPortFallbackStopsOnServerAnswer — сервер ответил отказом: перебирать
// порты бессмысленно, ошибка возвращается сразу и как есть.
func TestPortFallbackStopsOnServerAnswer(t *testing.T) {
	for name, e := range map[string]error{
		"ответ HTTP": &masque.ResponseError{StatusCode: http.StatusForbidden},
		"сертификат": errors.New("tls: failed to verify certificate"),
	} {
		s := &portScript{fail: map[string]error{"8443": e}}
		d := portDialer(t, "192.0.2.10:8443,2053", s)
		_, err := d.Dial(t.Context())
		if !errors.Is(err, e) && err != e {
			var re *masque.ResponseError
			if !errors.As(err, &re) {
				t.Errorf("%s: ошибка подменена: %v", name, err)
			}
		}
		if len(s.tried) != 1 {
			t.Errorf("%s: после ответа сервера перебирались порты: %v", name, s.tried)
		}
	}
}

// TestUnreachableOnSilentPort — настоящий QUIC-дозвон в порт, где никто не
// отвечает, классифицируется как «молчит». Без этого перебор не сработал
// бы на живой блокировке, а в тестах выше всё было бы зелёным.
func TestUnreachableOnSilentPort(t *testing.T) {
	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	_, port, _ := net.SplitHostPort(silent.LocalAddr().String())

	transports := []string{"quic"}
	if utlsquic.Available() {
		transports = append(transports, "utls") // оба стека QUIC: у каждого свои ошибки
	}
	for _, tr := range transports {
		cfg := testClientConfig()
		cfg.Server = "127.0.0.1:" + port
		cfg.ServerName = "example.test"
		cfg.Transport = tr
		d, err := NewDialer(cfg, Options{})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 1500*time.Millisecond)
		_, err = d.dialPort(ctx, "127.0.0.1", port, true)
		cancel()
		if err == nil {
			t.Fatalf("%s: дозвон в молчащий порт удался", tr)
		}
		if !unreachable(err) {
			t.Fatalf("%s: молчание не распознано: %T %v", tr, err, err)
		}
	}
	if unreachable(errors.New("tls: bad certificate")) || unreachable(&masque.ResponseError{StatusCode: 404}) {
		t.Fatal("ответ сервера принят за молчание")
	}
}

func TestConnectTimeoutCoversAllPorts(t *testing.T) {
	d := portDialer(t, "192.0.2.10:443,8443,2053,2083,2087,2096", &portScript{})
	if got, need := d.ConnectTimeout(), 6*perPortTimeout; got <= need {
		t.Fatalf("срок подключения %v не покрывает перебор шести портов (%v)", got, need)
	}
	if got := portDialer(t, "192.0.2.10:443", &portScript{}).ConnectTimeout(); got != 30*time.Second {
		t.Fatalf("срок для одного порта изменился: %v", got)
	}
}
