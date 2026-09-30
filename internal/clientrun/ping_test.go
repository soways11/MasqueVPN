package clientrun

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/soways11/masquevpn/internal/client"
	"github.com/soways11/masquevpn/internal/config"
	"github.com/soways11/masquevpn/internal/gui"
)

type pingLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *pingLog) add(s string) { l.mu.Lock(); l.lines = append(l.lines, s); l.mu.Unlock() }
func (l *pingLog) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

func prof(name, server string) config.Profile {
	return config.Profile{Name: name, Config: &config.Client{Server: server}}
}

// waitIdle ждёт, пока профиль перестанет проверяться.
func waitIdle(t *testing.T, b *PingBoard, name string) (gui.PingState, time.Duration) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if st, d := b.Get(name); st != gui.PingBusy {
			return st, d
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("%s: проверка не закончилась", name)
	return 0, 0
}

func TestPingBoardSingle(t *testing.T) {
	release := make(chan struct{})
	var calls atomic.Int32
	log := &pingLog{}
	b := newPingBoard(func(ctx context.Context, cfg *config.Client) (client.PingResult, error) {
		calls.Add(1)
		<-release
		if cfg.Server == "down.example:443" {
			return client.PingResult{}, errors.New("порт 443 не отвечает")
		}
		return client.PingResult{RTT: 37 * time.Millisecond, Port: "443", Target: "example.com", Status: "HTTP/1.1 200 OK"}, nil
	}, nil, log.add)
	defer b.Close()

	b.Ping(prof("Дом", "up.example:443"))
	if st, _ := b.Get("дом"); st != gui.PingBusy {
		t.Fatalf("сразу после нажатия состояние %v, ждали «идёт» (и имя без учёта регистра)", st)
	}
	// Повторное нажатие, пока идёт, второй проверки не запускает.
	b.Ping(prof("Дом", "up.example:443"))
	b.Ping(prof("Работа", "down.example:443"))
	close(release)
	if st, d := waitIdle(t, b, "Дом"); st != gui.PingOK || d != 37*time.Millisecond {
		t.Fatalf("Дом: %v %v", st, d)
	}
	if st, _ := waitIdle(t, b, "Работа"); st != gui.PingFail {
		t.Fatalf("Работа: %v", st)
	}
	if calls.Load() != 2 {
		t.Fatalf("проверок %d, ждали 2: повторное нажатие не должно запускать вторую", calls.Load())
	}
	b.Close()
	txt := log.text()
	if !strings.Contains(txt, "пинг Дом: 37 мс — GET example.com через туннель, HTTP/1.1 200 OK (порт 443)") || !strings.Contains(txt, "пинг Работа: нет ответа — порт 443 не отвечает") {
		t.Fatalf("журнал:\n%s", txt)
	}

	v := gui.View{Profiles: []gui.ProfileItem{{Name: "ДОМ"}, {Name: "Работа"}, {Name: "Новый"}}}
	b.Fill(&v)
	if v.Profiles[0].Ping != gui.PingOK || v.Profiles[1].Ping != gui.PingFail || v.Profiles[2].Ping != gui.PingNone {
		t.Fatalf("Fill: %+v", v.Profiles)
	}
}

// TestPingBoardAll — «Пинг всех» проверяет каждый профиль, не больше
// pingParallel разом, и пишет итог.
func TestPingBoardAll(t *testing.T) {
	var cur, peak atomic.Int32
	log := &pingLog{}
	b := newPingBoard(func(ctx context.Context, cfg *config.Client) (client.PingResult, error) {
		n := cur.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		cur.Add(-1)
		if strings.HasPrefix(cfg.Server, "bad") {
			return client.PingResult{}, context.DeadlineExceeded
		}
		return client.PingResult{RTT: time.Millisecond, Port: "443"}, nil
	}, nil, log.add)
	defer b.Close()

	var list []config.Profile
	for i := 0; i < 9; i++ {
		srv := "ok.example:443"
		if i%3 == 0 {
			srv = "bad.example:443"
		}
		list = append(list, prof(string(rune('a'+i)), srv))
	}
	list = append(list, config.Profile{Name: "пустой"}) // без конфигурации — пропускается
	b.PingAll(list)
	if !b.AllBusy() {
		t.Fatal("«Пинг всех» не отмечен как идущий")
	}
	b.PingAll(list) // повторное нажатие ничего не делает
	deadline := time.Now().Add(3 * time.Second)
	for b.AllBusy() && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if b.AllBusy() {
		t.Fatal("«Пинг всех» не закончился")
	}
	if peak.Load() > pingParallel {
		t.Fatalf("одновременно шло %d проверок, предел %d", peak.Load(), pingParallel)
	}
	for i, p := range list[:9] {
		st, _ := b.Get(p.Name)
		want := gui.PingOK
		if i%3 == 0 {
			want = gui.PingFail
		}
		if st != want {
			t.Errorf("%s: %v, ждали %v", p.Name, st, want)
		}
	}
	txt := log.text()
	if !strings.Contains(txt, "пинг всех: ответили 6 из 9") {
		t.Fatalf("журнал:\n%s", txt)
	}
	if !strings.Contains(txt, "нет ответа — время вышло") {
		t.Fatalf("срок не назван по-человечески:\n%s", txt)
	}
}

// TestPingBoardForget — итог удалённого или изменённого профиля стирается, и
// запоздалый ответ прежней проверки его не возвращает.
func TestPingBoardForget(t *testing.T) {
	release := make(chan struct{})
	b := newPingBoard(func(ctx context.Context, cfg *config.Client) (client.PingResult, error) {
		<-release
		return client.PingResult{RTT: time.Millisecond}, nil
	}, nil, nil)
	defer b.Close()
	b.Ping(prof("x", "a:1"))
	b.Forget("x")
	close(release)
	b.Close()
	if st, _ := b.Get("x"); st != gui.PingNone {
		t.Fatalf("после Forget: %v", st)
	}
}
