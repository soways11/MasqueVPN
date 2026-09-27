package masque

import (
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// Лимиты ресурсов сервера (пункт 2.3 плана).
//
// Зачем: аутентификация отсекает посторонних, но сама по себе не защищает от
// исчерпания ресурсов. Поток подключений — даже отклоняемых — заставляет сервер
// выполнять рукопожатия, а авторизованный, но сломавшийся или враждебный клиент
// может занять весь пул адресов или завалить сессию капсулами.
//
// Все лимиты по умолчанию выключены (0), кроме потолка на ADDRESS_REQUEST:
// его разумное значение есть всегда.

// Limits ограничивает ресурсы, занимаемые клиентами.
type Limits struct {
	// MaxSessions — сколько сессий сервер держит одновременно. 0 — без лимита.
	MaxSessions int
	// MaxSessionsPerIP — сколько сессий с одного адреса. 0 — без лимита.
	// Защищает пул адресов от захвата одним источником.
	MaxSessionsPerIP int
	// IdleTimeout — если за это время по сессии не прошло ни одного реального
	// IP-пакета, сессия закрывается. 0 — не закрывать.
	// Cover-трафик и keep-alive простоем не считаются: иначе лимит никогда бы
	// не срабатывал именно там, где он нужен.
	IdleTimeout time.Duration
	// MaxAddressRequests — потолок капсул ADDRESS_REQUEST на сессию.
	// 0 — значение по умолчанию (defaultMaxAddressRequests).
	MaxAddressRequests int
	// MaxUnknownCapsules — потолок неизвестных капсул на сессию. Их положено
	// игнорировать (RFC 9297), но не бесконечно: поток мусора занимает
	// процессор сервера. 0 — значение по умолчанию.
	MaxUnknownCapsules int
	// MaxBytesPerSecond — потолок исходящей полосы сессии (байт в секунду).
	// 0 — без ограничения.
	MaxBytesPerSecond int
	// BurstBytes — сколько можно накопить про запас; 0 — четверть секунды.
	BurstBytes int
	// AddressLeaseTTL — сколько адрес держится за ушедшим клиентом, чтобы он
	// получил его обратно при переподключении (см. lease.go).
	// 0 — DefaultAddressLeaseTTL.
	AddressLeaseTTL time.Duration
}

func (l *Limits) leaseTTL() time.Duration {
	if l == nil || l.AddressLeaseTTL <= 0 {
		return DefaultAddressLeaseTTL
	}
	return l.AddressLeaseTTL
}

func (l *Limits) maxUnknownCapsules() int {
	if l == nil || l.MaxUnknownCapsules == 0 {
		return defaultMaxUnknownCapsules
	}
	return l.MaxUnknownCapsules
}

const (
	defaultMaxAddressRequests = 16
	defaultMaxUnknownCapsules = 64
)

func (l *Limits) maxAddressRequests() int {
	if l == nil || l.MaxAddressRequests == 0 {
		return defaultMaxAddressRequests
	}
	return l.MaxAddressRequests
}

// sessionCounter считает активные сессии всего и по адресам клиентов.
type sessionCounter struct {
	mu    sync.Mutex
	total int
	perIP map[string]int
}

func newSessionCounter() *sessionCounter {
	return &sessionCounter{perIP: make(map[string]int)}
}

// acquire пытается занять место под сессию. Возвращает функцию освобождения
// и признак успеха.
func (s *sessionCounter) acquire(ip string, l *Limits) (release func(), ok bool) {
	if l == nil {
		l = &Limits{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if l.MaxSessions > 0 && s.total >= l.MaxSessions {
		return nil, false
	}
	if l.MaxSessionsPerIP > 0 && s.perIP[ip] >= l.MaxSessionsPerIP {
		return nil, false
	}
	s.total++
	s.perIP[ip]++
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.total--
			if n := s.perIP[ip] - 1; n <= 0 {
				delete(s.perIP, ip)
			} else {
				s.perIP[ip] = n
			}
		})
	}, true
}

// stats возвращает текущие счётчики (для тестов и диагностики).
func (s *sessionCounter) stats() (total, ips int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.total, len(s.perIP)
}

// clientIP выделяет адрес клиента из запроса. Порт отбрасывается: лимит
// осмысленно считать по адресу, а не по каждому эфемерному порту.
func clientIP(r *http.Request) string {
	if v, ok := r.Context().Value(http3RemoteAddrKey()).(net.Addr); ok && v != nil {
		if host, _, err := net.SplitHostPort(v.String()); err == nil {
			return host
		}
		return v.String()
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// idleWatchdog закрывает сессию, если по ней долго не было реальных пакетов.
func (c *Conn) idleWatchdog(timeout time.Duration) {
	if timeout <= 0 {
		return
	}
	c.recordPacket()
	tick := timeout / 2
	if tick < time.Second {
		tick = time.Second
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			last := time.Unix(0, c.lastPktNanos.Load())
			if time.Since(last) >= timeout {
				c.closeWithError(ErrIdleTimeout)
				return
			}
		}
	}
}

func (c *Conn) recordPacket() { c.lastPktNanos.Store(time.Now().UnixNano()) }

// http3RemoteAddrKey — ключ, под которым quic-go кладёт адрес клиента в контекст.
func http3RemoteAddrKey() any { return http3.RemoteAddrContextKey }
