package masque

import (
	"sync"
	"time"
)

// Политика по клиенту и отзыв доступа.
//
// До этого сервер знал про клиента ровно одно: его псевдоним, за которым
// закреплён адрес. Пускал он всех, у кого сходится подпись общим ключом, и
// проверял это ОДИН раз — при открытии сессии. Из второго следует неприятное:
// закрыть доступ уже подключённому было нечем. Токен больше не проверяется,
// сессия живёт, пока жива, — то есть отзыв доступа работал бы только до
// следующего переподключения, а его может не случиться неделями.
//
// Поэтому здесь две вещи: спросить политику ДО открытия сессии и уметь
// закрыть уже открытые сессии конкретного клиента.

// Policy — решение по клиенту. Реализуется реестром клиентов
// (internal/clients); nil означает «пускать всех», как было раньше.
type Policy interface {
	// Admit вызывается перед открытием сессии. live — сколько сессий у этого
	// клиента уже открыто. Ошибка — отказ; её текст идёт в журнал сервера, но
	// НЕ клиенту: снаружи отказ по политике неотличим от отказа по любой
	// другой причине (см. probe.go).
	Admit(clientID string, live int) error
	// RateLimit — персональный потолок полосы клиента (байт/с и запас).
	// Нули — общий лимит из Limits. Потолок общий на все сессии клиента:
	// иначе он обходится открытием второй сессии.
	RateLimit(clientID string) (bytesPerSecond, burst int)
	// Account учитывает n байт трафика клиента. Вызывается по таймеру и при
	// закрытии сессии, а не на каждый пакет.
	Account(clientID string, n int64)
}

// sessionStarter — необязательное расширение Policy: политика, которой важно
// знать не только объём, но и число открытых сессий. Отдельным интерфейсом,
// чтобы не заставлять всякую политику это реализовывать.
type sessionStarter interface {
	StartedSession(clientID string)
}

// liveSessions — живые сессии по клиентам. Нужен и для лимита сессий на
// клиента, и для отзыва: чтобы закрыть чужие сессии, их надо сначала найти.
type liveSessions struct {
	mu   sync.Mutex
	byID map[string]map[*liveSession]struct{}
}

type liveSession struct {
	conn    *Conn
	revoked bool
}

func newLiveSessions() *liveSessions {
	return &liveSessions{byID: map[string]map[*liveSession]struct{}{}}
}

// reserve проверяет доступ и занимает место до выделения адреса и отправки
// ответа. Отзыв видит и сессии, для которых поток ещё не готов.
func (s *liveSessions) reserve(id string, policy Policy) (*liveSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.byID[id]
	if policy != nil {
		if err := policy.Admit(id, len(m)); err != nil {
			return nil, err
		}
	}
	slot := new(liveSession)
	if id == "" {
		return slot, nil
	}
	if m == nil {
		m = map[*liveSession]struct{}{}
		s.byID[id] = m
	}
	m[slot] = struct{}{}
	return slot, nil
}

func (s *liveSessions) attach(slot *liveSession, c *Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if slot.revoked {
		return false
	}
	slot.conn = c
	return true
}

func (s *liveSessions) revoked(slot *liveSession) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slot.revoked
}

func (s *liveSessions) remove(id string, slot *liveSession) {
	if id == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.byID[id]
	if m == nil {
		return
	}
	delete(m, slot)
	if len(m) == 0 {
		delete(s.byID, id)
	}
}

func (s *liveSessions) count(id string) int {
	if id == "" {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byID[id])
}

// revoke запрещает завершить открытие отозванных сессий и возвращает
// уже открытые соединения. Сами потоки закрываются после снятия замка.
func (s *liveSessions) revoke(id string) (int, []*Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.byID[id]
	conns := make([]*Conn, 0, len(m))
	n := 0
	for slot := range m {
		if slot.revoked {
			continue
		}
		slot.revoked = true
		n++
		if slot.conn != nil {
			conns = append(conns, slot.conn)
		}
	}
	return n, conns
}

// CloseClient отменяет открываемые сессии клиента и закрывает открытые.
// Так работает отзыв: без этого запись из реестра исчезает, а трафик идёт.
func (h *Handler) CloseClient(id string) int {
	n, conns := h.live.revoke(id)
	for _, c := range conns {
		c.Close()
	}
	// Адрес отозванного клиента возвращаем в пул, не дожидаясь TTL аренды:
	// он не вернётся, а адрес всё это время числился бы занятым. Сессии
	// отпускают аренду асинхронно, поэтому пробуем и после них.
	h.leases.forget(id)
	return n
}

// LiveSessions — число активных и открываемых сессий клиента.
func (h *Handler) LiveSessions(id string) int { return h.live.count(id) }

// accountLoop снимает счётчики сессии по таймеру и отдаёт политике прирост.
// Возвращённая функция останавливает цикл и доносит остаток: без этого
// короткая сессия не учитывалась бы вовсе, а длинная теряла бы хвост.
func (h *Handler) accountLoop(c *Conn, clientID string) func() {
	every := h.cfg.AccountEvery
	if every <= 0 {
		every = DefaultAccountInterval
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		var last uint64
		flush := func() {
			st := c.Stats()
			cur := st.BytesIn + st.BytesOut
			if cur > last {
				h.cfg.Policy.Account(clientID, int64(cur-last))
				last = cur
			}
		}
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-stop:
				flush()
				return
			case <-c.Done():
				flush()
				return
			case <-t.C:
				flush()
			}
		}
	}()
	return func() {
		close(stop)
		<-done
	}
}
