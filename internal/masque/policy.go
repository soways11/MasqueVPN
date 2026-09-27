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
	byID map[string]map[*Conn]struct{}
}

func newLiveSessions() *liveSessions {
	return &liveSessions{byID: map[string]map[*Conn]struct{}{}}
}

func (s *liveSessions) add(id string, c *Conn) {
	if id == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.byID[id]
	if m == nil {
		m = map[*Conn]struct{}{}
		s.byID[id] = m
	}
	m[c] = struct{}{}
}

func (s *liveSessions) remove(id string, c *Conn) {
	if id == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.byID[id]
	if m == nil {
		return
	}
	delete(m, c)
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

// conns возвращает копию списка сессий клиента: закрывать их под замком
// нельзя, закрытие само дёргает remove.
func (s *liveSessions) conns(id string) []*Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.byID[id]
	out := make([]*Conn, 0, len(m))
	for c := range m {
		out = append(out, c)
	}
	return out
}

// CloseClient закрывает все сессии клиента и возвращает, сколько закрыл.
// Так работает отзыв: без этого запись из реестра исчезает, а трафик идёт.
func (h *Handler) CloseClient(id string) int {
	conns := h.live.conns(id)
	for _, c := range conns {
		c.Close()
	}
	// Адрес отозванного клиента возвращаем в пул, не дожидаясь TTL аренды:
	// он не вернётся, а адрес всё это время числился бы занятым. Сессии
	// отпускают аренду асинхронно, поэтому пробуем и после них.
	h.leases.forget(id)
	return len(conns)
}

// LiveSessions — сколько сессий сейчас у клиента (для журнала и тестов).
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
