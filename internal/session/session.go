// Package session добавляет над masque.Conn ротацию соединений (пункт 4 плана
// обхода DPI): долгоживущее QUIC-соединение с гигабайтами трафика к одному IP
// само по себе выглядит нетипично, поэтому Session периодически поднимает новую
// CONNECT-IP сессию и переключается на неё по принципу make-before-break —
// новое соединение готово раньше, чем закрывается старое, без разрыва трафика.
//
// Адрес, выданный сервером, при ротации может смениться (старая сессия ещё
// держит прежний адрес в момент дозвона). Session сообщает об этом через
// OnRotate, чтобы вышестоящий слой (TUN/netsetup) переустановил адрес. Чтобы
// сохранить адрес между ротациями, сервер и клиент могут использовать
// ADDRESS_REQUEST с предпочтительным адресом — это оставлено как настройка Dial.
package session

import (
	"context"
	"errors"
	"math/rand/v2"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/soways11/masquevpn/internal/masque"
)

// ErrClosed возвращается после закрытия Session.
var ErrClosed = errors.New("session: closed")

// DialFunc устанавливает новую CONNECT-IP сессию и дожидается выдачи адреса.
// Замыкание отвечает за свежий токен аутентификации, профиль отпечатка и shaping.
type DialFunc func(ctx context.Context) (*masque.Conn, error)

// Config настраивает ротацию.
type Config struct {
	Dial DialFunc
	// Every — ротация по времени (0 — выключено).
	Every time.Duration
	// AfterBytes — ротация после стольких байт (in+out) в текущей сессии (0 — выключено).
	AfterBytes uint64
	// Jitter — разброс срока ротации, доля от Every и AfterBytes.
	// 0 — DefaultJitter, отрицательное — без разброса (для тестов).
	//
	// Зачем: ровно периодическая ротация — метроном, и самый заметный из
	// всех. Рукопожатие QUIC наблюдатель узнаёт в открытую (Initial-пакеты),
	// так что «новое соединение к тому же адресу ровно каждые 30 минут»
	// читается без всякой расшифровки. Тот же изъян мы уже чинили в
	// cover-трафике и keep-alive, а на уровне соединения он оставался.
	Jitter float64
	// Grace — сколько ещё читать из старого соединения после переключения,
	// чтобы не потерять «хвост» ответов. По умолчанию 2 с.
	Grace time.Duration
	// DialTimeout — таймаут на установление новой сессии. По умолчанию 15 с.
	DialTimeout time.Duration
	// KeepAddress — после ротации попросить у сервера ПРЕЖНИЙ адрес.
	//
	// Без этого каждая ротация меняет адрес клиента, и все соединения внутри
	// туннеля рвутся — то есть мера против долгоживущих соединений ломает
	// пользователю работу. Прежний адрес освобождается только при закрытии
	// старой сессии, поэтому запрос уходит после Grace; до тех пор клиент
	// работает с временным адресом.
	//
	// При включённом KeepAddress OnRotate вызывается ПОСЛЕ этого обмена и
	// сообщает итоговый адрес, а не промежуточный.
	KeepAddress bool
	// OnRotate вызывается после переключения (старые и новые префиксы адресов).
	OnRotate func(old, new []netip.Prefix)
	// Reconnect — при обрыве текущего соединения (сеть пропала, сервер
	// перезапущен, закрытие по простою) дозваниваться заново с нарастающей
	// паузой, а не завершать сессию. Без этого клиент после первого же обрыва
	// остаётся с мёртвым туннелем.
	Reconnect bool
	// ReconnectMax — потолок паузы между попытками; по умолчанию 30 с.
	ReconnectMax time.Duration
	// OnReconnect, если задан, сообщает о попытках переподключения
	// (err == nil — успешно).
	OnReconnect func(attempt int, err error)

	// StallAfter — через сколько «мы шлём, а в ответ ничего» проверять, жив
	// ли путь (0 — не следить). Работает только вместе с Reconnect.
	//
	// Зачем. Когда порт начинают резать посреди сессии, пакеты пропадают
	// молча: ни ошибки, ни закрытия. QUIC заметит это только по таймауту
	// простоя — десятки секунд, всё это время туннель мёртв. Здесь мы
	// замечаем раньше: трафик уходит, а от сервера не приходит ничего —
	// проверяем путь запросом (masque.Conn.Probe); не ответил — рвём
	// соединение сами и переподключаемся.
	StallAfter time.Duration
	// ProbeTimeout — сколько ждать ответа на проверку; 0 — StallAfter.
	ProbeTimeout time.Duration
	// OnStall вызывается, когда путь признан мёртвым, — до переподключения.
	// Клиент здесь помечает порт как подозрительный, чтобы переподключение
	// начать со следующего.
	OnStall func()
}

// Session — фасад с единым ReadPacket/WritePacket поверх сменяемых соединений.
type Session struct {
	cfg     Config
	inbound chan []byte
	done    chan struct{}

	mu         sync.RWMutex
	cur        *masque.Conn
	prev       *masque.Conn // старое соединение на время Grace
	rotations  int
	reconnects int

	// retired — счётчики соединений, уже сменившихся при ротации или
	// переподключении. Без них расход трафика обнулялся бы посреди сессии:
	// счётчики живут в *masque.Conn, а он при ротации заменяется новым.
	retired masque.Stats

	lost    chan *masque.Conn // соединение, оборвавшееся не по нашей воле
	stalls  atomic.Int64      // сколько раз сторож признал путь мёртвым
	closed  bool              // под mu: после Close новые соединения не принимаются
	dropped atomic.Uint64     // пакеты, потерянные, пока не было связи

	ctx    context.Context // отменяется при Close
	cancel context.CancelFunc

	closeOnce sync.Once
	wg        sync.WaitGroup
}

// Open поднимает первую сессию и запускает авто-ротацию (если настроена).
func Open(ctx context.Context, cfg Config) (*Session, error) {
	if cfg.Dial == nil {
		return nil, errors.New("session: Config.Dial is required")
	}
	if cfg.Grace <= 0 {
		cfg.Grace = 2 * time.Second
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 15 * time.Second
	}
	if cfg.ReconnectMax <= 0 {
		cfg.ReconnectMax = 30 * time.Second
	}
	c, err := cfg.Dial(ctx)
	if err != nil {
		return nil, err
	}
	s := &Session{
		cfg:     cfg,
		inbound: make(chan []byte, 256),
		done:    make(chan struct{}),
		cur:     c,
		lost:    make(chan *masque.Conn, 1),
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.startPump(c)
	if cfg.Reconnect {
		s.wg.Add(1)
		go s.reconnectLoop()
	}
	if cfg.Every > 0 || cfg.AfterBytes > 0 {
		s.wg.Add(1)
		go s.autoRotate()
	}
	if cfg.Reconnect && cfg.StallAfter > 0 {
		s.wg.Add(1)
		go s.watchStall()
	}
	return s, nil
}

// Stalls — сколько раз путь признан мёртвым и соединение порвано сторожем.
func (s *Session) Stalls() int { return int(s.stalls.Load()) }

// received — настоящие пакеты туннеля от сервера (целые и куски).
//
// Маскировочные датаграммы (CoverIn) сюда сознательно не входят: сервер шлёт
// их сам по себе, не глядя, доходит ли что-нибудь от клиента. Когда порт
// режут только в сторону сервера — а режут чаще всего именно так, по порту
// назначения, — паддинг продолжает приходить, и путь выглядел бы живым, хотя
// ни один наш пакет до сервера не доходит. Так и было на стенде.
func received(st masque.Stats) uint64 {
	return st.PacketsIn + st.FragmentsIn
}

// watchStall — сторож пути (см. Config.StallAfter).
//
// Следит за двумя моментами: когда последний раз что-то пришло от сервера и
// когда последний раз мы что-то отправили. Если мы продолжаем отправлять, а
// от сервера тишина дольше StallAfter, — проверяем путь запросом. Ответ
// пришёл — всё в порядке, сервер просто молчал (так бывает: односторонний
// поток). Не пришёл — соединение мертво, рвём его, и дальше работает
// обычное переподключение.
//
// Без отправки сторож ничего не делает: простаивающий туннель проверять
// незачем, а проверка по расписанию была бы лишним трафиком и метрономом.
func (s *Session) watchStall() {
	defer s.wg.Done()
	probeTimeout := s.cfg.ProbeTimeout
	if probeTimeout <= 0 {
		probeTimeout = s.cfg.StallAfter
	}
	tick := max(s.cfg.StallAfter/4, 50*time.Millisecond)
	t := time.NewTicker(tick)
	defer t.Stop()

	var watched *masque.Conn
	var lastIn, lastOut uint64
	var inAt, outAt time.Time
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
		}
		c := s.Current()
		select {
		case <-c.Done():
			// Соединение уже закрыто (нами или сервером) — им занимается
			// переподключение, проверять его незачем.
			continue
		default:
		}
		now := time.Now()
		st := c.Stats()
		if c != watched { // новое соединение (ротация, переподключение) — считаем заново
			watched, lastIn, lastOut, inAt, outAt = c, received(st), st.PacketsOut, now, now
			continue
		}
		if in := received(st); in != lastIn {
			lastIn, inAt = in, now
		}
		if st.PacketsOut != lastOut {
			lastOut, outAt = st.PacketsOut, now
		}
		if now.Sub(inAt) < s.cfg.StallAfter || !outAt.After(inAt) {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
		err := c.Probe(ctx)
		cancel()
		if errors.Is(err, masque.ErrSessionClosed) {
			continue // закрылось, пока проверяли, — не наш случай
		}
		if err == nil || errors.Is(err, masque.ErrNoProber) {
			// Путь жив (или проверить нечем): следующая проверка — не раньше,
			// чем через StallAfter тишины.
			inAt = time.Now()
			continue
		}
		if s.Current() != c {
			continue // пока проверяли, соединение уже сменилось
		}
		select {
		case <-s.done:
			return
		default:
		}
		s.stalls.Add(1)
		if s.cfg.OnStall != nil {
			s.cfg.OnStall()
		}
		// Закрытие будит насос (ReadPacket вернёт ошибку), а он — цикл
		// переподключения: дальше всё как при любом обрыве, с просьбой
		// вернуть прежний адрес.
		c.Close()
	}
}

// Prefixes возвращает адреса текущего соединения.
func (s *Session) Prefixes() []netip.Prefix {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cur.AssignedPrefixes()
}

// Rotations — сколько раз произошла ротация.
func (s *Session) Rotations() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rotations
}

// Current возвращает текущее соединение (для чтения маршрутов/статистики).
func (s *Session) Current() *masque.Conn {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cur
}

// retire переносит счётчики уходящего соединения в общий итог. Вызывается
// под s.mu, перед сменой s.cur.
func (s *Session) retire(c *masque.Conn) {
	if c == nil {
		return
	}
	st := c.Stats()
	s.retired.PacketsIn += st.PacketsIn
	s.retired.PacketsOut += st.PacketsOut
	s.retired.BytesIn += st.BytesIn
	s.retired.BytesOut += st.BytesOut
	s.retired.DroppedIn += st.DroppedIn
	s.retired.RejectedOut += st.RejectedOut
}

// Stats — счётчики за всю сессию, включая соединения до ротаций.
//
// Именно эти числа показывает окно клиента. Брать их у Current() было бы
// неверно: при ротации соединение заменяется новым, и «принято за сессию»
// на экране падало бы до нуля посреди работы.
func (s *Session) Stats() masque.Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	total := s.retired
	if s.cur != nil {
		st := s.cur.Stats()
		total.PacketsIn += st.PacketsIn
		total.PacketsOut += st.PacketsOut
		total.BytesIn += st.BytesIn
		total.BytesOut += st.BytesOut
		total.DroppedIn += st.DroppedIn
		total.RejectedOut += st.RejectedOut
	}
	return total
}

// Reconnects — сколько раз соединение восстанавливалось после обрыва.
func (s *Session) Reconnects() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.reconnects
}

// WritePacket отправляет пакет через текущее соединение.
//
// Пока идёт ротация с KeepAddress, у нового соединения временный адрес, а
// интерфейс ещё работает от прежнего: такие пакеты новое соединение
// отвергает по политике. Их отправляем через старое соединение, которое ещё
// живо в течение Grace, — иначе ротация давала бы паузу в трафике.
func (s *Session) WritePacket(pkt []byte) error {
	s.mu.RLock()
	c, prev := s.cur, s.prev
	closed := s.closed
	s.mu.RUnlock()
	err := c.WritePacket(pkt)
	if errors.Is(err, masque.ErrPacketRejected) && prev != nil {
		if perr := prev.WritePacket(pkt); perr == nil {
			return nil
		}
	}
	// Соединение оборвалось, а переподключение включено: пакет теряется, как
	// теряется любой пакет при пропаже связи, и вызывающий продолжает
	// работать. Возвращать здесь ошибку нельзя — насос туннеля считает её
	// смертельной и завершает клиента. То есть сервер, закрывший сессию
	// (отзыв доступа, исчерпанная квота, перезапуск), убивал бы клиент
	// вместо того, чтобы вызвать переподключение, и вернуть его мог бы
	// только человек руками.
	if errors.Is(err, masque.ErrSessionClosed) && s.cfg.Reconnect && !closed {
		s.dropped.Add(1)
		return nil
	}
	return err
}

// Dropped — сколько пакетов потеряно, пока не было связи.
func (s *Session) Dropped() uint64 { return s.dropped.Load() }

// ReadPacket отдаёт следующий пакет из любого активного соединения.
func (s *Session) ReadPacket(b []byte) (int, error) {
	select {
	case pkt := <-s.inbound:
		return copy(b, pkt), nil
	case <-s.done:
		return 0, ErrClosed
	}
}

// Rotate выполняет ротацию немедленно (make-before-break).
func (s *Session) Rotate(ctx context.Context) error {
	nc, err := s.cfg.Dial(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		nc.Close()
		return ErrClosed
	}
	old := s.cur
	oldPrefixes := old.AssignedPrefixes()
	s.retire(old)
	s.cur = nc
	s.prev = old
	s.rotations++
	s.mu.Unlock()

	s.startPump(nc)

	// Старое соединение дочитываем ещё Grace, затем закрываем.
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		t := time.NewTimer(s.cfg.Grace)
		defer t.Stop()
		select {
		case <-t.C:
		case <-s.done:
			old.Close()
			return // сессия закрывается: адрес возвращать уже некому
		}
		old.Close()

		if s.cfg.KeepAddress && len(oldPrefixes) > 0 {
			s.reclaimAddress(nc, oldPrefixes)
		}
		s.mu.Lock()
		if s.prev == old {
			s.prev = nil
		}
		s.mu.Unlock()
		if s.cfg.KeepAddress && s.cfg.OnRotate != nil {
			s.cfg.OnRotate(oldPrefixes, nc.AssignedPrefixes())
		}
	}()

	// Без KeepAddress адрес уже окончательный — сообщаем сразу.
	if !s.cfg.KeepAddress && s.cfg.OnRotate != nil {
		s.cfg.OnRotate(oldPrefixes, nc.AssignedPrefixes())
	}
	return nil
}

// reclaimAddress просит сервер вернуть прежний адрес и ждёт подтверждения.
//
// Повторяем запрос несколько раз: сервер освобождает адрес асинхронно, уже
// после закрытия старой сессии, поэтому первый запрос вполне может прийти,
// когда адрес ещё числится занятым. Не вышло за отведённое время — остаёмся с
// временным адресом, это не повод рвать рабочую сессию.
func (s *Session) reclaimAddress(c *masque.Conn, want []netip.Prefix) {
	const attempts = 5
	for i := 0; i < attempts; i++ {
		if slices.Equal(c.AssignedPrefixes(), want) {
			return
		}
		if err := c.RequestAddresses(want...); err != nil {
			return // сессия закрыта — просить больше не у кого
		}
		deadline := time.Now().Add(400 * time.Millisecond)
		for time.Now().Before(deadline) {
			if slices.Equal(c.AssignedPrefixes(), want) {
				return
			}
			select {
			case <-time.After(20 * time.Millisecond):
			case <-c.Done():
				return
			case <-s.done:
				return
			}
		}
	}
}

func (s *Session) startPump(c *masque.Conn) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		buf := make([]byte, 65536)
		for {
			n, err := c.ReadPacket(buf)
			if err != nil {
				s.mu.RLock()
				isCur := s.cur == c
				s.mu.RUnlock()
				if isCur {
					select {
					case s.lost <- c:
					default:
					}
				}
				return
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			select {
			case s.inbound <- pkt:
			case <-s.done:
				return
			}
		}
	}()
}

// DefaultJitter — разброс срока ротации по умолчанию (±25%).
const DefaultJitter = 0.25

// period возвращает срок до следующей ротации со случайным разбросом.
func (s *Session) period() time.Duration {
	return time.Duration(float64(s.cfg.Every) * s.jitter())
}

// byteLimit — порог по объёму со случайным разбросом.
func (s *Session) byteLimit() uint64 {
	return uint64(float64(s.cfg.AfterBytes) * s.jitter())
}

func (s *Session) jitter() float64 {
	j := s.cfg.Jitter
	switch {
	case j < 0:
		return 1
	case j == 0:
		j = DefaultJitter
	case j > 0.9:
		j = 0.9
	}
	return 1 + (rand.Float64()*2-1)*j
}

// autoRotate следит за сроком ротации.
//
// Раньше здесь стоял тикер с периодом Every, а внутри — проверка «прошло ли
// Every с прошлой ротации». Из-за расхождения фаз очередной тик почти всегда
// приходил чуть раньше срока, проверка его отбраковывала, и ротация уезжала
// на следующий тик: заданные 2 с превращались в 4, а заданные 30 минут — в
// час. Теперь таймер ставится ровно на остаток срока.
func (s *Session) autoRotate() {
	defer s.wg.Done()
	last := time.Now()
	every, bytes := s.period(), s.byteLimit()
	for {
		d := time.Hour
		if s.cfg.Every > 0 {
			d = time.Until(last.Add(every))
		}
		if s.cfg.AfterBytes > 0 && d > time.Second {
			d = time.Second // порог по объёму проверяем чаще
		}
		if d < 10*time.Millisecond {
			d = 10 * time.Millisecond
		}
		t := time.NewTimer(d)
		select {
		case <-s.done:
			t.Stop()
			return
		case <-t.C:
		}
		if !s.shouldRotate(last, every, bytes) {
			continue
		}
		ctx, cancel := context.WithTimeout(s.ctx, s.cfg.DialTimeout)
		err := s.Rotate(ctx)
		cancel()
		if err == nil {
			last = time.Now()
			// Срок следующей ротации разыгрывается заново — иначе разброс
			// был бы одинаковым на всём сеансе, то есть тем же метрономом.
			every, bytes = s.period(), s.byteLimit()
		}
		// При ошибке дозвона остаёмся на текущем соединении и пробуем позже.
	}
}

func (s *Session) shouldRotate(last time.Time, every time.Duration, bytes uint64) bool {
	if s.cfg.Every > 0 && time.Since(last) >= every {
		return true
	}
	if s.cfg.AfterBytes > 0 {
		st := s.Current().Stats()
		if st.BytesIn+st.BytesOut >= bytes {
			return true
		}
	}
	return false
}

// reconnectLoop восстанавливает оборвавшееся соединение.
func (s *Session) reconnectLoop() {
	defer s.wg.Done()
	for {
		var dead *masque.Conn
		select {
		case <-s.done:
			return
		case dead = <-s.lost:
		}
		s.mu.RLock()
		stale := s.cur != dead
		s.mu.RUnlock()
		if stale {
			continue // уже заменено ротацией
		}
		oldPrefixes := dead.AssignedPrefixes()
		pause := 500 * time.Millisecond
		for attempt := 1; ; attempt++ {
			ctx, cancel := context.WithTimeout(s.ctx, s.cfg.DialTimeout)
			nc, err := s.cfg.Dial(ctx)
			cancel()
			if s.cfg.OnReconnect != nil {
				s.cfg.OnReconnect(attempt, err)
			}
			if err == nil {
				select {
				case <-s.done:
					nc.Close()
					return
				default:
				}
				s.mu.Lock()
				if s.closed {
					s.mu.Unlock()
					nc.Close()
					return
				}
				s.retire(s.cur)
				s.cur = nc
				s.reconnects++
				s.mu.Unlock()
				s.startPump(nc)
				if s.cfg.KeepAddress && len(oldPrefixes) > 0 {
					// Сервер освобождает прежний адрес, только когда заметит
					// обрыв; не успел — работаем с новым адресом.
					s.reclaimAddress(nc, oldPrefixes)
				}
				if s.cfg.OnRotate != nil {
					s.cfg.OnRotate(oldPrefixes, nc.AssignedPrefixes())
				}
				break
			}
			select {
			case <-s.done:
				return
			case <-time.After(pause):
			}
			pause = min(pause*2, s.cfg.ReconnectMax)
		}
	}
}

// Close закрывает Session и все её соединения.
func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		c, prev := s.cur, s.prev
		s.mu.Unlock()
		close(s.done)
		s.cancel()
		c.Close()
		if prev != nil {
			prev.Close()
		}
	})
	s.wg.Wait()
	return nil
}
