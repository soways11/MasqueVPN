package masque

import (
	"errors"
	"sync"
	"time"

	"github.com/quic-go/quic-go/quicvarint"
)

// Развязка «IP-пакет ↔ датаграмма» (пункт C2 плана).
//
// # Признак, который это закрывает
//
// Раньше один IP-пакет всегда ехал в одной датаграмме. Паддинг ломал
// РАЗМЕРЫ, но не количество и не ритм: всплеск из десяти пакетов внутри
// туннеля снаружи виден как всплеск ровно из десяти датаграмм, а пауза
// внутри — как пауза снаружи. Наблюдателю не нужно расшифровывать
// содержимое: достаточно посчитать датаграммы и померить интервалы, и
// поток внутри туннеля проступает почти как есть. Это и отличает
// «маскировку» (спрятать признаки протокола) от морфинга трафика
// (сделать поток похожим на другой).
//
// # Формат
//
// Context ID 2 — «кадрированная» полезная нагрузка: в одной датаграмме
// может ехать несколько IP-пакетов, кусок одного пакета или их смесь.
// Кадры идут подряд до конца датаграммы:
//
//	тип (varint):
//	  0 PADDING       — дальше до конца датаграммы паддинг, разбор окончен
//	  1 PACKET        — длина(varint) + IP-пакет целиком
//	  2 FRAGMENT      — id(varint) + смещение(varint) + длина(varint) + кусок
//	  3 FRAGMENT_FIN  — то же, но это последний кусок пакета
//
// Context ID 0 (пакет целиком, как в RFC 9484) остаётся и используется,
// пока другая сторона не подтвердила поддержку кадров, — см. капсулу
// согласования в conn.go. Так новый клиент работает со старым сервером и
// наоборот.
//
// # Что это даёт сверх маскировки ритма
//
//   - Потолок MTU перестаёт быть жёстким: пакет крупнее датаграммы больше
//     не отбивается ICMP, а режется на куски. IPv6 внутри туннеля больше
//     не зависит от размера QUIC-пакета.
//   - Мелкие пакеты (TCP-подтверждения, ввод в играх) перестают быть
//     отдельными событиями на проводе.
const contextIDFramed = 2

// Типы кадров.
const (
	frameTypePadding     = 0
	frameTypePacket      = 1
	frameTypeFragment    = 2
	frameTypeFragmentFin = 3
)

// frameOverhead — сколько байт занимает обвязка кадра PACKET для пакета
// длиной n. Тип — 1 байт (значения 0–3), длина — varint.
func packetFrameOverhead(n int) int { return 1 + quicvarint.Len(uint64(n)) }

// fragmentFrameOverhead — обвязка кадра FRAGMENT для данных id/offset/len.
func fragmentFrameOverhead(id uint64, off, n int) int {
	return 1 + quicvarint.Len(id) + quicvarint.Len(uint64(off)) + quicvarint.Len(uint64(n))
}

func appendFramedPrefix(b []byte) []byte { return quicvarint.Append(b, contextIDFramed) }

func appendPacketFrame(b, pkt []byte) []byte {
	b = quicvarint.Append(b, frameTypePacket)
	b = quicvarint.Append(b, uint64(len(pkt)))
	return append(b, pkt...)
}

func appendFragmentFrame(b []byte, id uint64, off int, chunk []byte, last bool) []byte {
	t := uint64(frameTypeFragment)
	if last {
		t = frameTypeFragmentFin
	}
	b = quicvarint.Append(b, t)
	b = quicvarint.Append(b, id)
	b = quicvarint.Append(b, uint64(off))
	b = quicvarint.Append(b, uint64(len(chunk)))
	return append(b, chunk...)
}

// appendPaddingFrame добивает датаграмму до total байт полезной нагрузки.
// Возвращает b без изменений, если добивать нечего.
func appendPaddingFrame(b []byte, total int) []byte {
	if n := total - len(b) - 1; n > 0 {
		b = quicvarint.Append(b, frameTypePadding)
		return appendZeros(b, n)
	}
	return b
}

var errMalformedFrame = errors.New("masque: malformed datagram frame")

// frame — разобранный кадр.
type frame struct {
	typ     uint64
	id      uint64
	off     int
	payload []byte
}

// parseFrames разбирает кадры датаграммы и вызывает fn на каждом.
// Разбор прекращается на PADDING или на конце данных.
func parseFrames(b []byte, fn func(frame) error) error {
	for len(b) > 0 {
		typ, n, err := quicvarint.Parse(b)
		if err != nil {
			return errMalformedFrame
		}
		b = b[n:]
		switch typ {
		case frameTypePadding:
			return nil
		case frameTypePacket:
			l, n, err := quicvarint.Parse(b)
			if err != nil {
				return errMalformedFrame
			}
			b = b[n:]
			if uint64(len(b)) < l {
				return errMalformedFrame
			}
			if err := fn(frame{typ: typ, payload: b[:l]}); err != nil {
				return err
			}
			b = b[l:]
		case frameTypeFragment, frameTypeFragmentFin:
			id, n, err := quicvarint.Parse(b)
			if err != nil {
				return errMalformedFrame
			}
			b = b[n:]
			off, n, err := quicvarint.Parse(b)
			if err != nil {
				return errMalformedFrame
			}
			b = b[n:]
			l, n, err := quicvarint.Parse(b)
			if err != nil {
				return errMalformedFrame
			}
			b = b[n:]
			if uint64(len(b)) < l || off > maxReassembly || off+l > maxReassembly {
				return errMalformedFrame
			}
			if err := fn(frame{typ: typ, id: id, off: int(off), payload: b[:l]}); err != nil {
				return err
			}
			b = b[l:]
		default:
			// Неизвестный тип кадра: дальше разобрать датаграмму нельзя,
			// но соединение из-за этого рвать не за что.
			return nil
		}
	}
	return nil
}

// ---------- сборка фрагментов ----------

const (
	// maxReassembly — потолок размера собираемого пакета.
	maxReassembly = 65535
	// defaultMaxPartial — сколько незавершённых пакетов держим одновременно.
	defaultMaxPartial = 64
	// defaultMaxPartialBytes — потолок памяти под сборку НА СЕССИЮ.
	//
	// Одного потолка по числу сборок мало: 64 пакета по 64 КБ — это 4 МБ,
	// и враждебный клиент может держать их постоянно, подсовывая куски без
	// хвоста. При сотнях сессий это гигабайты. Поэтому считаем именно
	// байты и вытесняем самые старые сборки.
	defaultMaxPartialBytes = 1 << 20
	// defaultPartialTTL — сколько ждём недостающие куски. Датаграммы QUIC не
	// переотправляются: потерянный кусок не придёт никогда, и держать его
	// дольше — только занимать память.
	defaultPartialTTL = 2 * time.Second
)

type partial struct {
	buf      []byte
	ranges   [][2]int // непересекающиеся полученные отрезки, по возрастанию
	total    int      // известен после FIN, иначе -1
	deadline time.Time
}

// reassembler собирает пакеты из фрагментов.
//
// Сборка устойчива к переупорядочиванию (датаграммы QUIC приходят не по
// порядку) и к повторам: учитываются именно отрезки байт, а не их
// количество, иначе дубликат кусочка «досрочно» собрал бы битый пакет.
type reassembler struct {
	mu         sync.Mutex
	parts      map[uint64]*partial
	bytes      int // сколько памяти занято сборками
	maxPartial int
	maxBytes   int
	ttl        time.Duration
	now        func() time.Time

	dropped uint64 // не собранные (протухли или вытеснены)
}

func newReassembler() *reassembler {
	return &reassembler{
		parts:      map[uint64]*partial{},
		maxPartial: defaultMaxPartial,
		maxBytes:   defaultMaxPartialBytes,
		ttl:        defaultPartialTTL,
		now:        time.Now,
	}
}

// add добавляет кусок. Возвращает собранный пакет, когда он готов.
func (r *reassembler) add(id uint64, off int, chunk []byte, last bool) []byte {
	if len(chunk) == 0 || off+len(chunk) > maxReassembly {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	r.expire(now)

	p := r.parts[id]
	if p == nil {
		if len(r.parts) >= r.maxPartial {
			r.evictOldest()
		}
		p = &partial{total: -1, deadline: now.Add(r.ttl)}
		r.parts[id] = p
	}
	if need := off + len(chunk); len(p.buf) < need {
		grow := need - len(p.buf)
		// Место под новую сборку освобождаем ДО выделения: иначе потолок
		// проверялся бы уже после того, как память занята.
		for r.bytes+grow > r.maxBytes && len(r.parts) > 1 {
			r.evictOldest()
		}
		if r.bytes+grow > r.maxBytes {
			// Даже в одиночку не помещается — бросаем эту сборку.
			r.remove(id)
			r.dropped++
			return nil
		}
		p.buf = append(p.buf, make([]byte, grow)...)
		r.bytes += grow
	}
	copy(p.buf[off:], chunk)
	p.insert(off, off+len(chunk))
	if last {
		p.total = off + len(chunk)
	}
	if p.total >= 0 && len(p.ranges) == 1 && p.ranges[0] == [2]int{0, p.total} {
		r.remove(id)
		return p.buf[:p.total]
	}
	return nil
}

// insert добавляет отрезок [start,end) и сливает соседние.
func (p *partial) insert(start, end int) {
	out := p.ranges[:0]
	added := false
	for _, r := range p.ranges {
		switch {
		case r[1] < start: // целиком левее
			out = append(out, r)
		case end < r[0]: // целиком правее
			if !added {
				out = append(out, [2]int{start, end})
				added = true
			}
			out = append(out, r)
		default: // пересекается или примыкает — сливаем
			start = min(start, r[0])
			end = max(end, r[1])
		}
	}
	if !added {
		out = append(out, [2]int{start, end})
	}
	p.ranges = out
	// После слияния отрезок мог «съесть» соседей — пересортировка не нужна,
	// порядок сохраняется, но объединённый отрезок мог встать не на место.
	for i := 1; i < len(p.ranges); i++ {
		for j := i; j > 0 && p.ranges[j][0] < p.ranges[j-1][0]; j-- {
			p.ranges[j], p.ranges[j-1] = p.ranges[j-1], p.ranges[j]
		}
	}
}

// remove убирает сборку и освобождает её память из учёта.
func (r *reassembler) remove(id uint64) {
	if p := r.parts[id]; p != nil {
		r.bytes -= len(p.buf)
		delete(r.parts, id)
	}
}

func (r *reassembler) expire(now time.Time) {
	for id, p := range r.parts {
		if now.After(p.deadline) {
			r.remove(id)
			r.dropped++
		}
	}
}

func (r *reassembler) evictOldest() {
	var oldestID uint64
	var oldest time.Time
	first := true
	for id, p := range r.parts {
		if first || p.deadline.Before(oldest) {
			oldestID, oldest, first = id, p.deadline, false
		}
	}
	if !first {
		r.remove(oldestID)
		r.dropped++
	}
}

// drops — сколько пакетов не удалось собрать.
func (r *reassembler) drops() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dropped
}

// pending — сколько пакетов сейчас собирается (для тестов и счётчиков).
func (r *reassembler) pending() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.parts)
}

// memory — сколько байт занято незавершёнными сборками.
func (r *reassembler) memory() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.bytes
}
