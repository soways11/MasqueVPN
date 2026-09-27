package masque

import (
	"math/rand/v2"
	"time"
)

// Упаковщик исходящих датаграмм (пункт C2 плана, вторая половина).
//
// Пока датаграмма делалась прямо в WritePacket, поток снаружи повторял
// поток внутри: пакет — датаграмма, пауза — пауза. Теперь между TUN и
// проводом стоит очередь и упаковщик: он складывает попутные пакеты в одну
// датаграмму, режет крупные на куски и — если задан профиль — отправляет
// датаграммы по своему расписанию, а не по мере поступления пакетов.

// Packing — параметры упаковки. Действуют, только когда другая сторона
// подтвердила поддержку кадров (см. капсулу согласования в conn.go).
type Packing struct {
	// Window — сколько ждать попутные пакеты, чтобы сложить их вместе.
	// Это ПРЯМАЯ прибавка к задержке, поэтому значения здесь микросекундные:
	// 200–500 мкс собирают залп TCP-подтверждений, не задевая интерактивность.
	// 0 — не ждать (складываются только те, что уже в очереди).
	Window time.Duration
	// MaxPayload — потолок полезной нагрузки датаграммы; 0 — потолок пути.
	MaxPayload int
	// QueueLen — длина очереди пакетов; 0 — defaultTxQueueLen.
	QueueLen int
	// Pace, если задан, включает формирование потока по профилю.
	Pace *Pacing
}

// Pacing — расписание отправки датаграмм.
//
// Смысл: у обычного приложения (игры, видеозвонка) датаграммы идут своим
// ритмом, слабо связанным с тем, что происходит у него внутри. Мы делаем
// так же — пока хватает пропускной способности. Под нагрузкой профиль
// уступает: держать темп в 30 датаграмм в секунду при скачивании значило бы
// уронить скорость в десятки раз, поэтому при очереди больше Burst байт
// упаковщик отдаёт всё подряд. То есть форма потока задаётся профилем
// именно там, где туннель иначе заметнее всего, — на малых скоростях.
type Pacing struct {
	// Interval возвращает паузу до следующей датаграммы.
	Interval func() time.Duration
	// Size возвращает целевой размер полезной нагрузки датаграммы.
	Size func() int
	// Burst — порог очереди (байт), после которого темп не держится.
	// 0 — defaultPaceBurst.
	Burst int
	// Idle — слать датаграмму, даже если отправлять нечего (тогда она
	// целиком паддинг). Именно это делает поток независимым от того, есть
	// ли трафик внутри.
	Idle bool
}

const (
	defaultTxQueueLen = 1024
	defaultPaceBurst  = 16 << 10
)

func (p *Packing) queueLen() int {
	if p != nil && p.QueueLen > 0 {
		return p.QueueLen
	}
	return defaultTxQueueLen
}

func (p *Pacing) burst() int {
	if p != nil && p.Burst > 0 {
		return p.Burst
	}
	return defaultPaceBurst
}

// enqueueForPacking кладёт пакет в очередь упаковщика. false — очередь
// переполнена (пакет отброшен, как на любом переполненном интерфейсе).
func (c *Conn) enqueueForPacking(pkt []byte) bool {
	b := make([]byte, len(pkt))
	copy(b, pkt)
	select {
	case c.txq <- b:
		return true
	default:
		c.queueDrop.Add(1)
		return false
	}
}

// packLoop — единственный писатель датаграмм при включённых кадрах.
func (c *Conn) packLoop() {
	if c.packing.Pace == nil {
		c.packLoopPlain()
		return
	}
	c.packLoopPaced(c.packing.Pace)
}

// packLoopPlain: датаграмма отправляется, как только есть что отправлять;
// попутные пакеты собираются за окно агрегации.
func (c *Conn) packLoopPlain() {
	for {
		var batch [][]byte
		select {
		case <-c.ctx.Done():
			return
		case p := <-c.txq:
			batch = append(batch, p)
		}
		c.sendBatch(c.drain(batch, c.packing.Window), nil)
	}
}

// packLoopPaced держит расписание профиля.
//
// Пока очередь меньше Burst, за такт уходит столько, сколько велит профиль
// (Size), — поток датаграмм задаётся расписанием, а не тем, что происходит
// внутри туннеля. Как только очередь перерастает Burst, расписание
// отпускается и накопленное уходит подряд: держать темп при скачивании
// значило бы уронить скорость в десятки раз. То есть форма потока задаётся
// профилем именно там, где туннель иначе заметнее всего, — на малых
// скоростях и в простое.
func (c *Conn) packLoopPaced(pace *Pacing) {
	var pending [][]byte
	pendingBytes := 0
	for {
		d := time.Millisecond
		if pace.Interval != nil {
			d = pace.Interval()
		}
		t := time.NewTimer(d)
		select {
		case <-c.ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		t.Stop()

		for { // забираем всё, что накопилось
			select {
			case p := <-c.txq:
				pending = append(pending, p)
				pendingBytes += len(p)
				continue
			default:
			}
			break
		}
		if len(pending) == 0 {
			if !pace.Idle {
				select { // ждём первый пакет, чтобы не крутить таймер впустую
				case <-c.ctx.Done():
					return
				case p := <-c.txq:
					pending = append(pending, p)
					pendingBytes += len(p)
				}
			} else {
				// Отправлять нечего — уходит датаграмма из одного паддинга.
				// Именно она делает поток независимым от трафика внутри.
				c.sendFramed(nil, c.paceSize(pace))
				continue
			}
		}

		batch := pending
		if pendingBytes <= pace.burst() {
			batch = nil
			room := c.paceSize(pace)
			if room <= 0 {
				room = c.payloadLimit()
			}
			used := 0
			for len(pending) > 0 {
				n := len(pending[0]) + packetFrameOverhead(len(pending[0]))
				if used > 0 && used+n > room {
					break
				}
				batch = append(batch, pending[0])
				used += n
				pendingBytes -= len(pending[0])
				pending = pending[1:]
			}
		} else {
			pending, pendingBytes = nil, 0
		}
		c.sendBatch(batch, pace)
	}
}

// drain добирает пакеты, уже лежащие в очереди, и (при window > 0) те,
// что появятся за это время.
func (c *Conn) drain(batch [][]byte, window time.Duration) [][]byte {
	for {
		select {
		case p := <-c.txq:
			batch = append(batch, p)
			continue
		default:
		}
		break
	}
	if window <= 0 {
		return batch
	}
	t := time.NewTimer(window)
	defer t.Stop()
	for {
		select {
		case p := <-c.txq:
			batch = append(batch, p)
			if len(batch) >= 64 {
				return batch
			}
		case <-t.C:
			return batch
		case <-c.ctx.Done():
			return batch
		}
	}
}

func (c *Conn) paceSize(pace *Pacing) int {
	if pace != nil && pace.Size != nil {
		return pace.Size()
	}
	return 0
}

// payloadLimit — сколько байт полезной нагрузки датаграммы можно занять.
func (c *Conn) payloadLimit() int {
	lim := c.capacity()
	if lim <= 0 {
		// Потолок ещё не выяснен: берём заведомо проходимый минимум.
		lim = 1200
	}
	if m := c.packing.MaxPayload; m > 0 && m < lim {
		lim = m
	}
	return lim
}

// sendBatch раскладывает пакеты по датаграммам и отправляет их.
func (c *Conn) sendBatch(batch [][]byte, pace *Pacing) {
	limit := c.payloadLimit()
	target := c.paceSize(pace)
	if target > limit {
		target = limit
	}

	buf := appendFramedPrefix(nil)
	flush := func() {
		if len(buf) > 1 {
			c.sendFramed(buf, target)
		}
		buf = appendFramedPrefix(nil)
	}
	for _, pkt := range batch {
		need := len(pkt) + packetFrameOverhead(len(pkt))
		if len(buf)+need > limit {
			if len(buf) > 1 {
				flush()
			}
			if len(pkt)+packetFrameOverhead(len(pkt))+1 > limit {
				// Пакет не помещается даже в пустую датаграмму — режем.
				c.sendFragmented(pkt, limit, target)
				continue
			}
		}
		buf = appendPacketFrame(buf, pkt)
		c.pktOut.Add(1)
		c.bytesOut.Add(uint64(len(pkt)))
		if len(batch) > 1 {
			c.packedOut.Add(1)
		}
	}
	flush()
}

// sendFragmented режет пакет на куски по датаграммам.
func (c *Conn) sendFragmented(pkt []byte, limit, target int) {
	id := c.nextFragID.Add(1)
	off := 0
	for off < len(pkt) {
		// Обвязку считаем по худшему случаю длины куска, чтобы не promахнуться.
		head := 1 + fragmentFrameOverhead(id, off, limit)
		room := limit - 1 - head
		if room <= 0 {
			c.droppedOut.Add(1)
			return
		}
		end := min(off+room, len(pkt))
		buf := appendFramedPrefix(nil)
		buf = appendFragmentFrame(buf, id, off, pkt[off:end], end == len(pkt))
		c.sendFramed(buf, target)
		c.fragOut.Add(1)
		off = end
	}
	c.pktOut.Add(1)
	c.bytesOut.Add(uint64(len(pkt)))
}

// sendFramed добивает датаграмму до целевого размера и отправляет её.
// buf уже содержит Context ID и кадры; nil — датаграмма из одного паддинга.
func (c *Conn) sendFramed(buf []byte, target int) {
	if buf == nil {
		buf = appendFramedPrefix(nil)
	}
	// Целевой размер: сначала профиль, затем «вёдра» паддинга — то и другое
	// не должно вылезать за потолок пути.
	limit := c.payloadLimit()
	want := target
	if p := c.shaping.padTo(len(buf)); p > want {
		want = p
	}
	if want > limit {
		want = limit
	}
	if want > len(buf) {
		buf = appendPaddingFrame(buf, want)
	}
	// Джиттер применяется к ДАТАГРАММЕ, а не к пакету: на проводе видна
	// именно она. Ждёт при этом упаковщик, а не насос TUN, — тот уже отдал
	// пакет в очередь и занят следующим.
	if d := c.shaping.delay(len(buf)); d > 0 {
		t := time.NewTimer(d)
		select {
		case <-c.ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
	c.limiter.wait(c.ctx, len(buf))
	if err := c.str.SendDatagram(buf); err != nil {
		if n, ok := datagramCapacity(err); ok {
			c.learnCapacity(n)
		}
		c.droppedOut.Add(1)
		return
	}
	c.dgramOut.Add(1)
	c.recordSend()
	c.recordPacket()
}

// randomFragID — начальное значение счётчика фрагментов. Начинать с нуля
// незачем: идентификаторы видны только внутри шифрованной датаграммы, но
// предсказуемая последовательность — лишняя зацепка.
func randomFragID() uint64 { return rand.Uint64() >> 2 }
