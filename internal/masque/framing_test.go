package masque

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"
)

// collect разбирает датаграмму в список кадров.
func collect(t *testing.T, b []byte) []frame {
	t.Helper()
	var out []frame
	if err := parseFrames(b, func(f frame) error {
		out = append(out, f)
		return nil
	}); err != nil {
		t.Fatalf("разбор кадров: %v", err)
	}
	return out
}

// TestFramesRoundTrip — несколько пакетов в одной датаграмме и кусок
// крупного пакета кодируются и разбираются без потерь.
func TestFramesRoundTrip(t *testing.T) {
	p1 := bytes.Repeat([]byte{1}, 40)
	p2 := bytes.Repeat([]byte{2}, 1200)
	chunk := bytes.Repeat([]byte{3}, 100)

	b := appendFramedPrefix(nil)
	if ctxID, payload, ok := parseDatagram(b); !ok || ctxID != contextIDFramed || len(payload) != 0 {
		t.Fatalf("префикс: ctx=%d ok=%v", ctxID, ok)
	}
	b = appendPacketFrame(b, p1)
	b = appendPacketFrame(b, p2)
	b = appendFragmentFrame(b, 7, 500, chunk, true)

	_, payload, _ := parseDatagram(b)
	fs := collect(t, payload)
	if len(fs) != 3 {
		t.Fatalf("кадров: %d", len(fs))
	}
	if !bytes.Equal(fs[0].payload, p1) || !bytes.Equal(fs[1].payload, p2) {
		t.Fatal("пакеты искажены")
	}
	if fs[2].typ != frameTypeFragmentFin || fs[2].id != 7 || fs[2].off != 500 || !bytes.Equal(fs[2].payload, chunk) {
		t.Fatalf("кусок: %+v", fs[2])
	}
}

// TestPaddingStopsParsing — паддинг завершает разбор, а не превращается в мусор.
func TestPaddingStopsParsing(t *testing.T) {
	b := appendFramedPrefix(nil)
	b = appendPacketFrame(b, []byte("пакет"))
	full := appendPaddingFrame(b, 300)
	if len(full) != 300 {
		t.Fatalf("длина после паддинга: %d, ожидалось 300", len(full))
	}
	_, payload, _ := parseDatagram(full)
	fs := collect(t, payload)
	if len(fs) != 1 || string(fs[0].payload) != "пакет" {
		t.Fatalf("кадры: %+v", fs)
	}
	// Добивать до размера меньше уже занятого нечем — данные не портятся.
	if got := appendPaddingFrame(b, 4); len(got) != len(b) {
		t.Fatalf("паддинг «назад»: %d → %d", len(b), len(got))
	}
}

func TestMalformedFrames(t *testing.T) {
	for name, b := range map[string][]byte{
		"обрезанная длина":    {frameTypePacket},
		"длина больше данных": {frameTypePacket, 10, 1, 2, 3},
		"обрезанный кусок":    {frameTypeFragment, 1, 0},
	} {
		if err := parseFrames(b, func(frame) error { return nil }); err == nil {
			t.Errorf("%s: ошибка не обнаружена", name)
		}
	}
	// Неизвестный тип кадра не ломает соединение: разбор просто прекращается.
	if err := parseFrames([]byte{60, 1, 2, 3}, func(frame) error { return nil }); err != nil {
		t.Errorf("неизвестный тип: %v", err)
	}
}

// TestReassembly — сборка устойчива к переупорядочиванию и повторам.
func TestReassembly(t *testing.T) {
	r := newReassembler()
	pkt := make([]byte, 300)
	for i := range pkt {
		pkt[i] = byte(i)
	}
	// Куски приходят задом наперёд, с повтором в середине.
	if got := r.add(1, 200, pkt[200:], true); got != nil {
		t.Fatal("собрано по последнему куску, хотя начала ещё нет")
	}
	if got := r.add(1, 100, pkt[100:200], false); got != nil {
		t.Fatal("собрано без первого куска")
	}
	if got := r.add(1, 100, pkt[100:200], false); got != nil {
		t.Fatal("повтор куска досрочно собрал пакет — считаются байты, а не отрезки")
	}
	got := r.add(1, 0, pkt[:100], false)
	if !bytes.Equal(got, pkt) {
		t.Fatalf("собрано %d байт из %d", len(got), len(pkt))
	}
	if r.pending() != 0 {
		t.Fatal("собранный пакет остался в памяти")
	}
}

// TestReassemblyDropsIncomplete — недостающий кусок не придёт никогда
// (датаграммы QUIC не переотправляются), поэтому сборка не копится.
func TestReassemblyDropsIncomplete(t *testing.T) {
	r := newReassembler()
	now := time.Now()
	r.now = func() time.Time { return now }
	r.add(1, 0, make([]byte, 100), false) // без хвоста
	if r.pending() != 1 {
		t.Fatal("кусок не принят")
	}
	now = now.Add(defaultPartialTTL + time.Second)
	r.add(2, 0, make([]byte, 10), true)
	if r.pending() != 0 {
		t.Fatalf("протухшая сборка осталась: %d", r.pending())
	}
	if r.drops() != 1 {
		t.Fatalf("счётчик потерь: %d", r.drops())
	}

	// Переполнение: сборок не больше потолка.
	r2 := newReassembler()
	r2.maxPartial = 4
	for i := 0; i < 20; i++ {
		r2.add(uint64(i), 0, make([]byte, 10), false)
	}
	if r2.pending() > 4 {
		t.Fatalf("сборок %d при потолке 4", r2.pending())
	}
	if r2.drops() == 0 {
		t.Fatal("вытеснение не посчитано")
	}
}

// TestReassemblyMemoryIsBounded — память под сборку ограничена в БАЙТАХ, а
// не только числом сборок. Иначе враждебный клиент держит 64 сборки по
// 64 КБ на сессию и выедает память сервера, ни разу не прислав хвост.
func TestReassemblyMemoryIsBounded(t *testing.T) {
	r := newReassembler()
	r.maxBytes = 64 << 10 // 64 КБ на сессию

	// Шлём куски «на дальнем конце» большого пакета: каждый такой кусок
	// заставляет выделить буфер под весь пакет.
	chunk := make([]byte, 100)
	for i := 0; i < 200; i++ {
		r.add(uint64(i), 60000, chunk, false)
	}
	if got := r.memory(); got > r.maxBytes {
		t.Fatalf("занято %d байт при потолке %d", got, r.maxBytes)
	}
	if r.drops() == 0 {
		t.Fatal("вытеснение не посчитано")
	}
	t.Logf("после 200 сборок по ~60 КБ занято %d КБ, сборок %d", r.memory()>>10, r.pending())

	// Учёт памяти не «протекает»: собранный пакет освобождает место.
	r2 := newReassembler()
	r2.add(1, 0, make([]byte, 500), false)
	if r2.memory() == 0 {
		t.Fatal("память не учтена")
	}
	if got := r2.add(1, 500, make([]byte, 500), true); len(got) != 1000 {
		t.Fatalf("пакет не собран: %d", len(got))
	}
	if r2.memory() != 0 {
		t.Fatalf("после сборки осталось %d байт", r2.memory())
	}
}

// TestCoverRequiresNegotiation — cover-датаграммы (Context ID 1) уходят
// только после подтверждения другой стороны. RFC 9484 отводит под IP-пакеты
// нулевой контекст, остальные — под расширения: слать их, не
// договорившись, значит слать сторонней реализации мусор.
func TestCoverRequiresNegotiation(t *testing.T) {
	r := newRecorder()
	sh := &Shaping{Cover: &CoverConfig{
		Next:   func() time.Duration { return 5 * time.Millisecond },
		Size:   func() int { return 100 },
		Always: true,
	}}
	c := NewClientConn(r, ClientConnOptions{Shaping: sh, Closer: func() error { return nil }})
	defer c.Close()

	time.Sleep(100 * time.Millisecond)
	if _, cover := r.counts(); cover != 0 {
		t.Fatalf("без подтверждения ушло %d cover-датаграмм", cover)
	}
	c.peerCover.Store(true)
	time.Sleep(100 * time.Millisecond)
	if _, cover := r.counts(); cover == 0 {
		t.Fatal("после подтверждения cover так и не пошёл")
	}
}

// TestClockSkewHint — при ответе «как постороннему» клиент подсказывает про
// часы: токен привязан ко времени, и разъехавшиеся часы дают ровно такой же
// 404, как чужой ключ. Без подсказки это ищут часами.
func TestClockSkewHint(t *testing.T) {
	past := time.Now().Add(-5 * time.Minute).UTC().Format(http.TimeFormat)
	skew := ClockSkewFromDate(past)
	if skew < 4*time.Minute || skew > 6*time.Minute {
		t.Fatalf("расхождение измерено как %v", skew)
	}
	msg := (&ResponseError{StatusCode: 404, ClockSkew: skew}).Error()
	if !strings.Contains(msg, "часы") || !strings.Contains(msg, "404") {
		t.Fatalf("сообщение без подсказки: %s", msg)
	}
	// В пределах допуска подсказки нет — иначе она будет мозолить глаза.
	msg = (&ResponseError{StatusCode: 404, ClockSkew: time.Second}).Error()
	if strings.Contains(msg, "часы") {
		t.Fatalf("подсказка при исправных часах: %s", msg)
	}
	// Неразобранный заголовок не ломает ничего.
	if got := ClockSkewFromDate("вчера"); got != 0 {
		t.Fatalf("мусорный Date дал %v", got)
	}
}
