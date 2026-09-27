package masque

import (
	"context"
	"encoding/binary"
	"math"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// recorder — поддельный поток: записывает, ЧТО и КОГДА ушло на провод.
// Это ровно то, что видит наблюдатель снаружи: размер датаграммы и момент
// отправки, без доступа к содержимому.
type recorder struct {
	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	at      []time.Time
	size    []int
	payload [][]byte
}

func newRecorder() *recorder {
	ctx, cancel := context.WithCancel(context.Background())
	return &recorder{ctx: ctx, cancel: cancel}
}

func (r *recorder) SendDatagram(b []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.at = append(r.at, time.Now())
	r.size = append(r.size, len(b))
	r.payload = append(r.payload, append([]byte(nil), b...))
	return nil
}

func (r *recorder) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (r *recorder) Read([]byte) (int, error)    { <-r.ctx.Done(); return 0, r.ctx.Err() }
func (r *recorder) Write(b []byte) (int, error) { return len(b), nil }
func (r *recorder) Close() error                { r.cancel(); return nil }
func (r *recorder) CancelRead(uint64)           {}
func (r *recorder) CancelWrite(uint64)          {}
func (r *recorder) Context() context.Context    { return r.ctx }

func (r *recorder) snapshot() (at []time.Time, size []int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]time.Time(nil), r.at...), append([]int(nil), r.size...)
}

// counts считает датаграммы по Context ID: сколько с пакетами и сколько
// маскирующих.
func (r *recorder) counts() (data, cover int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range r.payload {
		ctxID, _, ok := parseDatagram(p)
		if !ok {
			continue
		}
		if ctxID == contextIDPadding {
			cover++
		} else {
			data++
		}
	}
	return data, cover
}

// connOver поднимает клиентскую сессию поверх поддельного потока с уже
// выданным адресом, маршрутами и согласованными кадрами.
func connOver(t *testing.T, r *recorder, packing *Packing) *Conn {
	t.Helper()
	c := NewClientConn(r, ClientConnOptions{Packing: packing, Closer: func() error { return nil }})
	c.mu.Lock()
	c.assigned = []netip.Prefix{netip.MustParsePrefix("10.8.0.2/32")}
	c.routes = FullRoutes()
	c.mu.Unlock()
	c.peerFraming.Store(true)
	c.peerCover.Store(true) // на поддельном потоке капсуле согласования взяться неоткуда
	c.learnCapacity(1300)
	t.Cleanup(func() { c.Close() })
	return c
}

func cv(vals []float64) float64 {
	if len(vals) < 2 {
		return 0
	}
	var sum float64
	for _, v := range vals {
		sum += v
	}
	avg := sum / float64(len(vals))
	var d float64
	for _, v := range vals {
		d += (v - avg) * (v - avg)
	}
	return math.Sqrt(d/float64(len(vals))) / avg
}

// TestPacingShapesStream — критерий C2 на числах: при редком трафике внутри
// туннеля поток датаграмм снаружи задаётся ПРОФИЛЕМ, а не входом.
//
// Внутрь подаётся 5 пакетов за секунду. Снаружи за то же время должно уйти
// около сотни датаграмм одинакового размера — по расписанию профиля. То
// есть по числу датаграмм, их размеру и ритму наблюдатель не может сказать
// ни сколько пакетов было внутри, ни когда они были.
func TestPacingShapesStream(t *testing.T) {
	const (
		interval = 10 * time.Millisecond
		target   = 400
		duration = time.Second
	)
	r := newRecorder()
	c := connOver(t, r, &Packing{Pace: &Pacing{
		Interval: func() time.Duration { return interval },
		Size:     func() int { return target },
		Idle:     true,
	}})

	src := netip.MustParseAddr("10.8.0.2")
	dst := netip.MustParseAddr("1.1.1.1")
	done := time.After(duration)
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	sent := 0
loop:
	for {
		select {
		case <-done:
			break loop
		case <-tick.C:
			c.WritePacket(buildIPv4(src, dst, 17, binary.BigEndian.AppendUint32(nil, uint32(sent))))
			sent++
		}
	}
	at, sizes := r.snapshot()

	if sent > 6 {
		t.Fatalf("внутрь подано %d пакетов — тест рассчитан на редкий трафик", sent)
	}
	want := int(duration/interval) * 2 / 3
	if len(at) < want {
		t.Fatalf("за %v ушло %d датаграмм, профиль требует около %d", duration, len(at), duration/interval)
	}
	// Все датаграммы одного размера: по размеру не видно, какая несла пакет.
	for i, s := range sizes {
		if s != target {
			t.Fatalf("датаграмма %d размером %d, а не %d — размер выдаёт содержимое", i, s, target)
		}
	}
	// Ритм ровный и не связан с входом: интервалы близки к профилю.
	var gaps []float64
	for i := 1; i < len(at); i++ {
		gaps = append(gaps, float64(at[i].Sub(at[i-1])))
	}
	if got := cv(gaps); got > 0.5 {
		t.Fatalf("коэффициент вариации интервалов %.2f — ритм повторяет вход, а не профиль", got)
	}
	t.Logf("вход: %d пакетов, выход: %d датаграмм по %d байт", sent, len(at), target)

	st := c.Stats()
	if st.PacketsOut != uint64(sent) || st.DatagramsOut < uint64(want) {
		t.Fatalf("счётчики: %+v", st)
	}
}

// TestWithoutPacingStreamFollowsInput — контроль: без расписания поток
// датаграмм повторяет вход (по датаграмме на пакет). Именно это и было
// признаком до C2.
func TestWithoutPacingStreamFollowsInput(t *testing.T) {
	r := newRecorder()
	c := connOver(t, r, &Packing{})
	src := netip.MustParseAddr("10.8.0.2")
	dst := netip.MustParseAddr("1.1.1.1")
	for i := 0; i < 5; i++ {
		c.WritePacket(buildIPv4(src, dst, 17, []byte("x")))
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	at, _ := r.snapshot()
	if len(at) != 5 {
		t.Fatalf("датаграмм %d на 5 пакетов", len(at))
	}
}

// TestPacingYieldsUnderLoad — под нагрузкой расписание уступает пропускной
// способности: иначе скачивание упёрлось бы в темп профиля. Проверяем, что
// мегабайт уходит за такты, а не за тысячи тактов профиля.
func TestPacingYieldsUnderLoad(t *testing.T) {
	r := newRecorder()
	c := connOver(t, r, &Packing{Pace: &Pacing{
		Interval: func() time.Duration { return 10 * time.Millisecond },
		Size:     func() int { return 300 },
		Idle:     true,
		Burst:    8 << 10,
	}})
	src := netip.MustParseAddr("10.8.0.2")
	dst := netip.MustParseAddr("1.1.1.1")
	pkt := buildIPv4(src, dst, 6, make([]byte, 1200))
	const n = 800 // около мегабайта
	begin := time.Now()
	for i := 0; i < n; i++ {
		c.WritePacket(pkt)
	}
	deadline := time.Now().Add(3 * time.Second)
	for c.Stats().PacketsOut < n && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	took := time.Since(begin)
	if c.Stats().PacketsOut < n {
		t.Fatalf("за %v ушло %d пакетов из %d — расписание не уступило нагрузке", took, c.Stats().PacketsOut, n)
	}
	t.Logf("%d пакетов (≈1 МБ) ушли за %v", n, took.Round(time.Millisecond))
}

// TestCoverUnderLoad — cover-датаграммы идут и под нагрузкой, а не только в
// простое. Иначе сам факт «пошёл cover» размечает наблюдателю границы
// активности — ровно тот признак, ради которого cover и задуман.
func TestCoverUnderLoad(t *testing.T) {
	run := func(always bool) (data, cover int) {
		r := newRecorder()
		sh := &Shaping{Cover: &CoverConfig{
			Next:   func() time.Duration { return 5 * time.Millisecond },
			Size:   func() int { return 100 },
			Always: always,
		}}
		c := NewClientConn(r, ClientConnOptions{Shaping: sh, Closer: func() error { return nil }})
		c.mu.Lock()
		c.assigned = []netip.Prefix{netip.MustParsePrefix("10.8.0.2/32")}
		c.routes = FullRoutes()
		c.mu.Unlock()
		c.peerCover.Store(true) // см. connOver
		c.learnCapacity(1300)
		defer c.Close()

		// Непрерывная нагрузка: пакет каждые 2 мс в течение 300 мс.
		deadline := time.After(300 * time.Millisecond)
		tick := time.NewTicker(2 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-deadline:
				return r.counts()
			case <-tick.C:
				c.WritePacket(buildIPv4(netip.MustParseAddr("10.8.0.2"), netip.MustParseAddr("1.1.1.1"), 17, []byte("x")))
			}
		}
	}

	dataAlways, coverAlways := run(true)
	dataIdle, coverIdle := run(false)
	t.Logf("под нагрузкой: с Always %d cover на %d пакетов; без Always %d на %d",
		coverAlways, dataAlways, coverIdle, dataIdle)
	if coverAlways < 20 {
		t.Fatalf("под нагрузкой ушло лишь %d cover-датаграмм", coverAlways)
	}
	if coverIdle > coverAlways/4 {
		t.Fatalf("без Always cover тоже идёт (%d) — тест ничего не проверяет", coverIdle)
	}
}

// TestJitterAppliesWithFraming — джиттер должен работать и на пути с
// кадрами. Раньше ветка с кадрами стояла в WritePacket раньше джиттера, и
// включение кадров (а они включены по умолчанию) молча его отключало.
func TestJitterAppliesWithFraming(t *testing.T) {
	const jitter = 20 * time.Millisecond
	r := newRecorder()
	c := connOver(t, r, &Packing{})
	c.shaping = &Shaping{Delay: func(int) time.Duration { return jitter }}

	src := netip.MustParseAddr("10.8.0.2")
	dst := netip.MustParseAddr("1.1.1.1")
	begin := time.Now()
	const n = 5
	for i := 0; i < n; i++ {
		if err := c.WritePacket(buildIPv4(src, dst, 17, []byte("x"))); err != nil {
			t.Fatal(err)
		}
	}
	queued := time.Since(begin)
	if queued > jitter {
		t.Fatalf("насос ждал %v — джиттер блокирует запись пакетов", queued)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		at, _ := r.snapshot()
		if len(at) >= 1 {
			if at[0].Sub(begin) < jitter/2 {
				t.Fatalf("первая датаграмма ушла через %v — джиттера нет", at[0].Sub(begin))
			}
			t.Logf("постановка в очередь %v, первая датаграмма через %v",
				queued.Round(time.Millisecond), at[0].Sub(begin).Round(time.Millisecond))
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("датаграммы не ушли вовсе")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
