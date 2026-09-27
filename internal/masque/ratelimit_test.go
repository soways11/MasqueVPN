package masque

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func netipAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

// TestRateLimiterShapesRate — лимитер выдаёт ровно заданную полосу:
// накопленный запас тратится сразу, дальше — по расписанию.
func TestRateLimiterShapesRate(t *testing.T) {
	l := newRateLimiter(100_000, 10_000) // 100 КБ/с, запас 10 КБ
	now := time.Now()
	l.now = func() time.Time { return now }
	l.last = now

	// Запас тратится без ожидания.
	if d := l.reserve(10_000); d != 0 {
		t.Fatalf("запас не отдан сразу: %v", d)
	}
	// Дальше — ожидание, пропорциональное объёму.
	d := l.reserve(10_000)
	if d < 90*time.Millisecond || d > 110*time.Millisecond {
		t.Fatalf("ожидание %v, при 100 КБ/с ожидалось около 100 мс", d)
	}
	// Через полсекунды накопится ведро целиком, но не больше.
	now = now.Add(time.Second)
	if d := l.reserve(10_000); d != 0 {
		t.Fatalf("после паузы запас не восстановлен: %v", d)
	}
	if d := l.reserve(10_000); d == 0 {
		t.Fatal("ведро накопило больше своего объёма")
	}

	// Без ограничения лимитер не создаётся и ничего не ждёт.
	var nilLimiter *rateLimiter
	nilLimiter.wait(context.Background(), 1<<20)
	if newRateLimiter(0, 0) != nil {
		t.Fatal("нулевая скорость должна означать «без ограничения»")
	}
}

// TestRateLimitedSessionIsSlower — сессия с потолком полосы действительно
// отдаёт не больше заданного.
func TestRateLimitedSessionIsSlower(t *testing.T) {
	const rate = 200 << 10 // 200 КБ/с
	r := newRecorder()
	c := connOver(t, r, &Packing{})
	c.limiter = newRateLimiter(rate, 16<<10)

	pkt := buildIPv4(netipAddr("10.8.0.2"), netipAddr("1.1.1.1"), 6, make([]byte, 1200))
	begin := time.Now()
	const n = 300 // ≈360 КБ — при 200 КБ/с это около 1,8 с
	for i := 0; i < n; i++ {
		c.WritePacket(pkt)
	}
	deadline := time.Now().Add(10 * time.Second)
	for c.Stats().PacketsOut < n && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	took := time.Since(begin)
	if c.Stats().PacketsOut < n {
		t.Fatalf("ушло %d пакетов из %d за %v", c.Stats().PacketsOut, n, took)
	}
	sent := float64(n * 1220)
	got := sent / took.Seconds()
	t.Logf("%0.f КБ ушли за %v — %.0f КБ/с при потолке %d КБ/с", sent/1024, took.Round(time.Millisecond), got/1024, rate>>10)
	if got > rate*13/10 {
		t.Fatalf("фактическая полоса %.0f Б/с выше потолка %d Б/с", got, rate)
	}
}
