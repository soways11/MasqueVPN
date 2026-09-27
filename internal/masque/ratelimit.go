package masque

import (
	"context"
	"sync"
	"time"
)

// Лимит полосы на сессию (пункт C6 плана).
//
// Зачем: сессия без потолка — это и способ выесть канал сервера одним
// клиентом, и заметная аномалия. У обычного приложения скорость упирается
// в его собственную логику, а не в физику канала.
//
// Реализация — «дырявое ведро»: токены капают с постоянной скоростью,
// накопить можно не больше burst. Отправитель ждёт, а не отбрасывает:
// отброс на этом уровне TCP внутри туннеля переживает хуже, чем задержку.
type rateLimiter struct {
	mu     sync.Mutex
	rate   float64 // байт в секунду
	burst  float64
	tokens float64
	last   time.Time
	now    func() time.Time
}

// newRateLimiter создаёт лимитер; rate <= 0 — без ограничения (nil).
func newRateLimiter(rate int, burst int) *rateLimiter {
	if rate <= 0 {
		return nil
	}
	if burst <= 0 {
		burst = rate / 4
	}
	if burst < 1500 {
		burst = 1500 // хотя бы один полный пакет
	}
	return &rateLimiter{
		rate: float64(rate), burst: float64(burst),
		tokens: float64(burst), last: time.Now(), now: time.Now,
	}
}

// wait ждёт, пока на отправку n байт наберётся право. nil-лимитер не ждёт.
func (l *rateLimiter) wait(ctx context.Context, n int) {
	if l == nil {
		return
	}
	for {
		d := l.reserve(n)
		if d <= 0 {
			return
		}
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// reserve пытается списать n байт; возвращает, сколько ждать до следующей
// попытки (0 — списано).
func (l *rateLimiter) reserve(n int) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if el := now.Sub(l.last).Seconds(); el > 0 {
		l.tokens += el * l.rate
		if l.tokens > l.burst {
			l.tokens = l.burst
		}
		l.last = now
	}
	need := float64(n)
	if need > l.burst {
		need = l.burst // пакет крупнее ведра не должен вставать намертво
	}
	if l.tokens >= need {
		l.tokens -= need
		return 0
	}
	return time.Duration((need - l.tokens) / l.rate * float64(time.Second))
}
