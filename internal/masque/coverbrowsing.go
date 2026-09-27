package masque

import (
	"context"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// Прикрытие потоками (пункт 5 плана обхода DPI).
//
// Проблема: наша сессия открывает РОВНО ОДИН поток, который живёт часами, и весь
// объём гонит датаграммами. Браузер так себя не ведёт никогда — он открывает
// десятки потоков, качает ресурсы и закрывает соединение. Даже с идеальным
// отпечатком рукопожатия это видно классификатору, который смотрит на поведение.
//
// Решение: по тому же QUIC-соединению фоном выполнять обычные HTTP/3 GET-запросы
// к сайту-прикрытию (его отдаёт ServerConfig.Fallback). Каждый запрос — отдельный
// поток с настоящим содержимым. Снаружи это выглядит как приложение, которое и
// подгружает ресурсы, и гоняет датаграммы, — то есть как WebTransport-приложение,
// а не как туннель.
//
// Интервалы намеренно случайные: фиксированный период сам по себе был бы
// признаком (см. cover-трафик в obfuscation).

// CoverBrowsing настраивает фоновые запросы к сайту-прикрытию.
type CoverBrowsing struct {
	// Paths — пути, которые запрашиваются (выбирается случайный).
	// Пустой список — только "/".
	Paths []string
	// Next возвращает паузу до следующего запроса. nil — случайная пауза 5–30 с.
	Next func() time.Duration
	// MaxBodyBytes — сколько байт тела дочитывать (остальное отбрасывается).
	// 0 — 64 КиБ.
	MaxBodyBytes int64
}

func (cb *CoverBrowsing) paths() []string {
	if len(cb.Paths) == 0 {
		return []string{"/"}
	}
	return cb.Paths
}

func (cb *CoverBrowsing) next() time.Duration {
	if cb.Next != nil {
		return cb.Next()
	}
	return 5*time.Second + time.Duration(rand.Int64N(int64(25*time.Second)))
}

func (cb *CoverBrowsing) maxBody() int64 {
	if cb.MaxBodyBytes > 0 {
		return cb.MaxBodyBytes
	}
	return 64 << 10
}

// coverRequester умеет выполнить HTTP-запрос по уже установленному соединению.
// Реализуется *http3.ClientConn; вынесено в интерфейс ради тестов.
type coverRequester interface {
	RoundTrip(*http.Request) (*http.Response, error)
}

// startCoverBrowsing запускает фоновые запросы, пока жива сессия c.
func startCoverBrowsing(c *Conn, rt coverRequester, authority string, cb *CoverBrowsing) {
	go func() {
		paths := cb.paths()
		for {
			select {
			case <-c.ctx.Done():
				return
			case <-time.After(cb.next()):
			}
			p := paths[rand.IntN(len(paths))]
			if doCoverRequest(c.ctx, rt, authority, p, cb.maxBody()) == nil {
				c.coverReqs.Add(1)
			}
		}
	}()
}

func doCoverRequest(ctx context.Context, rt coverRequester, authority, path string, maxBody int64) error {
	u, err := url.Parse("https://" + authority + path)
	if err != nil {
		return err
	}
	req := (&http.Request{
		Method: http.MethodGet,
		URL:    u,
		Host:   authority,
		Header: http.Header{},
	}).WithContext(ctx)

	rsp, err := rt.RoundTrip(req)
	if err != nil {
		return err
	}
	defer rsp.Body.Close()
	// Тело действительно вычитываем: иначе поток закроется раньше времени и
	// по объёму будет видно, что содержимое никому не нужно.
	_, _ = io.Copy(io.Discard, io.LimitReader(rsp.Body, maxBody))
	return nil
}

// CountCoverRequest отмечает выполненный фоновый запрос. Нужен транспортам,
// которые выполняют прикрытие сами (см. internal/utlsquic).
func (c *Conn) CountCoverRequest() { c.coverReqs.Add(1) }

// CoverRequests возвращает число выполненных фоновых запросов прикрытия.
func (c *Conn) CoverRequests() uint64 { return c.coverReqs.Load() }

var _ = (*http3.ClientConn)(nil) // документирует, кто реализует coverRequester
