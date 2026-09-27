package masque

import (
	"bytes"
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/soways11/masquevpn/internal/fingerprint"
)

// Профиль, снятый с живого сервера, скупее нашей эвристики — и в одном месте
// опасно скупее: cloudflare-quic.com объявляет ВСЕГО ТРИ однонаправленных
// потока (у нашей эвристики их 103). HTTP/3 тратит ровно три: управляющий
// поток и два потока QPACK. Запас нулевой, и если клиент захочет четвёртый,
// сессия не поднимется вовсе.
//
// Проверять это рассуждением нельзя — только сессией на настоящем QUIC.
func capturedCloudflareProfile() fingerprint.ServerProfile {
	return fingerprint.ServerProfile{
		Source:               "cloudflare-quic.com:443 (снято 24.09.2026)",
		MaxIdleTimeoutMS:     180_000,
		InitialMaxData:       10 * 1024 * 1024,
		InitialMaxStreamData: 1024 * 1024,
		MaxBidiStreams:       100,
		MaxUniStreams:        3,
		InitialPacketSize:    fingerprint.DefaultInitialPacketSize,
		ConnectionIDLength:   fingerprint.DefaultConnectionIDLength,
	}
}

// TestCapturedProfileServesSession — сессия CONNECT-IP живёт под снятым с
// Cloudflare профилем, включая лимит в три однонаправленных потока.
func TestCapturedProfileServesSession(t *testing.T) {
	p := capturedCloudflareProfile()
	env := startServer(t, ServerConfig{OnSession: echoSession}, WithQUICConfig(p.QUICConfig()))
	c := mustDial(t, env)
	defer c.Close()

	src := c.AssignedPrefixes()[0].Addr()
	dst := netip.MustParseAddr("1.1.1.1")

	buf := make([]byte, 2000)
	for i, sz := range []int{0, 64, 512, 1150} {
		payload := bytes.Repeat([]byte{byte(i)}, sz)
		if err := c.WritePacket(buildIPv4(src, dst, 17, payload)); err != nil {
			t.Fatalf("размер %d: %v", sz, err)
		}
		n, err := readWithTimeout(c, buf, 5*time.Second)
		if err != nil {
			t.Fatalf("размер %d: эхо не вернулось: %v", sz, err)
		}
		if n != 20+sz {
			t.Fatalf("размер %d: вернулось %d байт", sz, n)
		}
	}
	t.Logf("сессия работает при initial_max_streams_uni=%d", p.MaxUniStreams)
}

// TestCapturedProfileAnnouncesDatagrams — под снятым профилем сервер всё ещё
// объявляет датаграммы и заявленные окна.
//
// Ни Cloudflare, ни Google датаграмм не объявляют, поэтому из снятого файла
// этот параметр прийти не может; включается он нами и всегда. Если это
// когда-нибудь перестанет быть так, туннель просто не заработает — тест
// скажет об этом здесь, а не на боевом сервере.
func TestCapturedProfileAnnouncesDatagrams(t *testing.T) {
	p := capturedCloudflareProfile()
	env := startServer(t, ServerConfig{}, WithQUICConfig(p.QUICConfig()))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, err := fingerprint.CaptureParams(ctx, env.addr, "localhost", true)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("сервер объявляет: %+v", got)

	if got.MaxDatagramFrameSize == 0 {
		t.Fatal("датаграммы не объявлены — CONNECT-IP не заработает")
	}
	if got.MaxIdleTimeout != 180*time.Second {
		t.Errorf("время простоя %v, в профиле 180 с", got.MaxIdleTimeout)
	}
	if got.InitialMaxData != p.InitialMaxData {
		t.Errorf("initial_max_data %d, в профиле %d", got.InitialMaxData, p.InitialMaxData)
	}
	if got.MaxUniStreams != p.MaxUniStreams {
		t.Errorf("initial_max_streams_uni %d, в профиле %d", got.MaxUniStreams, p.MaxUniStreams)
	}

	// И отличие от эвристики должно быть видно: иначе подстановка снятого
	// профиля ничего не меняет.
	h := fingerprint.CDNLike()
	if got.MaxIdleTimeout == time.Duration(h.MaxIdleTimeoutMS)*time.Millisecond &&
		got.InitialMaxData == h.InitialMaxData {
		t.Fatal("параметры совпали с эвристикой — снятый профиль не применился")
	}
}
