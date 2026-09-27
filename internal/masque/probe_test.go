package masque

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// probeReply — ровно то, что видит посторонний, постучавшийся в сервер.
type probeReply struct {
	status int
	header http.Header
	body   []byte
}

// probe отправляет один запрос и читает ответ целиком.
// proto: "" — обычный (не Extended) запрос, иначе значение :protocol.
func probe(t *testing.T, e *testEnv, method, proto, path string, hdr http.Header) probeReply {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tlsConf := e.client.Clone()
	tlsConf.NextProtos = []string{http3.NextProtoH3}
	qc, err := quic.DialAddr(ctx, e.addr, tlsConf, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatalf("QUIC: %v", err)
	}
	defer qc.CloseWithError(0, "")

	tr := &http3.Transport{EnableDatagrams: true, AdditionalSettings: WebTransportSettings()}
	defer tr.Close()
	cc := tr.NewClientConn(qc)
	select {
	case <-cc.ReceivedSettings():
	case <-ctx.Done():
		t.Fatal("сервер не прислал SETTINGS")
	}
	rstr, err := cc.OpenRequestStream(ctx)
	if err != nil {
		t.Fatalf("поток: %v", err)
	}
	u := &url.URL{Scheme: "https", Host: "localhost", Path: path}
	req := (&http.Request{
		Method: method,
		// "HTTP/1.1" — признак обычного запроса: quic-go шлёт :protocol,
		// только если Proto задан и отличается от него.
		Proto:  "HTTP/1.1",
		Host:   "localhost",
		URL:    u,
		Header: hdr,
	}).WithContext(ctx)
	if proto != "" {
		req.Proto = proto
	}
	if err := rstr.SendRequestHeader(req); err != nil {
		t.Fatalf("запрос: %v", err)
	}
	rsp, err := rstr.ReadResponse()
	if err != nil {
		t.Fatalf("ответ: %v", err)
	}
	body, _ := io.ReadAll(io.LimitReader(rsp.Body, 1<<16))
	rsp.Body.Close()
	return probeReply{status: rsp.StatusCode, header: rsp.Header, body: body}
}

// TestProbeGetsServerLikeAnswers — активное зондирование не должно отличать
// нас от обычного сервера.
//
// Сломано было вот что: всё нераспознанное уходило в Fallback, а сайт (тот же
// http.FileServer) на метод не смотрит и отдаёт 200 и тело страницы. Пробер
// слал Extended CONNECT с мусорным токеном и получал 200 и HTML — ответ,
// которого от CONNECT не даёт ни один нормальный сервер.
func TestProbeGetsServerLikeAnswers(t *testing.T) {
	const marker = "главная страница сайта"
	env := startServerWT(t, ServerConfig{
		Authorize: func(r *http.Request) bool { return r.Header.Get("Authorization") == "Bearer good" },
		Fallback: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			// Как http.FileServer: метод не проверяется вовсе.
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = io.WriteString(w, "<html><body>"+marker+"</body></html>")
		}),
	})
	good := http.Header{"Authorization": {"Bearer good"}}
	bad := http.Header{"Authorization": {"Bearer bad"}}

	// Обычный веб-запрос по-прежнему получает сайт — иначе домен выглядит
	// пустым, и всё прикрытие теряет смысл.
	if got := probe(t, env, http.MethodGet, "", "/", nil); got.status != http.StatusOK ||
		!bytes.Contains(got.body, []byte(marker)) {
		t.Fatalf("GET: статус %d, тело %q", got.status, got.body)
	}

	cases := []struct {
		name, method, proto, path string
		hdr                       http.Header
		want                      int
	}{
		// Мы origin-сервер, а не прокси.
		{"классический CONNECT", http.MethodConnect, "", "", nil, http.StatusMethodNotAllowed},
		// :protocol, которого сервер не поддерживает (RFC 8441, §5.1).
		{"чужой :protocol", http.MethodConnect, "connect-udp", DefaultPath, good, http.StatusNotImplemented},
		// Для приложения с WebTransport путь — обычный маршрут.
		{"чужой маршрут", http.MethodConnect, ProtocolWebTransport, "/live/v1/", good, http.StatusNotFound},
		{"чужой токен", http.MethodConnect, ProtocolWebTransport, DefaultPath, bad, http.StatusNotFound},
		{"без токена", http.MethodConnect, ProtocolWebTransport, DefaultPath, nil, http.StatusNotFound},
		{"connect-ip без токена", http.MethodConnect, ProtocolConnectIP, DefaultPath, bad, http.StatusNotFound},
	}
	replies := map[string]probeReply{}
	for _, c := range cases {
		got := probe(t, env, c.method, c.proto, c.path, c.hdr)
		replies[c.name] = got
		if got.status != c.want {
			t.Errorf("%s: статус %d, ожидался %d", c.name, got.status, c.want)
		}
		if bytes.Contains(got.body, []byte(marker)) {
			t.Errorf("%s: в ответе тело сайта — обычный сервер на CONNECT документ не отдаёт", c.name)
		}
		if len(got.body) > 256 {
			t.Errorf("%s: тело %d байт — страница ошибки на CONNECT сама по себе странность", c.name, len(got.body))
		}
	}

	// Ни один ответ не сообщает, что сервер вообще умеет CONNECT.
	if allow := replies["классический CONNECT"].header.Get("Allow"); allow == "" ||
		strings.Contains(strings.ToUpper(allow), "CONNECT") {
		t.Errorf("Allow: %q", allow)
	}

	// Главное: по ответу нельзя узнать, есть ли у сервера туннельный путь.
	a, b := replies["чужой маршрут"], replies["чужой токен"]
	if a.status != b.status || !bytes.Equal(a.body, b.body) ||
		a.header.Get("Content-Type") != b.header.Get("Content-Type") {
		t.Fatalf("чужой маршрут и чужой токен различимы:\n%+v\n%+v", a, b)
	}

	// И при всём этом свой клиент проходит.
	c, err := env.dial(t, func(cfg *ClientConfig) {
		cfg.Protocol = ProtocolWebTransport
		cfg.Header = good
	})
	if err != nil {
		t.Fatalf("свой клиент не прошёл: %v", err)
	}
	c.Close()
}
