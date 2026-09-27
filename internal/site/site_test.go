package site

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

func newTestSite(t *testing.T, o Options) *Site {
	t.Helper()
	if o.Built.IsZero() {
		o.Built = time.Date(2026, 3, 4, 10, 0, 0, 0, time.UTC)
	}
	s, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func get(t *testing.T, s *Site, method, path string, hdr http.Header) *http.Response {
	t.Helper()
	r := httptest.NewRequest(method, path, nil)
	for k, v := range hdr {
		r.Header[k] = v
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w.Result()
}

func bodyOf(t *testing.T, rsp *http.Response) []byte {
	t.Helper()
	b, err := io.ReadAll(rsp.Body)
	if err != nil {
		t.Fatal(err)
	}
	rsp.Body.Close()
	return b
}

var linkRe = regexp.MustCompile(`(?:href|src)="([^"]+)"`)

// TestSiteHasNoDeadLinks — главная проверка правдоподобия: по сайту можно
// ходить. Домен, где половина ссылок ведёт в 404, а favicon отсутствует,
// выглядит брошенным — а именно этого мы и избегаем.
func TestSiteHasNoDeadLinks(t *testing.T) {
	s := newTestSite(t, Options{Host: "nimbus-lab.io"})

	seen := map[string]bool{}
	queue := []string{"/"}
	pages := 0
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		if seen[p] {
			continue
		}
		seen[p] = true

		rsp := get(t, s, http.MethodGet, p, nil)
		body := bodyOf(t, rsp)
		if rsp.StatusCode != http.StatusOK {
			t.Errorf("%s: статус %d", p, rsp.StatusCode)
			continue
		}
		if rsp.Header.Get("Content-Type") == "" ||
			(p != statusPath && rsp.Header.Get("ETag") == "") {
			t.Errorf("%s: заголовки %v", p, rsp.Header)
		}
		if !strings.HasPrefix(rsp.Header.Get("Content-Type"), "text/html") {
			continue
		}
		pages++
		for _, m := range linkRe.FindAllSubmatch(body, -1) {
			link := string(m[1])
			if strings.HasPrefix(link, "/") {
				queue = append(queue, link)
			}
		}
	}
	if pages < 3 {
		t.Fatalf("страниц всего %d — на сайт из одной страницы это не похоже", pages)
	}
	// robots.txt на страницы не выносят — его проверяем отдельно, ниже.
	for _, must := range []string{"/", "/docs", "/status", "/favicon.ico", statusPath} {
		if !seen[must] {
			t.Errorf("%s не встретился при обходе", must)
		}
	}
	// robots.txt обещает карту сайта — она должна быть.
	robots := string(bodyOf(t, get(t, s, http.MethodGet, "/robots.txt", nil)))
	if !strings.Contains(robots, "nimbus-lab.io/sitemap.xml") {
		t.Fatalf("robots.txt: %q", robots)
	}
	if rsp := get(t, s, http.MethodGet, "/sitemap.xml", nil); rsp.StatusCode != http.StatusOK {
		t.Fatalf("sitemap.xml: статус %d", rsp.StatusCode)
	}
	if ico := bodyOf(t, get(t, s, http.MethodGet, "/favicon.ico", nil)); len(ico) < 100 ||
		!bytes.HasPrefix(ico, []byte{0, 0, 1, 0}) {
		t.Fatalf("favicon.ico длиной %d не похож на ICO", len(ico))
	}
}

// TestSiteMethodsAndErrors — сайт ведёт себя как сервер, а не как раздача
// файлов: на неизвестный путь у него своя страница, а на метод, которого он
// не знает, — 405 с Allow, а не 200 и страница.
func TestSiteMethodsAndErrors(t *testing.T) {
	s := newTestSite(t, Options{Host: "nimbus-lab.io"})

	rsp := get(t, s, http.MethodGet, "/no-such-page", nil)
	body := bodyOf(t, rsp)
	if rsp.StatusCode != http.StatusNotFound || !bytes.Contains(body, []byte("404")) {
		t.Fatalf("404: статус %d, тело %q", rsp.StatusCode, body)
	}

	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodConnect} {
		rsp := get(t, s, m, "/", nil)
		bodyOf(t, rsp)
		if rsp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s: статус %d — на этот метод сервер документ не отдаёт", m, rsp.StatusCode)
		}
		if allow := rsp.Header.Get("Allow"); allow == "" || strings.Contains(allow, "CONNECT") {
			t.Errorf("%s: Allow %q", m, allow)
		}
	}

	rsp = get(t, s, http.MethodOptions, "/", nil)
	bodyOf(t, rsp)
	if rsp.StatusCode != http.StatusNoContent || rsp.Header.Get("Allow") == "" {
		t.Fatalf("OPTIONS: статус %d, Allow %q", rsp.StatusCode, rsp.Header.Get("Allow"))
	}

	// HEAD — те же заголовки, но без тела.
	head := get(t, s, http.MethodHead, "/", nil)
	if b := bodyOf(t, head); len(b) != 0 {
		t.Fatalf("HEAD вернул %d байт тела", len(b))
	}
	if head.Header.Get("Content-Length") == "0" {
		t.Fatal("HEAD не сообщил длину документа")
	}
}

// TestSiteCachingAndCompression — повторный заход даёт 304, а браузеру
// предлагается gzip. Сервер, который этого не делает, сам по себе редкость.
func TestSiteCachingAndCompression(t *testing.T) {
	s := newTestSite(t, Options{Host: "nimbus-lab.io"})

	first := get(t, s, http.MethodGet, "/", nil)
	plain := bodyOf(t, first)
	etag := first.Header.Get("ETag")
	if etag == "" || first.Header.Get("Last-Modified") == "" {
		t.Fatal("нет ETag/Last-Modified")
	}

	again := get(t, s, http.MethodGet, "/", http.Header{"If-None-Match": {etag}})
	bodyOf(t, again)
	if again.StatusCode != http.StatusNotModified {
		t.Fatalf("If-None-Match: статус %d", again.StatusCode)
	}
	again = get(t, s, http.MethodGet, "/", http.Header{"If-Modified-Since": {first.Header.Get("Last-Modified")}})
	bodyOf(t, again)
	if again.StatusCode != http.StatusNotModified {
		t.Fatalf("If-Modified-Since: статус %d", again.StatusCode)
	}

	gz := get(t, s, http.MethodGet, "/", http.Header{"Accept-Encoding": {"gzip, deflate"}})
	packed := bodyOf(t, gz)
	if gz.Header.Get("Content-Encoding") != "gzip" || gz.Header.Get("Vary") != "Accept-Encoding" {
		t.Fatalf("gzip не предложен: %v", gz.Header)
	}
	if len(packed) >= len(plain) {
		t.Fatalf("сжатая страница не короче: %d ≥ %d", len(packed), len(plain))
	}
	zr, err := gzip.NewReader(bytes.NewReader(packed))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(zr)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("распаковка: err=%v, совпадает=%v", err, bytes.Equal(got, plain))
	}
	// Ассеты с хэшем в имени кэшируются навсегда, страницы — нет.
	asset := linkRe.FindStringSubmatch(string(plain))
	if asset == nil {
		t.Fatal("на странице нет ассетов")
	}
	css := regexp.MustCompile(`/assets/[^"]+\.css`).FindString(string(plain))
	if css == "" {
		t.Fatal("нет ссылки на css")
	}
	rsp := get(t, s, http.MethodGet, css, nil)
	bodyOf(t, rsp)
	if !strings.Contains(rsp.Header.Get("Cache-Control"), "immutable") {
		t.Fatalf("ассет %s: Cache-Control %q", css, rsp.Header.Get("Cache-Control"))
	}
	if strings.Contains(first.Header.Get("Cache-Control"), "immutable") {
		t.Fatal("страница объявлена неизменяемой — обновить сайт будет нельзя")
	}
}

// TestStatusFeedIsLive — страница статуса опрашивает /api/status.json, и он
// должен отвечать живыми данными, а не кэшем.
func TestStatusFeedIsLive(t *testing.T) {
	now := time.Date(2026, 3, 4, 10, 0, 0, 0, time.UTC)
	s := newTestSite(t, Options{Host: "nimbus-lab.io", Now: func() time.Time { return now }})

	rsp := get(t, s, http.MethodGet, "/api/status.json", nil)
	body := bodyOf(t, rsp)
	if rsp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control %q", rsp.Header.Get("Cache-Control"))
	}
	var doc statusDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("%v: %s", err, body)
	}
	if doc.Status == "" || len(doc.Components) == 0 {
		t.Fatalf("сводка пуста: %+v", doc)
	}
	if ts, err := time.Parse(time.RFC3339, doc.Updated); err != nil || !ts.Equal(now) {
		t.Fatalf("updated=%q err=%v", doc.Updated, err)
	}
	for _, c := range doc.Components {
		if c.LatencyMS <= 0 || c.LatencyMS > 500 {
			t.Fatalf("задержка %d мс у %s неправдоподобна", c.LatencyMS, c.Name)
		}
	}
	// Через время значения меняются: статика в «живой» сводке видна сразу.
	now = now.Add(time.Minute)
	var doc2 statusDoc
	if err := json.Unmarshal(bodyOf(t, get(t, s, http.MethodGet, "/api/status.json", nil)), &doc2); err != nil {
		t.Fatal(err)
	}
	if doc2.Updated == doc.Updated {
		t.Fatal("время в сводке не идёт")
	}
}

// TestSiteDiffersPerDomain — содержимое не должно быть байт в байт одинаковым
// у всех, кто собрал masquevpn: одинаковая страница у тысячи серверов — это и есть
// признак сборки, ради ухода от которого сайт и заведён.
func TestSiteDiffersPerDomain(t *testing.T) {
	a := bodyOf(t, get(t, newTestSite(t, Options{Host: "nimbus-lab.io"}), http.MethodGet, "/", nil))
	b := bodyOf(t, get(t, newTestSite(t, Options{Host: "harbor-metrics.net"}), http.MethodGet, "/", nil))
	if bytes.Equal(a, b) {
		t.Fatal("страницы двух разных доменов совпадают побайтно")
	}
	if !bytes.Contains(a, []byte("Nimbus Lab")) {
		t.Fatalf("название не выведено из домена: %s", firstLines(a))
	}
	if !bytes.Contains(b, []byte("Harbor Metrics")) {
		t.Fatalf("название не выведено из домена: %s", firstLines(b))
	}
	// Оформление тоже разное: акцент и имена ассетов зависят от домена.
	cssA := regexp.MustCompile(`/assets/[^"]+\.css`).FindString(string(a))
	cssB := regexp.MustCompile(`/assets/[^"]+\.css`).FindString(string(b))
	if cssA == cssB {
		t.Fatalf("ассеты названы одинаково: %s", cssA)
	}
}

func firstLines(b []byte) string {
	if len(b) > 300 {
		b = b[:300]
	}
	return string(b)
}

func TestTitleFromHost(t *testing.T) {
	for host, want := range map[string]string{
		"nimbus-lab.io":       "Nimbus Lab",
		"api.harbor.net":      "Harbor",
		"www.quiet-river.org": "Quiet River",
		"cdn.example.co.uk":   "Example",
		"vpn.example.test":    "Example",
		"localhost":           "Localhost",
		"":                    "Service",
	} {
		if got := titleFromHost(host); got != want {
			t.Errorf("%s → %q, ожидалось %q", host, got, want)
		}
	}
}
