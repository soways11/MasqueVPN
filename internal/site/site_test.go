package site

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
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
// выглядит брошенным — а именно этого мы и избегаем. Проверяется каждая
// легенда и каждое место раздела о статусе в документации.
func TestSiteHasNoDeadLinks(t *testing.T) {
	for i := range legends {
		for pos := 0; pos <= len(legends[i].docs); pos++ {
			v := variantFor(fmt.Sprintf("seed-%d-%d", i, pos))
			v.legend = &legends[i]
			v.healthPos = pos
			s, err := build(Options{Host: "quiet-river.io", Built: time.Date(2026, 3, 4, 10, 0, 0, 0, time.UTC)}, v)
			if err != nil {
				t.Fatal(err)
			}
			t.Run(fmt.Sprintf("legend%d/health%d", i, pos), func(t *testing.T) {
				checkNoDeadLinks(t, s, v)
			})
		}
	}
}

// TestLegendsExplainProtocol — сайт рассказывает то же, что видно в
// протоколе (см. legends.go). SETTINGS объявляют WebTransport — значит,
// каждая легенда о сервисе, которому он нужен, и документация говорит, как
// открыть сессию, какие у неё датаграммы и какие UDP-порты отвечают. Без
// этого теста новая легенда про, скажем, хостинг блогов прошла бы все
// остальные проверки — и противоречила бы SETTINGS того же домена.
func TestLegendsExplainProtocol(t *testing.T) {
	ports := []int{443, 8443, 2053, 2083}
	for i := range legends {
		lg := &legends[i]
		t.Run(fmt.Sprintf("legend%d", i), func(t *testing.T) {
			v := variantFor(fmt.Sprintf("seed-%d", i))
			v.legend = lg
			s, err := build(Options{Host: "quiet-river.io", UDPPorts: ports}, v)
			if err != nil {
				t.Fatal(err)
			}
			home := string(bodyOf(t, get(t, s, http.MethodGet, "/", nil)))
			docs := string(bodyOf(t, get(t, s, http.MethodGet, v.docsPath, nil)))

			// Главная сама говорит, на чём сервис работает: до документации
			// доходит не всякий.
			if !strings.Contains(home, "WebTransport") {
				t.Error("на главной ни слова о WebTransport, а SETTINGS его объявляют")
			}
			for _, must := range []string{
				"new WebTransport(",           // как открыть сессию
				"datagrams",                   // что идёт датаграммами
				"<code>404</code>",            // что ответит незнакомый адрес сессии
				"UDP port 443",                // основной порт
				"8443, 2053 and 2083",         // запасные — ровно те, что отвечают
				"keepalive",                   // почему соединение живёт часами
				"refresh their configuration", // фоновые GET по тому же соединению
				`id="wt-support"`,
			} {
				if !strings.Contains(docs, must) {
					t.Errorf("в документации нет %q", must)
				}
			}
			// Пример адреса сессии — из легенды, не путь туннеля.
			if strings.Contains(docs, ".well-known") || strings.Contains(docs, "masque") {
				t.Error("документация показывает путь туннеля")
			}
			// И на этот адрес сайт по GET отвечает своим 404, а не страницей.
			if rsp := get(t, s, http.MethodGet, lg.wtPath+"x", nil); rsp.StatusCode != http.StatusNotFound {
				t.Errorf("GET %sx: %d", lg.wtPath, rsp.StatusCode)
			}
			if lg.session == "" || lg.media == "" || !strings.HasPrefix(lg.wtPath, "/") || !strings.HasSuffix(lg.wtPath, "/") {
				t.Errorf("легенда без сессии, медиа или пути: %+v", lg)
			}
		})
	}
}

// TestSiteWithoutWebTransport — сервер с webtransport=false WebTransport не
// объявляет, и сайт его не обещает: ни в описании, ни в карточках, ни в
// примере. Один порт — и документация не выдумывает запасных.
func TestSiteWithoutWebTransport(t *testing.T) {
	for i := range legends {
		v := variantFor(fmt.Sprintf("seed-%d", i))
		v.legend = &legends[i]
		s, err := build(Options{Host: "quiet-river.io", NoWebTransport: true, UDPPorts: []int{8443}}, v)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range []string{"/", v.docsPath} {
			body := string(bodyOf(t, get(t, s, http.MethodGet, p, nil)))
			if strings.Contains(body, "WebTransport") {
				t.Errorf("legend%d %s: обещан WebTransport, которого нет в SETTINGS", i, p)
			}
		}
		docs := string(bodyOf(t, get(t, s, http.MethodGet, v.docsPath, nil)))
		for _, must := range []string{"Extended CONNECT", "UDP port 8443", "no TCP fallback"} {
			if !strings.Contains(docs, must) {
				t.Errorf("legend%d: в документации нет %q", i, must)
			}
		}
		if strings.Contains(docs, "alternate ports") {
			t.Errorf("legend%d: запасные порты при одном порте", i)
		}
		// Исходная легенда не испорчена заменой.
		if !strings.Contains(legends[i].tagline+legends[i].cards[0][1]+legends[i].cards[1][1]+legends[i].cards[2][1], "WebTransport") {
			t.Fatalf("legend%d: замена задела общий массив легенд", i)
		}
	}
}

func checkNoDeadLinks(t *testing.T, s *Site, v variant) {
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
			(p != s.FeedPath() && rsp.Header.Get("ETag") == "") {
			t.Errorf("%s: заголовки %v", p, rsp.Header)
		}
		if strings.HasSuffix(p, ".js") && !bytes.Contains(body, []byte(`"`+s.FeedPath()+`"`)) {
			t.Errorf("скрипт опрашивает не тот фид: %s", body)
		}
		if !strings.HasPrefix(rsp.Header.Get("Content-Type"), "text/html") {
			continue
		}
		if bytes.Contains(body, []byte("{{")) || bytes.Contains(body, []byte("$")) {
			t.Errorf("%s: неподставленный шаблон", p)
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
	for _, must := range []string{"/", v.docsPath, "/status", "/favicon.ico", v.feedPath} {
		if !seen[must] {
			t.Errorf("%s не встретился при обходе", must)
		}
	}
	// robots.txt обещает карту сайта — она должна быть, и в ней — реальные страницы.
	robots := string(bodyOf(t, get(t, s, http.MethodGet, "/robots.txt", nil)))
	if !strings.Contains(robots, "quiet-river.io/sitemap.xml") {
		t.Fatalf("robots.txt: %q", robots)
	}
	sm := get(t, s, http.MethodGet, "/sitemap.xml", nil)
	if sb := bodyOf(t, sm); sm.StatusCode != http.StatusOK || !bytes.Contains(sb, []byte(v.docsPath+"</loc>")) {
		t.Fatalf("sitemap.xml: статус %d, %s", sm.StatusCode, sb)
	}
	if ico := bodyOf(t, get(t, s, http.MethodGet, "/favicon.ico", nil)); len(ico) < 100 ||
		!bytes.HasPrefix(ico, []byte{0, 0, 1, 0}) {
		t.Fatalf("favicon.ico длиной %d не похож на ICO", len(ico))
	}
	// Страница статуса показывает те компоненты, о которых говорит легенда.
	var doc statusDoc
	if err := json.Unmarshal(bodyOf(t, get(t, s, http.MethodGet, v.feedPath, nil)), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Components) != 3 || doc.Components[0].Name != v.legend.components[0] {
		t.Fatalf("компоненты %+v, легенда %v", doc.Components, v.legend.components)
	}
}

// TestSiteMethodsAndErrors — сайт ведёт себя как сервер, а не как раздача
// файлов: на неизвестный путь у него своя страница, а на метод, которого он
// не знает, — 405 с Allow, а не 200 и страница.
func TestSiteMethodsAndErrors(t *testing.T) {
	s := newTestSite(t, Options{Host: "quiet-river.io"})

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
	s := newTestSite(t, Options{Host: "quiet-river.io"})

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
	s := newTestSite(t, Options{Host: "quiet-river.io", Now: func() time.Time { return now }})

	rsp := get(t, s, http.MethodGet, s.FeedPath(), nil)
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
	if err := json.Unmarshal(bodyOf(t, get(t, s, http.MethodGet, s.FeedPath(), nil)), &doc2); err != nil {
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
	a := bodyOf(t, get(t, newTestSite(t, Options{Host: "quiet-river.io"}), http.MethodGet, "/", nil))
	b := bodyOf(t, get(t, newTestSite(t, Options{Host: "harbor-metrics.net"}), http.MethodGet, "/", nil))
	if bytes.Equal(a, b) {
		t.Fatal("страницы двух разных доменов совпадают побайтно")
	}
	if !bytes.Contains(a, []byte("Quiet River")) {
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

// TestSiteDiffersPerSeed — главное свойство: у двух установок на одном и
// том же домене сайты разные, а у одной установки — одинаковые при каждом
// запуске. Первое не даёт вычислить страницу по домену, второе — заметить
// сервер по тому, что сайт «меняет дизайн» после каждой перезагрузки.
func TestSiteDiffersPerSeed(t *testing.T) {
	page := func(seed string) []byte {
		return bodyOf(t, get(t, newTestSite(t, Options{Host: "quiet-river.io", Seed: seed}), http.MethodGet, "/", nil))
	}
	a1, a2 := page("0123456789abcdef0123456789abcdef"), page("0123456789abcdef0123456789abcdef")
	if !bytes.Equal(a1, a2) {
		t.Fatal("один и тот же seed дал разные страницы")
	}
	if bytes.Equal(a1, page("fedcba9876543210fedcba9876543210")) {
		t.Fatal("разные seed'ы на одном домене дали одинаковые страницы")
	}
	if bytes.Equal(a1, bodyOf(t, get(t, newTestSite(t, Options{Host: "quiet-river.io"}), http.MethodGet, "/", nil))) {
		t.Fatal("страница с seed'ом совпала с той, что выводится из одного домена")
	}

	// На множестве установок выборы действительно расходятся.
	lg, feeds, docs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i := 0; i < 64; i++ {
		v := variantFor(fmt.Sprintf("install-%d", i))
		lg[v.legend.tagline] = true
		feeds[v.feedPath] = true
		docs[v.docsPath] = true
	}
	if len(lg) < len(legends)-1 || len(feeds) < 3 || len(docs) < 3 {
		t.Fatalf("мало разнообразия: легенд %d, фидов %d, путей документации %d", len(lg), len(feeds), len(docs))
	}
}

// TestNoStockName — название из прежних версий нигде не всплывает: «Nimbus
// Lab» стоял у всех установок и искался одной строкой.
func TestNoStockName(t *testing.T) {
	for i := 0; i < 16; i++ {
		s := newTestSite(t, Options{Host: "cdn.example.net", Seed: fmt.Sprintf("seed-%02d-xxxxxxxxxxxx", i)})
		for _, p := range []string{"/", "/status", s.FeedPath()} {
			if b := bodyOf(t, get(t, s, http.MethodGet, p, nil)); bytes.Contains(bytes.ToLower(b), []byte("nimbus")) {
				t.Fatalf("%s: в странице осталось прежнее название", p)
			}
		}
	}
}

func TestLoadSeed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "site-seed")
	s1, created, err := LoadSeed(path)
	if err != nil || !created || len(s1) != 32 {
		t.Fatalf("создание: %q created=%v err=%v", s1, created, err)
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("права файла: %v %v", fi.Mode(), err)
		}
	}
	s2, created, err := LoadSeed(path)
	if err != nil || created || s2 != s1 {
		t.Fatalf("повторное чтение: %q created=%v err=%v", s2, created, err)
	}
	if err := os.WriteFile(path, []byte("short\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadSeed(path); err == nil {
		t.Fatal("короткий seed принят")
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
		"quiet-river.io":      "Quiet River",
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
