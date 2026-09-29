// Package site — небольшой сайт прямо внутри сервера.
//
// Зачем он: сильная защита от активного зондирования — это когда пробер,
// постучавшись в наш домен, видит настоящий работающий сайт. Голый 404
// отличим от VPN не лучше, чем брошенный домен, а поднимать рядом nginx с
// содержимым хочется не всем. Поэтому сервер умеет отдавать сайт сам:
// несколько связанных страниц, ассеты с версией в имени и вечным кэшем,
// собственные страницы ошибок, robots.txt, sitemap.xml, favicon и
// машиночитаемый /api/status.json, который страница статуса опрашивает
// сама, — то есть ровно тот набор, по отсутствию которого домен и
// выглядит пустышкой.
//
// Чего он НЕ делает и не может: это не замена настоящему backend'у. Код
// masquevpn публичный, поэтому всё, что отличает сайт одной установки от
// другой, выводится из секретного случайного seed'а установки (Options.Seed):
// легенда сервиса и её тексты, пути документации и фида статуса, подписи в
// меню, акцент, шрифт, скругления, имена ассетов. Из домена — только
// название, как у любого настоящего сайта. Выводить остальное из домена
// нельзя: зная код, по домену можно было бы вычислить ожидаемую страницу и
// сверить её побайтно. Шаблон разметки всё равно общий, так что тот, кто
// ищет именно masquevpn, сайт узнает; если есть чем занять домен
// по-настоящему, fallback_proxy на живой сайт сильнее.
//
// Заголовок Server сознательно не ставится: назваться nginx'ом, оставаясь
// Go по TLS и QUIC, значит добавить противоречие, а не убрать признак.
package site

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"
)

// Options — что именно показывает сайт.
type Options struct {
	// Host — домен, на котором он стоит (для sitemap, canonical и примеров
	// в документации). Пусто — примеры пишутся с example-домена.
	Host string
	// Title — название сервиса. Пусто — производное от Host.
	Title string
	// Description — строка под заголовком и в meta description. Пусто —
	// из легенды, которую выбрал Seed.
	Description string
	// Seed — секрет установки, из которого выводятся легенда, пути и
	// оформление (см. LoadSeed). Пусто — выводятся из Host и Title; так
	// делать можно только в тестах: по домену страница вычисляется заранее.
	Seed string
	// Contact — адрес в подвале. Пусто — postmaster@Host.
	Contact string
	// Built — время «последнего изменения» страниц (Last-Modified).
	// Нулевое — момент создания сайта.
	Built time.Time
	// Now — источник текущего времени для /api/status.json (для тестов).
	Now func() time.Time

	// То, что видно в протоколе и о чём сайт обязан рассказывать то же
	// самое (см. legends.go).

	// UDPPorts — UDP-порты, на которых сервер отвечает по HTTP/3: основной
	// и запасные. Пусто — только 443. Документация называет их в разделе
	// о сети: сканер их всё равно найдёт, и сервис, который о своих портах
	// молчит, выглядит страннее того, что их перечисляет.
	UDPPorts []int
	// NoWebTransport — сервер не объявляет SETTINGS WebTransport
	// (webtransport=false в конфигурации). Тогда и сайт не обещает
	// WebTransport, а говорит об Extended CONNECT и HTTP-датаграммах —
	// тем, что в SETTINGS остаётся.
	NoWebTransport bool
}

const (
	allowHeader = "GET, HEAD, OPTIONS"
	// maxAge ассетов: имя содержит хэш содержимого, значит их можно кэшировать
	// навсегда — так делает любая современная сборка.
	assetCache = "public, max-age=31536000, immutable"
	pageCache  = "no-cache"
	fileCache  = "public, max-age=86400"
)

// resource — заранее собранный ответ.
type resource struct {
	body        []byte
	gz          []byte // сжатая версия; nil — не сжимать
	contentType string
	cache       string
	etag        string
	status      int
}

// Site — обработчик встроенного сайта.
type Site struct {
	res      map[string]*resource
	notFound *resource
	notOK    *resource // 405
	built    time.Time
	now      func() time.Time
	title    string
	feed     string // путь фида статуса
	comps    [3]string
}

// New собирает сайт. Все страницы и ассеты строятся один раз: дальше
// обработчик только отдаёт готовые байты.
func New(o Options) (*Site, error) {
	seed := o.Seed
	if seed == "" {
		seed = "host:" + o.Host + "|" + o.Title
	}
	return build(o, variantFor(seed))
}

func build(o Options, v variant) (*Site, error) {
	if o.NoWebTransport {
		v.legend = withoutWebTransport(v.legend)
	}
	if o.Description == "" {
		o.Description = v.legend.tagline
	}
	o.defaults()
	v.mark = markFor(o.Title)
	css := renderCSS(v)
	js := strings.ReplaceAll(scriptJS, "$FEED", v.feedPath)
	cssPath := assetPath("app", ".css", css)
	jsPath := assetPath("app", ".js", js)

	d := &pageData{
		Site: o.Title, Description: o.Description, Contact: o.Contact,
		Host: o.Host, Mark: v.mark, CSS: cssPath, JS: jsPath,
		Year: o.Built.Year(), Accent: v.accent, Word: v.word,
		DocsPath: v.docsPath, DocsLabel: v.docsLabel, FeedPath: v.feedPath,
		HomeLabel: v.homeLabel, FeedExample: v.legend.feedExample,
		WebTransport: !o.NoWebTransport,
		Port:         strconv.Itoa(o.UDPPorts[0]),
		AltPorts:     joinPorts(o.UDPPorts[1:]),
	}

	s := &Site{
		res:   map[string]*resource{},
		built: o.Built,
		now:   o.Now,
		title: o.Title,
		feed:  v.feedPath,
		comps: v.legend.components,
	}
	pages := []struct {
		path, title, tmpl string
	}{
		{"/", o.Title, indexBody(v.legend)},
		{v.docsPath, v.docsLabel + " — " + o.Title, docsBody(v)},
		{"/status", "Status — " + o.Title, statusBody},
	}
	for _, p := range pages {
		html, err := renderPage(p.title, p.tmpl, d)
		if err != nil {
			return nil, err
		}
		s.res[p.path] = newResource(html, "text/html; charset=utf-8", pageCache, http.StatusOK)
	}
	errPage := func(code int, text string) (*resource, error) {
		e := *d
		e.Code, e.CodeText = code, text
		html, err := renderPage(fmt.Sprintf("%d %s — %s", code, text, o.Title), errorBody, &e)
		if err != nil {
			return nil, err
		}
		return newResource(html, "text/html; charset=utf-8", "no-store", code), nil
	}
	var err error
	if s.notFound, err = errPage(http.StatusNotFound, "Not Found"); err != nil {
		return nil, err
	}
	if s.notOK, err = errPage(http.StatusMethodNotAllowed, "Method Not Allowed"); err != nil {
		return nil, err
	}

	s.res[cssPath] = newResource([]byte(css), "text/css; charset=utf-8", assetCache, http.StatusOK)
	s.res[jsPath] = newResource([]byte(js), "text/javascript; charset=utf-8", assetCache, http.StatusOK)
	s.res["/robots.txt"] = newResource([]byte(renderRobots(o.Host)), "text/plain; charset=utf-8", fileCache, http.StatusOK)
	s.res["/sitemap.xml"] = newResource([]byte(renderSitemap(o.Host, o.Built, v.docsPath)), "application/xml", fileCache, http.StatusOK)
	s.res["/favicon.ico"] = newResource(favicon(v.accentRGB), "image/x-icon", fileCache, http.StatusOK)
	return s, nil
}

// withoutWebTransport — легенда для сервера, который WebTransport не
// объявляет: обещать его на сайте значило бы разойтись с SETTINGS.
// Остаётся то, что в SETTINGS есть, — HTTP/3 с датаграммами.
func withoutWebTransport(lg *legend) *legend {
	r := strings.NewReplacer("WebTransport", "HTTP/3").Replace
	out := *lg
	out.tagline = r(lg.tagline)
	for i, c := range lg.cards {
		out.cards[i] = [2]string{r(c[0]), r(c[1])}
	}
	out.docs = make([][2]string, len(lg.docs))
	for i, d := range lg.docs {
		out.docs[i] = [2]string{r(d[0]), r(d[1])}
	}
	return &out
}

// FeedPath — путь машиночитаемой сводки статуса у этой установки.
func (s *Site) FeedPath() string { return s.feed }

func (o *Options) defaults() {
	if o.Host == "" {
		o.Host = "example.com"
	}
	if o.Title == "" {
		o.Title = titleFromHost(o.Host)
	}
	if o.Contact == "" {
		o.Contact = "postmaster@" + o.Host
	}
	if o.Built.IsZero() {
		o.Built = time.Now()
	}
	o.Built = o.Built.UTC().Truncate(time.Second)
	if o.Now == nil {
		o.Now = time.Now
	}
	if len(o.UDPPorts) == 0 {
		o.UDPPorts = []int{443}
	}
}

// joinPorts — «8443, 2053 and 2083»: так перечисляют в тексте, а не в
// конфигурации.
func joinPorts(ports []int) string {
	s := make([]string, len(ports))
	for i, p := range ports {
		s[i] = strconv.Itoa(p)
	}
	switch len(s) {
	case 0:
		return ""
	case 1:
		return s[0]
	}
	return strings.Join(s[:len(s)-1], ", ") + " and " + s[len(s)-1]
}

// titleFromHost делает из домена название сервиса: берётся регистрируемая
// часть (api.quiet-river.io → Quiet River), а не поддомен — «Api» или «Vpn» в
// шапке сайта выглядели бы ровно так, как не надо.
func titleFromHost(host string) string {
	h := host
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	h = strings.Trim(h, ".")
	parts := strings.Split(h, ".")
	i := max(len(parts)-2, 0)
	// example.co.uk и подобные: «Co» названием сервиса не бывает.
	if i > 0 && len(parts[len(parts)-1]) <= 3 && secondLevel[parts[i]] {
		i--
	}
	words := strings.FieldsFunc(parts[i], func(r rune) bool { return r == '-' || r == '_' })
	for i, w := range words {
		if w == "" {
			continue
		}
		words[i] = strings.ToUpper(w[:1]) + w[1:]
	}
	if len(words) == 0 {
		return "Service"
	}
	return strings.Join(words, " ")
}

// secondLevel — метки, которые сами по себе именем сервиса не бывают.
var secondLevel = map[string]bool{
	"co": true, "com": true, "net": true, "org": true,
	"gov": true, "edu": true, "ac": true,
}

func newResource(body []byte, ct, cache string, status int) *resource {
	sum := sha256.Sum256(body)
	r := &resource{
		body:        body,
		contentType: ct,
		cache:       cache,
		etag:        `"` + hex.EncodeToString(sum[:8]) + `"`,
		status:      status,
	}
	if compressible(ct) && len(body) >= 512 {
		var buf bytes.Buffer
		zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
		_, _ = zw.Write(body)
		if zw.Close() == nil && buf.Len() < len(body) {
			r.gz = buf.Bytes()
		}
	}
	return r
}

func compressible(ct string) bool {
	return strings.HasPrefix(ct, "text/") ||
		strings.HasPrefix(ct, "application/json") ||
		strings.HasPrefix(ct, "application/xml")
}

func (s *Site) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
	case http.MethodOptions:
		w.Header().Set("Allow", allowHeader)
		w.WriteHeader(http.StatusNoContent)
		return
	default:
		// Сюда попадают в том числе POST и CONNECT. Отдавать на них
		// страницу, как делает http.FileServer, нельзя: обычный сервер так
		// не отвечает, и по одному такому ответу нас можно было отличить.
		w.Header().Set("Allow", allowHeader)
		s.write(w, r, s.notOK)
		return
	}
	p := path.Clean(r.URL.Path)
	if p == s.feed {
		s.serveStatus(w, r)
		return
	}
	res, ok := s.res[p]
	if !ok {
		s.write(w, r, s.notFound)
		return
	}
	s.write(w, r, res)
}

// write отдаёт готовый ресурс с условными запросами и gzip — как это делает
// любой обычный сервер. Без них домен выглядит странно: браузер повторно
// качает неизменившуюся страницу, а gzip не предлагается вовсе.
func (s *Site) write(w http.ResponseWriter, r *http.Request, res *resource) {
	h := w.Header()
	h.Set("Content-Type", res.contentType)
	h.Set("Cache-Control", res.cache)
	h.Set("X-Content-Type-Options", "nosniff")
	if res.gz != nil {
		h.Set("Vary", "Accept-Encoding")
	}
	if res.status == http.StatusOK {
		h.Set("ETag", res.etag)
		h.Set("Last-Modified", s.built.Format(http.TimeFormat))
		if match := r.Header.Get("If-None-Match"); match != "" && strings.Contains(match, res.etag) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if since, err := http.ParseTime(r.Header.Get("If-Modified-Since")); err == nil && !s.built.After(since) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	body := res.body
	if res.gz != nil && acceptsGzip(r) {
		h.Set("Content-Encoding", "gzip")
		body = res.gz
	}
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(res.status)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}

func acceptsGzip(r *http.Request) bool {
	for _, v := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		if name, _, _ := strings.Cut(strings.TrimSpace(v), ";"); name == "gzip" {
			return true
		}
	}
	return false
}

// statusDoc — тело /api/status.json.
type statusDoc struct {
	Status     string            `json:"status"`
	Updated    string            `json:"updated"`
	Components []statusComponent `json:"components"`
}

type statusComponent struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	LatencyMS int    `json:"latency_ms"`
}

// serveStatus отдаёт живую сводку: её опрашивает страница статуса, поэтому
// она не кэшируется и от запроса к запросу слегка меняется — как у любого
// настоящего мониторинга.
func (s *Site) serveStatus(w http.ResponseWriter, r *http.Request) {
	now := s.now().UTC()
	// Значения выводятся из времени, а не из rand: страница, где задержки
	// прыгают на порядок каждую секунду, выглядела бы сломанной.
	seed := now.Unix() / 7
	lat := func(base, spread int) int {
		seed = seed*6364136223846793005 + 1442695040888963407
		return base + int((seed>>33)%int64(spread))
	}
	doc := statusDoc{
		Status:  "operational",
		Updated: now.Format(time.RFC3339),
		Components: []statusComponent{
			{s.comps[0], "operational", lat(12, 9)},
			{s.comps[1], "operational", lat(28, 17)},
			{s.comps[2], "operational", lat(41, 23)},
		},
	}
	body, err := json.Marshal(doc)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	body = append(body, '\n')
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}

// ---------- оформление ----------

// variant — то, чем сайт этой установки отличается от такого же сайта у
// соседа. Выводится из seed'а установки: одинаковые байты у всех установок
// сами по себе были бы признаком сборки.
type variant struct {
	legend    *legend
	word      string
	accent    string
	accentRGB [3]byte
	mark      string
	docsPath  string
	docsLabel string
	feedPath  string
	homeLabel string
	radius    int
	font      string
	width     int
	h1        int
	healthPos int // после какого раздела документации идёт раздел о статусе
}

var (
	palette = [][3]byte{
		{0x2b, 0x6c, 0xb0}, {0x27, 0x67, 0x49}, {0x7b, 0x34, 0x1e},
		{0x55, 0x3c, 0x9a}, {0x28, 0x5e, 0x61}, {0x82, 0x27, 0x27},
		{0x2c, 0x52, 0x82}, {0x97, 0x26, 0x6d}, {0x1f, 0x6f, 0x8b},
		{0x6b, 0x4f, 0x1d}, {0x3d, 0x5a, 0x80}, {0x4a, 0x2f, 0x7a},
		{0x0f, 0x76, 0x6e}, {0xb4, 0x3f, 0x0e},
	}
	fonts = []string{
		`-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif`,
		`system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif`,
		`"Inter",system-ui,-apple-system,"Segoe UI",sans-serif`,
		`ui-sans-serif,system-ui,sans-serif,"Apple Color Emoji","Segoe UI Emoji"`,
	}
	radii  = []int{4, 6, 8, 10, 12}
	widths = []int{820, 860, 900, 960}
	h1s    = []int{32, 34, 36, 38}
)

// variantFor раскладывает seed на независимые выборы: у каждого свой
// хэш, чтобы, скажем, цвет не определял легенду.
func variantFor(seed string) variant {
	pick := func(label string, n int) int {
		sum := sha256.Sum256([]byte(seed + "\x00" + label))
		return int(binary.BigEndian.Uint32(sum[:4]) % uint32(n))
	}
	lg := &legends[pick("legend", len(legends))]
	c := palette[pick("accent", len(palette))]
	docs := docsPaths[pick("docs", len(docsPaths))]
	return variant{
		legend:    lg,
		word:      lg.words[pick("word", len(lg.words))],
		accent:    fmt.Sprintf("#%02x%02x%02x", c[0], c[1], c[2]),
		accentRGB: c,
		docsPath:  docs[0],
		docsLabel: docs[1],
		feedPath:  feedPaths[pick("feed", len(feedPaths))],
		homeLabel: homeLabels[pick("home", len(homeLabels))],
		radius:    radii[pick("radius", len(radii))],
		font:      fonts[pick("font", len(fonts))],
		width:     widths[pick("width", len(widths))],
		h1:        h1s[pick("h1", len(h1s))],
		healthPos: pick("health", len(lg.docs)+1),
	}
}

// markFor — буква в значке: первая буква названия.
func markFor(title string) string {
	for _, r := range title {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return strings.ToUpper(string(r))
		}
	}
	return "S"
}

// assetPath даёт имя с хэшем содержимого — как сборщик фронтенда. Заодно это
// ещё одно отличие между установками.
func assetPath(name, ext, content string) string {
	sum := sha256.Sum256([]byte(content))
	return "/assets/" + name + "." + hex.EncodeToString(sum[:4]) + ext
}

// favicon собирает 16×16 ICO из акцентного цвета: браузер запрашивает
// /favicon.ico всегда, и 404 на него — мелкая, но заметная странность.
func favicon(c [3]byte) []byte {
	const n = 16
	var buf bytes.Buffer
	w16 := func(v uint16) { _ = binary.Write(&buf, binary.LittleEndian, v) }
	w32 := func(v uint32) { _ = binary.Write(&buf, binary.LittleEndian, v) }
	// ICONDIR
	w16(0)
	w16(1)
	w16(1)
	// ICONDIRENTRY
	buf.WriteByte(n)
	buf.WriteByte(n)
	buf.WriteByte(0)
	buf.WriteByte(0)
	w16(1)
	w16(32)
	w32(40 + n*n*4 + n*4)
	w32(6 + 16)
	// BITMAPINFOHEADER
	w32(40)
	w32(n)
	w32(n * 2) // изображение + маска
	w16(1)
	w16(32)
	w32(0)
	w32(uint32(n * n * 4))
	w32(0)
	w32(0)
	w32(0)
	w32(0)
	// Пиксели BGRA, снизу вверх: заливка акцентом, светлый знак посередине.
	for y := n - 1; y >= 0; y-- {
		for x := 0; x < n; x++ {
			b, g, r := c[2], c[1], c[0]
			if x >= 5 && x <= 10 && y >= 5 && y <= 10 {
				b, g, r = 0xf2, 0xf5, 0xf8
			}
			buf.Write([]byte{b, g, r, 0xff})
		}
	}
	buf.Write(make([]byte, n*4)) // маска прозрачности: всё непрозрачно
	return buf.Bytes()
}

// ---------- страницы ----------

type pageData struct {
	Site        string
	Description string
	Contact     string
	Host        string
	Mark        string
	CSS         string
	JS          string
	Accent      string
	Word        string
	DocsPath    string
	DocsLabel   string
	FeedPath    string
	FeedExample string
	HomeLabel   string
	// То, что видно в протоколе (см. Options.UDPPorts, NoWebTransport).
	WebTransport bool
	Port         string
	AltPorts     string
	Year         int
	Code         int
	CodeText     string
}

func renderPage(title, body string, d *pageData) ([]byte, error) {
	t, err := template.New("page").Parse(layoutHTML)
	if err != nil {
		return nil, err
	}
	if _, err := t.New("body").Parse(body); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, struct {
		*pageData
		Title string
	}{d, title}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

const layoutHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}}</title>
<meta name="description" content="{{.Description}}">
<link rel="icon" href="/favicon.ico" sizes="16x16">
<link rel="stylesheet" href="{{.CSS}}">
</head>
<body>
<header class="top">
<a class="brand" href="/"><span class="mark">{{.Mark}}</span>{{.Site}}</a>
<nav><a href="/">{{.HomeLabel}}</a><a href="{{.DocsPath}}">{{.DocsLabel}}</a><a href="/status">Status</a></nav>
</header>
<main>
{{template "body" .}}
</main>
<footer>
<p>&copy; {{.Year}} {{.Site}}. <a href="mailto:{{.Contact}}">{{.Contact}}</a></p>
</footer>
<script src="{{.JS}}" defer></script>
</body>
</html>
`

// indexBody — главная: описание и три блока легенды. Тексты легенд —
// константы из этого пакета, поэтому их можно склеивать в шаблон.
func indexBody(lg *legend) string {
	var b strings.Builder
	b.WriteString("<h1>{{.Site}}</h1>\n<p class=\"lead\">{{.Description}}</p>\n<div class=\"cards\">\n")
	for _, c := range lg.cards {
		b.WriteString("<section><h2>" + c[0] + "</h2><p>" + c[1] + "</p></section>\n")
	}
	b.WriteString("</div>\n<p class=\"note\">Interested in access? Write to <a href=\"mailto:{{.Contact}}\">{{.Contact}}</a>.</p>\n")
	return b.String()
}

const healthSection = `<h2>Health</h2>
<p>The status feed is public and needs no credentials:</p>
<pre><code>curl -s https://{{.Host}}{{.FeedPath}}</code></pre>
<p>It answers with the current state of every component:</p>
<pre><code>{
  "status": "operational",
  "updated": "2026-01-01T00:00:00Z",
  "components": [
    {"name": "{{.FeedExample}}", "status": "operational", "latency_ms": 14}
  ]
}</code></pre>
`

// connectSection — как клиент открывает сессию. Пишется ровно то, что
// увидит пробер: с WebTransport-SETTINGS — WebTransport, без них —
// Extended CONNECT; на неизвестный адрес сессии — 404 (masque/probe.go).
// Пример адреса — из легенды, не путь туннеля.
func connectSection(lg *legend) string {
	return `<h2>Connecting</h2>
{{if .WebTransport}}<p>Each ` + lg.session + ` runs as a WebTransport session over HTTP/3. Your backend asks
the API for a session URL; the URL carries a short-lived token and stops working when
it expires. Unknown and expired session URLs answer <code>404</code>, like any other
path that does not exist.</p>
<pre><code>const session = new WebTransport("https://{{.Host}}` + lg.wtPath + `&lt;token&gt;");
await session.ready;
const frames = session.datagrams.readable.getReader();</code></pre>
<p>` + lg.media + ` travel as datagrams: a packet that arrives too late is dropped
rather than retransmitted, so a lossy network costs quality, not delay. Control
messages use one bidirectional stream.</p>
<p class="note" id="wt-support"></p>
{{else}}<p>Each ` + lg.session + ` is opened with an Extended CONNECT request over HTTP/3 (RFC 9220) and uses
HTTP datagrams (RFC 9297); the client libraries handle both. Your backend asks the API
for a session URL; the URL carries a short-lived token, and unknown or expired session
URLs answer <code>404</code>, like any other path that does not exist.</p>
<p>` + lg.media + ` travel as datagrams: a packet that arrives too late is dropped
rather than retransmitted, so a lossy network costs quality, not delay.</p>
{{end}}`
}

// networkSection — что сервису нужно от сети. Объясняет то, что видно на
// канале: UDP и несколько портов, долгую сессию, keepalive, фоновые
// запросы по тому же соединению и переподключение, когда путь замолк.
func networkSection(lg *legend) string {
	return `<h2>Network requirements</h2>
<p>Sessions run over QUIC on UDP port {{.Port}}.{{if .AltPorts}} Some networks block or throttle
UDP {{.Port}}; clients then try the alternate ports {{.AltPorts}} in that order and
remember the one that worked.{{else}} There is no TCP fallback for a ` + lg.session + `: if UDP
{{.Port}} is blocked on your network, ask the administrator to allow it.{{end}}</p>
<p>A ` + lg.session + ` keeps one connection open for as long as it lasts, often for hours.
When there is nothing else to send, clients send a keepalive about every fifteen
seconds, and they refresh their configuration over the same connection from time to
time. If the path goes quiet for several seconds, the client reconnects on its own and
resumes where it left off.</p>
`
}

// docsBody — документация: сначала подключение, затем разделы легенды,
// между ними — раздел про фид статуса (его место тоже зависит от
// установки), в конце — требования к сети.
func docsBody(v variant) string {
	var b strings.Builder
	b.WriteString("<h1>{{.DocsLabel}}</h1>\n<p class=\"lead\">" + v.legend.docsLead + "</p>\n")
	b.WriteString(connectSection(v.legend))
	for i, d := range v.legend.docs {
		if i == v.healthPos {
			b.WriteString(healthSection)
		}
		b.WriteString("<h2>" + d[0] + "</h2>\n" + d[1] + "\n")
	}
	if v.healthPos >= len(v.legend.docs) {
		b.WriteString(healthSection)
	}
	b.WriteString(networkSection(v.legend))
	b.WriteString("<p class=\"note\">Questions: <a href=\"mailto:{{.Contact}}\">{{.Contact}}</a>.</p>\n")
	return b.String()
}

const statusBody = `<h1>Status</h1>
<p class="lead" id="summary">Loading current status&hellip;</p>
<table id="components">
<thead><tr><th>Component</th><th>State</th><th>Latency</th></tr></thead>
<tbody><tr><td colspan="3" class="muted">&hellip;</td></tr></tbody>
</table>
<p class="note">Machine-readable feed: <a href="{{.FeedPath}}">{{.FeedPath}}</a></p>
`

const errorBody = `<h1>{{.Code}}</h1>
<p class="lead">{{.CodeText}}</p>
<p>The page you asked for is not here. Start from the <a href="/">overview</a>
or check the <a href="/status">status page</a>.</p>
`

func renderCSS(v variant) string {
	return strings.NewReplacer(
		"$ACCENT", v.accent,
		"$FONT", v.font,
		"$RADIUS_S", strconv.Itoa(max(v.radius-3, 3)),
		"$RADIUS", strconv.Itoa(v.radius),
		"$WIDTH", strconv.Itoa(v.width),
		"$H1", strconv.Itoa(v.h1),
	).Replace(baseCSS)
}

const baseCSS = `:root{--accent:$ACCENT;--fg:#1a202c;--muted:#616e7c;--line:#e2e8f0;--bg:#fff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.6 $FONT}
.top{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:18px 24px;border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:10px;font-weight:600;color:var(--fg);text-decoration:none}
.mark{display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;border-radius:$RADIUS_Spx;background:var(--accent);color:#fff;font-size:15px}
nav a{margin-left:18px;color:var(--muted);text-decoration:none;font-size:15px}
nav a:hover{color:var(--accent)}
main{max-width:$WIDTHpx;margin:0 auto;padding:40px 24px 64px}
h1{font-size:$H1px;line-height:1.2;margin:0 0 12px}
h2{font-size:19px;margin:32px 0 8px}
a{color:var(--accent)}
.lead{font-size:18px;color:var(--muted);margin:0 0 28px}
.cards{display:grid;gap:18px;grid-template-columns:repeat(auto-fit,minmax(230px,1fr))}
.cards section{border:1px solid var(--line);border-radius:$RADIUSpx;padding:18px}
.cards h2{margin:0 0 6px;font-size:16px}
.cards p{margin:0;color:var(--muted);font-size:15px}
pre{background:#f7fafc;border:1px solid var(--line);border-radius:$RADIUS_Spx;padding:14px;overflow:auto}
code{font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
table{width:100%;border-collapse:collapse;margin-top:8px}
th,td{text-align:left;padding:10px 8px;border-bottom:1px solid var(--line);font-size:15px}
th{color:var(--muted);font-weight:500}
.ok{color:#276749}
.muted,.note{color:var(--muted)}
.note{font-size:14px;margin-top:28px}
footer{border-top:1px solid var(--line);color:var(--muted);font-size:14px}
footer p{max-width:$WIDTHpx;margin:0 auto;padding:18px 24px}
@media (prefers-color-scheme:dark){
:root{--fg:#e6ebf1;--muted:#98a4b3;--line:#2a3340;--bg:#12171f}
pre{background:#1a212b}
.ok{color:#68d391}
}
`

const scriptJS = `(function(){
  "use strict";
  var wt=document.getElementById("wt-support");
  if(wt){
    wt.textContent=("WebTransport" in window)
      ?"This browser supports WebTransport."
      :"This browser does not support WebTransport yet: try a current version of Chrome, Edge or Firefox.";
  }
  var tbody=document.querySelector("#components tbody");
  var summary=document.getElementById("summary");
  if(!tbody||!summary){return;}
  function row(c){
    var tr=document.createElement("tr");
    var name=document.createElement("td");name.textContent=c.name;
    var state=document.createElement("td");state.textContent=c.status;state.className="ok";
    var lat=document.createElement("td");lat.textContent=c.latency_ms+" ms";
    tr.appendChild(name);tr.appendChild(state);tr.appendChild(lat);
    return tr;
  }
  function draw(doc){
    tbody.textContent="";
    (doc.components||[]).forEach(function(c){tbody.appendChild(row(c));});
    var d=new Date(doc.updated);
    summary.textContent="All systems "+doc.status+" · updated "+d.toLocaleTimeString();
  }
  function load(){
    fetch("$FEED",{cache:"no-store"})
      .then(function(r){return r.json();})
      .then(draw)
      .catch(function(){summary.textContent="Status feed unavailable.";});
  }
  load();
  setInterval(load,20000);
})();
`

func renderRobots(host string) string {
	return "User-agent: *\nAllow: /\nDisallow: /api/\n\nSitemap: https://" + host + "/sitemap.xml\n"
}

func renderSitemap(host string, built time.Time, docsPath string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` + "\n")
	for _, p := range []string{"/", docsPath, "/status"} {
		b.WriteString("  <url><loc>https://" + host + p + "</loc><lastmod>" +
			built.Format("2006-01-02") + "</lastmod></url>\n")
	}
	b.WriteString("</urlset>\n")
	return b.String()
}
