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
// Чего он НЕ делает и не может: это не замена настоящему backend'у.
// Содержимое здесь одно и то же у всех, кто соберёт masquevpn, поэтому текст,
// заголовок и домен параметризованы, а оформление (акцент, знак, имена
// файлов ассетов) выводится из домена — чтобы страницы не были байт в байт
// одинаковыми у всех установок. Если есть чем занять домен по-настоящему,
// fallback_proxy на живой сайт по-прежнему сильнее.
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
	// Description — строка под заголовком и в meta description.
	Description string
	// Contact — адрес в подвале. Пусто — postmaster@Host.
	Contact string
	// Built — время «последнего изменения» страниц (Last-Modified).
	// Нулевое — момент создания сайта.
	Built time.Time
	// Now — источник текущего времени для /api/status.json (для тестов).
	Now func() time.Time
}

const (
	statusPath  = "/api/status.json"
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
}

// New собирает сайт. Все страницы и ассеты строятся один раз: дальше
// обработчик только отдаёт готовые байты.
func New(o Options) (*Site, error) {
	o.defaults()
	th := themeFor(o.Host + "|" + o.Title)
	css := renderCSS(th)
	js := scriptJS
	cssPath := assetPath("app", ".css", css)
	jsPath := assetPath("app", ".js", js)

	d := &pageData{
		Site: o.Title, Description: o.Description, Contact: o.Contact,
		Host: o.Host, Mark: th.mark, CSS: cssPath, JS: jsPath,
		Year: o.Built.Year(), Accent: th.accent, Word: th.word,
	}

	s := &Site{
		res:   map[string]*resource{},
		built: o.Built,
		now:   o.Now,
		title: o.Title,
	}
	pages := []struct {
		path, title, tmpl string
	}{
		{"/", o.Title, indexBody},
		{"/docs", "Documentation — " + o.Title, docsBody},
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
		html, err := renderPage(fmt.Sprintf("%d %s — %s", code, text, o.Title), errorBody, &pageData{
			Site: d.Site, Description: d.Description, Contact: d.Contact, Host: d.Host,
			Mark: d.Mark, CSS: d.CSS, JS: d.JS, Year: d.Year, Accent: d.Accent, Word: d.Word,
			Code: code, CodeText: text,
		})
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
	s.res["/sitemap.xml"] = newResource([]byte(renderSitemap(o.Host, o.Built)), "application/xml", fileCache, http.StatusOK)
	s.res["/favicon.ico"] = newResource(favicon(th.accentRGB), "image/x-icon", fileCache, http.StatusOK)
	return s, nil
}

func (o *Options) defaults() {
	if o.Host == "" {
		o.Host = "example.com"
	}
	if o.Title == "" {
		o.Title = titleFromHost(o.Host)
	}
	if o.Description == "" {
		o.Description = "Realtime delivery for applications that cannot wait: one connection, ordered messages, predictable latency."
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
}

// titleFromHost делает из домена название сервиса: берётся регистрируемая
// часть (api.nimbus-lab.io → Nimbus Lab), а не поддомен — «Api» или «Vpn» в
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
	if p == statusPath {
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
			{"Edge", "operational", lat(12, 9)},
			{"Delivery", "operational", lat(28, 17)},
			{"API", "operational", lat(41, 23)},
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

// theme — то, что отличает наш сайт от такого же сайта у соседа.
// Выводится из домена: одинаковые байты у всех установок сами по себе были бы
// признаком сборки.
type theme struct {
	accent    string
	accentRGB [3]byte
	mark      string
	word      string
}

func themeFor(seed string) theme {
	sum := sha256.Sum256([]byte(seed))
	palette := [][3]byte{
		{0x2b, 0x6c, 0xb0}, {0x27, 0x67, 0x49}, {0x7b, 0x34, 0x1e},
		{0x55, 0x3c, 0x9a}, {0x28, 0x5e, 0x61}, {0x82, 0x27, 0x27},
		{0x2c, 0x52, 0x82}, {0x97, 0x26, 0x6d},
	}
	words := []string{"platform", "service", "network", "cluster"}
	c := palette[int(sum[0])%len(palette)]
	mark := "S"
	for _, r := range seed {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
			mark = strings.ToUpper(string(r))
			break
		}
	}
	return theme{
		accent:    fmt.Sprintf("#%02x%02x%02x", c[0], c[1], c[2]),
		accentRGB: c,
		mark:      mark,
		word:      words[int(sum[1])%len(words)],
	}
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
	Year        int
	Code        int
	CodeText    string
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
<nav><a href="/">Overview</a><a href="/docs">Docs</a><a href="/status">Status</a></nav>
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

const indexBody = `<h1>{{.Site}}</h1>
<p class="lead">{{.Description}}</p>
<div class="cards">
<section><h2>One connection</h2><p>Subscribers keep a single long-lived connection open; the {{.Word}} fans out every update over it instead of asking clients to poll.</p></section>
<section><h2>Predictable latency</h2><p>Delivery is paced, so a burst upstream does not turn into a burst of jitter downstream. Current numbers are on the <a href="/status">status page</a>.</p></section>
<section><h2>Small API</h2><p>One endpoint, JSON in and JSON out, no SDK required. The <a href="/docs">documentation</a> fits on a single page.</p></section>
</div>
<p class="note">Interested in access? Write to <a href="mailto:{{.Contact}}">{{.Contact}}</a>.</p>
`

const docsBody = `<h1>Documentation</h1>
<p class="lead">Everything the {{.Word}} exposes, on one page.</p>
<h2>Health</h2>
<p>The status feed is public and needs no credentials:</p>
<pre><code>curl -s https://{{.Host}}/api/status.json</code></pre>
<p>It answers with the current state of every component:</p>
<pre><code>{
  "status": "operational",
  "updated": "2026-01-01T00:00:00Z",
  "components": [
    {"name": "Edge", "status": "operational", "latency_ms": 14}
  ]
}</code></pre>
<h2>Subscribing</h2>
<p>Client libraries open one connection per process and keep it open. Reconnects are
expected to be rare; when they happen, resume from the last sequence number you saw
instead of replaying the whole stream.</p>
<h2>Limits</h2>
<p>Per-connection throughput is shaped, and idle connections are closed after
ten minutes of silence. Send a keepalive if you have nothing else to send.</p>
<p class="note">Questions: <a href="mailto:{{.Contact}}">{{.Contact}}</a>.</p>
`

const statusBody = `<h1>Status</h1>
<p class="lead" id="summary">Loading current status&hellip;</p>
<table id="components">
<thead><tr><th>Component</th><th>State</th><th>Latency</th></tr></thead>
<tbody><tr><td colspan="3" class="muted">&hellip;</td></tr></tbody>
</table>
<p class="note">Machine-readable feed: <a href="/api/status.json">/api/status.json</a></p>
`

const errorBody = `<h1>{{.Code}}</h1>
<p class="lead">{{.CodeText}}</p>
<p>The page you asked for is not here. Start from the <a href="/">overview</a>
or check the <a href="/status">status page</a>.</p>
`

func renderCSS(th theme) string {
	return strings.ReplaceAll(baseCSS, "$ACCENT", th.accent)
}

const baseCSS = `:root{--accent:$ACCENT;--fg:#1a202c;--muted:#616e7c;--line:#e2e8f0;--bg:#fff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.top{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:18px 24px;border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:10px;font-weight:600;color:var(--fg);text-decoration:none}
.mark{display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;border-radius:7px;background:var(--accent);color:#fff;font-size:15px}
nav a{margin-left:18px;color:var(--muted);text-decoration:none;font-size:15px}
nav a:hover{color:var(--accent)}
main{max-width:860px;margin:0 auto;padding:40px 24px 64px}
h1{font-size:34px;line-height:1.2;margin:0 0 12px}
h2{font-size:19px;margin:32px 0 8px}
a{color:var(--accent)}
.lead{font-size:18px;color:var(--muted);margin:0 0 28px}
.cards{display:grid;gap:18px;grid-template-columns:repeat(auto-fit,minmax(230px,1fr))}
.cards section{border:1px solid var(--line);border-radius:10px;padding:18px}
.cards h2{margin:0 0 6px;font-size:16px}
.cards p{margin:0;color:var(--muted);font-size:15px}
pre{background:#f7fafc;border:1px solid var(--line);border-radius:8px;padding:14px;overflow:auto}
code{font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
table{width:100%;border-collapse:collapse;margin-top:8px}
th,td{text-align:left;padding:10px 8px;border-bottom:1px solid var(--line);font-size:15px}
th{color:var(--muted);font-weight:500}
.ok{color:#276749}
.muted,.note{color:var(--muted)}
.note{font-size:14px;margin-top:28px}
footer{border-top:1px solid var(--line);color:var(--muted);font-size:14px}
footer p{max-width:860px;margin:0 auto;padding:18px 24px}
@media (prefers-color-scheme:dark){
:root{--fg:#e6ebf1;--muted:#98a4b3;--line:#2a3340;--bg:#12171f}
pre{background:#1a212b}
.ok{color:#68d391}
}
`

const scriptJS = `(function(){
  "use strict";
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
    fetch("/api/status.json",{cache:"no-store"})
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

func renderSitemap(host string, built time.Time) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` + "\n")
	for _, p := range []string{"/", "/docs", "/status"} {
		b.WriteString("  <url><loc>https://" + host + p + "</loc><lastmod>" +
			built.Format("2006-01-02") + "</lastmod></url>\n")
	}
	b.WriteString("</urlset>\n")
	return b.String()
}
