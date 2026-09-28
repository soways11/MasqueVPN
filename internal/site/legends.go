package site

// legend — чем «занимается» сервис на сайте-прикрытии.
//
// Зачем их несколько. Код masquevpn публичный, и если бы у всех установок
// сайт рассказывал одну и ту же историю одними и теми же словами, поиск по
// одной фразе находил бы их все сразу. Легенда выбирается секретным seed'ом
// установки (см. Options.Seed), а не доменом: иначе, зная код, по домену
// можно было бы заранее вычислить страницу и сверить её побайтно.
//
// Тексты — шаблоны html/template: в них доступны поля pageData
// ({{.Word}}, {{.DocsPath}}, {{.FeedPath}}, {{.Contact}} и т.д.).
type legend struct {
	// tagline — описание по умолчанию (под заголовком и в meta).
	tagline string
	// words — как сервис называет себя в тексте («the platform»).
	words []string
	// cards — три блока на главной: заголовок и абзац.
	cards [3][2]string
	// docsLead — строка под заголовком документации.
	docsLead string
	// docs — разделы документации после общего раздела про статус.
	docs [][2]string
	// components — что показывает страница статуса.
	components [3]string
	// feedExample — имя компонента в примере ответа фида.
	feedExample string
}

var legends = []legend{
	{
		tagline: "Realtime delivery for applications that cannot wait: one connection, ordered messages, predictable latency.",
		words:   []string{"platform", "service", "network"},
		cards: [3][2]string{
			{"One connection", `Subscribers keep a single long-lived connection open; the {{.Word}} fans out every update over it instead of asking clients to poll.`},
			{"Predictable latency", `Delivery is paced, so a burst upstream does not turn into a burst of jitter downstream. Current numbers are on the <a href="/status">status page</a>.`},
			{"Small API", `One endpoint, JSON in and JSON out, no SDK required. The <a href="{{.DocsPath}}">documentation</a> fits on a single page.`},
		},
		docsLead: "Everything the {{.Word}} exposes, on one page.",
		docs: [][2]string{
			{"Subscribing", `<p>Client libraries open one connection per process and keep it open. Reconnects are
expected to be rare; when they happen, resume from the last sequence number you saw
instead of replaying the whole stream.</p>`},
			{"Limits", `<p>Per-connection throughput is shaped, and idle connections are closed after
ten minutes of silence. Send a keepalive if you have nothing else to send.</p>`},
		},
		components:  [3]string{"Edge", "Delivery", "API"},
		feedExample: "Edge",
	},
	{
		tagline: "Metrics ingestion for small teams: push counters over HTTP, query them a second later.",
		words:   []string{"collector", "service", "backend"},
		cards: [3][2]string{
			{"Push, don't scrape", `Send batches of samples from wherever your code runs. The {{.Word}} accepts line protocol and JSON, and never asks you to open a port.`},
			{"Fresh data", `Samples are queryable about a second after they arrive. Ingest lag is published on the <a href="/status">status page</a>.`},
			{"Retention you choose", `Raw points are kept for thirty days, hourly rollups for two years. Details are in the <a href="{{.DocsPath}}">docs</a>.`},
		},
		docsLead: "How to send data to the {{.Word}} and read it back.",
		docs: [][2]string{
			{"Sending samples", `<p>POST a batch of samples to your ingest endpoint with the token issued to your
project. Batches of a few hundred points are the sweet spot; a single request may
carry up to one megabyte.</p>`},
			{"Querying", `<p>Queries take a metric name, a label filter and a time range, and return evenly
spaced points. Ranges longer than a week are answered from hourly rollups.</p>`},
			{"Tokens", `<p>Tokens are scoped to one project and can be write-only. Rotate them from the
project settings; old tokens keep working for one hour.</p>`},
		},
		components:  [3]string{"Ingest", "Query", "Rollups"},
		feedExample: "Ingest",
	},
	{
		tagline: "A remote build cache that keeps CI fast without keeping it complicated.",
		words:   []string{"cache", "service", "system"},
		cards: [3][2]string{
			{"Content-addressed", `Artifacts are stored by hash, so identical outputs from different branches are uploaded once and served everywhere.`},
			{"Close to your runners", `The {{.Word}} answers from the nearest region; hit latency per region is on the <a href="/status">status page</a>.`},
			{"Works with your tools", `Speaks the plain HTTP cache protocol most build tools already support. Setup takes one line — see the <a href="{{.DocsPath}}">docs</a>.`},
		},
		docsLead: "Pointing your builds at the {{.Word}}.",
		docs: [][2]string{
			{"Configuration", `<p>Set the cache URL and a read-write token in your CI environment, and a
read-only token on developer machines. Nothing else needs to change.</p>`},
			{"Eviction", `<p>Entries that have not been read for fourteen days are evicted. Frequently used
entries stay regardless of age.</p>`},
		},
		components:  [3]string{"Cache", "Uploads", "API"},
		feedExample: "Cache",
	},
	{
		tagline: "Image resizing and delivery at the edge: upload once, request any size.",
		words:   []string{"pipeline", "service", "platform"},
		cards: [3][2]string{
			{"Any size on request", `Ask for a width, a format and a quality in the URL; the {{.Word}} renders it once and caches the result.`},
			{"Modern formats", `AVIF and WebP are served to browsers that accept them, with a JPEG fallback for everything else.`},
			{"Plain URLs", `No SDK and no build step. The URL grammar is described in the <a href="{{.DocsPath}}">documentation</a>; render times are on the <a href="/status">status page</a>.`},
		},
		docsLead: "The URL grammar and everything around it.",
		docs: [][2]string{
			{"Transformations", `<p>Parameters go in the path before the file name: width, height, fit mode, format
and quality. Unknown parameters are ignored rather than rejected.</p>`},
			{"Origins", `<p>Originals are fetched from your storage bucket on first request and kept for
thirty days. Purging an original purges every size derived from it.</p>`},
		},
		components:  [3]string{"Edge", "Transform", "Origin"},
		feedExample: "Transform",
	},
	{
		tagline: "Reliable webhooks: we receive, queue and retry, so your handlers can stay simple.",
		words:   []string{"relay", "service", "gateway"},
		cards: [3][2]string{
			{"Never lose an event", `Incoming calls are acknowledged only after they are written to durable storage. The {{.Word}} replays anything your endpoint did not accept.`},
			{"Retries with backoff", `Failed deliveries are retried for up to three days with exponential backoff. Queue depth is on the <a href="/status">status page</a>.`},
			{"Signed payloads", `Every delivery carries a signature you can verify in a few lines. Examples are in the <a href="{{.DocsPath}}">docs</a>.`},
		},
		docsLead: "Receiving, queuing and delivering events through the {{.Word}}.",
		docs: [][2]string{
			{"Endpoints", `<p>Each source gets its own receiving URL. Point the sender at it, then register
the endpoint that should get the events; filters by event type are optional.</p>`},
			{"Verifying signatures", `<p>Compute an HMAC-SHA256 of the raw body with your endpoint secret and compare it
with the signature header in constant time.</p>`},
			{"Retries", `<p>Any response other than 2xx counts as a failure. After the last retry the event
is kept for seven days and can be replayed by hand.</p>`},
		},
		components:  [3]string{"Receiver", "Queue", "Dispatcher"},
		feedExample: "Queue",
	},
	{
		tagline: "Offline-first sync for mobile apps: local writes, background merge, no conflicts to hand-roll.",
		words:   []string{"sync engine", "service", "backend"},
		cards: [3][2]string{
			{"Local first", `Apps write to a local store and stay usable without a network. The {{.Word}} merges changes when the device comes back online.`},
			{"Deterministic merges", `Concurrent edits are merged field by field in the same order on every device, so nobody has to write conflict screens.`},
			{"Small footprint", `Only changed fields travel over the wire. Protocol details are in the <a href="{{.DocsPath}}">documentation</a>, sync lag on the <a href="/status">status page</a>.`},
		},
		docsLead: "How data moves between devices and the {{.Word}}.",
		docs: [][2]string{
			{"Collections", `<p>Data lives in collections of JSON documents. Each document carries a version
vector; the client library maintains it for you.</p>`},
			{"Authentication", `<p>Devices authenticate with short-lived tokens issued by your own backend, so user
accounts stay where they already are.</p>`},
		},
		components:  [3]string{"Sync", "Storage", "Auth"},
		feedExample: "Sync",
	},
}

// Пути и подписи, которые тоже зависят от установки: одинаковый у всех
// адрес вроде /api/status.json — готовый запрос для сканера.
var (
	docsPaths = [][2]string{
		{"/docs", "Docs"}, {"/documentation", "Documentation"},
		{"/guide", "Guide"}, {"/developers", "Developers"},
	}
	feedPaths = []string{
		"/api/status.json", "/api/v1/status", "/status.json", "/api/health",
	}
	homeLabels = []string{"Overview", "Product", "Home"}
)
