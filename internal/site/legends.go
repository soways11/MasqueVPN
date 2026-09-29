package site

// legend — чем «занимается» сервис на сайте-прикрытии.
//
// Зачем их несколько. Код masquevpn публичный, и если бы у всех установок
// сайт рассказывал одну и ту же историю одними и теми же словами, поиск по
// одной фразе находил бы их все сразу. Легенда выбирается секретным seed'ом
// установки (см. Options.Seed), а не доменом: иначе, зная код, по домену
// можно было бы заранее вычислить страницу и сверить её побайтно.
//
// # Легенда обязана объяснять то, что видно в протоколе
//
// Сайт — не единственное, что посторонний видит у домена. Любой, кто
// доведёт рукопожатие HTTP/3 до конца, прочтёт SETTINGS: Extended CONNECT,
// HTTP-датаграммы и WebTransport. Кто смотрит на канал — увидит сессии по
// многу часов, тяжёлый поток датаграмм в обе стороны (весь трафик туннеля)
// и несколько UDP-портов. Убрать это нельзя: без Extended CONNECT и
// датаграмм не работает сам CONNECT-IP.
//
// Прежние легенды (кэш сборок, вебхуки, ресайз картинок, сбор метрик) этому
// противоречили: таким сервисам WebTransport незачем, и сессия на
// гигабайты им не свойственна. Сайт, рассказывающий одно, при протоколе,
// говорящем другое, — признак сильнее, чем отсутствие сайта. Поэтому все
// легенды теперь — сервисы, для которых именно такой трафик и есть работа:
// поток экрана или видео вниз, ввод или медиа вверх, датаграммами, часами.
// Тест TestLegendsExplainProtocol следит, чтобы новая легенда не выпала из
// этого ряда.
//
// Тексты — шаблоны html/template: в них доступны поля pageData
// ({{.Word}}, {{.DocsPath}}, {{.FeedPath}}, {{.Contact}} и т.д.).
type legend struct {
	// tagline — описание по умолчанию (под заголовком и в meta).
	tagline string
	// words — как сервис называет себя в тексте («the platform»).
	words []string
	// session — как называется одна сессия («desktop session»): из общих
	// разделов документации о подключении и о сети.
	session string
	// media — что идёт датаграммами, с заглавной буквы («Screen updates
	// and input events»).
	media string
	// wtPath — начало адреса сессии в примере подключения. Настоящий путь
	// туннеля здесь не показывается никогда: на этот пример без токена
	// сервер ответит 404, как и написано в документации.
	wtPath string
	// cards — три блока на главной: заголовок и абзац.
	cards [3][2]string
	// docsLead — строка под заголовком документации.
	docsLead string
	// docs — разделы документации после общего раздела о подключении.
	docs [][2]string
	// components — что показывает страница статуса.
	components [3]string
	// feedExample — имя компонента в примере ответа фида.
	feedExample string
}

var legends = []legend{
	{
		tagline: "Cloud workstations in a browser tab: a full desktop with low latency and nothing to install.",
		words:   []string{"platform", "service", "workspace"},
		session: "desktop session",
		media:   "Screen updates and input events",
		wtPath:  "/session/",
		cards: [3][2]string{
			{"Nothing to install", `Desktops stream straight into a browser tab over WebTransport. The {{.Word}} sends screen updates one way and keyboard and mouse input the other.`},
			{"Made for real networks", `Lost packets are skipped rather than waited for, so a flaky Wi-Fi costs sharpness, not responsiveness. Frame latency per region is on the <a href="/status">status page</a>.`},
			{"A working day long", `Sessions stay connected for hours and resume after a network change without losing open windows. The details are in the <a href="{{.DocsPath}}">documentation</a>.`},
		},
		docsLead: "How a desktop gets from the {{.Word}} to your screen.",
		docs: [][2]string{
			{"Display", `<p>The encoder adapts to the available bandwidth every second: a static document
costs almost nothing, full-screen video can take tens of megabits. Resolution follows
the browser window, including high-DPI screens.</p>`},
			{"Clipboard and files", `<p>Text and images copied on either side appear on the other. Files dropped onto the
browser tab are uploaded to the desktop over the same connection.</p>`},
		},
		components:  [3]string{"Streaming", "Sessions", "API"},
		feedExample: "Streaming",
	},
	{
		tagline: "Live video with sub-second delay: ingest once and deliver to every viewer over WebTransport.",
		words:   []string{"relay", "network", "platform"},
		session: "playback session",
		media:   "Video and audio frames",
		wtPath:  "/watch/",
		cards: [3][2]string{
			{"Sub-second delay", `Viewers are less than a second behind the camera, close enough for auctions, sports and live Q&amp;A. The {{.Word}} forwards frames as datagrams the moment they arrive.`},
			{"Every viewer, one origin", `Publish one stream and the {{.Word}} fans it out. Relay latency is published on the <a href="/status">status page</a>.`},
			{"Standard players", `Playback uses WebTransport, available in current browsers; native apps use the same protocol. See the <a href="{{.DocsPath}}">docs</a>.`},
		},
		docsLead: "Publishing to the {{.Word}} and playing back from it.",
		docs: [][2]string{
			{"Publishing", `<p>Encoders publish over the same protocol as players, one session per stream.
Renditions are produced at the edge, so upload only the highest quality you have.</p>`},
			{"Quality switching", `<p>Players measure throughput continuously and move between renditions without a
rebuffer. A late frame is dropped instead of stalling the picture.</p>`},
			{"Recording", `<p>Every stream can be recorded; recordings are available for download for thirty
days after the stream ends.</p>`},
		},
		components:  [3]string{"Ingest", "Relay", "Playback"},
		feedExample: "Relay",
	},
	{
		tagline: "Video meetings as an API: rooms, tracks and recording, delivered over WebTransport.",
		words:   []string{"service", "platform", "media server"},
		session: "call",
		media:   "Audio and video",
		wtPath:  "/rooms/",
		cards: [3][2]string{
			{"Rooms in one call", `Create a room from your backend, hand the join URL to your users, and the {{.Word}} does the rest: routing, simulcast and bandwidth estimation.`},
			{"Media without the wait", `Audio and video travel as datagrams, so a lost packet is concealed instead of retransmitted. Media latency is on the <a href="/status">status page</a>.`},
			{"Recording built in", `Record a room to a single file or to one track per participant. The API is in the <a href="{{.DocsPath}}">documentation</a>.`},
		},
		docsLead: "Rooms, participants and media on the {{.Word}}.",
		docs: [][2]string{
			{"Rooms", `<p>A room exists while anyone is in it. Participants publish tracks and subscribe to
the tracks of others; the server forwards the best layer each subscriber can take.</p>`},
			{"Bandwidth", `<p>A participant in a large call sends one stream and receives several. Expect a few
megabits per second in each direction for HD video.</p>`},
		},
		components:  [3]string{"Media", "Signaling", "Recording"},
		feedExample: "Media",
	},
	{
		tagline: "Games streamed from the cloud to any screen: sixty frames a second, controller input in milliseconds.",
		words:   []string{"platform", "service", "network"},
		session: "game session",
		media:   "Video frames and controller input",
		wtPath:  "/play/",
		cards: [3][2]string{
			{"Play anywhere", `Games run on our hardware and stream to a browser, a TV or a phone over WebTransport. The {{.Word}} needs no download and no install.`},
			{"Input first", `Controller and keyboard input goes upstream as datagrams and reaches the game within a few milliseconds of the press. Round-trip times are on the <a href="/status">status page</a>.`},
			{"Long sessions", `Play for hours on one connection; if the network drops, the session waits for you to come back. See the <a href="{{.DocsPath}}">docs</a>.`},
		},
		docsLead: "What the {{.Word}} needs from your network and your client.",
		docs: [][2]string{
			{"Video", `<p>Streams start at 720p and go up to 4K at 60 frames per second, which takes up to
forty megabits per second. The encoder backs off within a frame when the link gets
congested.</p>`},
			{"Controllers", `<p>Gamepads are read through the browser Gamepad API. Touch controls are drawn on
top of the stream on phones and tablets.</p>`},
		},
		components:  [3]string{"Streaming", "Matchmaking", "Edge"},
		feedExample: "Streaming",
	},
	{
		tagline: "Interactive 3D in any browser: render in the cloud, stream the pixels, keep the models on our side.",
		words:   []string{"platform", "service", "renderer"},
		session: "viewing session",
		media:   "Rendered frames and pointer input",
		wtPath:  "/view/",
		cards: [3][2]string{
			{"Any device", `Heavy scenes render on cloud GPUs and stream to laptops and phones over WebTransport. The {{.Word}} sends frames down and pointer input up.`},
			{"Models stay private", `Only pixels leave the data centre: source geometry is never downloaded to the viewer. Render times are on the <a href="/status">status page</a>.`},
			{"Embeddable", `Drop a viewer into your product page with one script tag. Options are listed in the <a href="{{.DocsPath}}">documentation</a>.`},
		},
		docsLead: "Uploading scenes to the {{.Word}} and embedding the viewer.",
		docs: [][2]string{
			{"Scenes", `<p>Upload glTF or USD; scenes are prepared once and cached on every render node.
Configurations such as colours and materials switch without reloading.</p>`},
			{"Embedding", `<p>The viewer takes the size of its container. It keeps one connection open while
visible and closes it after a minute in a background tab.</p>`},
		},
		components:  [3]string{"Render", "Streaming", "Assets"},
		feedExample: "Render",
	},
	{
		tagline: "Real phones in the cloud for app testing: stream the screen, send touches, collect the logs.",
		words:   []string{"device cloud", "service", "lab"},
		session: "device session",
		media:   "Screen frames and touch input",
		wtPath:  "/devices/",
		cards: [3][2]string{
			{"Real hardware", `Tests run on physical phones and tablets, not emulators. The {{.Word}} streams each screen to your browser over WebTransport and sends your touches back.`},
			{"Manual or automated", `Drive a device by hand from the browser or from your test runner; both use the same session. Device availability is on the <a href="/status">status page</a>.`},
			{"Everything captured", `Screen recordings, device logs and network traces are kept for every session. See the <a href="{{.DocsPath}}">docs</a>.`},
		},
		docsLead: "Reserving devices on the {{.Word}} and working with them.",
		docs: [][2]string{
			{"Reserving", `<p>Ask for a model and an OS version; the API returns a session URL as soon as a
matching device is free. A reservation lasts until you release it.</p>`},
			{"Installing apps", `<p>Upload an APK or IPA once and install it on any number of devices. Builds are
kept for ninety days.</p>`},
		},
		components:  [3]string{"Devices", "Streaming", "API"},
		feedExample: "Devices",
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
