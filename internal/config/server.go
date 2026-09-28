package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/soways11/masquevpn/internal/fingerprint"
	"github.com/soways11/masquevpn/internal/masque"
)

// Server — конфигурация vpnserver.
type Server struct {
	// Listen — UDP-адрес, по умолчанию ":443".
	Listen string `json:"listen,omitempty"`
	// CertFile, KeyFile — сертификат и ключ (PEM). При включённом ACME не
	// обязательны: если заданы, используются как запасные, пока Let's Encrypt
	// недоступен.
	CertFile string `json:"cert_file,omitempty"`
	KeyFile  string `json:"key_file,omitempty"`
	// ACME — автоматический сертификат Let's Encrypt.
	ACME ACME `json:"acme"`
	// AuthKey — общий ключ клиентов (base64, ≥32 байт) или «file:/путь».
	// Не задаётся вместе с clients_file: общий ключ рядом с личными — это
	// чёрный ход, по которому заходит и отозванный.
	AuthKey Key `json:"auth_key"`
	// ClientsFile — реестр клиентов (см. internal/clients): у каждого свой
	// ключ, свои лимиты и своя квота. Задан — работает режим ключей по
	// клиентам, и auth_key не нужен.
	ClientsFile string `json:"clients_file,omitempty"`
	// UsageFile — файл учёта расхода. Пусто — рядом с реестром,
	// <clients_file>.usage. Учёт нужен квотам: без сохранения квота
	// обнуляется перезапуском.
	UsageFile string `json:"usage_file,omitempty"`
	// ClientsReload — как часто перечитывать реестр. 0 — 10 секунд.
	ClientsReload Duration `json:"clients_reload,omitempty"`
	// AuthHeader — заголовок с токеном; по умолчанию Authorization: Bearer.
	AuthHeader string `json:"auth_header,omitempty"`
	// Path — путь CONNECT-IP; по умолчанию masque.DefaultPath.
	Path string `json:"path,omitempty"`

	TUN TUN `json:"tun"`
	// Pool4, Pool6 — сети клиентов. Первый адрес — шлюз (адрес сервера на TUN).
	Pool4 string `json:"pool4,omitempty"`
	Pool6 string `json:"pool6,omitempty"`

	NAT NAT `json:"nat"`
	// AllowClientToClient — разрешить клиентам видеть друг друга.
	AllowClientToClient bool `json:"allow_client_to_client,omitempty"`

	// Packing — упаковка датаграмм (C2): агрегация, фрагментация, профиль.
	Packing *Packing `json:"packing,omitempty"`

	// ServerProfile — профиль транспортных параметров сервера (C1):
	// "cloudflare" (по умолчанию) — снятый с живого сервера и встроенный в
	// бинарник; "cdn" — прежняя эвристика, выдуманные числа; "stock" —
	// умолчания quic-go, по которым сервер узнаётся сразу.
	ServerProfile string `json:"server_profile,omitempty"`
	// ServerProfileFile — профиль, снятый с живого сервера утилитой
	// fpserver; имеет приоритет над ServerProfile.
	ServerProfileFile string `json:"server_profile_file,omitempty"`

	// Shaping — профиль маскировки трафика сервер→клиент.
	Shaping string `json:"shaping,omitempty"`
	// WebTransport — объявлять SETTINGS WebTransport; по умолчанию true.
	WebTransport *bool `json:"webtransport,omitempty"`

	Limits ServerLimits `json:"limits"`
	// FallbackDir — каталог статического сайта-прикрытия. Пусто — 404.
	FallbackDir string `json:"fallback_dir,omitempty"`
	// FallbackProxy — адрес живого backend'а (http://host:port), на который
	// проксируется всё, что не наш туннель. Сильнее статики: пробер видит
	// настоящий работающий сайт. Имеет приоритет над FallbackDir.
	FallbackProxy string `json:"fallback_proxy,omitempty"`
	// FallbackSite — встроенный небольшой сайт (см. internal/site). Работает,
	// когда не заданы fallback_proxy и fallback_dir; отключается — чтобы
	// посторонний видел голый 404 — полем disabled.
	FallbackSite FallbackSite `json:"fallback_site"`

	// TCP — обычный HTTPS на TCP рядом с HTTP/3.
	TCP TCPListener `json:"tcp"`

	// LogLevel — debug, info, warn, error.
	LogLevel string `json:"log_level,omitempty"`
}

// ACME — автоматический выпуск и продление сертификата.
//
// Проверка идёт по tls-alpn-01 на TCP/443, то есть на том же слушателе, что
// отдаёт сайт-прикрытие: отдельный HTTP-порт и доступ к DNS-зоне не нужны.
// Поэтому ACME требует включённого tcp-слушателя на порту 443.
type ACME struct {
	// Domains — имена, на которые выпускается сертификат. Пусто — ACME
	// выключен, сертификат берётся из cert_file/key_file.
	Domains []string `json:"domains,omitempty"`
	// Email — контакт для удостоверяющего центра: на него приходят
	// предупреждения об истечении.
	Email string `json:"email,omitempty"`
	// CacheDir — каталог с ключом аккаунта и сертификатами. Его надо
	// сохранять между перезапусками, иначе каждый запуск — новый заказ, а
	// у удостоверяющего центра лимиты. Пусто — DefaultACMECache.
	CacheDir string `json:"cache_dir,omitempty"`
	// DirectoryURL — каталог ACME. Пусто — боевой Let's Encrypt. Для
	// обкатки полезен staging: лимиты мягче, но сертификат не доверенный.
	DirectoryURL string `json:"directory_url,omitempty"`
}

// DefaultACMECache — каталог кэша ACME по умолчанию.
const DefaultACMECache = VarLibDir + "/acme"

// Enabled сообщает, включён ли автоматический сертификат.
func (a ACME) Enabled() bool { return len(a.Domains) > 0 }

// TCPListener — обычный HTTPS по TCP.
//
// Зачем он нужен: домен, у которого есть HTTP/3, но по TCP соединение
// отбивается, — аномалия, видимая одним curl. Вдобавок браузеры узнают про
// HTTP/3 из заголовка Alt-Svc, который приходит именно по TCP: без него
// «обычный сайт» выглядит так, будто к нему никто не ходит обычным
// способом. И сертификат ACME по tls-alpn-01 тоже выпускается по TCP.
type TCPListener struct {
	// Disabled выключает TCP-слушатель.
	Disabled bool `json:"disabled,omitempty"`
	// Listen — адрес; пусто — тот же порт, что и у QUIC.
	Listen string `json:"listen,omitempty"`
}

// TCPAddr возвращает адрес TCP-слушателя; пусто — слушатель выключен.
func (c *Server) TCPAddr() string {
	if c.TCP.Disabled {
		return ""
	}
	if c.TCP.Listen != "" {
		return c.TCP.Listen
	}
	return c.Listen
}

// FallbackSite — встроенный сайт-прикрытие.
//
// Чем он отличается от сайта соседней установки, решает секретный seed
// (см. site.LoadSeed): легенда, тексты, пути и оформление. Название по
// умолчанию — из домена. Живой backend за fallback_proxy всё равно сильнее.
type FallbackSite struct {
	// Disabled — не поднимать встроенный сайт (посторонний увидит 404).
	Disabled bool `json:"disabled,omitempty"`
	// Host — домен в примерах, sitemap и robots.txt.
	// Пусто — имя из сертификата.
	Host string `json:"host,omitempty"`
	// Title — название сервиса. Пусто — производное от Host.
	Title string `json:"title,omitempty"`
	// Description — строка под заголовком и в meta description.
	Description string `json:"description,omitempty"`
	// Contact — адрес в подвале. Пусто — postmaster@Host.
	Contact string `json:"contact,omitempty"`
	// Seed — секрет, из которого выводится сайт. Пусто — берётся из
	// SeedFile, а файла нет — он создаётся со случайным значением.
	Seed string `json:"seed,omitempty"`
	// SeedFile — где хранится seed. Пусто — DefaultSiteSeedFile().
	SeedFile string `json:"seed_file,omitempty"`
}

// Название и описание, которые установщик до 28.09.2026 вписывал в каждую
// конфигурацию. Одна строка у всех установок искалась поиском, поэтому
// сервер считает их незаданными (см. WithoutLegacyText).
const (
	legacySiteTitle       = "Nimbus Lab"
	legacySiteDescription = "Realtime delivery for applications that cannot wait."
)

// WithoutLegacyText возвращает копию, в которой название и описание из
// прежних версий установщика сброшены, и сообщает, было ли что сбрасывать.
func (f FallbackSite) WithoutLegacyText() (FallbackSite, bool) {
	changed := false
	if f.Title == legacySiteTitle {
		f.Title, changed = "", true
	}
	if f.Description == legacySiteDescription {
		f.Description, changed = "", true
	}
	return f, changed
}

// NAT — выпуск клиентов в интернет.
type NAT struct {
	// Disabled — не настраивать NAT (например, если он уже настроен иначе).
	Disabled bool `json:"disabled,omitempty"`
	// OutInterface — ограничить маскарадинг интерфейсом. Пусто — любой, кроме TUN.
	OutInterface string `json:"out_interface,omitempty"`
	// NoMSSClamp — не подрезать MSS TCP под MTU туннеля.
	NoMSSClamp bool `json:"no_mss_clamp,omitempty"`
	// NoIPv6 — не маскарадить IPv6: включайте, если хостер выдал
	// маршрутизируемый префикс и клиентам раздаются адреса из него.
	NoIPv6 bool `json:"no_ipv6,omitempty"`
}

// ServerLimits — лимиты ресурсов.
type ServerLimits struct {
	MaxSessions      int      `json:"max_sessions,omitempty"`
	MaxSessionsPerIP int      `json:"max_sessions_per_ip,omitempty"`
	IdleTimeout      Duration `json:"idle_timeout,omitempty"`
	// MaxUnknownCapsules — потолок неизвестных капсул на сессию (0 — 64).
	MaxUnknownCapsules int `json:"max_unknown_capsules,omitempty"`
	// MaxBytesPerSecond — потолок исходящей полосы одной сессии, байт в
	// секунду (0 — без ограничения).
	MaxBytesPerSecond int `json:"max_bytes_per_second,omitempty"`
	// BurstBytes — сколько полосы можно накопить про запас.
	BurstBytes int `json:"burst_bytes,omitempty"`
	// AddressLeaseTTL — сколько адрес держится за ушедшим клиентом, чтобы
	// при переподключении он получил прежний (0 — 2 минуты).
	AddressLeaseTTL Duration `json:"address_lease_ttl,omitempty"`
}

// LoadServer читает и проверяет конфигурацию сервера.
func LoadServer(path string) (*Server, error) {
	var c Server
	if err := readFile(path, &c); err != nil {
		return nil, err
	}
	c.Defaults()
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

// Defaults заполняет значения по умолчанию.
func (c *Server) Defaults() {
	if c.Listen == "" {
		c.Listen = ":443"
	}
	if c.Path == "" {
		c.Path = masque.DefaultPath
	}
	if c.Pool4 == "" && c.Pool6 == "" {
		c.Pool4 = "10.66.0.0/24"
	}
	if c.WebTransport == nil {
		t := true
		c.WebTransport = &t
	}
	if c.ACME.Enabled() && c.ACME.CacheDir == "" {
		c.ACME.CacheDir = defaultACMECache()
	}
	c.TUN.defaults()
}

// Validate проверяет конфигурацию.
func (c *Server) Validate() error {
	var errs []error
	if n := len(c.FallbackSite.Seed); n > 0 && n < 16 {
		errs = append(errs, errors.New("fallback_site.seed: нужно не меньше 16 символов — seed должен быть неугадываемым"))
	}
	switch {
	case c.ACME.Enabled():
		// Проверка tls-alpn-01 приходит по TCP: без слушателя её пройти нечем.
		if c.TCPAddr() == "" {
			errs = append(errs, errors.New("acme: нужен tcp-слушатель — проверка tls-alpn-01 идёт по TCP"))
		} else if _, port, err := splitHostPort("tcp.listen", c.TCPAddr()); err == nil && port != "443" {
			errs = append(errs, fmt.Errorf("acme: проверка приходит на порт 443, а tcp-слушатель на %s", port))
		}
		if (c.CertFile == "") != (c.KeyFile == "") {
			errs = append(errs, errors.New("cert_file и key_file задаются вместе"))
		}
		for _, d := range c.ACME.Domains {
			if d == "" || !strings.Contains(strings.Trim(d, "."), ".") {
				errs = append(errs, fmt.Errorf("acme: %q не похоже на доменное имя", d))
			}
		}
	case c.CertFile == "" || c.KeyFile == "":
		errs = append(errs, errors.New("нужны cert_file и key_file (или acme.domains)"))
	}
	switch {
	case c.ClientsFile != "" && c.AuthKey != "":
		errs = append(errs, errors.New("auth_key и clients_file вместе не работают: "+
			"общий ключ остаётся чёрным ходом для отозванных клиентов — оставьте что-то одно"))
	case c.ClientsFile != "":
		// Ключи лежат в реестре; сам файл проверяется при запуске.
	default:
		if _, err := c.AuthKey.Bytes(); err != nil {
			errs = append(errs, err)
		}
	}
	if _, _, err := splitHostPort("listen", c.Listen); err != nil {
		errs = append(errs, err)
	}
	if err := c.TUN.validate(); err != nil {
		errs = append(errs, err)
	}
	if _, err := c.Pools(); err != nil {
		errs = append(errs, err)
	}
	if _, err := ShapingProfile(c.Shaping); err != nil {
		errs = append(errs, err)
	}
	if _, err := c.Packing.Options(); err != nil {
		errs = append(errs, err)
	}
	if _, err := c.Profile(); err != nil {
		errs = append(errs, err)
	}
	if c.FallbackProxy != "" {
		u, err := url.Parse(c.FallbackProxy)
		if err != nil || u.Scheme == "" || u.Host == "" {
			errs = append(errs, fmt.Errorf("fallback_proxy: нужен адрес вида http://host:port, получено %q", c.FallbackProxy))
		}
	}
	if a := c.TCPAddr(); a != "" {
		if _, _, err := splitHostPort("tcp.listen", a); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// UsagePath — путь к файлу учёта расхода.
func (c *Server) UsagePath() string {
	switch {
	case c.UsageFile != "":
		return c.UsageFile
	case c.ClientsFile != "":
		return c.ClientsFile + ".usage"
	default:
		return ""
	}
}

// Profile возвращает профиль транспортных параметров сервера;
// nil — оставить умолчания quic-go.
func (c *Server) Profile() (*fingerprint.ServerProfile, error) {
	if c.ServerProfileFile != "" {
		p, err := fingerprint.LoadServerProfile(c.ServerProfileFile)
		if err != nil {
			return nil, fmt.Errorf("server_profile_file: %w", err)
		}
		return &p, nil
	}
	switch c.ServerProfile {
	case "", "cloudflare":
		// Умолчание — профиль, снятый с живого сервера и встроенный в
		// бинарник. Файл нужен только чтобы подставить свой.
		p := fingerprint.Captured()
		return &p, nil
	case "cdn":
		// Прежняя эвристика: выдуманные числа порядков величин. Оставлена
		// для сравнения и на случай, если снятый профиль где-то помешает.
		p := fingerprint.CDNLike()
		return &p, nil
	case "stock":
		return nil, nil
	}
	return nil, fmt.Errorf("неизвестный server_profile %q (cloudflare, cdn, stock)", c.ServerProfile)
}

// Pools возвращает сети клиентов.
func (c *Server) Pools() ([]netip.Prefix, error) {
	var out []netip.Prefix
	if c.Pool4 != "" {
		p, err := parsePrefix("pool4", c.Pool4)
		if err != nil {
			return nil, err
		}
		if !p.Addr().Is4() {
			return nil, fmt.Errorf("pool4: %s не IPv4", p)
		}
		out = append(out, p.Masked())
	}
	if c.Pool6 != "" {
		p, err := parsePrefix("pool6", c.Pool6)
		if err != nil {
			return nil, err
		}
		if !p.Addr().Is6() || p.Addr().Is4In6() {
			return nil, fmt.Errorf("pool6: %s не IPv6", p)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}
