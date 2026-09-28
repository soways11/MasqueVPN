package config

import (
	"errors"
	"fmt"
	"net/netip"
)

// Client — конфигурация клиента. Один формат для всех платформ.
type Client struct {
	// Server — адрес сервера host:port. Host — домен (он же SNI) или IP.
	// Запасные порты перечисляются через запятую: host:8443,2053,2083 —
	// клиент перебирает их, если предыдущий не отвечает (см. ports.go).
	Server string `json:"server"`
	// ServerName — SNI и :authority, если отличаются от host из Server.
	ServerName string `json:"server_name,omitempty"`
	// AuthKey — общий ключ (base64, ≥32 байт) или «file:/путь».
	AuthKey    Key    `json:"auth_key"`
	AuthHeader string `json:"auth_header,omitempty"`
	// ClientID — постоянный псевдоним этой установки. За ним сервер
	// закрепляет туннельный адрес, поэтому при переподключении и перезапуске
	// клиент получает прежний адрес и соединения внутри туннеля не рвутся.
	// Пусто — случайный на время работы процесса (ротацию и переподключение
	// это покрывает, перезапуск — нет). Секретом не является.
	//
	// Ровно 16 шестнадцатеричных цифр — это псевдоним, ВЫДАННЫЙ сервером
	// вместе с личным ключом (vpnserver clients add): такое значение едет в
	// токене как есть, по нему сервер находит запись клиента и его ключ.
	// Любая другая строка сворачивается хэшем в 8 байт, как раньше.
	ClientID string `json:"client_id,omitempty"`
	Path     string `json:"path,omitempty"`

	// CAFile — доверенный корневой сертификат (для самоподписанного сервера).
	// Пусто — системные корни.
	CAFile string `json:"ca_file,omitempty"`

	// Transport — utls (отпечаток браузера, нужна сборка -tags utls) или
	// quic (стоковый quic-go). По умолчанию utls, если он собран.
	Transport string `json:"transport,omitempty"`
	// Parrot — встроенный профиль отпечатка (utls).
	Parrot string `json:"parrot,omitempty"`
	// FingerprintFile — снятый отпечаток браузера (JSON от fpcapture).
	FingerprintFile string `json:"fingerprint_file,omitempty"`
	// Protocol — webtransport (по умолчанию) или connect-ip.
	Protocol string `json:"protocol,omitempty"`

	TUN TUN `json:"tun"`
	// FullTunnel — весь трафик устройства через туннель (по умолчанию true).
	FullTunnel *bool `json:"full_tunnel,omitempty"`
	// Routes — сети через туннель, если full_tunnel=false.
	Routes []string `json:"routes,omitempty"`
	// IPv6 — туннелировать IPv6 (по умолчанию true). Если выключено при
	// полном туннеле, IPv6 всё равно не уходит мимо туннеля: он блокируется.
	IPv6 *bool `json:"ipv6,omitempty"`
	// KillSwitch — аварийное отключение (Windows). Пока туннель поднят,
	// наружу выпускается только туннель, петля, локальная сеть и адреса из
	// KillSwitchAllow; всё остальное блокируется в ядре, поэтому трафик не
	// утекает мимо туннеля даже там, где таблица маршрутов бессильна
	// (соединение, привязанное к физическому адаптеру).
	//
	// При смерти процесса блокировка снимается сама: она живёт в
	// динамической сессии WFP. Это осознанный размен — «минуту без VPN»
	// против «без интернета до переустановки системы», см.
	// netsetup/killswitch_windows.go.
	//
	// По умолчанию ВКЛЮЧЕНО при полном туннеле (решение 24.09.2026): без
	// него защита неполна, а узнать об утечке мимо туннеля можно только
	// снаружи. Выключается явным false. При раздельном туннеле не
	// действует.
	//
	// Указатель, а не bool: «не задано» и «выключено» — разные вещи. По
	// умолчанию ВКЛЮЧЕНО, поэтому обычный bool означал бы, что старая
	// конфигурация без этого поля молча меняет смысл, а выключить его стало
	// бы нечем.
	KillSwitch *bool `json:"kill_switch,omitempty"`
	// KillSwitchAllow — адреса и подсети, которым аварийное отключение
	// разрешает выход МИМО туннеля (адрес или CIDR).
	//
	// Сам сервер и резолверы прикрытия DNS добавляются автоматически.
	// Это поле — для стороннего, о чём знает только пользователь: другой
	// прокси-клиент, рабочий VPN, принтер в чужой подсети. Без него
	// аварийное отключение рубит такие соединения молча, и причину ищут
	// снаружи.
	KillSwitchAllow []string `json:"kill_switch_allow,omitempty"`
	// FwMark, Table — параметры маршрутизации полного туннеля (Linux).
	FwMark uint32 `json:"fwmark,omitempty"`
	Table  int    `json:"table,omitempty"`
	// DNS — DNS-серверы на время работы туннеля (Linux: /etc/resolv.conf).
	// Пусто — системные настройки не трогаются.
	DNS []string `json:"dns,omitempty"`

	// DNSByDefault — резолвер не задан в файле, а подставлен нами. В файл не
	// пишется; нужен, чтобы сказать об этом в журнале: подстановка меняет
	// то, кто видит имена, и происходить молча она не должна.
	DNSByDefault bool `json:"-"`

	// Packing — упаковка датаграмм (C2): агрегация, фрагментация, профиль.
	Packing *Packing `json:"packing,omitempty"`

	// DNSCover — фоновые DNS-запросы МИМО туннеля. При полном туннеле
	// включены по умолчанию: иначе хост часами льёт объём на один адрес,
	// не спрашивая имён, — дешёвый и устойчивый признак туннеля.
	DNSCover *DNSCover `json:"dns_cover,omitempty"`

	// Shaping — профиль маскировки трафика клиент→сервер.
	Shaping string `json:"shaping,omitempty"`
	// CoverBrowsing — фоновые запросы к сайту-прикрытию.
	CoverBrowsing *CoverBrowsing `json:"cover_browsing,omitempty"`

	Rotation Rotation `json:"rotation"`
	// NoReconnect — не переподключаться при обрыве.
	NoReconnect bool `json:"no_reconnect,omitempty"`

	LogLevel string `json:"log_level,omitempty"`
}

// CoverBrowsing — фоновые GET-запросы.
type CoverBrowsing struct {
	Paths        []string `json:"paths,omitempty"`
	MeanInterval Duration `json:"mean_interval,omitempty"`
}

// DNSCover — фоновые DNS-запросы мимо туннеля (признак «хост не делает
// DNS-запросов»). Имена берутся только из списка, настоящий DNS
// пользователя по-прежнему уходит внутрь туннеля.
type DNSCover struct {
	// Disabled выключает прикрытие.
	Disabled bool `json:"disabled,omitempty"`
	// Servers — резолверы, куда слать запросы (порт по умолчанию 53).
	// Пусто — те, которыми система пользовалась до туннеля.
	Servers []string `json:"servers,omitempty"`
	// Domains — имена для запросов; пусто — встроенный список.
	// Случайные поддомены недопустимы: это признак DNS-туннеля.
	Domains []string `json:"domains,omitempty"`
	// MeanInterval — средний интервал между группами запросов
	// (фактические паузы случайные); 0 — 45 с.
	MeanInterval Duration `json:"mean_interval,omitempty"`
}

// DNSCoverEnabled сообщает, нужно ли прикрытие DNS.
func (c *Client) DNSCoverEnabled() bool {
	if c.DNSCover != nil && c.DNSCover.Disabled {
		return false
	}
	// При раздельном туннеле DNS и так идёт мимо него — прикрывать нечего.
	return *c.FullTunnel
}

// DNSCoverServers разбирает Servers (адрес или адрес:порт).
func (c *Client) DNSCoverServers() ([]netip.AddrPort, error) {
	if c.DNSCover == nil {
		return nil, nil
	}
	var out []netip.AddrPort
	for _, s := range c.DNSCover.Servers {
		if ap, err := netip.ParseAddrPort(s); err == nil {
			out = append(out, ap)
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("dns_cover.servers: %w", err)
		}
		out = append(out, netip.AddrPortFrom(a, 53))
	}
	return out, nil
}

// Rotation — ротация соединений.
type Rotation struct {
	Every      Duration `json:"every,omitempty"`
	AfterBytes uint64   `json:"after_bytes,omitempty"`
	// KeepAddress — сохранять адрес при ротации (по умолчанию true).
	KeepAddress *bool `json:"keep_address,omitempty"`
	// Jitter — разброс срока ротации, доля от every и after_bytes
	// (0 — 0.25, отрицательное — ровно по сроку). Ровная периодичность
	// рукопожатий видна наблюдателю в открытую, поэтому разброс нужен.
	Jitter float64 `json:"jitter,omitempty"`
}

// ParseClient разбирает конфигурацию клиента из JSON (мобильные обёртки
// передают её строкой).
func ParseClient(b []byte) (*Client, error) {
	var c Client
	if err := decodeStrict(b, &c); err != nil {
		return nil, err
	}
	c.Defaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// LoadClient читает конфигурацию клиента из файла.
func LoadClient(path string) (*Client, error) {
	var c Client
	if err := readFile(path, &c); err != nil {
		return nil, err
	}
	c.Defaults()
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

func boolPtr(b bool) *bool { return &b }

// Defaults заполняет значения по умолчанию.
func (c *Client) Defaults() {
	if c.FullTunnel == nil {
		c.FullTunnel = boolPtr(true)
	}
	if c.IPv6 == nil {
		c.IPv6 = boolPtr(true)
	}
	if c.Rotation.KeepAddress == nil {
		c.Rotation.KeepAddress = boolPtr(true)
	}
	if c.KillSwitch == nil {
		// Только при полном туннеле: при раздельном блокировать всё, кроме
		// сервера, значит отрезать ровно тот трафик, который пользователь
		// сознательно оставил вне туннеля.
		c.KillSwitch = boolPtr(c.FullTunnel != nil && *c.FullTunnel)
	}
	// При полном туннеле резолвер обязателен, и вот почему. Если его не
	// задать, система продолжит спрашивать имена у резолвера локальной сети
	// — обычно у домашнего роутера, а до него можно дотянуться напрямую,
	// мимо туннеля. Получается худшее из двух: байты идут через сервер, а
	// список посещённых сайтов по-прежнему виден провайдеру. Туннель есть,
	// приватности нет, и снаружи это ничем не проявляется.
	//
	// Своего резолвера сервер не держит, поэтому по умолчанию берём
	// публичный. Обе семьи — при живом IPv6 система предпочтёт его, и
	// резолвер только для IPv4 оставил бы ту же дыру. Лишняя семья
	// отсеется при настройке интерфейса: см. UsableDNS.
	if *c.FullTunnel && len(c.DNS) == 0 {
		c.DNS = []string{"1.1.1.1", "2606:4700:4700::1111"}
		c.DNSByDefault = true
	}
	c.TUN.defaults()
}

// UsableDNS оставляет только те резолверы, до которых туннель способен
// дотянуться: у интерфейса без адреса IPv6 резолвер IPv6 не заработает, а
// система будет честно ждать ответа и упираться в таймаут на каждом имени.
func UsableDNS(servers []netip.Addr, addrs []netip.Prefix) []netip.Addr {
	var has4, has6 bool
	for _, p := range addrs {
		if p.Addr().Unmap().Is4() {
			has4 = true
		} else {
			has6 = true
		}
	}
	out := make([]netip.Addr, 0, len(servers))
	for _, s := range servers {
		if s.Unmap().Is4() {
			if has4 {
				out = append(out, s)
			}
			continue
		}
		if has6 {
			out = append(out, s)
		}
	}
	return out
}

// Validate проверяет конфигурацию.
func (c *Client) Validate() error {
	var errs []error
	if _, _, err := SplitServer(c.Server); err != nil {
		errs = append(errs, err)
	}
	if _, err := c.AuthKey.Bytes(); err != nil {
		errs = append(errs, err)
	}
	switch c.Transport {
	case "", "utls", "quic":
	default:
		errs = append(errs, fmt.Errorf("transport: %q (utls, quic)", c.Transport))
	}
	if _, err := Protocol(c.Protocol); err != nil {
		errs = append(errs, err)
	}
	if _, err := ShapingProfile(c.Shaping); err != nil {
		errs = append(errs, err)
	}
	if err := c.TUN.validate(); err != nil {
		errs = append(errs, err)
	}
	if _, err := c.RoutePrefixes(); err != nil {
		errs = append(errs, err)
	}
	if !*c.FullTunnel && len(c.Routes) == 0 {
		errs = append(errs, errors.New("full_tunnel=false, но routes пуст — через туннель ничего не пойдёт"))
	}
	if _, err := c.DNSServers(); err != nil {
		errs = append(errs, err)
	}
	if _, err := c.DNSCoverServers(); err != nil {
		errs = append(errs, err)
	}
	if _, err := c.Packing.Options(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Host возвращает имя сервера для SNI и :authority.
func (c *Client) Host() string {
	if c.ServerName != "" {
		return c.ServerName
	}
	h, _, _ := SplitServer(c.Server)
	return h
}

// ServerPorts — порты сервера в порядке перебора.
func (c *Client) ServerPorts() []string {
	_, p, _ := SplitServer(c.Server)
	return p
}

// KillSwitchAllowed разбирает KillSwitchAllow: принимает и адрес, и подсеть.
func (c *Client) KillSwitchAllowed() ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(c.KillSwitchAllow))
	for _, s := range c.KillSwitchAllow {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p)
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("kill_switch_allow: %q — не адрес и не подсеть", s)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// RoutePrefixes разбирает Routes.
func (c *Client) RoutePrefixes() ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, r := range c.Routes {
		p, err := parsePrefix("routes", r)
		if err != nil {
			return nil, err
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// DNSServers разбирает DNS.
func (c *Client) DNSServers() ([]netip.Addr, error) {
	var out []netip.Addr
	for _, s := range c.DNS {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("dns: %w", err)
		}
		out = append(out, a)
	}
	return out, nil
}
