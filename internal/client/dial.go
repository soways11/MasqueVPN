// Package client собирает клиентскую сторону из конфигурации: дозвон с
// нужным транспортом, аутентификацией и маскировкой, ротацию и
// переподключение. Платформенно-независим: настройку сети и TUN делает
// вызывающий (cmd/vpnclient на Linux, мобильные обёртки — через систему).
package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/soways11/masquevpn/internal/auth"
	"github.com/soways11/masquevpn/internal/config"
	"github.com/soways11/masquevpn/internal/fingerprint"
	"github.com/soways11/masquevpn/internal/masque"
	"github.com/soways11/masquevpn/internal/obfuscation"
	"github.com/soways11/masquevpn/internal/session"
	"github.com/soways11/masquevpn/internal/utlsquic"
)

// Options — платформенные зацепки.
type Options struct {
	// Protect помечает сокет так, чтобы его трафик шёл МИМО туннеля:
	// SO_MARK на Linux, VpnService.protect на Android. nil — не помечать.
	// Применяется и к UDP-сокету QUIC, и к DNS-запросам имени сервера.
	Protect func(syscall.RawConn) error
	Logger  *slog.Logger
	// DeviceID — псевдоним этого устройства. Пусто — берётся из
	// config.DeviceID (файл рядом с программой). Задаётся там, где такого
	// файла нет: на Android место для данных приложение знает само.
	//
	// Нужен для одновременной работы нескольких устройств по одному ключу:
	// адрес сервер закрепляет за парой клиент+устройство (см. internal/auth).
	DeviceID string
	// Resolvers — DNS-серверы, которыми разрешать имя сервера, вместо
	// системного списка. Действуют только вместе с Protect (встроенный
	// резолвер Go).
	//
	// Нужны на Android: /etc/resolv.conf там нет, и встроенный резолвер,
	// не найдя его, стучится в [::1]:53 и 127.0.0.1:53 — туда, где никто не
	// слушает («connection refused»). Настоящие резолверы сети знает
	// только система, и приложение передаёт их сюда.
	Resolvers []netip.AddrPort
	// Ports — где помнить удачный порт сервера между запусками (см.
	// PortMemory). nil — помнить только до конца процесса.
	Ports PortMemory
}

func deviceID(opt Options) string {
	if opt.DeviceID != "" {
		return opt.DeviceID
	}
	return config.DeviceID()
}

// Dialer устанавливает CONNECT-IP сессии по конфигурации.
type Dialer struct {
	cfg   *config.Client
	opt   Options
	log   *slog.Logger
	auth  *auth.Authenticator
	roots *x509.CertPool
	spec  any
	proto string
	host  string
	// ports — порты сервера в порядке перебора (см. config.SplitServer);
	// cur — номер последнего ответившего: следующий дозвон начинается с него.
	ports    []string
	cur      atomic.Int32
	okPort   atomic.Value // string: порт последнего удачного дозвона
	resolver *net.Resolver
	// fixed — резолверы по одному на сервер из Options.Resolvers, по порядку.
	fixed []*net.Resolver

	// tickets — общий на все дозвоны кэш TLS-билетов. Благодаря ему
	// ротация и переподключение идут возобновлением сессии, как у браузера,
	// а не полным рукопожатием каждый раз.
	tickets tls.ClientSessionCache

	// legacy — сервер не понимает токен с устройством (см. legacyRetry).
	legacy atomic.Bool

	// attempt — одна попытка на одном порту; подменяется в тестах.
	attempt func(ctx context.Context, ip, port string, last bool) (*masque.Conn, error)

	mu       sync.Mutex
	lastAddr netip.Addr
}

// NewDialer проверяет конфигурацию и готовит дозвон.
func NewDialer(cfg *config.Client, opt Options) (*Dialer, error) {
	key, err := cfg.AuthKey.Bytes()
	if err != nil {
		return nil, err
	}
	authOpts := auth.Options{Header: cfg.AuthHeader, DeviceID: []byte(deviceID(opt))}
	// Псевдоним, выданный сервером, едет как есть: по нему сервер находит
	// клиента в реестре. Произвольную строку по-прежнему сворачиваем хэшем.
	if raw, ok := exactClientID(cfg.ClientID); ok {
		authOpts.ClientIDExact = raw
	} else {
		authOpts.ClientID = []byte(cfg.ClientID)
	}
	a, err := auth.New(key, authOpts)
	if err != nil {
		return nil, err
	}
	d := &Dialer{cfg: cfg, opt: opt, log: opt.Logger, auth: a, tickets: tls.NewLRUClientSessionCache(8)}
	if d.log == nil {
		d.log = slog.New(slog.DiscardHandler)
	}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("ca_file: %w", err)
		}
		d.roots = x509.NewCertPool()
		if !d.roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_file: в %s нет сертификатов", cfg.CAFile)
		}
	}
	switch cfg.Transport {
	case "":
		if utlsquic.Available() {
			cfg.Transport = "utls"
		} else {
			cfg.Transport = "quic"
		}
	case "utls":
		if !utlsquic.Available() {
			return nil, utlsquic.ErrNotBuilt
		}
	}
	if cfg.FingerprintFile != "" {
		if cfg.Transport != "utls" {
			return nil, errors.New("fingerprint_file требует transport=utls")
		}
		if d.spec, err = utlsquic.LoadSpec(cfg.FingerprintFile); err != nil {
			return nil, fmt.Errorf("fingerprint_file: %w", err)
		}
	}
	if d.proto, err = config.Protocol(cfg.Protocol); err != nil {
		return nil, err
	}
	host, ports, err := config.SplitServer(cfg.Server)
	if err != nil {
		return nil, err
	}
	d.host, d.ports = host, ports
	d.attempt = d.dialPort
	// Начинаем с порта, который ответил в прошлый раз, — если он всё ещё в
	// списке (порты сервера могли смениться с тех пор).
	if opt.Ports != nil {
		if p := opt.Ports.Port(d.host); p != "" {
			for i, q := range d.ports {
				if q == p {
					d.cur.Store(int32(i))
					break
				}
			}
		}
	}
	// Резолвер по умолчанию системный, и это не мелочь. Системный знает
	// порядок адаптеров, NRPT, файл hosts и настройки DNS-over-HTTPS;
	// встроенный в Go берёт серверы со ВСЕХ адаптеров подряд — включая
	// отключённые виртуальные, которые оставляют после себя VirtualBox,
	// WSL или VPN-клиенты, — и упирается в таймаут на первом же мёртвом.
	// Снаружи это выглядит как «клиент не может найти сервер», хотя
	// браузер на той же машине открывает тот же домен без запинки.
	//
	// Встроенный нужен ровно в одном случае: когда сокет резолвера надо
	// увести мимо туннеля (метка на Linux, protect на Android) — своё Dial
	// уважает только он. Там же это и обязательно: при переподключении
	// туннель не работает, и запрос через него не дошёл бы никуда.
	d.resolver = &net.Resolver{}
	if opt.Protect != nil {
		d.resolver.PreferGo = true
		protectedDial := func(ctx context.Context, network, address string) (net.Conn, error) {
			nd := net.Dialer{Control: func(_, _ string, rc syscall.RawConn) error { return opt.Protect(rc) }}
			return nd.DialContext(ctx, network, address)
		}
		d.resolver.Dial = protectedDial
		// Серверы заданы явно — по резолверу на каждый, опрашиваются по
		// очереди (см. lookup). Не «по кругу в одном резолвере»: Go шлёт
		// запросы A и AAAA параллельно, и круг развёл бы их по разным
		// серверам — A ушёл бы на недоступный запасной, пока основной
		// отвечает. Так и было на стенде: имя не находилось при живом
		// резолвере.
		for _, srv := range opt.Resolvers {
			addr := srv.String()
			d.fixed = append(d.fixed, &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return protectedDial(ctx, network, addr)
				},
			})
		}
	}
	return d, nil
}

// Transport возвращает выбранный транспорт (utls или quic).
func (d *Dialer) Transport() string { return d.cfg.Transport }

// ServerIP — адрес, по которому клиент фактически подключается (после
// разрешения имени). Нужен там, где трафик самого туннеля уводится мимо
// туннеля маршрутом, а не меткой сокета, — то есть на Windows.
func (d *Dialer) ServerIP() netip.Addr {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.lastAddr
}

// resolve возвращает IP-адрес сервера (без порта). При ошибке разрешения
// используется последний удачный адрес.
func (d *Dialer) resolve(ctx context.Context) (string, error) {
	if ip, err := netip.ParseAddr(d.host); err == nil {
		// Адрес записываем и в этом случае: по ServerIP платформы уводят
		// трафик туннеля МИМО туннеля (маршрут-исключение на Windows,
		// список исключений у мобильного ядра). Без этой строки конфигурация
		// с адресом вместо имени давала пустой ServerIP — и полный туннель
		// заворачивал сам себя, молча и без единой ошибки в журнале.
		d.mu.Lock()
		d.lastAddr = ip
		d.mu.Unlock()
		return ip.String(), nil
	}
	ips, err := d.lookup(ctx)
	d.mu.Lock()
	defer d.mu.Unlock()
	if err == nil && len(ips) > 0 {
		// Предпочитаем IPv4: QUIC-пакеты по IPv4 крупнее (1252 против 1232
		// в uTLS-пути), а IPv6 у части провайдеров работает хуже.
		pick := ips[0]
		for _, ip := range ips {
			if ip.Unmap().Is4() {
				pick = ip.Unmap()
				break
			}
		}
		d.lastAddr = pick
	} else if !d.lastAddr.IsValid() {
		return "", fmt.Errorf("разрешение %s: %w", d.host, err)
	} else {
		d.log.Warn("не удалось разрешить имя сервера, используется прежний адрес", "host", d.host, "addr", d.lastAddr, "err", err)
	}
	return d.lastAddr.String(), nil
}

// perServerTimeout — сколько ждать один резолвер из явного списка, прежде
// чем спросить следующий. Мобильная сеть отвечает за сотни миллисекунд;
// молчание дольше двух секунд — почти всегда недоступный сервер.
const perServerTimeout = 2 * time.Second

// lookup разрешает имя сервера: системным (или встроенным) резолвером либо,
// если серверы заданы явно, каждым по очереди до первого ответа с адресами.
func (d *Dialer) lookup(ctx context.Context) ([]netip.Addr, error) {
	if len(d.fixed) == 0 {
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return d.resolver.LookupNetIP(rctx, "ip", d.host)
	}
	var lastErr error
	for _, r := range d.fixed {
		if ctx.Err() != nil {
			break
		}
		sctx, cancel := context.WithTimeout(ctx, perServerTimeout)
		ips, err := r.LookupNetIP(sctx, "ip", d.host)
		cancel()
		if err == nil && len(ips) > 0 {
			return ips, nil
		}
		if err == nil {
			err = fmt.Errorf("нет адресов для %s", d.host)
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = ctx.Err()
	}
	return nil, lastErr
}

func (d *Dialer) authority(port string) string {
	h := d.cfg.Host()
	if port == "443" {
		return h // как браузер: порт по умолчанию не пишется
	}
	return net.JoinHostPort(h, port)
}

func (d *Dialer) listenUDP() (*net.UDPConn, error) {
	c, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	if d.opt.Protect != nil {
		rc, err := c.SyscallConn()
		if err == nil {
			err = d.opt.Protect(rc)
		}
		if err != nil {
			c.Close()
			return nil, fmt.Errorf("защита сокета: %w", err)
		}
	}
	return c, nil
}

func (d *Dialer) coverBrowsing() *masque.CoverBrowsing {
	cb := d.cfg.CoverBrowsing
	if cb == nil {
		return nil
	}
	out := &masque.CoverBrowsing{Paths: cb.Paths}
	if cb.MeanInterval > 0 {
		out.Next = obfuscation.CoverInterval(cb.MeanInterval.D())
	}
	return out
}

// Dial устанавливает одну сессию и дожидается адреса и маршрутов.
// Каждый вызов — свежий токен и свежий профиль маскировки.
//
// Портов у сервера может быть несколько (host:8443,2053,…). Начинаем с
// того, что ответил в прошлый раз, и идём по кругу, пока какой-нибудь не
// ответит. На следующий порт переходим, только когда этот МОЛЧИТ (см.
// unreachable): отказ сервера, чужой сертификат или неверный ключ на
// другом порту не исправятся, и перебор лишь затянул бы ошибку.
func (d *Dialer) Dial(ctx context.Context) (*masque.Conn, error) {
	ip, err := d.resolve(ctx)
	if err != nil {
		return nil, err
	}
	n := len(d.ports)
	start := int(d.cur.Load()) % n
	var silent []string
	for i := 0; i < n; i++ {
		idx := (start + i) % n
		port := d.ports[idx]
		last := i == n-1
		c, err := d.attempt(ctx, ip, port, last)
		if err == nil {
			d.cur.Store(int32(idx))
			// Сообщаем и запоминаем, только когда порт сменился: ротация и
			// переподключения на том же порту — обычное дело.
			if prev, _ := d.okPort.Swap(port).(string); prev != port && n > 1 {
				d.log.Info("сервер отвечает на порту "+port, "port", port)
				if d.opt.Ports != nil {
					d.opt.Ports.Remember(d.host, port)
				}
			}
			return c, nil
		}
		if ctx.Err() != nil || !unreachable(err) {
			return nil, err
		}
		silent = append(silent, port)
		if !last {
			d.log.Warn("порт "+port+" не отвечает — пробую следующий", "port", port, "next", d.ports[(idx+1)%n], "err", err)
		}
		if i == n-1 {
			return nil, &PortsError{Host: d.host, Ports: silent, Err: err}
		}
	}
	return nil, errors.New("client: нет портов сервера") // недостижимо: SplitServer даёт хотя бы один
}

// perPortTimeout — сколько ждать рукопожатия на одном порту, когда впереди
// есть другие. Сам QUIC сдаётся через 5 с тишины; предел чуть больше нужен
// на случай, когда пакеты идут, а рукопожатие всё не завершается.
const perPortTimeout = 8 * time.Second

// ConnectTimeout — сколько отводить на первое подключение: столько, чтобы
// успеть перебрать все порты. Вызывающие ставят этот срок на OpenSession.
func (d *Dialer) ConnectTimeout() time.Duration {
	return max(30*time.Second, time.Duration(len(d.ports))*perPortTimeout+10*time.Second)
}

// stall — сторож сессии признал путь мёртвым (см. session.Config.StallAfter):
// порт, по которому шла связь, посреди сессии перестал пропускать пакеты.
// Переподключение начнётся со следующего порта: этот, скорее всего, начали
// резать. Если это была не блокировка, а пропавшая сеть, — не беда: перебор
// идёт по кругу и дойдёт до него снова.
func (d *Dialer) stall() {
	n := len(d.ports)
	cur := int(d.cur.Load()) % n
	if n == 1 {
		d.log.Warn("связь с сервером пропала посреди сессии — переподключаюсь", "port", d.ports[cur])
		return
	}
	next := (cur + 1) % n
	d.cur.Store(int32(next))
	d.log.Warn("порт "+d.ports[cur]+" перестал отвечать посреди сессии — переподключаюсь через "+d.ports[next],
		"port", d.ports[cur], "next", d.ports[next])
}

// Сторож пути (см. session.Config.StallAfter): через сколько тишины при
// отправке проверять путь и сколько ждать ответа на проверку. Вместе с
// рукопожатием на следующем порту туннель оживает секунд за 10–15 — против
// 30–60 по таймауту простоя QUIC.
const (
	stallAfter   = 6 * time.Second
	probeTimeout = 4 * time.Second
)

// Ports — порты сервера в порядке перебора.
func (d *Dialer) Ports() []string { return append([]string(nil), d.ports...) }

// dialPort — попытка на одном порту: транспорт, затем адрес и маршруты.
// Предел perPortTimeout ставится только на транспорт и только если после
// этого порта есть другие: дальше сервер уже ответил, и ожидание адреса к
// выбору порта отношения не имеет.
func (d *Dialer) dialPort(ctx context.Context, ip, port string, last bool) (*masque.Conn, error) {
	shaping, err := config.ShapingProfile(d.cfg.Shaping)
	if err != nil {
		return nil, err
	}
	packing, err := d.cfg.Packing.Options()
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(ip, port)
	dialWith := func(hdr http.Header) (*masque.Conn, error) {
		tctx, cancel := ctx, context.CancelFunc(func() {})
		if !last {
			tctx, cancel = context.WithTimeout(ctx, perPortTimeout)
		}
		defer cancel()
		return d.dialTransport(tctx, addr, port, hdr, shaping, packing)
	}
	hdr, err := d.tokenHeader()
	if err != nil {
		return nil, err
	}
	c, err := dialWith(hdr)
	if err != nil {
		if hdr2, ok := d.legacyRetry(err); ok {
			c, err = dialWith(hdr2)
			if err == nil {
				// Сервер прошлой сборки: дальше сразу старым токеном, чтобы
				// не платить лишним дозвоном за каждое подключение.
				d.legacy.Store(true)
				d.log.Warn("сервер не понимает токен с устройством — работаем по-старому; " +
					"на таком сервере одновременно живёт только одно устройство ключа")
			}
		}
	}
	if err != nil {
		return nil, err
	}
	if _, err := c.WaitForAddress(ctx); err != nil {
		c.Close()
		return nil, fmt.Errorf("ожидание адреса: %w", err)
	}
	return d.finishDial(ctx, c)
}

// unreachable — ошибка значит «с этого порта никто не ответил»: истёк срок
// или рукопожатие не состоялось за отведённое QUIC время (так выглядит и
// выключенный сервер, и порт, который режут по пути), пришёл ICMP «порт
// недоступен», либо пакет не выпустил файрвол на самой машине (EPERM,
// EACCES при отправке — корпоративные правила, антивирус). Всё остальное —
// ответ сервера, и другой порт его не изменит.
func unreachable(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// PortsError — сервер не ответил ни на одном из портов.
//
// Раньше человек видел «timeout: no recent network activity» и не мог
// отличить блокировку от опечатки в адресе или выключенного сервера. Текст
// короткий: в окне под ошибку две строки по 50 знаков.
type PortsError struct {
	Host  string
	Ports []string // в порядке попыток
	Err   error    // последняя ошибка
}

func (e *PortsError) Error() string {
	if len(e.Ports) == 1 {
		return "порт " + e.Ports[0] + " не отвечает: закрыт по пути или сервер выключен"
	}
	return "порты " + strings.Join(e.Ports, ", ") + " не отвечают: закрыты по пути или сервер выключен"
}

func (e *PortsError) Unwrap() error { return e.Err }

// tokenHeader — заголовок со свежим токеном. Версия зависит от того, понял ли
// её сервер (см. legacyRetry).
func (d *Dialer) tokenHeader() (http.Header, error) {
	if d.legacy.Load() {
		return d.auth.HeaderLegacy()
	}
	return d.auth.Header()
}

// legacyRetry решает, повторить ли дозвон токеном прошлой версии.
//
// Токен с устройством — версии 3, и сервер, собранный до него, отвечает на
// такой токен как постороннему: обычной страницей, не выдавая, что он VPN
// (см. probe.go на сервере). Отличить это от «не тот путь» или «не тот ключ»
// снаружи нельзя, поэтому не разбираемся, а просто пробуем ещё раз старым
// токеном: там, где дело не в версии, он получит тот же отказ, и потеряется
// один дозвон на неудачной попытке.
//
// Без этого обновление клиента раньше сервера выглядело бы как «перестало
// работать без причины».
func (d *Dialer) legacyRetry(err error) (http.Header, bool) {
	if d.legacy.Load() {
		return nil, false
	}
	var re *masque.ResponseError
	if !errors.As(err, &re) || re.StatusCode != http.StatusNotFound {
		return nil, false
	}
	hdr, herr := d.auth.HeaderLegacy()
	if herr != nil {
		return nil, false
	}
	return hdr, true
}

// dialTransport поднимает сессию выбранным транспортом.
func (d *Dialer) dialTransport(ctx context.Context, addr, port string, hdr http.Header,
	shaping *masque.Shaping, packing *masque.Packing) (*masque.Conn, error) {

	var c *masque.Conn
	var err error
	switch d.cfg.Transport {
	case "utls":
		c, err = utlsquic.Dial(ctx, utlsquic.Config{
			Addr:          addr,
			ServerName:    d.cfg.Host(),
			RootCAs:       d.roots,
			Authority:     d.authority(port),
			Path:          d.cfg.Path,
			Header:        hdr,
			Shaping:       shaping,
			Packing:       packing,
			CoverBrowsing: d.coverBrowsing(),
			Parrot:        d.cfg.Parrot,
			CustomSpec:    d.spec,
			Protocol:      d.proto,
			ListenUDP:     d.listenUDP,
		})
	default:
		prof := fingerprint.Chrome()
		// Размер пакета — не как в профиле (1200): иначе в датаграмму не
		// влезает IPv6-пакет минимального MTU. См. masque.DefaultInitialPacketSize.
		prof.InitialPacketSize = masque.DefaultInitialPacketSize
		prof.KeepAlivePeriod = 0 // случайный, выбирает masque.Dial
		c, err = masque.Dial(ctx, masque.ClientConfig{
			Addr: addr,
			TLSConfig: prof.TLSConfig(&tls.Config{
				ServerName:         d.cfg.Host(),
				RootCAs:            d.roots,
				ClientSessionCache: d.tickets,
			}),
			QUICConfig:    prof.QUICConfig(),
			Authority:     d.authority(port),
			Path:          d.cfg.Path,
			Header:        hdr,
			Shaping:       shaping,
			Packing:       packing,
			Protocol:      d.proto,
			CoverBrowsing: d.coverBrowsing(),
			ListenUDP:     d.listenUDP,
		})
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

// finishDial доводит поднятую сессию до готовности: маршруты, прогрев канала.
func (d *Dialer) finishDial(ctx context.Context, c *masque.Conn) (*masque.Conn, error) {
	// Маршруты приходят отдельной капсулой; без них WritePacket отвергает всё.
	for len(c.Routes()) == 0 {
		select {
		case <-ctx.Done():
			c.Close()
			return nil, fmt.Errorf("ожидание маршрутов: %w", ctx.Err())
		case <-c.Done():
			return nil, c.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	if c.Resumed() {
		// Браузер возобновляет сессии постоянно; для нас это ещё и дешевле.
		d.log.Debug("TLS-сессия возобновлена по билету")
	}
	// IPv6 требует от канала 1280 байт; в uTLS-пути столько помещается не
	// сразу, а после первых проб PMTUD — ждём их, но недолго.
	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	capacity := c.WarmUp(wctx, minIPv6MTU)
	cancel()
	if capacity < minIPv6MTU {
		d.log.Warn("в датаграмму помещается меньше 1280 байт: IPv6 в туннеле работать не будет, IPv4 — через ICMP", "capacity", capacity)
	}
	return c, nil
}

const minIPv6MTU = 1280

// OpenSession поднимает сессию с ротацией и переподключением по конфигурации.
// onRotate вызывается при смене адресов (ротация, переподключение).
func (d *Dialer) OpenSession(ctx context.Context, onRotate func(old, new []netip.Prefix)) (*session.Session, error) {
	return session.Open(ctx, session.Config{
		Dial: d.Dial,
		// Переподключение и ротация — тот же перебор портов, срок нужен на все.
		DialTimeout: max(15*time.Second, time.Duration(len(d.ports))*perPortTimeout+7*time.Second),
		Every:       d.cfg.Rotation.Every.D(),
		AfterBytes:  d.cfg.Rotation.AfterBytes,
		Jitter:      d.cfg.Rotation.Jitter,
		KeepAddress: *d.cfg.Rotation.KeepAddress,
		Reconnect:   !d.cfg.NoReconnect,
		OnRotate:    onRotate,
		// Порт могут начать резать посреди сессии — пакеты тогда пропадают
		// молча. Сторож замечает это и переводит клиент на следующий порт
		// (см. stall); адрес в туннеле при этом сохраняется.
		StallAfter:   stallAfter,
		ProbeTimeout: probeTimeout,
		OnStall:      d.stall,
		OnReconnect: func(attempt int, err error) {
			if err != nil {
				d.log.Warn("переподключение не удалось", "attempt", attempt, "err", err)
			} else {
				d.log.Info("соединение восстановлено", "attempt", attempt)
			}
		},
	})
}

// exactClientID распознаёт псевдоним, выданный сервером: 16 шестнадцатеричных
// цифр. Всё остальное — произвольная строка пользователя.
func exactClientID(s string) ([]byte, bool) {
	if len(s) != 2*auth.ClientIDLen {
		return nil, false
	}
	b, err := hex.DecodeString(strings.ToLower(s))
	if err != nil {
		return nil, false
	}
	return b, true
}
