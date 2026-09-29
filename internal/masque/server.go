package masque

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const settingsTimeout = 10 * time.Second

// SessionFunc обслуживает установленную сессию. Должна блокироваться,
// пока сессия нужна; после возврата сессия закрывается, адрес возвращается в пул.
type SessionFunc func(ctx context.Context, c *Conn, clientAddr netip.Prefix)

// ServerConfig — параметры серверной стороны CONNECT-IP.
type ServerConfig struct {
	// Pool — пул адресов для клиентов. Для двойного стека используйте Pools.
	Pool *IPPool
	// Pools — пулы адресов, по одному на семейство. Клиент получает адрес из
	// каждого: без этого работает только IPv4 ИЛИ IPv6, но не оба сразу, и
	// половина трафика уходит мимо туннеля. Если пусто, берётся Pool.
	Pools []*IPPool
	// AllowClientToClient разрешает клиентам общаться между собой внутри
	// туннеля. По умолчанию запрещено: маршруты по умолчанию — весь интернет,
	// а он включает и нашу туннельную сеть, так что без этой проверки клиент
	// может слать пакеты на адрес соседа.
	AllowClientToClient bool
	// Routes — объявляемые клиенту маршруты; по умолчанию FullRoutes().
	Routes []IPRoute
	// Path — путь, на котором принимаются CONNECT-IP запросы; по умолчанию DefaultPath.
	Path string
	// Authorize — проверка доступа до открытия сессии. nil — пускать всех.
	// Отклонённый запрос получает ответ обычного сервера (см. probe.go).
	Authorize func(*http.Request) bool
	// Identify — то же, но вдобавок возвращает псевдонимы клиента и его
	// устройства. Адрес закрепляется за парой (см. lease.go и auth): ключ у
	// человека один, а устройств несколько, и каждому нужен свой адрес.
	// Имеет приоритет над Authorize. Пустой псевдоним клиента при ok = true
	// означает «пускать, адрес не закреплять»; пустое устройство — «все
	// устройства этого клиента считать одним» (клиент старой сборки).
	Identify func(*http.Request) (clientID, deviceID string, ok bool)
	// Fallback — обработчик всех прочих запросов; по умолчанию http.NotFound.
	Fallback http.Handler
	// OnSession — обработчик сессии. nil — держать сессию до закрытия клиентом.
	OnSession SessionFunc
	// Shaping — маскировка исходящего (сервер→клиент) трафика.
	Shaping *Shaping
	// Packing — упаковка датаграмм (агрегация, фрагментация, профиль потока).
	Packing *Packing
	// Protocols — принимаемые значения :protocol.
	// По умолчанию оба: ProtocolConnectIP и ProtocolWebTransport.
	Protocols []string
	// OnAddressChange вызывается после смены адресов клиента по его
	// ADDRESS_REQUEST (например, возврат прежнего адреса после ротации).
	// Нужен маршрутизатору сервера: таблица «адрес → сессия» должна
	// следовать за выдачей.
	OnAddressChange func(c *Conn, old, new []netip.Prefix)
	// Limits — ограничения ресурсов (пункт 2.3). nil — только потолок
	// ADDRESS_REQUEST по умолчанию.
	Limits *Limits
	// Policy — политика по клиентам: пускать ли, с какой полосой, учёт
	// трафика (см. policy.go). nil — пускать всех, как было до реестра
	// клиентов.
	Policy Policy
	// AccountEvery — как часто снимать счётчики сессии для учёта.
	// 0 — DefaultAccountInterval. Учёт идёт по таймеру, а не на каждом
	// пакете: в горячий путь ради точности до килобайта лезть незачем.
	AccountEvery time.Duration
}

// DefaultAccountInterval — период снятия счётчиков для учёта трафика.
const DefaultAccountInterval = 15 * time.Second

// Handler — http.Handler, принимающий CONNECT-IP запросы.
type Handler struct {
	cfg      ServerConfig
	sessions *sessionCounter
	leases   *leaseRegistry
	live     *liveSessions
}

// NewHandler проверяет конфигурацию и создаёт обработчик.
func NewHandler(cfg ServerConfig) (*Handler, error) {
	if len(cfg.Pools) == 0 {
		if cfg.Pool == nil {
			return nil, errors.New("masque: требуется ServerConfig.Pool или Pools")
		}
		cfg.Pools = []*IPPool{cfg.Pool}
	}
	seen := map[bool]bool{}
	for _, p := range cfg.Pools {
		if p == nil {
			return nil, errors.New("masque: в ServerConfig.Pools есть nil")
		}
		is4 := p.Prefix().Addr().Is4()
		if seen[is4] {
			return nil, fmt.Errorf("masque: два пула одного семейства адресов (%s)", p.Prefix())
		}
		seen[is4] = true
	}
	if cfg.Pool == nil {
		cfg.Pool = cfg.Pools[0]
	}
	if cfg.Routes == nil {
		cfg.Routes = FullRoutes()
	}
	for i := 1; i < len(cfg.Routes); i++ {
		if err := checkRouteOrder(cfg.Routes[i-1], cfg.Routes[i]); err != nil {
			return nil, err
		}
	}
	if cfg.Path == "" {
		cfg.Path = DefaultPath
	}
	if cfg.Fallback == nil {
		cfg.Fallback = http.HandlerFunc(http.NotFound)
	}
	if len(cfg.Protocols) == 0 {
		cfg.Protocols = []string{ProtocolConnectIP, ProtocolWebTransport}
	}
	for _, p := range cfg.Protocols {
		if _, ok := normalizeProtocol(p); !ok {
			return nil, fmt.Errorf("masque: unknown protocol %q", p)
		}
	}
	return &Handler{
		cfg:      cfg,
		sessions: newSessionCounter(),
		leases:   newLeaseRegistry(cfg.Pools, cfg.Limits.leaseTTL()),
		live:     newLiveSessions(),
	}, nil
}

type settingser interface {
	ReceivedSettings() <-chan struct{}
	Settings() *http3.Settings
}

// accepts сообщает, принимает ли обработчик такую метку :protocol.
func (h *Handler) accepts(proto string) bool {
	for _, p := range h.cfg.Protocols {
		if p == proto {
			return true
		}
	}
	return false
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		// Обычный веб-запрос — обычный ответ сайта-прикрытия.
		h.cfg.Fallback.ServeHTTP(w, r)
		return
	}
	// Дальше только CONNECT, и сайту его отдавать нельзя: он ответит 200 и
	// телом страницы, чего обычный сервер на CONNECT не делает. См. probe.go.
	switch {
	case !isExtendedCONNECT(r):
		// Классический CONNECT: мы origin-сервер, а не прокси.
		rejectCONNECT(w, http.StatusMethodNotAllowed)
	case !h.accepts(r.Proto):
		// :protocol, которого сервер не поддерживает (RFC 8441, §5.1).
		rejectCONNECT(w, http.StatusNotImplemented)
	case r.URL.Path != h.cfg.Path:
		// Для приложения с WebTransport путь — обычный маршрут.
		rejectStranger(w, r)
	default:
		id, device, ok := h.identify(r)
		if !ok {
			// Тот же ответ, что и у несуществующего маршрута: по нему нельзя
			// узнать, что туннельный путь вообще существует.
			rejectStranger(w, r)
			return
		}
		h.serveTunnel(w, r, id, device)
	}
}

// identify проверяет доступ и возвращает псевдонимы клиента и устройства
// (пустые, если проверки нет или токен без них).
func (h *Handler) identify(r *http.Request) (clientID, deviceID string, ok bool) {
	switch {
	case h.cfg.Identify != nil:
		return h.cfg.Identify(r)
	case h.cfg.Authorize != nil:
		return "", "", h.cfg.Authorize(r)
	default:
		return "", "", true
	}
}

// serveTunnel обслуживает принятый запрос CONNECT-IP.
func (h *Handler) serveTunnel(w http.ResponseWriter, r *http.Request, clientID, deviceID string) {
	if v := r.Header.Get(http3.CapsuleProtocolHeader); v != "" && v != "?1" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	streamer, ok1 := w.(http3.HTTPStreamer)
	st, ok2 := w.(settingser)
	if !ok1 || !ok2 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Датаграммы должны быть согласованы с обеих сторон.
	timer := time.NewTimer(settingsTimeout)
	defer timer.Stop()
	select {
	case <-st.ReceivedSettings():
	case <-r.Context().Done():
		return
	case <-timer.C:
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !st.Settings().EnableDatagrams {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Лимиты ресурсов занимаем до выделения адреса: отказ не должен
	// расходовать адрес из пула.
	releaseSlot, ok := h.sessions.acquire(clientIP(r), h.cfg.Limits)
	if !ok {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	defer releaseSlot()

	// Политика клиента — до выделения адреса и по той же причине: отказ не
	// должен расходовать адрес из пула. Причина отказа уходит в журнал
	// сервера, а клиент получает ровно тот же ответ, что посторонний.
	if h.cfg.Policy != nil {
		if err := h.cfg.Policy.Admit(clientID, h.live.count(clientID)); err != nil {
			rejectStranger(w, r)
			return
		}
	}

	// Адреса берутся в аренду за УСТРОЙСТВОМ клиента (см. lease.go):
	// вернувшееся устройство получает свой прежний адрес сразу, а не
	// выпрашивает его капсулой после того, как старая сессия наконец
	// закроется, — а два устройства одного клиента работают каждое со своим
	// адресом и потому одновременно. По адресу из каждого пула: иначе двойной
	// стек не работает.
	lease, err := h.leases.acquire(clientID, deviceID)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	defer h.leases.release(lease)
	addrs := h.leases.addrsOf(lease)

	w.Header().Set(http3.CapsuleProtocolHeader, "?1")
	w.WriteHeader(http.StatusOK)
	str := streamer.HTTPStream() // отправляет заголовки ответа

	c := newConn(serverStream{str}, roleServer, nil)
	c.shaping = h.cfg.Shaping
	c.packing = h.cfg.Packing
	if !h.cfg.AllowClientToClient {
		// Туннельные сети закрыты для клиента: внутрь них он слать не может,
		// кроме собственных адресов (их проверяет общая политика).
		for _, p := range h.cfg.Pools {
			c.tunnelNets = append(c.tunnelNets, p.Prefix())
			// Шлюз — это сам сервер, а не сосед: до него можно (ping,
			// в будущем — DNS на адресе шлюза).
			c.tunnelOpen = append(c.tunnelOpen, p.Gateway())
		}
	}
	c.maxAddrReqs = h.cfg.Limits.maxAddressRequests()
	c.maxUnknownCaps = h.cfg.Limits.maxUnknownCapsules()
	if h.cfg.Limits != nil {
		c.idleTimeout = h.cfg.Limits.IdleTimeout
		c.limiter = newRateLimiter(h.cfg.Limits.MaxBytesPerSecond, h.cfg.Limits.BurstBytes)
	}
	if h.cfg.Policy != nil {
		if bps, burst := h.cfg.Policy.RateLimit(clientID); bps > 0 {
			c.limiter = newRateLimiter(bps, burst)
		}
	}
	h.live.add(clientID, c)
	defer h.live.remove(clientID, c)
	if ss, ok := h.cfg.Policy.(sessionStarter); ok && clientID != "" {
		ss.StartedSession(clientID)
	}
	c.onAddrReq = func(c *Conn, reqs []RequestedAddress) {
		// RFC 9484: клиент может попросить конкретный адрес — например, свой
		// прежний, чтобы соединения внутри туннеля пережили переподключение.
		// Выдаём запрошенный, если он свободен; иначе оставляем текущий.
		cur := h.leases.addrsOf(lease)
		ids := make([]uint64, len(cur))
		changed := false
		for _, rq := range reqs {
			want := rq.Prefix.Addr()
			idx := -1
			for i, a := range cur {
				if a.Addr().Is4() == want.Is4() {
					idx = i
					break
				}
			}
			if idx < 0 {
				continue // этого семейства сервер не обслуживает
			}
			ids[idx] = rq.RequestID
			if want == cur[idx].Addr() || want.IsUnspecified() {
				continue // просят то, что уже выдано, либо без предпочтений
			}
			got, err := h.cfg.Pools[idx].Allocate(want)
			if err != nil {
				continue // пул исчерпан — остаёмся при своём
			}
			if got.Addr() != want {
				h.cfg.Pools[idx].Release(got) // дали не то, что просили
				continue
			}
			h.cfg.Pools[idx].Release(cur[idx])
			cur[idx] = got
			changed = true
		}
		if changed {
			prev := h.leases.addrsOf(lease)
			h.leases.setAddrs(lease, cur)
			_ = c.AssignAddresses(cur, ids...)
			if h.cfg.OnAddressChange != nil {
				h.cfg.OnAddressChange(c, prev, slices.Clone(cur))
			}
			return
		}
		_ = c.AssignAddresses(cur, ids...)
	}
	// Первичную выдачу делаем ДО запуска обработчика капсул: иначе он может
	// начать менять адреса по ADDRESS_REQUEST одновременно с чтением здесь.
	// Запись капсул обработчика не требует.
	initial := slices.Clone(addrs)
	if err := c.AssignAddresses(initial); err != nil {
		return
	}
	if err := c.AdvertiseRoutes(h.cfg.Routes); err != nil {
		return
	}

	c.start()
	defer c.Close()

	if h.cfg.Policy != nil && clientID != "" {
		stopAcct := h.accountLoop(c, clientID)
		defer stopAcct()
	}

	if h.cfg.OnSession != nil {
		// Передаётся адрес на момент открытия сессии; далее он может смениться
		// по ADDRESS_REQUEST — актуальный смотреть через Conn.
		h.cfg.OnSession(c.ctx, c, initial[0])
		return
	}
	<-c.Done()
}

// HTTP3Option настраивает HTTP/3-сервер.
type HTTP3Option func(*http3.Server)

// WithWebTransportSettings заставляет сервер объявлять SETTINGS настоящего
// WebTransport-сервера. Нужно, чтобы маскировка под WebTransport была
// согласованной: метка :protocol без этих SETTINGS выглядит подозрительно.
func WithWebTransportSettings() HTTP3Option {
	return func(s *http3.Server) {
		if s.AdditionalSettings == nil {
			s.AdditionalSettings = map[uint64]uint64{}
		}
		for k, v := range WebTransportSettings() {
			s.AdditionalSettings[k] = v
		}
	}
}

// WithQUICConfig подменяет настройки QUIC сервера — так подставляется
// профиль транспортных параметров (отпечаток серверной стороны, C1).
// Датаграммы и выключенный PMTUD выставляются поверх в любом случае:
// без первых невозможен CONNECT-IP, второй ломает оценку потолка
// датаграммы в quic-go v0.59 (см. Dial).
func WithQUICConfig(conf *quic.Config) HTTP3Option {
	return func(s *http3.Server) {
		c := conf.Clone()
		c.EnableDatagrams = true
		c.DisablePathMTUDiscovery = true
		if c.InitialPacketSize == 0 {
			c.InitialPacketSize = DefaultInitialPacketSize
		}
		if c.KeepAlivePeriod == 0 {
			c.KeepAlivePeriod = randomKeepAlive()
		}
		s.QUICConfig = c
	}
}

// NewHTTP3Server создаёт HTTP/3-сервер с включёнными датаграммами.
func NewHTTP3Server(addr string, tlsConf *tls.Config, h http.Handler, opts ...HTTP3Option) *http3.Server {
	srv := &http3.Server{
		Addr:            addr,
		TLSConfig:       http3.ConfigureTLSConfig(tlsConf),
		Handler:         h,
		EnableDatagrams: true,
		QUICConfig: &quic.Config{
			EnableDatagrams: true,
			// Случайный, а не ровно 15 с: одинаковый период у всех серверов
			// сборки — метроном и признак.
			KeepAlivePeriod: randomKeepAlive(),
			// 1350 байт с первого пакета: при меньшем размере (по умолчанию
			// 1280) в датаграмму не влезает IPv6-пакет минимального MTU 1280,
			// и IPv6 внутри туннеля не работает, пока не отработает PMTUD.
			InitialPacketSize: DefaultInitialPacketSize,
			// PMTUD выключен из-за ошибки оценки в quic-go v0.59 — см. Dial.
			DisablePathMTUDiscovery: true,
			MaxIdleTimeout:          60 * time.Second,
		},
	}
	for _, o := range opts {
		o(srv)
	}
	return srv
}
