//go:build linux

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"time"

	acmeclient "github.com/soways11/masquevpn/internal/acme"
	"github.com/soways11/masquevpn/internal/auth"
	"github.com/soways11/masquevpn/internal/certfile"
	"github.com/soways11/masquevpn/internal/config"
	"github.com/soways11/masquevpn/internal/fingerprint"
	"github.com/soways11/masquevpn/internal/masque"
	"github.com/soways11/masquevpn/internal/netsetup"
	"github.com/soways11/masquevpn/internal/site"
	"github.com/soways11/masquevpn/internal/tun"
	"github.com/soways11/masquevpn/internal/tunnel"
)

// certHost достаёт домен из сертификата: именно он стоит в SNI, и именно его
// логично показывать на сайте-прикрытии.
func certHost(cert *tls.Certificate) string {
	leaf := cert.Leaf
	if leaf == nil {
		if len(cert.Certificate) == 0 {
			return ""
		}
		c, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return ""
		}
		leaf = c
	}
	for _, n := range leaf.DNSNames {
		if !strings.HasPrefix(n, "*.") {
			return n
		}
	}
	return leaf.Subject.CommonName
}

// buildFallback собирает обработчик сайта-прикрытия: реверс-прокси на живой
// backend, статика, встроенный сайт или 404.
//
// Сильная защита от активного зондирования — это когда пробер, постучавшись,
// видит настоящий работающий сайт. 404 отличим от VPN не лучше, чем от
// пустого домена, поэтому по умолчанию поднимается встроенный сайт, а про
// голый 404 честно предупреждаем.
func buildFallback(cfg *config.Server, host string, log *slog.Logger) (http.Handler, error) {
	switch {
	case cfg.FallbackProxy != "":
		u, err := url.Parse(cfg.FallbackProxy)
		if err != nil {
			return nil, fmt.Errorf("fallback_proxy: %w", err)
		}
		proxy := httputil.NewSingleHostReverseProxy(u)
		proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
			// Backend лежит — отвечаем как обычный веб-сервер, а не
			// чем-то, по чему нас можно отличить.
			log.Debug("сайт-прикрытие недоступен", "err", err)
			http.Error(w, "502 Bad Gateway", http.StatusBadGateway)
		}
		log.Info("сайт-прикрытие", "proxy", cfg.FallbackProxy)
		return proxy, nil
	case cfg.FallbackDir != "":
		log.Info("сайт-прикрытие", "dir", cfg.FallbackDir)
		return http.FileServer(http.Dir(cfg.FallbackDir)), nil
	case !cfg.FallbackSite.Disabled:
		s, legacy := cfg.FallbackSite.WithoutLegacyText()
		if legacy {
			log.Info("в fallback_site название или описание из прежних версий установщика — " +
				"оно было одинаковым у всех установок и не используется; строки можно удалить из конфигурации")
		}
		if s.Host != "" {
			host = s.Host
		}
		seed := siteSeed(s, log)
		h, err := site.New(site.Options{
			Host:        host,
			Title:       s.Title,
			Description: s.Description,
			Contact:     s.Contact,
			Seed:        seed,
		})
		if err != nil {
			return nil, fmt.Errorf("fallback_site: %w", err)
		}
		log.Info("сайт-прикрытие", "встроенный", host)
		return h, nil
	default:
		log.Warn("сайта-прикрытия нет: посторонний увидит только 404 — задайте fallback_proxy, fallback_dir " +
			"или включите встроенный сайт (fallback_site.disabled=false)")
		return http.HandlerFunc(http.NotFound), nil
	}
}

// siteSeed — секрет, из которого выводится встроенный сайт: из
// конфигурации, из файла, а если файла нет — новый, записанный в файл.
// Записать некуда — сайт всё равно поднимается, но со случайным seed'ом на
// этот запуск: вычисляемая по домену страница хуже, чем сменившаяся после
// перезапуска.
func siteSeed(s config.FallbackSite, log *slog.Logger) string {
	if s.Seed != "" {
		return s.Seed
	}
	path := s.SeedFile
	if path == "" {
		path = config.DefaultSiteSeedFile()
	}
	seed, created, err := site.LoadSeed(path)
	if err != nil {
		log.Warn("seed сайта-прикрытия не сохранить — сайт будет другим после перезапуска", "file", path, "err", err)
		return site.RandomSeed()
	}
	if created {
		log.Info("создан seed сайта-прикрытия: оформление и тексты этой установки", "file", path)
	}
	return seed
}

// withoutCONNECT отвечает на CONNECT так, как отвечает origin-сервер, и не
// пускает такой запрос в сайт-прикрытие.
//
// Нужно это для TCP-слушателя: там сайт стоит без нашего обработчика
// CONNECT-IP, а http.FileServer (и реверс-прокси) на метод не смотрят — и
// «curl -X CONNECT https://домен/» получал 200 и страницу. Обычный сервер
// документ на CONNECT не отдаёт никогда, так что это был признак.
func withoutCONNECT(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			w.Header().Set("Allow", "GET, HEAD, OPTIONS")
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// withAltSvc добавляет заголовок Alt-Svc — так браузер и узнаёт, что у
// домена есть HTTP/3. Обычный сайт с HTTP/3 его шлёт всегда; без него мы
// выглядели бы доменом, к которому по HTTP/3 никто не ходит.
func withAltSvc(h http.Handler, quicAddr string) http.Handler {
	_, port, err := net.SplitHostPort(quicAddr)
	if err != nil || port == "" {
		port = "443"
	}
	value := fmt.Sprintf(`h3=":%s"; ma=86400`, port)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", value)
		h.ServeHTTP(w, r)
	})
}

// serveTCP поднимает обычный HTTPS по TCP рядом с HTTP/3.
func serveTCP(ctx context.Context, addr string, tlsConf *tls.Config, h http.Handler, log *slog.Logger) (func(), error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("TCP %s: %w", addr, err)
	}
	srv := &http.Server{
		Handler:           h,
		TLSConfig:         tlsConf,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		if err := srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Warn("TCP-слушатель остановлен", "err", err)
		}
	}()
	log.Info("TCP-слушатель запущен", "listen", addr)
	return func() {
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
		_ = ln.Close()
	}, nil
}

// certificates готовит источники сертификата: автоматический (ACME) или из
// файлов. Возвращает настройки TLS для QUIC и для TCP, менеджер ACME (nil,
// если выключен) и домен для сайта-прикрытия.
func certificates(cfg *config.Server, log *slog.Logger) (quicConf, tcpConf *tls.Config, mgr *acmeclient.Manager, host string, err error) {
	// Файлы читаются через загрузчик, который следит за их изменением:
	// сертификат обновляет кто-то посторонний (certbot, acme.sh, соседний
	// nginx), и сервер, прочитавший его один раз при старте, через три
	// месяца начнёт отдавать просроченный. Снаружи это выглядит как
	// внезапно сломавшийся домен.
	var reloader *certfile.Reloader
	var file *tls.Certificate
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		reloader, err = certfile.New(cfg.CertFile, cfg.KeyFile, log)
		if err != nil {
			return nil, nil, nil, "", err
		}
		file = reloader.Certificate()
	}
	if !cfg.ACME.Enabled() {
		if reloader == nil {
			return nil, nil, nil, "", errors.New("нет ни cert_file/key_file, ни acme.domains")
		}
		// Настройки те же, что у ACME-пути, и это не косметика: слушатель
		// TCP без NextProtos не договорится об h2, а настоящий сайт на
		// таком домене договорился бы. Для QUIC список протоколов
		// проставляет http3, поэтому там только нижняя граница версии.
		quic := &tls.Config{
			GetCertificate: reloader.GetCertificate,
			MinVersion:     tls.VersionTLS13,
		}
		tcp := &tls.Config{
			GetCertificate: reloader.GetCertificate,
			NextProtos:     []string{"h2", "http/1.1"},
			MinVersion:     tls.VersionTLS12,
		}
		log.Info("сертификат из файлов", "cert", cfg.CertFile,
			"обновление", "подхватывается без перезапуска")
		return quic, tcp, nil, certHost(file), nil
	}
	mgr, err = acmeclient.New(acmeclient.Config{
		Domains:      cfg.ACME.Domains,
		Email:        cfg.ACME.Email,
		CacheDir:     cfg.ACME.CacheDir,
		DirectoryURL: cfg.ACME.DirectoryURL,
		Fallback:     file,
		Logger:       log,
	})
	if err != nil {
		return nil, nil, nil, "", err
	}
	log.Info("сертификат ACME", "домены", cfg.ACME.Domains, "кэш", cfg.ACME.CacheDir,
		"запасной", file != nil)
	if file == nil {
		log.Info("запасного сертификата нет: до первой выдачи клиенты подключиться не смогут — " +
			"это нормально на чистой машине, но задайте cert_file/key_file, если важен запуск без сети")
	}
	return mgr.QUICConfig(), mgr.TCPConfig(), mgr, mgr.Domain(), nil
}

// profileName — что писать в журнал про отпечаток серверной стороны.
func profileName(cfg *config.Server, p *fingerprint.ServerProfile) string {
	switch {
	case p == nil:
		return "умолчания quic-go"
	case cfg.ServerProfileFile != "":
		return cfg.ServerProfileFile
	default:
		return p.Source
	}
}

func run(ctx context.Context, cfg *config.Server, log *slog.Logger) error {
	tlsQUIC, tlsTCP, acmeMgr, host, err := certificates(cfg, log)
	if err != nil {
		return err
	}
	registry, accountant, err := openClients(cfg, log)
	if err != nil {
		return err
	}
	authOpts := auth.Options{Header: cfg.AuthHeader}
	var key []byte
	if registry != nil {
		// Режим «ключ на клиента»: подпись проверяется ключом того, чей
		// псевдоним стоит в токене. Общего ключа в этом режиме нет вовсе —
		// иначе он остался бы чёрным ходом для отозванных.
		authOpts.Keys = func(id string) ([]byte, bool) {
			c, ok := registry.Lookup(id)
			if !ok || c.Disabled {
				return nil, false
			}
			k, err := c.Key.Bytes()
			if err != nil {
				return nil, false
			}
			return k, true
		}
	} else {
		if key, err = cfg.AuthKey.Bytes(); err != nil {
			return err
		}
	}
	authn, err := auth.New(key, authOpts)
	if err != nil {
		return err
	}
	shaping, err := config.ShapingProfile(cfg.Shaping)
	if err != nil {
		return err
	}
	packing, err := cfg.Packing.Options()
	if err != nil {
		return err
	}

	prefixes, _ := cfg.Pools()
	var pools []*masque.IPPool
	var gwAddrs, sources []netip.Prefix
	for _, p := range prefixes {
		if p.Addr().Is6() && !netsetup.IPv6Available() {
			log.Warn("IPv6 выключен в ядре — pool6 пропущен", "pool", p)
			continue
		}
		pool, err := masque.NewIPPool(p)
		if err != nil {
			return err
		}
		if p.Addr().Is6() {
			// Выдать адрес и не иметь IPv6 наружу — значит отправить
			// клиента в чёрную дыру: он предпочтёт IPv6, и соединения
			// будут молча висеть.
			if _, err := netsetup.DefaultRouteInterface(6); err != nil {
				log.Warn("pool6 задан, но у сервера нет маршрута IPv6 наружу — клиенты получат адрес и чёрную дыру",
					"pool", p, "err", err)
			}
		}
		pools = append(pools, pool)
		// Шлюз — адрес сервера на TUN, с длиной префикса пула: ядро само
		// добавит маршрут на всю сеть клиентов через TUN.
		gwAddrs = append(gwAddrs, netip.PrefixFrom(pool.Gateway(), p.Bits()))
		sources = append(sources, p)
	}
	if len(pools) == 0 {
		return errors.New("нет пригодных пулов адресов")
	}

	dev, err := tun.Open(cfg.TUN.Name, cfg.TUN.MTU)
	if err != nil {
		return err
	}
	defer dev.Close()
	if err := netsetup.ConfigureInterface(dev.Name(), dev.MTU(), gwAddrs); err != nil {
		return err
	}
	if err := netsetup.EnableForwarding(); err != nil {
		return err
	}
	if !cfg.NAT.Disabled {
		nat := &netsetup.NAT{
			TunIface:   dev.Name(),
			Sources:    sources,
			OutIface:   cfg.NAT.OutInterface,
			NoMSSClamp: cfg.NAT.NoMSSClamp,
			NoIPv6:     cfg.NAT.NoIPv6,
		}
		if err := nat.Up(); err != nil {
			return err
		}
		defer func() {
			if err := nat.Down(); err != nil {
				log.Warn("снятие NAT", "err", err)
			}
		}()
		out := cfg.NAT.OutInterface
		if out == "" {
			out, _ = netsetup.DefaultRouteInterface(4)
		}
		log.Info("NAT включён", "sources", sources, "out", out, "mss_clamp", !cfg.NAT.NoMSSClamp)
	}

	router := tunnel.NewRouter(dev, tunnel.RouterOptions{Logger: log})

	fallback, err := buildFallback(cfg, host, log)
	if err != nil {
		return err
	}
	fallback = withoutCONNECT(fallback)
	var limits *masque.Limits
	if l := cfg.Limits; l.MaxSessions > 0 || l.MaxSessionsPerIP > 0 || l.IdleTimeout > 0 ||
		l.MaxUnknownCapsules > 0 || l.MaxBytesPerSecond > 0 || l.AddressLeaseTTL > 0 {
		limits = &masque.Limits{
			MaxSessions:        l.MaxSessions,
			MaxSessionsPerIP:   l.MaxSessionsPerIP,
			IdleTimeout:        l.IdleTimeout.D(),
			MaxUnknownCapsules: l.MaxUnknownCapsules,
			MaxBytesPerSecond:  l.MaxBytesPerSecond,
			BurstBytes:         l.BurstBytes,
			AddressLeaseTTL:    l.AddressLeaseTTL.D(),
		}
	}
	if addr := cfg.TCPAddr(); addr != "" {
		stop, err := serveTCP(ctx, addr, tlsTCP, withAltSvc(fallback, cfg.Listen), log)
		if err != nil {
			return err
		}
		defer stop()
	}

	h, err := masque.NewHandler(masque.ServerConfig{
		Pools:               pools,
		AllowClientToClient: cfg.AllowClientToClient,
		Path:                cfg.Path,
		Identify:            authn.Identify,
		Fallback:            fallback,
		OnSession:           router.Serve,
		OnAddressChange:     router.AddressChanged,
		Shaping:             shaping,
		Packing:             packing,
		Limits:              limits,
		Policy:              policyOf(accountant),
	})
	if err != nil {
		return err
	}
	if registry != nil {
		stopClients := watchClients(h, registry, accountant, cfg, log)
		defer stopClients()
	}
	var opts []masque.HTTP3Option
	if *cfg.WebTransport {
		opts = append(opts, masque.WithWebTransportSettings())
	}
	profile, err := cfg.Profile()
	if err != nil {
		return err
	}
	if profile != nil {
		// Отпечаток серверной стороны: клиент видит не умолчания quic-go,
		// а заданный профиль транспортных параметров.
		opts = append(opts, masque.WithQUICConfig(profile.QUICConfig()))
	}
	// Alt-Svc навешивается на весь обработчик, а не только на сайт: этот
	// заголовок обычный сервер ставит на каждый ответ, включая ответы на
	// нештатные запросы. Ставить его лишь на часть ответов — различие,
	// заметное одним сравнением.
	srv := masque.NewHTTP3Server(cfg.Listen, tlsQUIC, withAltSvc(h, cfg.Listen), opts...)

	rctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if acmeMgr != nil {
		// Слушатель TCP уже поднят — значит, проверке tls-alpn-01 есть куда
		// прийти. Получаем сертификат в фоне: держать запуск сервера на
		// удостоверяющем центре нельзя, а до выдачи работает запасной.
		go func() {
			octx, ocancel := context.WithTimeout(rctx, 5*time.Minute)
			defer ocancel()
			if err := acmeMgr.Obtain(octx); err != nil {
				log.Warn("сертификат ACME пока не получен", "err", err)
			}
		}()
		go acmeMgr.Maintain(rctx)
	}
	routerDone := make(chan error, 1)
	go func() { routerDone <- router.Run(rctx) }()

	// Слушаем через masque.ListenAndServeUDP, а не srv.ListenAndServe: только
	// так задаётся длина Connection ID сервера — её видно в открытую (см.
	// masque.DefaultConnectionIDLength).
	cidLen := masque.DefaultConnectionIDLength
	if profile != nil && profile.CIDLength() > 0 {
		cidLen = profile.CIDLength()
	}
	srvDone := make(chan error, 1)
	go func() { srvDone <- masque.ListenAndServeUDP(srv, cfg.Listen, cidLen) }()
	log.Info("сервер запущен", "listen", cfg.Listen, "tun", dev.Name(), "gateway", gwAddrs,
		"mtu", dev.MTU(), "webtransport", *cfg.WebTransport, "кадры", packing != nil,
		"профиль", profileName(cfg, profile))

	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-rctx.Done():
				return
			case <-t.C:
				c := router.Counters()
				log.Debug("счётчики", "sessions", router.Sessions(),
					"to_clients", c.ToTunnel.Load(), "from_clients", c.FromTunnel.Load(),
					"icmp", c.ICMP.Load(), "no_route", c.NoRoute.Load(), "overflow", c.Overflow.Load())
			}
		}
	}()

	select {
	case <-ctx.Done():
		log.Info("остановка")
		// Сначала закрываем сессии: клиент узнаёт об остановке по закрытому
		// потоку сразу, а не по таймауту простоя.
		router.CloseAll()
		sctx, scancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer scancel()
		_ = srv.Shutdown(sctx)
		_ = srv.Close()
		// Дожидаемся, пока слушатель действительно закроется: закрытие
		// QUIC-транспорта рассылает клиентам CONNECTION_CLOSE. Если выйти
		// раньше, клиент узнает об остановке только по таймауту простоя —
		// то есть будет висеть десятки секунд вместо мгновенного
		// переподключения. Слушатель теперь наш (см. masque.ServeUDP),
		// поэтому и ждать его закрытия должны мы.
		select {
		case <-srvDone:
		case <-time.After(2 * time.Second):
		}
		cancel()
		<-routerDone
		return nil
	case err := <-srvDone:
		cancel()
		return fmt.Errorf("HTTP/3: %w", err)
	case err := <-routerDone:
		_ = srv.Close()
		return fmt.Errorf("TUN: %w", err)
	}
}
