// Package clientrun — запуск клиента: TUN, сессия, настройка сети.
//
// Вынесено из cmd/vpnclient, чтобы консольный клиент и оконное приложение
// работали на одном и том же коде, а не на двух похожих.
package clientrun

import (
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"syscall"
	"time"

	"github.com/soways11/masquevpn/internal/config"
	"github.com/soways11/masquevpn/internal/dnscover"
	"github.com/soways11/masquevpn/internal/masque"
	"github.com/soways11/masquevpn/internal/netsetup"
	"github.com/soways11/masquevpn/internal/obfuscation"
)

// Hooks — необязательные уведомления о ходе подключения.
//
// Нужны оконному приложению: оно рисует состояние и должно узнавать о нём
// от движка напрямую, а не вылавливая строки из журнала. Вызываются из
// горутины Run; вызывающий сам заботится о потоках.
type Hooks struct {
	// Up вызывается один раз, когда туннель поднят и сеть настроена.
	Up func(addrs []netip.Prefix)

	// Session отдаёт источник счётчиков, как только сессия установлена.
	// Окно опрашивает его по таймеру: подписка на каждое изменение означала
	// бы вызов из горячего пути насоса на каждый пакет.
	Session func(Counters)
}

// Counters — то, откуда окно берёт объём трафика. Узкий интерфейс вместо
// *session.Session: окну незачем уметь закрывать сессию или менять адреса.
type Counters interface {
	Stats() masque.Stats
}

func (h Hooks) up(addrs []netip.Prefix) {
	if h.Up != nil {
		h.Up(addrs)
	}
}

func (h Hooks) session(c Counters) {
	if h.Session != nil {
		h.Session(c)
	}
}

// usable отбирает адреса, которые можно назначить интерфейсу.
func usable(ps []netip.Prefix, v6 bool, log *slog.Logger) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range ps {
		if p.Addr().Is6() {
			if !v6 {
				continue
			}
			if !netsetup.IPv6Available() {
				log.Warn("сервер выдал IPv6-адрес, но IPv6 выключен в ядре — пропускаю", "addr", p)
				continue
			}
		}
		out = append(out, p)
	}
	return out
}

// StartDNSCover включает фоновые DNS-запросы мимо туннеля.
//
// Без них хост часами льёт объём на один адрес, почти не спрашивая имён:
// весь DNS уехал внутрь туннеля. Это заметно на одних только потоках,
// независимо от того, насколько хорош отпечаток рукопожатия.
//
// Неудача здесь туннель не рушит: прикрытие — мера маскировки, а не
// условие работы.
func StartDNSCover(ctx context.Context, cfg *config.Client, protect func(syscall.RawConn) error, log *slog.Logger) []netip.Addr {
	if !cfg.DNSCoverEnabled() {
		return nil
	}
	servers, _ := cfg.DNSCoverServers()
	if len(servers) == 0 {
		addrs, err := netsetup.SystemResolvers()
		if err != nil {
			log.Warn("прикрытие DNS выключено: не нашёл внешних резолверов системы",
				"err", err, "подсказка", "задайте dns_cover.servers")
			return nil
		}
		for _, a := range addrs {
			servers = append(servers, netip.AddrPortFrom(a, 53))
		}
	}
	// Заданные вручную (и подставленные мобильным приложением из
	// ConnectivityManager) тоже просеиваем: заглушки попадают и туда, а
	// прикрытие, ушедшее в несуществующий адрес, — это не прикрытие.
	servers = slices.DeleteFunc(servers, func(ap netip.AddrPort) bool {
		return !netsetup.UsableResolver(ap.Addr())
	})
	if len(servers) == 0 {
		log.Warn("прикрытие DNS выключено: среди резолверов не осталось настоящих",
			"подсказка", "задайте dns_cover.servers")
		return nil
	}

	var domains []string
	var mean time.Duration
	if cfg.DNSCover != nil {
		domains = cfg.DNSCover.Domains
		mean = cfg.DNSCover.MeanInterval.D()
	}
	if len(domains) == 0 {
		domains = append(domains, dnscover.DefaultDomains...)
	}
	// Имя своего же сервера — тоже часть картины: обычный клиент
	// спрашивает домен, к которому подключается, а не ходит сразу на IP.
	if host := cfg.Host(); host != "" {
		if _, err := netip.ParseAddr(host); err != nil && !slices.Contains(domains, host) {
			domains = append(domains, host)
		}
	}
	if mean <= 0 {
		mean = dnscover.DefaultMeanInterval
	}

	cover, err := dnscover.New(dnscover.Config{
		Servers: servers,
		Domains: domains,
		Next:    obfuscation.CoverInterval(mean),
		Protect: protect,
		Logger:  log,
	})
	if err != nil {
		log.Warn("прикрытие DNS выключено", "err", err)
		return nil
	}
	go cover.Run(ctx)
	log.Info("прикрытие DNS включено", "servers", servers, "domains", len(domains), "mean", mean)

	// Возвращаем адреса резолверов: на Windows их нужно увести мимо туннеля
	// маршрутом — пометить сокет там нечем.
	out := make([]netip.Addr, 0, len(servers))
	for _, s := range servers {
		out = append(out, s.Addr())
	}
	return out
}
