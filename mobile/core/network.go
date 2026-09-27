package core

import (
	"net/netip"

	"github.com/soways11/masquevpn/internal/config"
)

// Здесь собирается то, что система должна настроить на интерфейсе.
//
// На desktop это делает netsetup: адреса, маршруты, MTU, DNS. На мобильных
// платформах всё то же самое делает система по описанию, которое мы ей
// даём, — поэтому вместо вызовов netlink тут построение описания.

// networkFor собирает параметры интерфейса из конфигурации и выданных
// сервером адресов.
//
// Принимает адреса, а не сессию: так построение описания сети проверяется
// само по себе, без поднятого туннеля. Это ровно то место, где легко
// ошибиться молча — лишний маршрут ::/0 без адреса IPv6 превращает половину
// интернета в чёрную дыру, и заметно это будет не на стенде, а у человека.
func networkFor(cfg *config.Client, addrs []netip.Prefix, serverIP netip.Addr) network {
	nw := network{MTU: cfg.TUN.MTU}
	if nw.MTU <= 0 {
		nw.MTU = 1280
	}

	hasV6 := false
	for _, p := range addrs {
		if p.Addr().Is6() {
			// IPv6 отдаём системе, только если он разрешён конфигурацией:
			// иначе на устройстве появится адрес, которым нельзя ходить.
			if cfg.IPv6 == nil || !*cfg.IPv6 {
				continue
			}
			hasV6 = true
		}
		nw.Addresses = append(nw.Addresses, p.String())
	}

	if cfg.FullTunnel != nil && *cfg.FullTunnel {
		nw.Routes = append(nw.Routes, "0.0.0.0/0")
		// IPv6 заворачиваем, только когда у интерфейса есть адрес IPv6.
		// На desktop мы заворачиваем его всегда — там маршрут без адреса
		// упирается в интерфейс и трафик не утекает. На Android так
		// нельзя: маршрут ::/0 без адреса система не примет, а если
		// примет — получится чёрная дыра вместо туннеля.
		if hasV6 {
			nw.Routes = append(nw.Routes, "::/0")
		}
	} else {
		routes, _ := cfg.RoutePrefixes()
		for _, r := range routes {
			if r.Addr().Is6() && !hasV6 {
				continue
			}
			nw.Routes = append(nw.Routes, r.String())
		}
	}

	if dns, _ := cfg.DNSServers(); len(dns) > 0 {
		for _, a := range dns {
			if a.Is6() && !hasV6 {
				continue
			}
			nw.DNS = append(nw.DNS, a.String())
		}
	}

	// Адрес сервера — справочно: на Android его уводит мимо туннеля защита
	// сокета, а не маршрут. Пригодится платформам без защиты сокета и для
	// понятного журнала.
	if serverIP.IsValid() {
		nw.Bypass = append(nw.Bypass, serverIP.String())
	}
	return nw
}

func prefixStrings(ps []netip.Prefix) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.String())
	}
	return out
}

func sameAddrs(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
