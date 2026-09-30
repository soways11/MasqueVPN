//go:build linux

package clientrun

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"syscall"
	"time"

	"github.com/soways11/masquevpn/internal/client"
	"github.com/soways11/masquevpn/internal/config"
	"github.com/soways11/masquevpn/internal/netsetup"
	"github.com/soways11/masquevpn/internal/tun"
	"github.com/soways11/masquevpn/internal/tunnel"
)

func Run(ctx context.Context, cfg *config.Client, log *slog.Logger, hooks Hooks) error {
	// Убираем следы прошлого, возможно аварийного, запуска: оставшаяся
	// аварийная блокировка заперла бы сеть, а подменённый resolv.conf увёл бы
	// системный DNS в несуществующий туннель.
	if rep, err := netsetup.Cleanup(); err != nil {
		log.Warn("уборка следов прошлого запуска", "err", err)
	} else if !rep.Empty() {
		log.Info("уборка следов прошлого запуска", "итог", rep.String())
	}

	fwmark := cfg.FwMark
	if fwmark == 0 {
		fwmark = netsetup.DefaultFwMark
	}
	opt := client.Options{Logger: log, Ports: portMemory()}
	if *cfg.FullTunnel {
		opt.Protect = func(rc syscall.RawConn) error { return netsetup.MarkSocket(rc, fwmark) }
	}
	dialer, err := client.NewDialer(cfg, opt)
	if err != nil {
		return err
	}

	dev, err := tun.Open(cfg.TUN.Name, cfg.TUN.MTU)
	if err != nil {
		return err
	}
	// dev закрывает RunClient; до него — мы.
	started := false
	defer func() {
		if !started {
			dev.Close()
		}
	}()

	log.Info("подключение", "server", cfg.Server, "sni", cfg.Host(), "transport", dialer.Transport())
	dctx, cancel := context.WithTimeout(ctx, dialer.ConnectTimeout())
	defer cancel()
	onRotate := func(old, new []netip.Prefix) {
		o, n := usable(old, *cfg.IPv6, log), usable(new, *cfg.IPv6, log)
		if slices.Equal(o, n) {
			return
		}
		log.Info("адрес сменился", "old", o, "new", n)
		if err := netsetup.ReplaceAddresses(dev.Name(), o, n); err != nil {
			log.Error("смена адреса на интерфейсе", "err", err)
		}
	}
	sess, err := dialer.OpenSession(dctx, onRotate)
	if err != nil {
		return fmt.Errorf("подключение: %w", err)
	}
	addrs := usable(sess.Prefixes(), *cfg.IPv6, log)
	// Кадрирование согласуется капсулой сразу после открытия сессии —
	// дожидаемся ответа, чтобы честно сказать, в каком режиме работаем.
	framing := false
	for i := 0; i < 20 && !framing; i++ {
		if framing = sess.Current().FramingActive(); !framing {
			time.Sleep(50 * time.Millisecond)
		}
	}
	log.Info("сессия установлена", "addrs", addrs,
		"capacity", sess.Current().DatagramCapacity(), "кадры", framing)

	if err := netsetup.ConfigureInterface(dev.Name(), dev.MTU(), addrs); err != nil {
		sess.Close()
		return err
	}
	var ks *netsetup.KillSwitch
	if *cfg.FullTunnel {
		ft := &netsetup.FullTunnel{
			Iface:  dev.Name(),
			Table:  cfg.Table,
			FwMark: fwmark,
			// IPv6 заворачиваем в туннель ВСЕГДА, даже если ipv6=false или
			// сервер его не выдал: тогда он упирается в интерфейс без
			// адреса и не уходит мимо туннеля (утечка).
			IPv6: true,
		}
		if err := ft.Up(); err != nil {
			sess.Close()
			return err
		}
		defer func() {
			if err := ft.Down(); err != nil {
				log.Warn("снятие маршрутизации", "err", err)
			}
		}()
		log.Info("весь трафик идёт через туннель", "iface", dev.Name(), "fwmark", fmt.Sprintf("%#x", fwmark))

		// Аварийное отключение: пока туннель поднят, наружу выпускаем только
		// туннель, помеченный сокет клиента, петлю, established, локальные сети
		// и kill_switch_allow. Иначе трафик, привязанный к физическому
		// адаптеру, утёк бы мимо туннеля даже при верной таблице маршрутов.
		if cfg.KillSwitch != nil && *cfg.KillSwitch {
			allow, err := cfg.KillSwitchAllowed()
			if err != nil {
				sess.Close()
				return err
			}
			failClosed := cfg.KillSwitchFailClosed != nil && *cfg.KillSwitchFailClosed
			var stopWatch func()
			if !failClosed {
				// Fail-open: за упавшим клиентом приберётся сторож. При
				// fail-closed сторожа нет — блокировка держится до следующего
				// запуска или `vpnclient -cleanup`.
				if s, err := StartWatchdog(); err != nil {
					log.Warn("сторож не запустился: после аварийного завершения "+
						"снять блокировку можно командой vpnclient -cleanup", "err", err)
				} else {
					stopWatch = s
				}
			}
			k, err := netsetup.KillSwitchArm(dev.Name(), fwmark, allow)
			if err != nil {
				if stopWatch != nil {
					stopWatch()
				}
				sess.Close()
				return fmt.Errorf("аварийное отключение: %w", err)
			}
			ks = k
			defer func() {
				if err := ks.Disarm(); err != nil {
					log.Warn("снятие аварийного отключения", "err", err)
				}
				if stopWatch != nil {
					stopWatch()
				}
			}()
			log.Info("аварийное отключение включено", "fail_closed", failClosed)
		}
	} else {
		routes, _ := cfg.RoutePrefixes()
		if err := netsetup.AddRoutes(dev.Name(), routes); err != nil {
			sess.Close()
			return err
		}
		log.Info("через туннель идут сети", "routes", routes)
	}

	// Прикрытие DNS поднимаем ДО подмены resolv.conf: адреса исходных
	// резолверов нужны как раз оттуда.
	resolvers := StartDNSCover(ctx, cfg, opt.Protect, log)
	if ks != nil && len(resolvers) > 0 {
		// Резолверы прикрытия помечены той же меткой (opt.Protect), так что
		// правило по метке их уже пропускает; добавляем их адреса в список
		// разрешённых явно — на случай пути без метки.
		allow, _ := cfg.KillSwitchAllowed()
		for _, r := range resolvers {
			allow = append(allow, netip.PrefixFrom(r, r.BitLen()))
		}
		if err := ks.Reapply(allow); err != nil {
			log.Warn("аварийное отключение: не удалось разрешить резолверы прикрытия", "err", err)
		}
	}

	// Резолвер семьи, которой в туннеле нет, не заработает: система будет
	// честно ждать его ответа на каждом имени и упираться в таймаут.
	all, _ := cfg.DNSServers()
	if dns := config.UsableDNS(all, addrs); len(dns) > 0 {
		if cfg.DNSByDefault {
			log.Info("резолвер не задан в конфигурации, подставлен публичный",
				"servers", dns, "иначе", "имена резолвились бы мимо туннеля")
		}
		restore, err := netsetup.SetDNS(dns)
		if err != nil {
			sess.Close()
			return err
		}
		defer func() {
			if err := restore(); err != nil {
				log.Warn("восстановление DNS", "err", err)
			}
		}()
		log.Info("DNS", "servers", dns)
	}

	started = true
	hooks.session(sess)
	hooks.up(addrs)
	cnt := new(tunnel.Counters)
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				log.Debug("счётчики", "to_tunnel", cnt.ToTunnel.Load(), "from_tunnel", cnt.FromTunnel.Load(),
					"icmp", cnt.ICMP.Load(), "rejected", cnt.Rejected.Load(),
					"rotations", sess.Rotations(), "reconnects", sess.Reconnects())
			}
		}
	}()
	return tunnel.RunClient(ctx, dev, sess, tunnel.ClientOptions{Logger: log, Counters: cnt})
}
