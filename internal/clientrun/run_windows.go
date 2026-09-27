//go:build windows

package clientrun

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/soways11/masquevpn/internal/client"
	"github.com/soways11/masquevpn/internal/config"
	"github.com/soways11/masquevpn/internal/netsetup"
	"github.com/soways11/masquevpn/internal/tun"
	"github.com/soways11/masquevpn/internal/tunnel"
)

// luider — адаптер, умеющий сообщить свой LUID (Wintun). В Windows настройка
// сети идёт по LUID, а не по имени: имя пользователь может переименовать.
type luider interface{ LUID() uint64 }

func Run(ctx context.Context, cfg *config.Client, log *slog.Logger, hooks Hooks) error {
	// Следы упавшего прошлого запуска убираются до всего остального —
	// безусловно, даже если сейчас аварийное отключение не просят и туннель
	// поднимается раздельным.
	//
	// Убирается не только блокировка WFP: она-то как раз умирает вместе с
	// процессом. Дольше живут правило разрешения имён и маршруты-исключения
	// на физическом интерфейсе — их снять некому, если клиента убили. Молча
	// оставленное правило имён уводит весь системный DNS на резолвер, до
	// которого больше нет пути.
	if rep, err := netsetup.Cleanup(); err != nil {
		log.Warn("уборка следов прошлого запуска", "err", err)
	} else if !rep.Empty() {
		log.Info("прошлый запуск завершился аварийно, прибрался за ним", "что", rep.String())
	}

	// Метки сокета в Windows нет: трафик самого туннеля уводит мимо туннеля
	// маршрут-исключение к адресу сервера (см. netsetup.FullTunnel).
	dialer, err := client.NewDialer(cfg, client.Options{Logger: log})
	if err != nil {
		return err
	}

	dev, err := tun.Open(cfg.TUN.Name, cfg.TUN.MTU)
	if err != nil {
		return err
	}
	started := false
	defer func() {
		if !started {
			dev.Close()
		}
	}()
	luid := uint64(0)
	if l, ok := dev.(luider); ok {
		luid = l.LUID()
	} else {
		return fmt.Errorf("адаптер не сообщил LUID")
	}

	log.Info("подключение", "server", cfg.Server, "sni", cfg.Host(), "transport", dialer.Transport())
	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	onRotate := func(old, new []netip.Prefix) {
		o, n := usable(old, *cfg.IPv6, log), usable(new, *cfg.IPv6, log)
		if slices.Equal(o, n) {
			return
		}
		log.Info("адрес сменился", "old", o, "new", n)
		if err := netsetup.ReplaceAddressesLUID(luid, o, n); err != nil {
			log.Error("смена адреса на интерфейсе", "err", err)
		}
	}
	sess, err := dialer.OpenSession(dctx, onRotate)
	if err != nil {
		return fmt.Errorf("подключение: %w", err)
	}
	addrs := usable(sess.Prefixes(), *cfg.IPv6, log)
	framing := false
	for i := 0; i < 20 && !framing; i++ {
		if framing = sess.Current().FramingActive(); !framing {
			time.Sleep(50 * time.Millisecond)
		}
	}
	log.Info("сессия установлена", "addrs", addrs,
		"capacity", sess.Current().DatagramCapacity(), "кадры", framing)

	if err := netsetup.ConfigureInterfaceLUID(luid, dev.MTU(), addrs); err != nil {
		sess.Close()
		return err
	}

	var ft *netsetup.FullTunnel
	// Блокировка живёт, пока жив этот объект: он держит дескриптор движка
	// WFP. Поэтому его нужно донести до выхода из Run, а не «поставить и
	// забыть».
	var ks *netsetup.KillSwitch
	var ksServer netip.Addr    // адрес сервера, разрешённый аварийным отключением
	var ksAllow []netip.Prefix // весь список разрешённых: сервер, резолверы прикрытия, свои
	if *cfg.FullTunnel {
		ft = &netsetup.FullTunnel{
			LUID:   luid,
			Server: dialer.ServerIP(),
			// IPv6 заворачиваем всегда: иначе при живом IPv6 у провайдера
			// он пойдёт мимо туннеля.
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
		log.Info("весь трафик идёт через туннель", "iface", dev.Name(),
			"мимо туннеля", dialer.ServerIP())

		// Сторож. Правило разрешения имён и маршрут-исключение переживают
		// смерть процесса, и снять их изнутри убитого клиента нечем: defer
		// не выполнится, обработчика не позовут. Поэтому за нами следит
		// отдельный процесс — он дождётся конца и приберётся.
		if stopWatch, err := StartWatchdog(); err != nil {
			log.Warn("сторож не запустился: после аварийного завершения следы придётся "+
				"убрать командой vpnclient -cleanup", "err", err)
		} else {
			defer stopWatch()
			log.Info("сторож запущен", "зачем", "уберёт за клиентом, если тот не доживёт до выхода")
		}

		// Аварийное отключение: пока туннель поднят, наружу выпускается
		// только сервер, локальная сеть и петля. Если клиент упадёт,
		// маршруты исчезнут вместе с адаптером, но эта блокировка в ядре
		// останется — и трафик не утечёт напрямую. Включается по запросу:
		// функция трогает файрвол, и это осознанный выбор.
		if cfg.KillSwitch != nil && *cfg.KillSwitch {
			extra, err := cfg.KillSwitchAllowed()
			if err != nil {
				sess.Close()
				return err
			}
			ksAllow = append(allowList(dialer.ServerIP()), extra...)
			k, err := netsetup.KillSwitchArm(luid, ksAllow)
			if err != nil {
				// Не поднялась — не поднимаем и туннель молча в опасном
				// виде: пользователь просил защиту, а её нет.
				sess.Close()
				return fmt.Errorf("аварийное отключение: %w", err)
			}
			ks = k
			defer func() {
				if err := ks.Disarm(); err != nil {
					log.Warn("снятие аварийного отключения", "err", err)
				}
			}()
			ksServer = dialer.ServerIP()
			log.Info("аварийное отключение включено",
				"пока клиент жив", "трафик мимо туннеля заблокирован",
				"если клиент упадёт", "блокировка снимется сама")
		}
	} else {
		routes, _ := cfg.RoutePrefixes()
		if err := netsetup.AddRoutesLUID(luid, routes); err != nil {
			sess.Close()
			return err
		}
		log.Info("через туннель идут сети", "routes", routes)
	}

	// Прикрытие DNS должно ходить к резолверам МИМО туннеля — иначе это не
	// прикрытие, а обычный туннельный трафик. На Linux это делает метка
	// сокета, здесь — отдельные маршруты-исключения.
	if resolvers := StartDNSCover(ctx, cfg, nil, log); len(resolvers) > 0 && ft != nil {
		// Резолверы прикрытия известны только здесь, а блокировка встала
		// выше — без этого дополнения прикрытие DNS упиралось бы в
		// собственный kill switch и запросы никуда бы не уходили.
		if ks != nil {
			ksAllow = append(ksAllow, allowList(resolvers...)...)
			if err := ks.Reapply(luid, ksAllow); err != nil {
				log.Warn("аварийное отключение: не удалось разрешить резолверы прикрытия",
					"err", err)
			} else {
				log.Info("аварийное отключение: резолверы прикрытия DNS разрешены",
					"адреса", resolvers)
			}
		}
		if err := ft.Bypass(resolvers); err != nil {
			log.Warn("прикрытие DNS пойдёт через туннель: не удалось увести его мимо", "err", err)
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
		restore, err := netsetup.SetDNSOn(luid, dns)
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

		// Резолвера на интерфейсе недостаточно. Windows разрешает имена
		// «умно»: шлёт запрос сразу во все интерфейсы и берёт первый
		// ответ, а домашний роутер отвечает быстрее, чем публичный
		// резолвер за туннелем. Имена продолжают утекать провайдеру, и
		// изнутри системы это никак не видно.
		//
		// Только при полном туннеле: правило перекрывает разрешение имён
		// целиком, и при раздельном туннеле это было бы самоуправством.
		if ft != nil {
			restoreNRPT, err := netsetup.SetNRPT(dns)
			if err != nil {
				log.Warn("имена могут резолвиться мимо туннеля: не удалось поставить правило NRPT",
					"err", err)
			} else {
				defer func() {
					if err := restoreNRPT(); err != nil {
						log.Warn("снятие правила разрешения имён", "err", err)
					}
				}()
				log.Info("разрешение имён закреплено за туннелем", "правило", "NRPT",
					"иначе", "Windows опрашивает все интерфейсы сразу")
			}
		}
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
				// Имя сервера могло переехать на другой адрес при
				// переподключении: маршрут-исключение должен за ним следовать,
				// иначе туннель начнёт заворачивать сам себя.
				if ft != nil {
					cur := dialer.ServerIP()
					if err := ft.SetServer(cur); err != nil {
						log.Warn("обновление маршрута к серверу", "err", err)
					}
					// Аварийное отключение пропускает конкретный адрес
					// сервера. Переехал сервер — переставим блокировку на
					// новый адрес, иначе к нему нельзя будет переподключиться.
					if ks != nil && cur.IsValid() && cur != ksServer {
						if err := ks.Reapply(luid, replaceServer(ksAllow, ksServer, cur)); err != nil {
							log.Warn("обновление аварийного отключения", "err", err)
						} else {
							ksAllow = replaceServer(ksAllow, ksServer, cur)
							ksServer = cur
						}
					}
				}
				log.Debug("счётчики", "to_tunnel", cnt.ToTunnel.Load(), "from_tunnel", cnt.FromTunnel.Load(),
					"icmp", cnt.ICMP.Load(), "rejected", cnt.Rejected.Load(),
					"rotations", sess.Rotations(), "reconnects", sess.Reconnects())
			}
		}
	}()
	return tunnel.RunClient(ctx, dev, sess, tunnel.ClientOptions{Logger: log, Counters: cnt})
}

// allowList превращает адреса в префиксы /32 и /128 для аварийного
// отключения. Невалидные адреса отбрасываются: пустой ServerIP означает лишь,
// что имя ещё не разрешилось.
func allowList(addrs ...netip.Addr) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(addrs))
	for _, a := range addrs {
		if a.IsValid() {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out
}

// replaceServer меняет в списке разрешённых прежний адрес сервера на новый,
// не трогая остальные: сервер переезжает при переподключении, а резолверы
// прикрытия и пользовательские исключения остаются прежними.
func replaceServer(allow []netip.Prefix, old, now netip.Addr) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(allow)+1)
	for _, p := range allow {
		if old.IsValid() && p.Addr() == old && p.Bits() == old.BitLen() {
			continue
		}
		out = append(out, p)
	}
	if now.IsValid() {
		out = append(out, netip.PrefixFrom(now, now.BitLen()))
	}
	return out
}
