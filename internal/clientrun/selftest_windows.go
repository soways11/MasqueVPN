//go:build windows

package clientrun

import (
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/soways11/masquevpn/internal/netsetup"
	"github.com/soways11/masquevpn/internal/tun"
)

// Самопроверка платформенной части Windows.
//
// Зачем она. Всё, что здесь задействовано, — создание адаптера Wintun,
// раскладка структур IP Helper API, назначение адреса, MTU, маршрутов и DNS —
// написано против документации и проверить это можно только на живой Windows.
// Ошибка в раскладке структуры не обязательно даст отказ: система прочитает
// не то поле, и последствия всплывут позже. Поэтому самопроверка делает
// каждый шаг и тут же читает результат обратно.
//
// По умолчанию она безобидна: адаптер получает адрес из 10.66.0.0/24 и
// маршрут только на эту же сеть, интернет не затрагивается. Полный туннель
// (он уводит ВЕСЬ трафик и на время самопроверки рвёт связь) включается
// отдельным флагом.

func Selftest(full bool, seconds int, log *slog.Logger) error {
	const (
		ifname = "masquevpn-selftest"
		mtu    = 1280
	)
	addr := netip.MustParsePrefix("10.66.0.2/32")
	testNet := netip.MustParsePrefix("10.66.0.0/24")

	log.Info("самопроверка: создаю адаптер", "имя", ifname, "mtu", mtu)
	dev, err := tun.Open(ifname, mtu)
	if err != nil {
		return fmt.Errorf("адаптер: %w", err)
	}
	defer dev.Close()

	l, ok := dev.(interface {
		LUID() uint64
		DriverVersion() uint32
	})
	if !ok {
		return fmt.Errorf("адаптер не сообщил LUID")
	}
	v := l.DriverVersion()
	log.Info("адаптер создан", "luid", fmt.Sprintf("%#x", l.LUID()),
		"драйвер Wintun", fmt.Sprintf("%d.%d", v>>16, v&0xffff))

	if err := netsetup.ConfigureInterfaceLUID(l.LUID(), mtu, []netip.Prefix{addr}); err != nil {
		return fmt.Errorf("адрес и MTU: %w", err)
	}
	log.Info("адрес и MTU назначены", "addr", addr, "mtu", mtu)

	if err := netsetup.AddRoutesLUID(l.LUID(), []netip.Prefix{testNet}); err != nil {
		return fmt.Errorf("маршрут: %w", err)
	}
	log.Info("маршрут добавлен", "сеть", testNet)

	// Читаем обратно: через какой интерфейс система теперь пойдёт в нашу сеть
	// и через какой — в интернет.
	if luid, hop, err := netsetup.BestRoute(netip.MustParseAddr("10.66.0.77")); err != nil {
		log.Warn("маршрут до тестовой сети не найден", "err", err)
	} else if luid != l.LUID() {
		return fmt.Errorf("маршрут до 10.66.0.77 идёт мимо адаптера (luid %#x вместо %#x)", luid, l.LUID())
	} else {
		log.Info("проверка маршрута: 10.66.0.77 идёт через адаптер", "шлюз", hop)
	}
	outLUID, outHop, err := netsetup.BestRoute(netip.MustParseAddr("1.1.1.1"))
	if err != nil {
		return fmt.Errorf("нет маршрута в интернет: %w", err)
	}
	log.Info("интернет пока идёт мимо адаптера", "luid", fmt.Sprintf("%#x", outLUID), "шлюз", outHop)

	restoreDNS, err := netsetup.SetDNSOn(l.LUID(), []netip.Addr{netip.MustParseAddr("10.66.0.1")})
	if err != nil {
		log.Warn("DNS назначить не удалось", "err", err)
	} else {
		log.Info("DNS назначен на адаптер", "server", "10.66.0.1")
		defer func() {
			if err := restoreDNS(); err != nil {
				log.Warn("возврат DNS", "err", err)
			} else {
				log.Info("DNS возвращён")
			}
		}()
	}

	if full {
		log.Warn("включаю полный туннель: на время самопроверки интернета не будет",
			"секунд", seconds)
		// Куда система шлёт IPv6 ДО нас. Без этого снимка проверка ниже
		// вырождается: после Up() маршрут ::/1 наш в любом случае, и
		// «IPv6 идёт через адаптер» окажется верно даже на машине, где
		// IPv6 нет вовсе и перехватывать было нечего.
		v6 := netip.MustParseAddr("2606:4700:4700::1111")
		v6Before, _, v6Err := netsetup.BestRoute(v6)
		ft := &netsetup.FullTunnel{
			LUID:   l.LUID(),
			Server: netip.MustParseAddr("1.1.1.1"), // «адрес сервера» для маршрута-исключения
			IPv6:   true,
		}
		if err := ft.Up(); err != nil {
			return fmt.Errorf("полный туннель: %w", err)
		}
		defer func() {
			if err := ft.Down(); err != nil {
				log.Warn("снятие маршрутов", "err", err)
			} else {
				log.Info("маршруты сняты, система вернулась в исходное состояние")
			}
		}()
		// Теперь в интернет система должна ходить через адаптер, а к
		// «серверу» — мимо него. Это и есть проверка расстановки маршрутов.
		if luid, _, err := netsetup.BestRoute(netip.MustParseAddr("8.8.8.8")); err != nil {
			return fmt.Errorf("после включения туннеля пропал маршрут: %w", err)
		} else if luid != l.LUID() {
			return fmt.Errorf("трафик не пошёл в туннель: 8.8.8.8 идёт через luid %#x", luid)
		} else {
			log.Info("проверка: весь трафик идёт через адаптер")
		}
		if luid, _, err := netsetup.BestRoute(netip.MustParseAddr("1.1.1.1")); err != nil {
			return fmt.Errorf("маршрут-исключение пропал: %w", err)
		} else if luid == l.LUID() {
			return fmt.Errorf("маршрут-исключение не работает: трафик к серверу пошёл бы в туннель")
		} else {
			log.Info("проверка: трафик к серверу идёт мимо туннеля", "luid", fmt.Sprintf("%#x", luid))
		}

		// IPv6 — отдельная проверка, и она здесь главная.
		//
		// Половинки ::/1 и 8000::/1 мы кладём на адаптер, у которого адреса
		// IPv6 нет вовсе. Примет ли Windows такой маршрут и предпочтёт ли его
		// маршруту провайдера — из документации не следует; если нет, то при
		// живом IPv6 у провайдера весь IPv6-трафик пойдёт МИМО туннеля, то
		// есть утечёт в открытую, пока IPv4 честно завёрнут. Читаем решение
		// маршрутизации у самой системы — и сравниваем со снимком до туннеля.
		v6After, _, err := netsetup.BestRoute(v6)
		switch {
		case v6Err != nil:
			log.Warn("IPv6 ПЕРЕХВАТ НЕ ПРОВЕРЕН: до туннеля у системы не было "+
				"маршрута к IPv6, перехватывать было нечего; нужна машина с живым IPv6",
				"err", v6Err)
		case err != nil:
			return fmt.Errorf("после включения туннеля пропал маршрут IPv6: %w", err)
		case v6After != l.LUID():
			return fmt.Errorf("УТЕЧКА IPv6: при поднятом туннеле %s идёт через luid %#x, "+
				"а не через адаптер %#x", v6, v6After, l.LUID())
		case v6Before == l.LUID():
			log.Warn("IPv6 ПЕРЕХВАТ НЕ ПРОВЕРЕН: маршрут к IPv6 вёл на наш адаптер " +
				"ещё до поднятия туннеля (не убрано с прошлого прогона?)")
		default:
			log.Info("проверка: IPv6 перехвачен",
				"было", fmt.Sprintf("%#x", v6Before), "стало", fmt.Sprintf("%#x", l.LUID()))
		}

		// Разрешение имён. Маршрутами оно не закрывается: Windows шлёт
		// запрос сразу во все интерфейсы и берёт первый ответ, так что
		// домашний роутер отвечает раньше резолвера за туннелем — и имена
		// утекают провайдеру при полностью исправном туннеле.
		//
		// Доказать отсутствие утечки изнутри системы нельзя, это видно
		// только снаружи (какой резолвер пришёл за именем к авторитетному
		// серверу). Поэтому проверяем своё: что правило поставлено, что оно
		// указывает на наши серверы и что оно снимается.
		want := []netip.Addr{netip.MustParseAddr("1.1.1.1")}
		restore, err := netsetup.SetNRPT(want)
		if err != nil {
			return fmt.Errorf("правило разрешения имён: %w", err)
		}
		if got, err := netsetup.CurrentNRPT(); err != nil {
			_ = restore()
			return fmt.Errorf("правило разрешения имён не читается обратно: %w", err)
		} else if len(got) != 1 || got[0] != want[0] {
			_ = restore()
			return fmt.Errorf("правило разрешения имён указывает на %v, а не на %v", got, want)
		}
		log.Info("проверка: разрешение имён закреплено за туннелем", "серверы", want)
		if err := restore(); err != nil {
			return fmt.Errorf("снятие правила разрешения имён: %w", err)
		}
		if got, err := netsetup.CurrentNRPT(); err != nil || len(got) != 0 {
			return fmt.Errorf("правило разрешения имён не снялось: %v (%v) — "+
				"имена будут уходить в резолвер, до которого нет пути", got, err)
		}
		log.Info("проверка: правило снимается, система возвращается к своему резолверу")

		// А это — проверка уборки за УПАВШИМ клиентом. Ставим правило и
		// НЕ снимаем его сами: так выглядит система после снятой задачи,
		// краха или выключения питания. Убрать это должна Cleanup — без
		// конфигурации и без туннеля.
		//
		// Поймано на живой машине 24.09.2026: kill switch после снятия
		// задачи снялся сам (он в динамической сессии WFP), а правило имён
		// осталось, и весь DNS продолжил уходить на резолвер за туннелем,
		// которого больше нет.
		if _, err := netsetup.SetNRPT(want); err != nil {
			return fmt.Errorf("правило разрешения имён (проверка уборки): %w", err)
		}
		rep, err := netsetup.Cleanup()
		if err != nil {
			return fmt.Errorf("аварийная уборка: %w", err)
		}
		if !rep.NRPT {
			return fmt.Errorf("уборка не заметила правило разрешения имён: %s", rep)
		}
		if got, err := netsetup.CurrentNRPT(); err != nil || len(got) != 0 {
			return fmt.Errorf("уборка не сняла правило разрешения имён: %v (%v)", got, err)
		}
		log.Info("проверка: следы упавшего клиента убираются", "уборка", rep.String())

		// И повторный вызов на чистой системе должен быть безвреден: он
		// делается при КАЖДОМ запуске клиента.
		if rep, err := netsetup.Cleanup(); err != nil {
			return fmt.Errorf("уборка на чистой системе: %w", err)
		} else if !rep.Empty() {
			return fmt.Errorf("уборка на чистой системе что-то нашла: %s", rep)
		}
		log.Info("проверка: уборка безвредна, когда убирать нечего")

		// Аварийное отключение. Доказать снаружи, что при падении клиента
		// трафик заблокирован, самопроверкой нельзя — для этого клиент надо
		// убить. Но можно проверить механизм: блокировка ставится, ядро её
		// видит, и она снимается начисто. Ставим и сразу снимаем, чтобы не
		// отрезать интернет во время самопроверки.
		ks, err := netsetup.KillSwitchArm(l.LUID(), allowList(netip.MustParseAddr("1.1.1.1")))
		if err != nil {
			return fmt.Errorf("аварийное отключение не включилось: %w", err)
		}
		if active, err := netsetup.KillSwitchActive(); err != nil {
			_ = ks.Disarm()
			return fmt.Errorf("аварийное отключение не читается обратно: %w", err)
		} else if !active {
			_ = ks.Disarm()
			return fmt.Errorf("аварийное отключение включили, но ядро его не видит")
		}
		log.Info("проверка: аварийное отключение встало (файрвол ядра)")

		// Переустановка на другой адрес сервера: она случается при каждом
		// переезде имени сервера, и провалиться ей нельзя — иначе клиент
		// останется с блокировкой на старый адрес и не переподключится.
		if err := ks.Reapply(l.LUID(), allowList(netip.MustParseAddr("8.8.8.8"))); err != nil {
			_ = ks.Disarm()
			return fmt.Errorf("аварийное отключение не переставляется на новый адрес: %w", err)
		}
		if active, err := netsetup.KillSwitchActive(); err != nil || !active {
			_ = ks.Disarm()
			return fmt.Errorf("после переустановки блокировки нет: active=%v (%v)", active, err)
		}
		log.Info("проверка: аварийное отключение переставляется на новый адрес сервера")

		if err := ks.Disarm(); err != nil {
			return fmt.Errorf("аварийное отключение не снялось — сеть могла остаться "+
				"заблокированной, снимите: vpnclient -killswitch-off: %w", err)
		}
		if active, err := netsetup.KillSwitchActive(); err != nil || active {
			return fmt.Errorf("аварийное отключение не снялось начисто: active=%v (%v)", active, err)
		}
		log.Info("проверка: аварийное отключение снимается начисто")

		// И последнее: аварийный выход должен работать, когда снимать нечего.
		// Он вызывается при каждом запуске клиента, и ошибка здесь означала
		// бы, что клиент не стартует на чистой машине.
		if err := netsetup.KillSwitchOff(); err != nil {
			return fmt.Errorf("аварийный выход спотыкается на пустом месте: %w", err)
		}
		log.Info("проверка: -killswitch-off безвреден, когда снимать нечего")
	}

	log.Info("всё настроено; держу адаптер", "секунд", seconds)
	time.Sleep(time.Duration(seconds) * time.Second)
	log.Info("самопроверка пройдена, убираю за собой")
	return nil
}
