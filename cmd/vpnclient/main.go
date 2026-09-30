// Команда vpnclient — клиент masquevpn для Linux: поднимает TUN, устанавливает
// CONNECT-IP сессию (MASQUE) и заворачивает в неё трафик устройства.
//
//	vpnclient -config /etc/masquevpn/client.json
//
// Нужны права root (или CAP_NET_ADMIN): создание TUN, маршруты, SO_MARK.
// Внешние утилиты (ip, iptables, nft) не используются — всё через netlink.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/soways11/masquevpn/internal/client"
	"github.com/soways11/masquevpn/internal/clientrun"
	"github.com/soways11/masquevpn/internal/config"
	"github.com/soways11/masquevpn/internal/logx"
	"github.com/soways11/masquevpn/internal/netsetup"
	"github.com/soways11/masquevpn/internal/version"
)

func main() {
	cfgPath := flag.String("config", config.DefaultClientConfig(), "файл конфигурации")
	check := flag.Bool("check", false, "только проверить конфигурацию и выйти")
	self := flag.Bool("selftest", false, "проверить платформенную часть (адаптер, адрес, MTU, маршруты, DNS) без подключения к серверу")
	selfFull := flag.Bool("selftest-full", false, "то же, но с полным туннелем: на время проверки интернет уходит в никуда")
	selfSeconds := flag.Int("selftest-seconds", 10, "сколько держать адаптер при самопроверке")
	cleanup := flag.Bool("cleanup", false, "убрать следы упавшего клиента: в Windows — блокировку сети, правило разрешения имён и маршруты, в Linux — подменённый DNS")
	watchdog := flag.Int("watchdog", 0, "служебное: ждать завершения процесса с этим pid и прибраться за ним")

	// Профили: несколько доступов в одном клиенте. Флаг -config остаётся
	// главным — если он задан явно, профили не трогаются вовсе.
	prof := profileCommands{}
	flag.StringVar(&prof.path, "profiles", "", "файл профилей (по умолчанию profiles.json рядом с программой)")
	flag.BoolVar(&prof.list, "profiles-list", false, "показать профили и выйти")
	flag.StringVar(&prof.add, "profile-add", "", "добавить профиль: ссылка masquevpn://… или путь к файлу конфигурации")
	flag.StringVar(&prof.name, "profile-name", "", "имя для добавляемого профиля")
	flag.StringVar(&prof.use, "profile-use", "", "выбрать профиль по имени")
	flag.StringVar(&prof.remove, "profile-remove", "", "удалить профиль по имени")
	killOff := flag.Bool("killswitch-off", false, "то же, что -cleanup (прежнее имя)")
	showVersion := flag.Bool("version", false, "показать версию и выйти")
	pingOnly := flag.Bool("ping", false, "пинг профиля: поднять сессию, сделать через неё HTTP GET на "+client.DefaultPingTarget+" и выйти")
	pingTarget := flag.String("ping-target", client.DefaultPingTarget, "куда идёт запрос пинга: хост[:порт]")
	flag.Parse()
	if *showVersion {
		fmt.Println("masquevpn-cli", version.Version)
		return
	}

	// Страховка на случай, если клиент не дожил до выхода: убитая задача,
	// краш, выключение по питанию. Работает всегда — без конфигурации и без
	// поднятого туннеля.
	//
	// Убирается не только блокировка WFP (она и так умирает вместе с
	// процессом), но и то, что переживает его: правило разрешения имён и
	// маршруты-исключения на физическом интерфейсе. Прежнее имя флага
	// оставлено, чтобы не ломать то, что уже записано в инструкциях.
	// Сторож. Запускается самим клиентом: снять следы, переживающие
	// процесс, можно только ПОСЛЕ его смерти.
	if *watchdog > 0 {
		rep, err := clientrun.RunWatchdog(*watchdog)
		if err != nil {
			fmt.Fprintln(os.Stderr, "vpnclient:", err)
			os.Exit(1)
		}
		fmt.Println(rep.String())
		return
	}

	if *cleanup || *killOff {
		rep, err := netsetup.Cleanup()
		if err != nil {
			fmt.Fprintln(os.Stderr, "vpnclient:", err)
			os.Exit(1)
		}
		fmt.Println(rep.String())
		return
	}

	if *self || *selfFull {
		log := logx.New("info")
		if err := clientrun.Selftest(*selfFull, *selfSeconds, log); err != nil {
			log.Error("самопроверка не пройдена", "err", err)
			os.Exit(1)
		}
		log.Info("самопроверка завершена успешно")
		return
	}

	if prof.any() {
		os.Exit(prof.run())
	}

	// Откуда брать конфигурацию. Явный -config главнее профилей: у тех, кто
	// уже пользуется файлом, ничего не должно поменяться от появления
	// профилей.
	cfg, profileName, err := loadConfig(*cfgPath, prof.path, isFlagSet("config"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "vpnclient:", err)
		os.Exit(2)
	}
	if *check {
		fmt.Println("конфигурация в порядке")
		return
	}
	if *pingOnly {
		os.Exit(runPing(cfg, *pingTarget))
	}
	log := logx.New(cfg.LogLevel)
	log.Info("masquevpn", "version", version.Version)
	if profileName != "" {
		// Имя профиля в журнале: при нескольких доступах «подключён» без
		// уточнения, куда именно, — половина ответа.
		log.Info("профиль", "имя", profileName, "сервер", cfg.Server)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := clientrun.Run(ctx, cfg, log, clientrun.Hooks{}); err != nil && !errors.Is(err, context.Canceled) {
		log.Error("клиент остановлен с ошибкой", "err", err)
		os.Exit(1)
	}
	log.Info("клиент остановлен")
}

// runPing — то же, что кнопка пинга в окне: сессия CONNECT-IP и GET через
// неё. Туннель в системе при этом не поднимается.
func runPing(cfg *config.Client, target string) int {
	ctx, cancel := context.WithTimeout(context.Background(), clientrun.PingTimeout)
	defer cancel()
	opt := clientrun.PingOptions(cfg)
	opt.Logger = logx.New(cfg.LogLevel)
	res, err := client.Ping(ctx, cfg, opt, target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "пинг: нет ответа —", clientrun.PingReason(err))
		return 1
	}
	fmt.Printf("пинг: %d мс — GET %s через туннель, %s (порт %s, адрес сессии пинга %s)\n",
		res.RTT.Milliseconds(), res.Target, res.Status, res.Port, res.Addr)
	return 0
}

// loadConfig берёт конфигурацию из файла или из выбранного профиля.
//
// Порядок такой: явный -config, затем выбранный профиль, затем файл по
// умолчанию. Последнее нужно, чтобы у тех, у кого рядом лежит client.json,
// всё продолжало работать без единой правки.
func loadConfig(cfgPath, profilesPath string, explicit bool) (*config.Client, string, error) {
	if !explicit {
		if cfg, name, ok := activeProfileConfig(profilesPath); ok {
			return cfg, name, nil
		}
	}
	cfg, err := config.LoadClient(cfgPath)
	if err != nil && !explicit && errors.Is(err, os.ErrNotExist) {
		// Ни профилей, ни файла по умолчанию — обычное дело сразу после
		// установки. «Нет файла /etc/masquevpn/client.json» такому человеку
		// ничего не говорит; говорим, что сделать.
		if profilesPath == "" {
			profilesPath = config.DefaultProfilesPath()
		}
		return nil, "", fmt.Errorf("доступов пока нет (%s пуст, %s не найден) — добавьте: "+
			"masquevpn-cli -profile-add %s://…", profilesPath, cfgPath, config.LinkScheme)
	}
	return cfg, "", err
}

// isFlagSet сообщает, задавали ли флаг в командной строке. Умолчание и
// явно переданное значение для нас не одно и то же.
func isFlagSet(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}
