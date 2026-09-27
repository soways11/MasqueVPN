//go:build linux

// Команда androidsim — имитатор VpnService для стенда.
//
// Зачем она. Ядро mobile/core предназначено для Android, а собрать и
// запустить Android здесь нечем: нет ни NDK, ни эмулятора. Но сам контракт,
// по которому система разговаривает с ядром, к Android не привязан:
//
//	система создаёт интерфейс  →  отдаёт приложению дескриптор
//	приложение защищает сокет  →  трафик туннеля идёт мимо туннеля
//	система настраивает адреса и маршруты по описанию от ядра
//
// Всё это воспроизводится на Linux один в один. Эта команда играет роль
// системы: сама открывает /dev/net/tun (как это делает Android), отдаёт
// ядру голый дескриптор, настраивает интерфейс ПО ТОМУ ЖЕ JSON, который
// ядро вернуло из Connect, и защищает сокет — только меткой SO_MARK вместо
// VpnService.protect. Дальше в дело идёт ровно тот код, который поедет на
// телефон.
//
// То есть проверяется не «похожий» путь, а тот же самый — кроме двух
// системных вызовов, которые на Android делает Android.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/soways11/masquevpn/internal/netsetup"
	"github.com/soways11/masquevpn/mobile/core"
)

func main() {
	cfgPath := flag.String("config", "", "файл конфигурации клиента")
	ifname := flag.String("iface", "masquevpn0", "имя интерфейса, который создаёт «система»")
	breakProtect := flag.Bool("break-protect", false,
		"мутация: делать вид, что сокет защищён, не защищая его")
	flag.Parse()

	if *cfgPath == "" {
		fatal("нужен -config")
	}
	raw, err := os.ReadFile(*cfgPath)
	if err != nil {
		fatal(err)
	}

	// 1. Система создаёт интерфейс. На Android это делает VpnService.Builder
	//    внутри establish(); здесь — мы сами, потому что здесь система это мы.
	fd, err := openTUN(*ifname)
	if err != nil {
		fatal(fmt.Errorf("создание интерфейса: %w", err))
	}
	fmt.Printf("система: интерфейс %s создан, дескриптор %d\n", *ifname, fd)

	tun := core.NewTunnel()
	ev := &events{}
	prot := &protector{mark: netsetup.DefaultFwMark, broken: *breakProtect}

	// 2. Ядро открывает сессию БЕЗ интерфейса и говорит, что настроить.
	netJSON, err := tun.Connect(string(raw), prot, ev)
	if err != nil {
		fatal(fmt.Errorf("подключение: %w", err))
	}
	fmt.Printf("ядро: параметры сети %s\n", netJSON)

	var nw netParams
	if err := json.Unmarshal([]byte(netJSON), &nw); err != nil {
		fatal(err)
	}
	if prot.calls == 0 {
		fatal(fmt.Errorf("ядро ни разу не попросило защитить сокет — " +
			"на Android это означало бы туннель, замкнутый сам на себя"))
	}

	// 3. Система применяет то, что сказало ядро. На Android этим занимается
	//    Builder: addAddress, addRoute, addDnsServer, setMtu.
	ft, err := applyNetwork(*ifname, nw)
	if err != nil {
		fatal(fmt.Errorf("настройка интерфейса: %w", err))
	}
	if ft != nil {
		defer func() {
			if err := ft.Down(); err != nil {
				fmt.Println("система: снятие маршрутов:", err)
			}
		}()
	}
	fmt.Println("система: интерфейс настроен")

	// 4. Дескриптор уходит ядру, и начинается перекачка пакетов.
	if err := tun.Attach(fd); err != nil {
		fatal(fmt.Errorf("передача дескриптора: %w", err))
	}
	fmt.Println("туннель работает")

	// Смена адреса: система должна построить интерфейс заново. Здесь это
	// новый дескриптор на тот же интерфейс плюс переназначение адресов.
	ev.onRebind = func(j string) {
		var n netParams
		if err := json.Unmarshal([]byte(j), &n); err != nil {
			fmt.Println("система: не разобран JSON перестроения:", err)
			return
		}
		fmt.Println("система: перестраиваю интерфейс, адреса", n.Addresses)
		if _, err := applyNetwork(*ifname, n); err != nil {
			fmt.Println("система: переназначение адресов:", err)
			return
		}
		nfd, err := unix.Dup(fd)
		if err != nil {
			fmt.Println("система: дубликат дескриптора:", err)
			return
		}
		if err := tun.Rebind(nfd); err != nil {
			fmt.Println("система: перепривязка:", err)
			return
		}
		fmt.Println("система: интерфейс перестроен")
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for range t.C {
			fmt.Println("счётчики:", tun.StatsJSON())
		}
	}()
	<-stop

	fmt.Println("остановка")
	tun.Stop()
	fmt.Println("счётчики:", tun.StatsJSON())
	fmt.Println("остановлено")
}

// netParams — параметры сети так, как их видит приложение: разобранный JSON.
//
// Своя структура, а не тип из ядра, намеренно: Kotlin тоже увидит только
// JSON, и имитатор должен работать ровно с тем же — иначе он проверял бы
// договорённость, которой на телефоне не будет.
type netParams struct {
	Addresses []string `json:"addresses"`
	Routes    []string `json:"routes"`
	DNS       []string `json:"dns"`
	MTU       int      `json:"mtu"`
	Bypass    []string `json:"bypass"`
}

// applyNetwork делает то, что на Android делает VpnService.Builder.
func applyNetwork(iface string, nw netParams) (*netsetup.FullTunnel, error) {
	addrs, err := prefixes(nw.Addresses)
	if err != nil {
		return nil, err
	}
	if err := netsetup.ConfigureInterface(iface, nw.MTU, addrs); err != nil {
		return nil, err
	}

	full := false
	var routes []netip.Prefix
	for _, r := range nw.Routes {
		p, err := netip.ParsePrefix(r)
		if err != nil {
			return nil, fmt.Errorf("маршрут %q: %w", r, err)
		}
		if p.Bits() == 0 {
			full = true
			continue
		}
		routes = append(routes, p)
	}
	if len(routes) > 0 {
		if err := netsetup.AddRoutes(iface, routes); err != nil {
			return nil, err
		}
	}
	if !full {
		return nil, nil
	}
	// Полный туннель. На Android система сама уводит защищённые сокеты мимо
	// туннеля; на Linux ту же роль играет метка, поэтому здесь правило
	// «не помеченное — в таблицу туннеля».
	ft := &netsetup.FullTunnel{Iface: iface, IPv6: hasV6(addrs)}
	if err := ft.Up(); err != nil {
		return nil, err
	}
	return ft, nil
}

func hasV6(ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Addr().Is6() {
			return true
		}
	}
	return false
}

func prefixes(ss []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("адрес %q: %w", s, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// protector — VpnService.protect на стенде: метка сокета.
type protector struct {
	mark   uint32
	broken bool
	calls  int
}

func (p *protector) Protect(fd int) bool {
	p.calls++
	if p.broken {
		// Мутация: говорим «защитил», не защитив. Ровно так выглядит
		// забытый или неудавшийся VpnService.protect — и туннель после
		// этого замыкается сам на себя.
		return true
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, int(p.mark)); err != nil {
		fmt.Println("система: защитить сокет не удалось:", err)
		return false
	}
	return true
}

// events — приложение: печатает всё, что сообщает ядро.
type events struct {
	onRebind func(string)
}

func (e *events) OnState(s string) { fmt.Println("состояние:", s) }

func (e *events) OnLog(level, msg string) {
	fmt.Printf("%s: %s\n", level, strings.TrimSpace(msg))
}

func (e *events) OnRebind(j string) {
	fmt.Println("ядро: нужен новый интерфейс")
	if e.onRebind != nil {
		e.onRebind(j)
	}
}

// openTUN открывает интерфейс так же, как это делает система: без заголовка
// packet info, с заданным именем.
func openTUN(name string) (int, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(fd)
		return -1, err
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func fatal(v any) {
	log.SetFlags(0)
	log.Fatalln("androidsim:", v)
}
