//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

// Сквозная проверка того, на что жалуются чаще всего: «по одному ключу с
// разных устройств работает только на одном».
//
// Юнит-тесты показывают, что аренда адресов теперь различает устройства, а
// маршрутизатор разводит пакеты по адресам. Здесь проверяется то, чего они
// показать не могут: два НАСТОЯЩИХ клиента, каждый со своим TUN в своём
// сетевом окружении, одновременно ходят в интернет по одному ключу — и ни
// один из них не замолкает после подключения другого.
//
// Разные устройства изображаются двумя копиями программы в разных каталогах:
// псевдоним устройства клиент хранит рядом с собой (см. config.DeviceID), и
// так у каждого он свой — как на двух разных компьютерах.

// nsCli2 — сеть второго устройства. Своя, а не общая с первым: два клиента в
// одном окружении делили бы таблицу маршрутов и мешали друг другу, а вопрос
// в другом — мешают ли они друг другу НА СЕРВЕРЕ.
const nsCli2 = "gv-cli2"

var addrInLog = regexp.MustCompile(`addrs=\[([0-9a-f.:]+)/`)

func TestTwoDevicesOnOneKey(t *testing.T) {
	requireEnv(t)
	bin := buildBinaries(t)
	dir := t.TempDir()
	registry := filepath.Join(dir, "clients.json")
	id, key := clientsAdd(t, bin, registry, "Ноутбук")

	// Сервер в режиме реестра — как на живом сервере: ключ личный, псевдоним
	// клиента выдан сервером и на обоих устройствах один и тот же.
	s := newStand(t, opts{noClient: true, extraSrv: map[string]any{
		"auth_key": "", "clients_file": registry,
	}})
	secondClientNetwork(t)

	dev := func(name, ns, tun string) *proc {
		t.Helper()
		// Отдельный каталог программы = отдельное устройство: файл device.id
		// лежит рядом с исполняемым.
		exe := filepath.Join(t.TempDir(), "vpnclient")
		raw, err := os.ReadFile(filepath.Join(bin, "vpnclient-quic"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(exe, raw, 0o755); err != nil {
			t.Fatal(err)
		}
		cfg := writeJSON(t, filepath.Join(dir, name+".json"), map[string]any{
			"server": "10.0.0.1:443", "server_name": sni, "ca_file": s.ca,
			"auth_key": key, "client_id": id,
			"transport": "quic",
			"tun":       map[string]any{"name": tun, "mtu": 1280},
			"log_level": "debug",
			"dns_cover": map[string]any{"disabled": true},
		})
		p := start(t, ns, name, exe, "-config", cfg)
		p.waitLog(t, "весь трафик идёт через туннель", 30*time.Second)
		return p
	}

	// Первое устройство подключается и работает.
	laptop := dev("ноутбук", nsCli, "masquevpn0")
	if _, err := ping(nsCli, "-c", "2", "-i", "0.2", internet); err != nil {
		t.Fatalf("ноутбук не ходит в интернет сразу после подключения: %v", err)
	}

	// Второе — то самое место, где раньше всё ломалось: сервер выдавал ему
	// адрес первого, и входящий трафик переставал доходить до ноутбука.
	phone := dev("телефон", nsCli2, "masquevpn0")

	addrLaptop := assignedAddr(t, laptop)
	addrPhone := assignedAddr(t, phone)
	if addrLaptop == addrPhone {
		t.Fatalf("оба устройства получили адрес %s — входящий трафик дойдёт только до одного", addrLaptop)
	}
	t.Logf("ноутбук %s, телефон %s", addrLaptop, addrPhone)

	// Оба устройства ходят наружу ОДНОВРЕМЕННО. Порядок проверки важен:
	// сначала то, что подключилось раньше, — именно оно раньше замолкало.
	for _, d := range []struct{ name, ns string }{
		{"ноутбук", nsCli},
		{"телефон", nsCli2},
	} {
		if out, err := ping(d.ns, "-c", "3", "-i", "0.2", internet); err != nil {
			t.Fatalf("%s не ходит в интернет при двух подключённых устройствах: %v\n%s", d.name, err, out)
		}
	}

	// И то же под нагрузкой, вперемешку: пакеты обоих устройств идут через
	// один сервер и не должны путаться.
	done := make(chan error, 2)
	for _, ns := range []string{nsCli, nsCli2} {
		go func(ns string) {
			_, err := nsRun(ns, "curl", "-sS", "--fail", "--noproxy", "*", "--max-time", "60",
				"-o", "/dev/null", fmt.Sprintf("http://%s:8080/blob?n=%d", internet, 2<<20))
			done <- err
		}(ns)
	}
	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatalf("скачивание на одном из устройств не удалось: %v", err)
		}
	}

	// Ни одно из подключений не оборвалось по пути.
	for name, p := range map[string]*proc{"ноутбук": laptop, "телефон": phone} {
		if got := countLog(p, "сессия установлена"); got != 1 {
			t.Fatalf("%s: записей «сессия установлена» %d — подключение обрывалось и восстанавливалось", name, got)
		}
	}
}

// secondClientNetwork добавляет к стенду сеть второго устройства: своё
// namespace и канал до сервера.
func secondClientNetwork(t *testing.T) {
	t.Helper()
	exec.Command("ip", "netns", "del", nsCli2).Run()
	sh(t, "ip", "netns", "add", nsCli2)
	t.Cleanup(func() { exec.Command("ip", "netns", "del", nsCli2).Run() })
	mustNS(t, nsCli2, "ip", "link", "set", "lo", "up")

	sh(t, "ip", "link", "add", "cli1", "netns", nsCli2, "type", "veth", "peer", "name", "srv2", "netns", nsSrv)
	mustNS(t, nsCli2, "ip", "addr", "add", "10.0.1.2/24", "dev", "cli1")
	mustNS(t, nsCli2, "ip", "link", "set", "cli1", "up")
	mustNS(t, nsSrv, "ip", "addr", "add", "10.0.1.1/24", "dev", "srv2")
	mustNS(t, nsSrv, "ip", "link", "set", "srv2", "up")
	// Второе устройство сидит не в одной сети с сервером, а за шлюзом — как
	// любая машина в интернете.
	mustNS(t, nsCli2, "ip", "route", "add", "default", "via", "10.0.1.1")
}

// assignedAddr — адрес, выданный клиенту, из его же журнала.
func assignedAddr(t *testing.T, p *proc) string {
	t.Helper()
	m := addrInLog.FindStringSubmatch(p.Log())
	if m == nil {
		t.Fatalf("в журнале %s нет выданного адреса:\n%s", p.name, p.Log())
	}
	return m[1]
}

func countLog(p *proc, what string) int {
	n, log := 0, p.Log()
	for i := 0; i+len(what) <= len(log); i++ {
		if log[i:i+len(what)] == what {
			n++
			i += len(what) - 1
		}
	}
	return n
}
