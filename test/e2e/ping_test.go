//go:build e2e && linux

package e2e

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestPingThroughTunnel — пинг профиля настоящим бинарником клиента.
//
// «Интернет» стенда изображает example.com: резолвер в nsInet знает имя,
// HTTP отвечает на 8080. Из netns клиента в «интернет» НЕТ маршрута — туда
// можно попасть только через туннель. Поэтому ответ на пинг сам доказывает,
// что и DNS-запрос, и HTTP-запрос прошли через сессию CONNECT-IP, а журнал
// резолвера подтверждает: запрос пришёл с адреса сервера (после NAT), а не
// клиента.
//
// Во второй половине тот же пинг идёт при поднятом клиенте с тем же ключом:
// сессия пинга живёт под своим псевдонимом устройства и не должна отнять
// адрес у живой — после пинга туннель обязан работать как работал.
func TestPingThroughTunnel(t *testing.T) {
	for _, tr := range []string{"quic", "utls"} {
		t.Run(tr, func(t *testing.T) {
			requireEnv(t)
			bin := buildBinaries(t)
			dir := t.TempDir()
			// Реестр клиентов, как на живом сервере: только в нём адрес
			// закрепляется за парой клиент+устройство — ради этого и проверка.
			registry := filepath.Join(dir, "clients.json")
			id, key := clientsAdd(t, bin, registry, "Ноутбук")
			s := newStand(t, opts{transport: tr, noClient: true, extraSrv: map[string]any{
				"auth_key": "", "clients_file": registry,
			}})
			dns := start(t, nsInet, "pingdns", filepath.Join(s.bin, "inetsrv"),
				"-dns", internet+":53", "-dns-a", "example.com="+internet, "-addr", "", "-udp", "")
			time.Sleep(300 * time.Millisecond)

			// Одна копия программы — одно устройство: и пинг, и живой клиент
			// читают один device.id рядом с исполняемым.
			exe := filepath.Join(t.TempDir(), "vpnclient")
			raw, err := os.ReadFile(filepath.Join(bin, "vpnclient-"+tr))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(exe, raw, 0o755); err != nil {
				t.Fatal(err)
			}
			path := writeJSON(t, filepath.Join(dir, "client.json"), map[string]any{
				"server":      "10.0.0.1:443",
				"server_name": sni,
				"auth_key":    key,
				"client_id":   id,
				"ca_file":     s.ca,
				"transport":   tr,
				"tun":         map[string]any{"name": "masquevpn0", "mtu": 1280},
				"dns":         []string{internet},
				"log_level":   "debug",
				"dns_cover":   map[string]any{"disabled": true},
			})

			ping := func() (int, string) {
				t.Helper()
				out := mustNS(t, nsCli, exe, "-config", path, "-ping", "-ping-target", "example.com:8080")
				m := regexp.MustCompile(`пинг: (\d+) мс — GET example\.com:8080 через туннель, HTTP/1\.1 \d+[^(]*\(порт 443, адрес сессии пинга ([0-9.]+)\)`).FindStringSubmatch(out)
				if m == nil {
					t.Fatalf("вывод пинга:\n%s", out)
				}
				ms, _ := strconv.Atoi(m[1])
				if ms <= 0 || ms > 2000 {
					t.Fatalf("время %d мс", ms)
				}
				return ms, m[2]
			}

			ms, _ := ping()
			t.Logf("пинг без поднятого туннеля: %d мс", ms)
			if !strings.Contains(dns.Log(), "src=203.0.113.1") || !strings.Contains(dns.Log(), "name=example.com") {
				t.Fatalf("резолвер не видел запроса с адреса сервера:\n%s", dns.Log())
			}

			// Живой клиент того же устройства, пинг, и туннель работает дальше.
			live := start(t, nsCli, "live", exe, "-config", path)
			live.waitLog(t, "весь трафик идёт через туннель", 30*time.Second)
			checkDownload(t, 1<<20)
			liveAddr := mustNS(t, nsCli, "ip", "-4", "-o", "addr", "show", "dev", "masquevpn0")
			ms, pingAddr := ping()
			t.Logf("пинг при поднятом туннеле: %d мс, адрес сессии пинга %s", ms, pingAddr)
			// Общий адрес значил бы, что входящий трафик живой сессии на время
			// пинга уходил в сессию пинга: маршрутизатор сервера отдаёт его
			// последней сессии адреса.
			if strings.Contains(liveAddr, " "+pingAddr+"/") {
				t.Fatalf("сессия пинга получила адрес живой сессии %s:\n%s", pingAddr, liveAddr)
			}
			time.Sleep(time.Second)
			checkDownload(t, 1<<20)
			if strings.Contains(live.Log(), "переподключение") {
				t.Fatalf("пинг сбил живую сессию:\n%s", live.Log())
			}
		})
	}
}
