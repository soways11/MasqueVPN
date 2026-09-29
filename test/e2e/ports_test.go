//go:build e2e

package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/soways11/masquevpn/internal/client"
)

// Запасные UDP-порты — сквозная проверка настоящими бинарниками.
//
// Провайдер режет порт так, как это делает фильтр: пакеты молча пропадают,
// ни ответа, ни ICMP. Клиент должен сам уйти на следующий порт из адреса,
// а если закрыты все — сказать об этом словами, а не таймаутом QUIC.

// dropUDP молча выбрасывает входящие UDP-пакеты на порт в пространстве ns —
// как фильтр по пути: у клиента отправка проходит, ответа нет.
func dropUDP(t *testing.T, ns string, port int) {
	t.Helper()
	p := strconv.Itoa(port)
	if _, err := exec.LookPath("nft"); err == nil {
		exec.Command("ip", "netns", "exec", ns, "nft", "add", "table", "inet", "blk").Run()
		exec.Command("ip", "netns", "exec", ns, "nft", "add", "chain", "inet", "blk", "in",
			"{ type filter hook input priority 0 ; }").Run()
		mustNS(t, ns, "nft", "add", "rule", "inet", "blk", "in", "udp", "dport", p, "drop")
		return
	}
	mustNS(t, ns, "iptables", "-A", "INPUT", "-p", "udp", "--dport", p, "-j", "DROP")
}

// dropUDPLocal не выпускает UDP на порт с самой машины: так выглядит
// файрвол на компьютере клиента — отправка падает с EPERM.
func dropUDPLocal(t *testing.T, ns string, port int) {
	t.Helper()
	mustNS(t, ns, "iptables", "-A", "OUTPUT", "-p", "udp", "--dport", strconv.Itoa(port), "-j", "DROP")
}

// forgetPorts стирает запомненный клиентом порт: vpnclient держит его рядом
// с собой (client.PortsFile), а бинарники на стенде общие для всех тестов.
func forgetPorts(t *testing.T, s *stand) {
	t.Helper()
	os.Remove(filepath.Join(s.bin, client.PortsFile))
}

func TestPortFallback(t *testing.T) {
	for _, tr := range []string{"quic", "utls"} {
		t.Run(tr, func(t *testing.T) {
			s := newStand(t, opts{noClient: true, extraSrv: map[string]any{"alt_ports": []int{8443}}})
			forgetPorts(t, s)
			if !strings.Contains(s.server.Log(), "8443") {
				t.Fatalf("сервер не сообщил о запасном порте:\n%s", s.server.Log())
			}
			// Сервер действительно слушает оба порта.
			ss := mustNS(t, nsSrv, "ss", "-lnu")
			for _, p := range []string{"10.0.0.1:443", "10.0.0.1:8443"} {
				if !strings.Contains(ss, p) {
					t.Fatalf("не слушается %s:\n%s", p, ss)
				}
			}

			dropUDP(t, nsSrv, 443)
			t0 := time.Now()
			s.startClient(t, opts{transport: tr, extraCli: map[string]any{"server": "10.0.0.1:443,8443"}})
			s.client.waitLog(t, "сервер отвечает на порту 8443", 5*time.Second)
			if !strings.Contains(s.client.Log(), "порт 443 не отвечает — пробую следующий") {
				t.Fatalf("переход на запасной порт не объяснён в журнале:\n%s", s.client.Log())
			}
			// Переход — за время одного рукопожатия, а не за весь срок подключения.
			if el := time.Since(t0); el > 15*time.Second {
				t.Fatalf("подключение через запасной порт заняло %v", el)
			}
			if o, err := ping(nsCli, "-c", "2", internet); err != nil {
				t.Fatalf("туннель через запасной порт не работает: %v\n%s", err, o)
			}
			s.client.stop(t)

			// Перезапуск: клиент помнит, что ответил 8443, и начинает с него —
			// не тратя ~5 с на закрытый 443.
			t1 := time.Now()
			s.startClient(t, opts{transport: tr, extraCli: map[string]any{"server": "10.0.0.1:443,8443"}})
			if strings.Contains(s.client.Log(), "порт 443 не отвечает") {
				t.Fatalf("после перезапуска клиент снова начал с закрытого порта:\n%s", s.client.Log())
			}
			if el := time.Since(t1); el > 4*time.Second {
				t.Fatalf("подключение после перезапуска заняло %v — порт не запомнен", el)
			}
			s.client.stop(t)

			// Закрыты оба порта — понятная ошибка, а не «timeout: no recent network activity».
			// Память портов стираем, чтобы порядок попыток в ошибке был 443, 8443.
			forgetPorts(t, s)
			dropUDP(t, nsSrv, 8443)
			path := writeJSON(t, filepath.Join(s.dir, "client-blocked.json"), map[string]any{
				"server":      "10.0.0.1:443,8443",
				"server_name": sni,
				"auth_key":    s.authKey,
				"ca_file":     s.ca,
				"transport":   tr,
				"dns_cover":   map[string]any{"disabled": true},
			})
			c := start(t, nsCli, "vpnclient-blocked-"+tr, filepath.Join(s.bin, "vpnclient-"+tr), "-config", path)
			c.waitLog(t, "порты 443, 8443 не отвечают: закрыты по пути или сервер выключен", 40*time.Second)
		})
	}
}

// TestPortFallbackLocalFirewall — порт не выпускает файрвол самой машины
// клиента: ошибка отправки (EPERM) тоже повод перейти на следующий порт.
func TestPortFallbackLocalFirewall(t *testing.T) {
	if _, err := exec.LookPath("iptables"); err != nil {
		t.Skip("нет iptables")
	}
	s := newStand(t, opts{noClient: true, extraSrv: map[string]any{"alt_ports": []int{8443}}})
	forgetPorts(t, s)
	dropUDPLocal(t, nsCli, 443)
	s.startClient(t, opts{extraCli: map[string]any{"server": "10.0.0.1:443,8443"}})
	s.client.waitLog(t, "сервер отвечает на порту 8443", 5*time.Second)
	if o, err := ping(nsCli, "-c", "1", internet); err != nil {
		t.Fatalf("туннель: %v\n%s", err, o)
	}
}

// TestPortSwitchMidSession — порт начали резать посреди сессии: пакеты
// пропадают молча, ни ошибки, ни закрытия. Клиент замечает это сам (трафик
// уходит, ответа нет, проверочный запрос не вернулся), переходит на
// следующий порт и получает прежний адрес в туннеле — соединения внутри
// туннеля не рвутся. Раньше туннель лежал до таймаута простоя QUIC и
// переподключался в тот же закрытый порт.
func TestPortSwitchMidSession(t *testing.T) {
	for _, tr := range []string{"quic", "utls"} {
		t.Run(tr, func(t *testing.T) {
			s := newStand(t, opts{noClient: true, extraSrv: map[string]any{"alt_ports": []int{8443}}})
			forgetPorts(t, s)
			s.startClient(t, opts{transport: tr, extraCli: map[string]any{"server": "10.0.0.1:443,8443"}})
			s.client.waitLog(t, "сервер отвечает на порту 443", 5*time.Second)
			if o, err := ping(nsCli, "-c", "1", internet); err != nil {
				t.Fatalf("туннель до блокировки: %v\n%s", err, o)
			}

			dropUDP(t, nsSrv, 443)
			t0 := time.Now()
			// Трафик идёт всё время: сторож следит только за путём, по
			// которому что-то отправляют.
			stop := make(chan struct{})
			defer close(stop)
			go func() {
				for {
					select {
					case <-stop:
						return
					default:
					}
					ping(nsCli, "-c", "1", "-W", "1", internet)
				}
			}()

			s.client.waitLog(t, "порт 443 перестал отвечать посреди сессии — переподключаюсь через 8443", 25*time.Second)
			s.client.waitLog(t, "соединение восстановлено", 15*time.Second)
			if el := time.Since(t0); el > 20*time.Second {
				t.Errorf("переход на другой порт занял %v", el)
			}
			if o, err := ping(nsCli, "-c", "2", internet); err != nil {
				t.Fatalf("туннель после перехода на 8443 не работает: %v\n%s", err, o)
			}
			if strings.Contains(s.client.Log(), "адрес сменился") {
				t.Fatalf("при переходе сменился адрес в туннеле — соединения внутри порвались бы:\n%s", s.client.Log())
			}
			t.Logf("переход на запасной порт посреди сессии: %v", time.Since(t0).Round(100*time.Millisecond))
		})
	}
}
