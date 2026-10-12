//go:build e2e && linux

// Полнота перехвата: все виды трафика уходят ТОЛЬКО через туннель.
//
// Почему отдельным файлом и отдельным стендом. Остальные тесты устроены так,
// что из netns клиента в «интернет» нет маршрута вовсе: там успех запроса сам
// по себе доказывает, что он прошёл через туннель. Для полноты перехвата этого
// мало — нужен обратный вопрос: не уходит ли что-то МИМО. Пока прямого пути
// нет, «перехвачено» и «просто некуда идти» неразличимы, и тест на утечку
// оказался бы зелёным даже при снятых правилах маршрутизации.
//
// Поэтому здесь у клиента есть рабочий путь наружу (directInternet), как у
// обычной машины, а за физическим интерфейсом следит сторож (leaktap): он
// перечисляет всё исходящее. Разрешено ровно одно — UDP к адресу сервера, то
// есть сам туннель. Что угодно ещё — утечка.
package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	// vpnServer — адрес сервера на отрезке клиент↔сервер: UDP к нему и есть
	// туннель, единственное разрешённое исходящее.
	vpnServer = "10.0.0.1"
	// internet6 — «интернет» по IPv6. Нужен там, где у машины IPv6 есть, а
	// туннель его не выдал: классическая утечка «VPN только на IPv4».
	internet6 = "2001:db8:113::10"
	cliV6     = "fd00:5:5::2"
	srvV6     = "fd00:5:5::1"
)

// ipv6InKernel — IPv6 есть в ядре. В контейнерах его часто нет целиком, и
// тогда проверять нечего: трафика этой семьи не бывает.
func ipv6InKernel() bool {
	_, err := os.Stat("/proc/sys/net/ipv6")
	return err == nil
}

// directInternet достраивает стенд до «обычной машины»: обратный маршрут у
// «интернета» (иначе прямой путь не работал бы и без туннеля) и, если IPv6
// живой, вторая семья адресов из конца в конец.
func directInternet(t *testing.T) {
	t.Helper()
	mustNS(t, nsInet, "ip", "route", "add", "10.0.0.0/24", "via", "203.0.113.1")
	if !ipv6InKernel() {
		return
	}
	// nodad: без него адрес несколько секунд висит tentative и первые
	// пакеты с него ядро не отправляет — тест ловил бы не утечку, а DAD.
	mustNS(t, nsCli, "ip", "-6", "addr", "add", cliV6+"/64", "dev", "cli0", "nodad")
	mustNS(t, nsSrv, "ip", "-6", "addr", "add", srvV6+"/64", "dev", "srv0", "nodad")
	mustNS(t, nsSrv, "ip", "-6", "addr", "add", "2001:db8:113::1/64", "dev", "srv1", "nodad")
	mustNS(t, nsInet, "ip", "-6", "addr", "add", "2001:db8:113::2/64", "dev", "inet0", "nodad")
	mustNS(t, nsInet, "ip", "-6", "addr", "add", internet6+"/128", "dev", "inet0", "nodad")
	mustNS(t, nsInet, "ip", "-6", "route", "add", "fd00:5:5::/64", "via", "2001:db8:113::1")
	mustNS(t, nsCli, "ip", "-6", "route", "add", "default", "via", srvV6)
}

// leakFlow — поток, который сторож увидел на проводе (см. test/e2e/leaktap).
type leakFlow struct {
	Proto   string `json:"proto"`
	Src     string `json:"src"`
	Dst     string `json:"dst"`
	SPort   int    `json:"sport"`
	DPort   int    `json:"dport"`
	Link    bool   `json:"link"`
	Packets int    `json:"packets"`
	Bytes   int    `json:"bytes"`
}

func (f leakFlow) String() string {
	return fmt.Sprintf("%s %s:%d → %s:%d (%d пакетов)", f.Proto, f.Src, f.SPort, f.Dst, f.DPort, f.Packets)
}

// watchLeaks ставит сторожа на физический интерфейс клиента. Возвращённая
// функция останавливает его и отдаёт то, что ушло мимо туннеля.
func watchLeaks(t *testing.T, s *stand, name string) func(*testing.T) []leakFlow {
	t.Helper()
	out := filepath.Join(s.dir, "leaks-"+name+".json")
	p := start(t, nsCli, "leaktap-"+name, filepath.Join(s.bin, "leaktap"),
		"-iface", "cli0", "-duration", "150s", "-json", out)
	// Ждём, пока сокет встанет на интерфейс: иначе трафик успеет уйти
	// раньше сторожа, и утечка не будет видна.
	p.waitLog(t, "слежу за cli0", 10*time.Second)
	return func(t *testing.T) []leakFlow {
		t.Helper()
		p.stop(t)
		raw, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("сторож не оставил отчёта: %v\n%s", err, p.Log())
		}
		var flows []leakFlow
		if err := json.Unmarshal(raw, &flows); err != nil {
			t.Fatal(err)
		}
		var leaks []leakFlow
		for _, f := range flows {
			switch {
			case f.Link:
				// Multicast, broadcast, link-local: за пределы канала не
				// уходят, туннель их и не обещает.
			case f.Proto == "udp" && f.Dst == vpnServer:
				// Сам туннель.
			default:
				leaks = append(leaks, f)
			}
		}
		return leaks
	}
}

// noLeaks — обёртка одной проверки: сторож на время трафика, потом разбор.
func noLeaks(t *testing.T, s *stand, name string, traffic func(t *testing.T)) {
	t.Helper()
	done := watchLeaks(t, s, name)
	traffic(t)
	// Пакет мог уйти уже после возврата curl (повторы, FIN, ICMP).
	time.Sleep(500 * time.Millisecond)
	if leaks := done(t); len(leaks) > 0 {
		for _, f := range leaks {
			t.Errorf("утечка мимо туннеля: %s", f)
		}
	}
}

// TestNothingEscapesTunnel — при полном туннеле наружу своим ходом не уходит
// ничего, кроме самого туннеля: ни TCP, ни UDP, ни ICMP, ни DNS, ни IPv6, ни
// трафик сокета, привязанного к физическому интерфейсу или его адресу, ни
// соединение, открытое ДО подключения.
//
// Прогон идёт дважды — с выключенным аварийным отключением
// (kill_switch: false) и с включённым (как по умолчанию), — потому что
// выключенный флаг не должен делать перехват слабее: он про то, что будет
// после краха клиента, а не про то, что уходит мимо туннеля при живом
// клиенте. Именно в этом прогоне и нашлась утечка сокета с привязкой к
// интерфейсу: прежде при kill_switch: false фильтры не ставились вовсе.
func TestNothingEscapesTunnel(t *testing.T) {
	for _, ks := range []struct {
		name string
		on   bool
	}{
		{"без аварийного отключения", false},
		{"с аварийным отключением", true},
	} {
		t.Run(ks.name, func(t *testing.T) { testNothingEscapes(t, ks.on) })
	}
}

func testNothingEscapes(t *testing.T, killSwitch bool) {
	o := opts{
		transport:      "quic",
		directInternet: true,
		dnsResolver:    true,
		noClient:       true,
		extraCli:       map[string]any{"kill_switch": killSwitch},
	}
	s := newStand(t, o)

	// 1. Контроль стенда и сторожа: пока туннеля нет, прямой путь работает,
	//    «интернет» видит настоящий адрес клиента, и сторож это видит тоже.
	//    Без этой проверки весь тест мог бы быть зелёным при негодном стенде.
	t.Run("контроль-утечка-видна", func(t *testing.T) {
		done := watchLeaks(t, s, "control")
		who := strings.TrimSpace(curl(t, "http://"+internet+":8080/whoami"))
		leaks := done(t)
		if who != "10.0.0.2" {
			t.Fatalf("без туннеля «интернет» видит %q, ожидался настоящий адрес клиента 10.0.0.2", who)
		}
		if len(leaks) == 0 {
			t.Fatal("сторож не увидел прямого запроса — проверять им нечего")
		}
		// И IPv6 до туннеля тоже должен ходить: иначе проверка «IPv6 не
		// утёк» ничего не значит — он бы и так никуда не дошёл.
		if ipv6InKernel() {
			if out, err := nsRun(nsCli, "ping", "-6", "-n", "-W", "2", "-c", "1", internet6); err != nil {
				t.Fatalf("стенд негоден: IPv6 до «интернета» не ходит и без туннеля: %v\n%s", err, out)
			}
		}
		t.Logf("без туннеля сторож видит %d поток(ов), первый: %s", len(leaks), leaks[0])
	})

	// Соединение, открытое ДО подключения, да ещё и привязанное к
	// физическому интерфейсу: самый тяжёлый случай. Маршрутизация его не
	// перехватывает (ядро отправляет такой пакет на интерфейс само), а для
	// таблицы nftables он уже «established» — то есть ровно то, что правило
	// об установленных соединениях пропускало бы наружу. На Windows это
	// известная дырка (ALE_AUTH_CONNECT не видит открытых соединений);
	// проверяем, что на Linux её нет.
	before := start(t, nsCli, "slowcurl", "curl", "-sS", "--noproxy", "*",
		"--interface", "cli0", "--limit-rate", "2k", "-o", "/dev/null",
		fmt.Sprintf("http://%s:8080/blob?n=%d", internet, 4<<20))
	time.Sleep(time.Second)

	s.startClient(t, o)
	if killSwitch {
		s.client.waitLog(t, "аварийное отключение включено", 10*time.Second)
	} else {
		s.client.waitLog(t, "перехват включён", 10*time.Second)
	}

	t.Run("соединение-открытое-до-туннеля", func(t *testing.T) {
		noLeaks(t, s, "established", func(t *testing.T) {
			time.Sleep(3 * time.Second)
		})
	})
	before.stop(t)

	t.Run("tcp", func(t *testing.T) {
		noLeaks(t, s, "tcp", func(t *testing.T) {
			who := strings.TrimSpace(curl(t, "http://"+internet+":8080/whoami"))
			if who != "203.0.113.1" {
				t.Fatalf("«интернет» видит %q — ожидался адрес сервера после NAT, то есть путь через туннель", who)
			}
		})
	})

	t.Run("udp", func(t *testing.T) {
		noLeaks(t, s, "udp", func(t *testing.T) {
			out := mustNS(t, nsCli, "bash", "-c",
				"exec 3<>/dev/udp/"+internet+"/7; printf 'udp-through-tunnel' >&3; timeout 3 head -c 18 <&3")
			if out != "udp-through-tunnel" {
				t.Fatalf("UDP-эхо через туннель: %q", out)
			}
		})
	})

	t.Run("icmp", func(t *testing.T) {
		noLeaks(t, s, "icmp", func(t *testing.T) {
			if out, err := ping(nsCli, "-c", "2", "-i", "0.2", internet); err != nil {
				t.Fatalf("ping через туннель: %v\n%s", err, out)
			}
		})
	})

	// DNS к резолверу ПРОВАЙДЕРА (он вне туннеля, за шлюзом): запрос обязан
	// уехать внутрь туннеля, а не к нему напрямую. Журнал резолвера
	// показывает адрес источника — по нему и видно, какой дорогой пришло.
	t.Run("dns", func(t *testing.T) {
		noLeaks(t, s, "dns", func(t *testing.T) {
			// Запрос A для example.com, собранный руками: внешних утилит
			// разбора имён (dig, host) в окружении может не быть.
			const query = `\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01`
			mustNS(t, nsCli, "bash", "-c",
				"exec 3<>/dev/udp/"+ispResolver+"/53; printf '"+query+"' >&3; timeout 3 head -c 12 <&3 >/dev/null")
			got := dnsQueries(s.dns)
			if len(got) == 0 {
				t.Fatalf("резолвер не увидел запроса:\n%s", s.dns.Log())
			}
			for _, q := range got {
				if !strings.HasPrefix(q.src, "10.66.") {
					t.Fatalf("DNS-запрос пришёл к резолверу с %s — это адрес мимо туннеля, "+
						"через туннель он пришёл бы с туннельного 10.66.0.x", q.src)
				}
			}
		})
	})

	// Сокет, привязанный к физическому интерфейсу (SO_BINDTODEVICE). Такие
	// сокеты обходят решение по таблице маршрутов: именно так ходят
	// systemd-resolved за DNS провайдера и всякий «ping -I eth0».
	t.Run("сокет-привязан-к-интерфейсу", func(t *testing.T) {
		noLeaks(t, s, "bindtodevice", func(t *testing.T) {
			// Запрос имеет полное право не пройти — важно лишь, что он не
			// уходит наружу открытым текстом.
			out, err := nsRun(nsCli, "curl", "-sS", "--noproxy", "*", "--max-time", "5",
				"--interface", "cli0", "http://"+internet+":8080/whoami")
			t.Logf("curl --interface cli0: err=%v out=%q", err, strings.TrimSpace(out))
		})
	})

	// Сокет, привязанный к адресу физического интерфейса: маршрут выберется
	// туннельный, но адрес источника останется чужим.
	t.Run("сокет-привязан-к-адресу", func(t *testing.T) {
		noLeaks(t, s, "bindtoaddr", func(t *testing.T) {
			out, err := nsRun(nsCli, "curl", "-sS", "--noproxy", "*", "--max-time", "5",
				"--interface", "10.0.0.2", "http://"+internet+":8080/whoami")
			t.Logf("curl --interface 10.0.0.2: err=%v out=%q", err, strings.TrimSpace(out))
		})
	})

	// IPv6 у машины есть, а туннель его не выдал (pool6 на сервере не
	// задан). Уходить наружу он не должен: на Linux маршрут ::/0 заворачивается
	// в туннель всегда и упирается в интерфейс без адреса IPv6.
	t.Run("ipv6-без-адреса-в-туннеле", func(t *testing.T) {
		if !ipv6InKernel() {
			t.Skip("IPv6 выключен в ядре: трафика этой семьи не бывает")
		}
		noLeaks(t, s, "ipv6", func(t *testing.T) {
			out, err := nsRun(nsCli, "ping", "-6", "-n", "-W", "2", "-c", "2", internet6)
			if err == nil {
				t.Errorf("IPv6 до «интернета» дошёл, хотя туннель адреса IPv6 не выдавал:\n%s", out)
			}
		})
	})
}
