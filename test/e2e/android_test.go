//go:build e2e && linux

package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Проверка мобильного ядра (mobile/core) на стенде через тот самый контракт,
// по которому его будет вызывать Android.
//
// Собрать и запустить Android здесь нечем — нет ни NDK, ни эмулятора. Но
// контракт к Android не привязан: система создаёт интерфейс и отдаёт голый
// дескриптор, приложение защищает сокет, система настраивает адреса и
// маршруты по описанию от ядра. Всё это воспроизводится на Linux, и роль
// системы играет test/e2e/androidsim. Дальше работает ровно тот код, который
// поедет на телефон, — кроме двух системных вызовов, которые на Android
// делает Android.

// androidStand поднимает стенд, где сервер доступен клиенту ТОЛЬКО через
// маршрут по умолчанию, а не напрямую по соседству.
//
// Это существенно. Если сервер в одной подсети с клиентом, то путь к нему
// задан связным маршрутом, и правило «весь трафик в туннель» его не
// затрагивает: проверка защиты сокета превращается в проверку ничего.
// Первая версия этого теста именно так и прошла мутацию — туннель продолжал
// работать без защиты, потому что защищать было не от чего. У настоящего
// телефона сервер всегда за шлюзом, поэтому стенд должен быть таким же.
func androidStand(t *testing.T) *stand {
	t.Helper()
	return newStand(t, opts{
		noClient:    true,
		dnsResolver: true,                             // даёт клиенту маршрут по умолчанию
		extraSrv:    map[string]any{"listen": ":443"}, // сервер слушает на обоих адресах
	})
}

// androidConfig — конфигурация для мобильного ядра. Отличается от desktop
// тем, что ядро не трогает ни маршруты, ни DNS: их применяет «система».
func androidConfig(t *testing.T, s *stand) string {
	t.Helper()
	return writeJSON(t, filepath.Join(s.dir, "android.json"), map[string]any{
		// Адрес «за шлюзом», а не соседний: см. androidStand.
		"server":      "203.0.113.1:443",
		"server_name": sni,
		"auth_key":    s.authKey,
		"ca_file":     s.ca,
		"transport":   "quic",
		"full_tunnel": true,
		"tun":         map[string]any{"mtu": 1280},
		"shaping":     "cloud-gaming-up",
		"log_level":   "debug",
		// Резолверов на стенде нет; прикрытие DNS проверяется своим тестом.
		"dns_cover": map[string]any{"disabled": true},
	})
}

func TestAndroidCoreOnStand(t *testing.T) {
	s := androidStand(t)
	cfg := androidConfig(t, s)

	sim := start(t, nsCli, "androidsim", filepath.Join(s.bin, "androidsim"),
		"-config", cfg, "-iface", "masquevpn0")
	sim.waitLog(t, "туннель работает", 30*time.Second)

	// Ядро само сказало системе, что настраивать. Проверяем, что сказало
	// разумное: адрес из пула сервера и полный маршрут.
	nw := networkFromLog(t, sim.Log())
	if len(nw.Addresses) == 0 || !strings.HasPrefix(nw.Addresses[0], "10.66.0.") {
		t.Fatalf("ядро выдало адреса %v, ожидался адрес из пула сервера", nw.Addresses)
	}
	if !containsStr(nw.Routes, "0.0.0.0/0") {
		t.Fatalf("при полном туннеле ядро не попросило маршрут по умолчанию: %v", nw.Routes)
	}
	// Без адреса IPv6 маршрут ::/0 отдавать нельзя: система заберёт в
	// интерфейс весь IPv6-трафик, а уйти ему оттуда будет некуда.
	if containsStr(nw.Routes, "::/0") && !hasV6Addr(nw.Addresses) {
		t.Fatalf("маршрут ::/0 без адреса IPv6: %v / %v", nw.Routes, nw.Addresses)
	}
	if nw.MTU <= 0 {
		t.Fatalf("MTU %d", nw.MTU)
	}
	if !containsStr(nw.Bypass, "203.0.113.1") {
		t.Fatalf("адрес сервера не попал в исключения: %v", nw.Bypass)
	}

	// А теперь то, ради чего всё: настоящий трафик через туннель, поднятый
	// мобильным ядром.
	if out := curl(t, "http://"+internet+":8080/"); out != "hello from internet\n" {
		t.Fatalf("«интернет» ответил не то: %q", out)
	}
	mustNS(t, nsCli, "ping", "-c", "2", "-W", "3", internet)
	checkDownload(t, 2<<20)

	// «Интернет» видит адрес сервера, а не клиента: NAT работает так же,
	// как с desktop-клиентом.
	if seen := strings.TrimSpace(curl(t, "http://"+internet+":8080/whoami")); seen != "203.0.113.1" {
		t.Fatalf("«интернет» увидел %q, ожидался адрес сервера", seen)
	}

	// Счётчики ядра растут — то есть пакеты идут через него, а не мимо.
	sim.waitLog(t, "счётчики:", 45*time.Second)
	if st := statsFromLog(t, sim.Log()); st["from_tunnel"] == 0 || st["to_tunnel"] == 0 {
		t.Fatalf("счётчики ядра пустые: %v", st)
	}

	// Остановка разбирает всё за собой.
	sim.stop(t)
	if out, _ := nsRun(nsCli, "ip", "rule", "show"); strings.Contains(out, "7443") {
		t.Fatalf("после остановки остались правила маршрутизации:\n%s", out)
	}
}

// Ротация через мобильное ядро. Проверяется не столько сама ротация (она
// закрыта своим тестом), сколько схема насоса: чтение из сессии вынесено в
// отдельную долгоживущую горутину, чтобы пережить смену интерфейса. Если бы
// она разъехалась с ротацией, пакеты начали бы теряться именно здесь.
//
// Заодно видно, нужна ли приложению перестройка интерфейса: аренда адреса
// держится за клиентом, поэтому при ротации адрес остаётся прежним и
// перестраивать нечего.
func TestAndroidSurvivesRotation(t *testing.T) {
	s := androidStand(t)
	cfg := writeJSON(t, filepath.Join(s.dir, "android-rot.json"), map[string]any{
		"server":      "203.0.113.1:443",
		"server_name": sni,
		"auth_key":    s.authKey,
		"ca_file":     s.ca,
		"transport":   "quic",
		"full_tunnel": true,
		"tun":         map[string]any{"mtu": 1280},
		"rotation":    map[string]any{"every": "2s", "keep_address": true, "jitter": 0},
		"dns_cover":   map[string]any{"disabled": true},
		"log_level":   "debug",
	})

	sim := start(t, nsCli, "androidsim-rot", filepath.Join(s.bin, "androidsim"),
		"-config", cfg, "-iface", "masquevpn0")
	sim.waitLog(t, "туннель работает", 30*time.Second)

	// Качаем дольше, чем длится период ротации: передача обязана пережить
	// несколько смен соединения без паузы и без потери данных.
	checkDownload(t, 8<<20, "--limit-rate", "1M")

	if strings.Contains(sim.Log(), "нужен новый интерфейс") {
		t.Fatal("при ротации потребовалась перестройка интерфейса — значит адрес " +
			"не сохранился, и на телефоне порвались бы все соединения внутри туннеля")
	}
	sim.waitLog(t, "счётчики:", 45*time.Second)
	st := statsFromLog(t, sim.Log())
	if st["rotations"] == 0 {
		t.Fatalf("ротаций не было, проверять нечего: %v", st)
	}
	// Счётчик принятого — за весь туннель, а не за текущее соединение:
	// иначе на экране телефона «Принято» обнулялось бы на каждой ротации.
	if st["bytes_in"] < 8<<20 {
		t.Fatalf("принято по счётчику %d байт, а скачано 8 МБ — счётчик сбросился на ротации",
			st["bytes_in"])
	}
	t.Logf("ротаций %d, переподключений %d, потеряно пакетов %d",
		st["rotations"], st["reconnects"], st["dropped"])
}

// Мутация: приложение говорит «сокет защищён», не защитив его. На Android
// это забытый или неудавшийся VpnService.protect. Пакеты самого туннеля
// после поднятия маршрутов уходят В туннель, и он замыкается сам на себя.
//
// Проверка нужна именно сквозная: по коду это место выглядит безобидно, а
// симптом — «просто не работает», без единой ошибки в журнале.
func TestAndroidWithoutProtectLoopsOnItself(t *testing.T) {
	s := androidStand(t)
	cfg := androidConfig(t, s)

	sim := start(t, nsCli, "androidsim-broken", filepath.Join(s.bin, "androidsim"),
		"-config", cfg, "-iface", "masquevpn0", "-break-protect")
	// Сессия открывается до применения маршрутов, поэтому туннель успевает
	// «заработать» — и ломается, как только система заворачивает трафик.
	sim.waitLog(t, "туннель работает", 30*time.Second)

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := nsRun(nsCli, "curl", "-sS", "--fail", "--noproxy", "*",
			"--max-time", "5", "http://"+internet+":8080/"); err != nil {
			return // туннель сломался, как и должен был
		}
		time.Sleep(time.Second)
	}
	t.Fatal("туннель продолжает работать без защиты сокета — значит проверка " +
		"ничего не проверяет: на Android без protect он замкнулся бы сам на себя")
}

// ---------- разбор журнала имитатора ----------

type simNetwork struct {
	Addresses []string `json:"addresses"`
	Routes    []string `json:"routes"`
	DNS       []string `json:"dns"`
	MTU       int      `json:"mtu"`
	Bypass    []string `json:"bypass"`
}

func networkFromLog(t *testing.T, log string) simNetwork {
	t.Helper()
	const marker = "ядро: параметры сети "
	i := strings.Index(log, marker)
	if i < 0 {
		t.Fatalf("в журнале нет параметров сети:\n%s", log)
	}
	line := log[i+len(marker):]
	if j := strings.IndexByte(line, '\n'); j >= 0 {
		line = line[:j]
	}
	var nw simNetwork
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &nw); err != nil {
		t.Fatalf("параметры сети не разобраны (%v): %s", err, line)
	}
	return nw
}

func statsFromLog(t *testing.T, log string) map[string]uint64 {
	t.Helper()
	const marker = "счётчики: "
	i := strings.LastIndex(log, marker)
	if i < 0 {
		t.Fatalf("в журнале нет счётчиков:\n%s", log)
	}
	line := log[i+len(marker):]
	if j := strings.IndexByte(line, '\n'); j >= 0 {
		line = line[:j]
	}
	// В счётчиках есть и готовые к показу строки («1,2 МБ») — берём только
	// числа: их и сравнивают тесты.
	var all map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &all); err != nil {
		t.Fatalf("счётчики не разобраны (%v): %s", err, line)
	}
	raw := map[string]uint64{}
	for k, v := range all {
		if f, ok := v.(float64); ok && f >= 0 {
			raw[k] = uint64(f)
		}
	}
	return raw
}

func containsStr(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func hasV6Addr(addrs []string) bool {
	for _, a := range addrs {
		if strings.Contains(a, ":") {
			return true
		}
	}
	return false
}

// Сервер по ИМЕНИ, как в настоящих доступах, и резолвер системы «как на
// Android».
//
// На телефоне у Go нет своего списка DNS-серверов: /etc/resolv.conf там
// нет, и встроенный резолвер спрашивает локальный адрес, где никто не
// слушает. Первый живой запуск упал ровно на этом: «lookup … on
// [::1]:53: connection refused». Здесь то же самое воспроизводится
// файлом resolv.conf, который `ip netns exec` подставляет в пространство
// клиента: nameserver 127.0.0.1 — та же глухая заглушка.
//
// Имя сервера знает только «резолвер провайдера» за шлюзом, и его адрес
// ядро получает так же, как на телефоне: приложение кладёт резолверы сети
// в dns_cover.servers. Без bootstrapResolvers тест падает той же ошибкой,
// что и телефон.
func TestAndroidResolvesServerByName(t *testing.T) {
	etc := filepath.Join("/etc/netns", nsCli)
	if err := os.MkdirAll(etc, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(etc) })
	if err := os.WriteFile(filepath.Join(etc, "resolv.conf"), []byte("nameserver 127.0.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := newStand(t, opts{
		noClient:    true,
		dnsResolver: true,
		dnsAnswer:   sni + "=203.0.113.1",
		extraSrv:    map[string]any{"listen": ":443"},
	})
	cfg := writeJSON(t, filepath.Join(s.dir, "android-name.json"), map[string]any{
		"server":      sni + ":443",
		"auth_key":    s.authKey,
		"ca_file":     s.ca,
		"transport":   "quic",
		"full_tunnel": true,
		"tun":         map[string]any{"mtu": 1280},
		"log_level":   "debug",
		// Так приложение передаёт ядру резолверы сети (Store.withSystemResolvers).
		// Само прикрытие выключено: здесь проверяется только поиск имени.
		"dns_cover": map[string]any{"disabled": true, "servers": []string{ispResolver + ":53"}},
	})

	sim := start(t, nsCli, "androidsim", filepath.Join(s.bin, "androidsim"),
		"-config", cfg, "-iface", "masquevpn0")
	sim.waitLog(t, "туннель работает", 30*time.Second)
	if out := curl(t, "http://"+internet+":8080/"); out != "hello from internet\n" {
		t.Fatalf("«интернет» ответил не то: %q", out)
	}

	// Имя спросили у резолвера провайдера, с настоящего адреса и мимо
	// туннеля (туннеля в тот момент ещё и нет).
	asked := false
	for _, q := range dnsQueries(s.dns) {
		if q.name == sni {
			asked = true
			if q.src != "10.0.0.2" {
				t.Fatalf("запрос имени сервера пришёл с %s, а не с адреса клиента", q.src)
			}
		}
	}
	if !asked {
		t.Fatal("резолвер провайдера не получил запроса имени сервера — откуда тогда адрес?")
	}
}
