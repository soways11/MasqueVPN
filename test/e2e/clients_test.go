//go:build e2e

package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Сквозная проверка реестра клиентов: настоящий сервер, настоящий клиент,
// настоящий отзыв доступа правкой файла.
//
// Юнит-тесты показывают, что каждая часть работает по отдельности. Здесь
// проверяется то, чего они показать не могут: что сервер действительно
// перечитывает файл на ходу и закрывает туннель тому, кого отозвали, — то
// есть что отзыв доходит до работающей системы, а не только до структуры в
// памяти.

// clientsAdd создаёт клиента через ту же команду, которой пользуется человек.
func clientsAdd(t *testing.T, bin, file, name string, extra ...string) (id, key string) {
	t.Helper()
	args := append([]string{filepath.Join(bin, "vpnserver"), "clients", "add", "-file", file, "-name", name}, extra...)
	out := sh(t, args...)

	// Разбираем не вывод команды, а сам файл: так проверяется ещё и то, что
	// команда действительно записала клиента на диск.
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("реестр не записан: %v\nвывод команды:\n%s", err, out)
	}
	var f struct {
		Clients []struct {
			ID, Name, Key string
		}
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.Clients {
		if c.Name == name {
			return c.ID, c.Key
		}
	}
	t.Fatalf("клиент %q не найден в реестре:\n%s", name, raw)
	return "", ""
}

func TestPerClientKeysAndRevocation(t *testing.T) {
	requireEnv(t)
	bin := buildBinaries(t)
	dir := t.TempDir()
	registry := filepath.Join(dir, "clients.json")

	id, key := clientsAdd(t, bin, registry, "Ноутбук", "-quota", "1GB")
	otherID, otherKey := clientsAdd(t, bin, registry, "Сосед")
	if id == otherID || key == otherKey {
		t.Fatal("двум клиентам выданы одинаковые псевдоним или ключ")
	}

	s := newStand(t, opts{
		// В режиме реестра общего ключа нет вовсе: сервер должен подняться
		// без auth_key и пускать только по личным ключам.
		extraSrv: map[string]any{"auth_key": "", "clients_file": registry, "clients_reload": "1s"},
		extraCli: map[string]any{"auth_key": key, "client_id": id},
	})

	// Клиент подключился своим ключом — туннель работает.
	checkDownload(t, 256*1024)

	// Чужой ключ под своим псевдонимом не проходит: иначе личные ключи были
	// бы декорацией.
	badCfg := writeJSON(t, filepath.Join(s.dir, "imposter.json"), map[string]any{
		"server": "10.0.0.1:443", "server_name": sni, "ca_file": s.ca,
		"auth_key": otherKey, "client_id": id,
		"tun": map[string]any{"name": "masquevpn9", "mtu": 1280}, "log_level": "debug",
		"dns_cover": map[string]any{"disabled": true},
	})
	imposter := start(t, nsCli, "imposter", filepath.Join(bin, "vpnclient-quic"), "-config", badCfg)
	time.Sleep(8 * time.Second)
	if strings.Contains(imposter.Log(), "сессия установлена") {
		t.Fatalf("клиент прошёл с чужим ключом под чужим псевдонимом:\n%s", imposter.Log())
	}
	imposter.stop(t)

	// Отзыв: выключаем клиента той же командой, что и человек.
	sh(t, filepath.Join(bin, "vpnserver"), "clients", "disable", "-file", registry, "-id", id)

	// Сервер обязан САМ заметить правку файла и закрыть живую сессию.
	// Без этого отзыв не отзыв: токен проверяется один раз, при подключении.
	s.server.waitLog(t, "доступ отозван", 20*time.Second)

	// И клиент больше не проходит: попытки переподключения ни к чему не ведут.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(s.server.Log(), "доступ отозван, сессии закрыты") {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !strings.Contains(s.server.Log(), "доступ отозван, сессии закрыты") {
		t.Fatal("сервер не закрыл живую сессию отозванного клиента")
	}

	// Возвращаем доступ — клиент должен снова заработать сам, без
	// перезапуска сервера.
	sh(t, filepath.Join(bin, "vpnserver"), "clients", "enable", "-file", registry, "-id", id)
	s.client.waitLog(t, "сессия установлена", 60*time.Second)
	checkDownload(t, 256*1024)

	// Учёт: расход клиента посчитан и сохранён на диск.
	usage := registry + ".usage"
	var got, sessions int64
	for deadline := time.Now().Add(60 * time.Second); time.Now().Before(deadline); {
		raw, err := os.ReadFile(usage)
		if err == nil {
			var f struct {
				Usage []struct {
					ID       string
					Bytes    int64
					Sessions int64
				}
			}
			if json.Unmarshal(raw, &f) == nil {
				for _, u := range f.Usage {
					if u.ID == id {
						got, sessions = u.Bytes, u.Sessions
					}
				}
			}
		}
		if got > 256*1024 {
			break
		}
		time.Sleep(time.Second)
	}
	if got <= 256*1024 {
		t.Fatalf("учтено %d байт, а скачано больше полумегабайта двумя заходами", got)
	}
	if sessions < 2 {
		t.Fatalf("учтено %d сессий, а клиент подключался дважды (до отзыва и после)", sessions)
	}
	t.Logf("учтено %d байт и %d сессий клиента %s", got, sessions, id)
}
