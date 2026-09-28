package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/soways11/masquevpn/internal/config"
)

// Конфигурация в том виде, в каком её пишет install.sh: с вложенным
// tcp.listen, который правка трогать не должна.
const installLike = `{
  "listen": ":8443",
  "cert_file": "/root/cert/fullchain.pem",
  "key_file": "/root/cert/privkey.pem",

  "clients_file": "/etc/masquevpn/clients.json",

  "tun": { "name": "masquevpn0", "mtu": 1280 },
  "pool4": "10.66.0.0/24",
  "fallback_site": {
    "contact": "hello@example.com"
  },
  "tcp": { "listen": ":443" },
  "log_level": "info"
}
`

func TestSetPortsJSON(t *testing.T) {
	out, err := setPortsJSON([]byte(installLike), []int{443, 8443, 2053})
	if err != nil {
		t.Fatal(err)
	}
	t.Log("\n" + string(out))
	var m map[string]json.RawMessage
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("результат — не JSON: %v", err)
	}
	if string(m["listen"]) != `":443"` || string(m["alt_ports"]) != `[8443, 2053]` {
		t.Fatalf("listen=%s alt_ports=%s", m["listen"], m["alt_ports"])
	}
	// Вложенный tcp.listen не тронут, порядок полей сохранён, alt_ports — за listen.
	if !strings.Contains(string(out), `"listen": ":443"`) || !bytes.Contains(out, []byte(`"tcp": {`)) {
		t.Fatal("структура поменялась")
	}
	var tcp struct{ Listen string }
	json.Unmarshal(m["tcp"], &tcp)
	if tcp.Listen != ":443" {
		t.Fatalf("tcp.listen = %q", tcp.Listen)
	}
	order := []string{`"listen"`, `"alt_ports"`, `"cert_file"`, `"clients_file"`, `"tcp"`, `"log_level"`}
	last := -1
	for _, k := range order {
		i := bytes.Index(out, []byte(k))
		if i <= last {
			t.Fatalf("порядок полей нарушен на %s", k)
		}
		last = i
	}

	// Повторная правка — с одним портом: alt_ports исчезает, адрес listen сохраняется.
	withHost := strings.Replace(string(out), `":443"`, `"0.0.0.0:443"`, 1)
	out2, err := setPortsJSON([]byte(withHost), []int{2083})
	if err != nil {
		t.Fatal(err)
	}
	m = nil
	if err := json.Unmarshal(out2, &m); err != nil {
		t.Fatal(err)
	}
	if string(m["listen"]) != `"0.0.0.0:2083"` || m["alt_ports"] != nil {
		t.Fatalf("один порт: listen=%s alt_ports=%s", m["listen"], m["alt_ports"])
	}
}

func testServerConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "server.json")
	// Путь — через json.Marshal: в Windows в нём обратные слэши, и
	// вставленный как есть он ломал бы JSON («\U» — не escape-последовательность).
	clients, _ := json.Marshal(filepath.Join(dir, "clients.json"))
	cfg := strings.Replace(installLike, `"clients_file": "/etc/masquevpn/clients.json",`,
		`"clients_file": `+string(clients)+`,`, 1)
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPortsCommand(t *testing.T) {
	p := testServerConfig(t)
	run := func(args ...string) (int, string) {
		var out, errb bytes.Buffer
		code := portsCommand(append([]string{"-config", p}, args...), &out, &errb)
		return code, out.String() + errb.String()
	}
	if code, out := run(); code != 0 || strings.TrimSpace(out) != "8443" {
		t.Fatalf("показ: %d %q", code, out)
	}
	if code, out := run("-set", "default"); code != 0 {
		t.Fatalf("default: %d %q", code, out)
	}
	if code, out := run(); code != 0 || strings.TrimSpace(out) != "443 8443 2053 2083 2087 2096" {
		t.Fatalf("после default: %d %q", code, out)
	}
	backups, _ := filepath.Glob(p + ".bak.*")
	if len(backups) != 1 {
		t.Fatalf("копий прежней конфигурации: %d", len(backups))
	}
	if code, out := run("-set", "443,8443,2053,2083,2087,2096"); code != 0 || !strings.Contains(out, "уже такие") {
		t.Fatalf("повтор: %d %q", code, out)
	}
	// Опечатка — файл не тронут.
	before, _ := os.ReadFile(p)
	if code, _ := run("-set", "8443,abc"); code == 0 {
		t.Fatal("опечатка принята")
	}
	after, _ := os.ReadFile(p)
	if !bytes.Equal(before, after) {
		t.Fatal("файл изменён после ошибки")
	}
}

func TestWithServerPorts(t *testing.T) {
	cfgPorts := []int{443, 8443, 2053}
	for _, c := range []struct {
		in     string
		single bool
		want   string
	}{
		{"vpn.example.com:8443", false, "vpn.example.com:8443,443,2053"},
		{"vpn.example.com", false, "vpn.example.com:443,8443,2053"},
		{"vpn.example.com:8443,2053", false, "vpn.example.com:8443,2053"}, // выбрано сознательно
		{"vpn.example.com:8443", true, "vpn.example.com:8443"},
		{"vpn.example.com:8443,2053", true, "vpn.example.com:8443"},
	} {
		got, err := withServerPorts(c.in, cfgPorts, c.single)
		if err != nil || got != c.want {
			t.Errorf("%q single=%v → %q %v, ожидалось %q", c.in, c.single, got, err, c.want)
		}
	}
	// Сервер с одним портом — адрес как есть.
	if got, _ := withServerPorts("vpn.example.com:8443", []int{8443}, false); got != "vpn.example.com:8443" {
		t.Errorf("один порт: %q", got)
	}
	// Итоговый адрес понимает клиент.
	if _, err := config.BuildClient("vpn.example.com:8443,443,2053", base64.StdEncoding.EncodeToString(make([]byte, 32)), ""); err != nil {
		t.Fatal(err)
	}
}
