//go:build e2e && linux

package e2e

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestACMEIssuesCertificate — сервер сам получает сертификат.
//
// Настоящий бинарник сервера поднимается БЕЗ файла сертификата: только с
// доменом и адресом удостоверяющего центра. Центр стоит в соседнем
// namespace, приходит на проверку владения доменом на наш же TCP/443 с ALPN
// «acme-tls/1» и выдаёт сертификат. Клиент затем подключается, доверяя
// только корню этого центра, — то есть туннель работает на сертификате,
// который сервер добыл сам.
func TestACMEIssuesCertificate(t *testing.T) {
	requireEnv(t)
	bin := buildBinaries(t)
	topology(t)
	s := &stand{dir: t.TempDir(), bin: bin}
	s.ca, s.cert, s.key = certs(t, s.dir)
	s.authKey = strings.TrimSpace(sh(t, filepath.Join(bin, "vpnserver"), "genkey"))
	start(t, nsInet, "inetsrv", filepath.Join(bin, "inetsrv"), "-addr", internet+":8080", "-udp", internet+":7")

	// Центру нужен обратный путь к серверу: он идёт на проверку сам.
	mustNS(t, nsInet, "ip", "route", "add", "10.0.0.0/24", "via", "203.0.113.1")
	caPEM := filepath.Join(s.dir, "acme-ca.pem")
	ca := start(t, nsInet, "acmeca", filepath.Join(bin, "acmeca"),
		"-listen", "203.0.113.2:8081", "-target", "10.0.0.1:443", "-ca-out", caPEM)
	ca.waitLog(t, "удостоверяющий центр запущен", 10*time.Second)

	o := opts{transport: "quic", extraSrv: map[string]any{
		// Ни cert_file, ни key_file: сервер обязан справиться сам.
		"cert_file": "",
		"key_file":  "",
		"acme": map[string]any{
			"domains":       []string{sni},
			"email":         "admin@" + sni,
			"cache_dir":     filepath.Join(s.dir, "acme-cache"),
			"directory_url": "http://203.0.113.2:8081/directory",
		},
	}}
	s.startServer(t, o)
	s.server.waitLog(t, "сертификат получен", 60*time.Second)
	if !strings.Contains(ca.Log(), "POST /finalize/") {
		t.Fatalf("заказ не дошёл до выдачи:\n%s", ca.Log())
	}

	// Клиент верит ТОЛЬКО этому центру: сертификат из файлов стенда здесь
	// не при чём.
	o.extraCli = map[string]any{"ca_file": caPEM}
	s.startClient(t, o)
	if out, err := ping(nsCli, "-c", "2", internet); err != nil {
		t.Fatalf("туннель на сертификате ACME не работает: %v\n%s", err, out)
	}
	checkDownload(t, 1<<20)

	// Проверка владения доменом была настоящей: центр ходил на наш TCP/443.
	if !strings.Contains(ca.Log(), "POST /chal/") {
		t.Fatalf("проверка tls-alpn-01 не выполнялась:\n%s", ca.Log())
	}
	t.Logf("сертификат выпущен и туннель на нём работает")
}
