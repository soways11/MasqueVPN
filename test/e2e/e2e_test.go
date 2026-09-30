//go:build e2e && linux

// Сквозной тест Этапа 1: настоящие бинарники vpnserver и vpnclient в трёх
// network namespace, настоящий ping, curl и TCP через туннель.
//
//	sudo go test -tags e2e ./test/e2e/ -v
//
// Топология:
//
//	[gv-cli] cli0 10.0.0.2 ──── srv0 10.0.0.1 [gv-srv] srv1 203.0.113.1 ──── inet0 203.0.113.2 [gv-inet]
//	  vpnclient, masquevpn0        vpnserver, masquevpn0 10.66.0.1/24, NAT         «интернет»: 198.51.100.10
//
// У клиента нет маршрута в «интернет» — туда можно попасть только через
// туннель. У «интернета» нет маршрута к 10.66.0.0/24 — ответы доходят
// только благодаря NAT на сервере.
//
// Утилиты ip/ping/curl используются ТОЛЬКО тестом для построения стенда и
// проверок; сами бинарники настраивают сеть через netlink.
package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/soways11/masquevpn/internal/fingerprint"
)

const (
	nsCli  = "gv-cli"
	nsSrv  = "gv-srv"
	nsInet = "gv-inet"

	internet = "198.51.100.10"
	// ispResolver — «резолвер провайдера»: он ЗА шлюзом, а не в одной
	// подсети с клиентом. Это важно для проверки: попасть к нему можно
	// только по маршруту по умолчанию, то есть выбор «мимо туннеля или
	// внутрь него» здесь реальный.
	ispResolver = "203.0.113.53"
	gateway     = "10.66.0.1"
	sni         = "vpn.example.test"
)

var (
	binOnce sync.Once
	binDir  string
	binErr  error
)

func sh(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func nsRun(ns string, args ...string) (string, error) {
	out, err := exec.Command("ip", append([]string{"netns", "exec", ns}, args...)...).CombinedOutput()
	return string(out), err
}

func mustNS(t *testing.T, ns string, args ...string) string {
	t.Helper()
	out, err := nsRun(ns, args...)
	if err != nil {
		t.Fatalf("[%s] %s: %v\n%s", ns, strings.Join(args, " "), err, out)
	}
	return out
}

func requireEnv(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("нужен root")
	}
	for _, b := range []string{"ip", "ping", "curl"} {
		if _, err := exec.LookPath(b); err != nil {
			t.Skipf("для стенда нужна утилита %s", b)
		}
	}
}

// buildBinaries собирает бинарники один раз на весь прогон.
func buildBinaries(t *testing.T) string {
	t.Helper()
	binOnce.Do(func() {
		binDir, binErr = os.MkdirTemp("", "masquevpn-e2e-bin")
		if binErr != nil {
			return
		}
		for _, b := range []struct{ out, pkg, tags string }{
			{"vpnserver", "./cmd/vpnserver", ""},
			{"vpnclient-quic", "./cmd/vpnclient", ""},
			{"vpnclient-utls", "./cmd/vpnclient", "utls"},
			{"inetsrv", "./test/e2e/inetsrv", ""},
			{"fpserver", "./cmd/fpserver", ""},
			{"dpitap", "./test/e2e/dpitap", ""},
			{"acmeca", "./test/e2e/acmeca", ""},
			{"androidsim", "./test/e2e/androidsim", ""},
		} {
			args := []string{"build", "-o", filepath.Join(binDir, b.out)}
			if b.tags != "" {
				args = append(args, "-tags", b.tags)
			}
			args = append(args, b.pkg)
			cmd := exec.Command("go", args...)
			cmd.Dir = "../.."
			if out, err := cmd.CombinedOutput(); err != nil {
				binErr = fmt.Errorf("go %s: %v\n%s", strings.Join(args, " "), err, out)
				return
			}
		}
	})
	if binErr != nil {
		t.Fatal(binErr)
	}
	return binDir
}

// topology строит три namespace и удаляет их по завершении теста.
func topology(t *testing.T) {
	t.Helper()
	hostResolvUntouched(t)
	for _, ns := range []string{nsCli, nsSrv, nsInet} {
		exec.Command("ip", "netns", "del", ns).Run()
		sh(t, "ip", "netns", "add", ns)
		ns := ns
		t.Cleanup(func() { exec.Command("ip", "netns", "del", ns).Run() })
		mustNS(t, ns, "ip", "link", "set", "lo", "up")
	}
	sh(t, "ip", "link", "add", "cli0", "netns", nsCli, "type", "veth", "peer", "name", "srv0", "netns", nsSrv)
	sh(t, "ip", "link", "add", "srv1", "netns", nsSrv, "type", "veth", "peer", "name", "inet0", "netns", nsInet)

	mustNS(t, nsCli, "ip", "addr", "add", "10.0.0.2/24", "dev", "cli0")
	mustNS(t, nsCli, "ip", "link", "set", "cli0", "up")

	mustNS(t, nsSrv, "ip", "addr", "add", "10.0.0.1/24", "dev", "srv0")
	mustNS(t, nsSrv, "ip", "link", "set", "srv0", "up")
	mustNS(t, nsSrv, "ip", "addr", "add", "203.0.113.1/24", "dev", "srv1")
	mustNS(t, nsSrv, "ip", "link", "set", "srv1", "up")
	mustNS(t, nsSrv, "ip", "route", "add", "default", "via", "203.0.113.2")

	mustNS(t, nsInet, "ip", "addr", "add", "203.0.113.2/24", "dev", "inet0")
	mustNS(t, nsInet, "ip", "link", "set", "inet0", "up")
	mustNS(t, nsInet, "ip", "addr", "add", internet+"/32", "dev", "lo")
}

type proc struct {
	name string
	cmd  *exec.Cmd
	mu   sync.Mutex
	log  bytes.Buffer
	done chan struct{}
}

func (p *proc) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.log.Write(b)
}

func (p *proc) Log() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.log.String()
}

func (p *proc) waitLog(t *testing.T, substr string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if strings.Contains(p.Log(), substr) {
			return
		}
		select {
		case <-p.done:
			// Процесс мог записать строку и сразу выйти — между проверкой
			// выше и этим select. Весь вывод к этому моменту уже прочитан
			// (Wait дожидается копирования), так что смотрим ещё раз.
			if strings.Contains(p.Log(), substr) {
				return
			}
			t.Fatalf("%s завершился, не дождавшись %q:\n%s", p.name, substr, p.Log())
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Fatalf("%s: не дождались %q:\n%s", p.name, substr, p.Log())
}

// stop посылает SIGTERM и ждёт корректного завершения.
func (p *proc) stop(t *testing.T) {
	t.Helper()
	select {
	case <-p.done:
		return
	default:
	}
	p.cmd.Process.Signal(os.Interrupt)
	select {
	case <-p.done:
	case <-time.After(10 * time.Second):
		p.cmd.Process.Kill()
		<-p.done
		t.Errorf("%s не завершился по SIGTERM", p.name)
	}
}

// isolateEtc — обёртка запуска: процесс получает свою копию /etc поверх
// настоящей (overlayfs в отдельном пространстве монтирования).
//
// `ip netns exec` разделяет с хостом сеть — нет, а файловую систему — да.
// Клиент в полном туннеле подменяет /etc/resolv.conf, и без обёртки он
// подменял его ХОСТУ: на раннере GitHub это отрезало DNS самому агенту, и
// задание обрывалось через час с «runner lost communication». Теперь
// изменения /etc остаются внутри процесса и исчезают вместе с ним.
const isolateEtc = `set -e
d=$(mktemp -d)
mount -t tmpfs none "$d"
mkdir "$d/u" "$d/w"
mount -t overlay overlay -o "lowerdir=/etc,upperdir=$d/u,workdir=$d/w" /etc
exec "$0" "$@"`

func start(t *testing.T, ns, name string, args ...string) *proc {
	t.Helper()
	p := &proc{name: name, done: make(chan struct{})}
	// androidsim сам проверяет resolv.conf, который `ip netns exec` берёт из
	// /etc/netns/<ns>/ (см. android_test.go); overlay его бы спрятал, а
	// resolv.conf он не трогает.
	if !strings.HasPrefix(name, "androidsim") {
		args = append([]string{"unshare", "--mount", "--propagation", "private", "sh", "-c", isolateEtc}, args...)
	}
	p.cmd = exec.Command("ip", append([]string{"netns", "exec", ns}, args...)...)
	p.cmd.Stdout, p.cmd.Stderr = p, p
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { p.cmd.Wait(); close(p.done) }()
	t.Cleanup(func() {
		p.stop(t)
		// Журналы процессов объёмные (log_level debug): при -v в CI они
		// утопили бы строки === RUN, по которым видно, где стенд встал.
		// Показываются при падении или по MASQUEVPN_E2E_LOGS=1.
		if t.Failed() || os.Getenv("MASQUEVPN_E2E_LOGS") != "" {
			t.Logf("---- журнал %s ----\n%s", name, p.Log())
		}
	})
	return p
}

// certs создаёт CA и серверный сертификат на sni.
func certs(t *testing.T, dir string) (caFile, certFile, keyFile string) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "masquevpn e2e CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: sni}, DNSNames: []string{sni},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	keyDER, _ := x509.MarshalECPrivateKey(key)

	write := func(name, typ string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b}), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	return write("ca.pem", "CERTIFICATE", caDER), write("cert.pem", "CERTIFICATE", der), write("key.pem", "EC PRIVATE KEY", keyDER)
}

func writeJSON(t *testing.T, path string, v any) string {
	t.Helper()
	b, _ := json.MarshalIndent(v, "", "  ")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

type stand struct {
	dir     string
	bin     string
	ca      string
	cert    string
	key     string
	authKey string
	server  *proc
	client  *proc
	dns     *proc // «резолвер провайдера» на пути клиента, вне туннеля
}

type opts struct {
	transport string // quic | utls
	clientMTU int
	serverMTU int
	noClamp   bool
	extraCli  map[string]any
	extraSrv  map[string]any
	// noFraming выключает кадрирование (C2) с обеих сторон — нужно там, где
	// проверяется именно старый путь «пакет = датаграмма».
	noFraming bool
	// dnsResolver поднимает «резолвер провайдера» за шлюзом и даёт клиенту
	// маршрут по умолчанию, как у обычной машины до подключения VPN.
	// По журналу резолвера видно, что именно уходит наружу и с какого адреса.
	dnsResolver bool
	// dnsAnswer — «имя=IPv4»: резолвер провайдера знает эту одну запись
	// (остальное — пустой ответ). Нужен, чтобы клиент мог найти сервер по
	// имени, как в жизни.
	dnsAnswer string
	// noClient поднимает только сервер: клиента тест запускает сам. Нужно
	// там, где вместо vpnclient работает другой клиент — например имитатор
	// VpnService для мобильного ядра.
	noClient bool
}

func newStand(t *testing.T, o opts) *stand {
	t.Helper()
	requireEnv(t)
	bin := buildBinaries(t)
	topology(t)
	s := &stand{dir: t.TempDir(), bin: bin}
	s.ca, s.cert, s.key = certs(t, s.dir)
	s.authKey = strings.TrimSpace(sh(t, filepath.Join(bin, "vpnserver"), "genkey"))

	start(t, nsInet, "inetsrv", filepath.Join(bin, "inetsrv"), "-addr", internet+":8080", "-udp", internet+":7")
	if o.dnsResolver {
		// Резолвер за шлюзом и маршрут по умолчанию у клиента — то, что
		// есть у любой машины ДО включения VPN.
		mustNS(t, nsSrv, "ip", "addr", "add", ispResolver+"/32", "dev", "lo")
		mustNS(t, nsCli, "ip", "route", "add", "default", "via", "10.0.0.1")
		args := []string{filepath.Join(bin, "inetsrv"), "-dns", ispResolver + ":53", "-addr", "", "-udp", ""}
		if o.dnsAnswer != "" {
			args = append(args, "-dns-a", o.dnsAnswer)
		}
		s.dns = start(t, nsSrv, "dnssrv", args...)
	}
	s.startServer(t, o)
	if !o.noClient {
		s.startClient(t, o)
	}
	return s
}

func (s *stand) startServer(t *testing.T, o opts) {
	t.Helper()
	if o.serverMTU == 0 {
		o.serverMTU = 1280
	}
	site := filepath.Join(s.dir, "site")
	os.MkdirAll(site, 0o755)
	os.WriteFile(filepath.Join(site, "index.html"), []byte("<html><body>сайт-прикрытие</body></html>\n"), 0o644)
	cfg := map[string]any{
		"listen":       "10.0.0.1:443",
		"fallback_dir": site,
		"cert_file":    s.cert,
		"key_file":     s.key,
		"auth_key":     s.authKey,
		"tun":          map[string]any{"name": "masquevpn0", "mtu": o.serverMTU},
		"pool4":        "10.66.0.0/24",
		"nat":          map[string]any{"no_mss_clamp": o.noClamp},
		"shaping":      "cloud-gaming-down",
		"log_level":    "debug",
	}
	if o.noFraming {
		cfg["packing"] = map[string]any{"disabled": true}
	}
	for k, v := range o.extraSrv {
		if str, ok := v.(string); ok && str == "" {
			delete(cfg, k) // пустая строка — «убрать поле», а не «пустое значение»
			continue
		}
		cfg[k] = v
	}
	path := writeJSON(t, filepath.Join(s.dir, "server.json"), cfg)
	s.server = start(t, nsSrv, "vpnserver", filepath.Join(s.bin, "vpnserver"), "-config", path)
	s.server.waitLog(t, "сервер запущен", 10*time.Second)
}

func (s *stand) startClient(t *testing.T, o opts) {
	t.Helper()
	if o.clientMTU == 0 {
		o.clientMTU = 1280
	}
	if o.transport == "" {
		o.transport = "quic"
	}
	cfg := map[string]any{
		"server":      "10.0.0.1:443",
		"server_name": sni,
		"auth_key":    s.authKey,
		"ca_file":     s.ca,
		"transport":   o.transport,
		"tun":         map[string]any{"name": "masquevpn0", "mtu": o.clientMTU},
		"shaping":     "cloud-gaming-up",
		"log_level":   "debug",
		// В большинстве тестов прикрытие DNS только мешает: резолверов в
		// стенде нет. Свой тест включает его явно.
		"dns_cover": map[string]any{"disabled": true},
	}
	if o.noFraming {
		cfg["packing"] = map[string]any{"disabled": true}
	}
	for k, v := range o.extraCli {
		cfg[k] = v
	}
	path := writeJSON(t, filepath.Join(s.dir, "client-"+o.transport+".json"), cfg)
	s.client = start(t, nsCli, "vpnclient-"+o.transport, filepath.Join(s.bin, "vpnclient-"+o.transport), "-config", path)
	s.client.waitLog(t, "весь трафик идёт через туннель", 20*time.Second)
}

func curl(t *testing.T, args ...string) string {
	t.Helper()
	// --noproxy: в окружении разработки задан HTTPS-прокси, внутри netns
	// его нет, и curl иначе стучится в него, а не к нам.
	return mustNS(t, nsCli, append([]string{"curl", "-sS", "--fail", "--noproxy", "*", "--max-time", "60"}, args...)...)
}

// patternHash — sha256 от первых n байт данных inetsrv.
func patternHash(n int64) (string, []byte) {
	b := make([]byte, n)
	for i := range b {
		off := int64(i)
		b[i] = byte((off*7 + off>>8) & 0xff)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), b
}

func checkDownload(t *testing.T, n int64, extra ...string) {
	t.Helper()
	want, _ := patternHash(n)
	out := filepath.Join(t.TempDir(), "blob")
	curl(t, append(extra, "-o", out, fmt.Sprintf("http://%s:8080/blob?n=%d", internet, n))...)
	f, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	got, _ := io.Copy(h, f)
	if got != n || hex.EncodeToString(h.Sum(nil)) != want {
		t.Fatalf("скачано %d байт из %d, хеш не совпал", got, n)
	}
}

func checkUpload(t *testing.T, n int64) {
	t.Helper()
	want, data := patternHash(n)
	in := filepath.Join(t.TempDir(), "up")
	if err := os.WriteFile(in, data, 0o600); err != nil {
		t.Fatal(err)
	}
	out := curl(t, "--data-binary", "@"+in, "http://"+internet+":8080/sink")
	if strings.TrimSpace(out) != fmt.Sprintf("%d %s", n, want) {
		t.Fatalf("сервер получил: %q, ожидалось %d %s", out, n, want)
	}
}

func ping(ns string, args ...string) (string, error) {
	return nsRun(ns, append([]string{"ping", "-n", "-W", "2"}, args...)...)
}

// ---------------------------------------------------------------------------

// TestNoTunnelNoInternet — контроль стенда: без клиента «интернет» недоступен.
func TestNoTunnelNoInternet(t *testing.T) {
	requireEnv(t)
	topology(t)
	if out, err := ping(nsCli, "-c", "1", internet); err == nil {
		t.Fatalf("стенд негоден: интернет доступен без туннеля\n%s", out)
	}
}

func testTunnel(t *testing.T, transport string) {
	s := newStand(t, opts{transport: transport})

	t.Run("ping", func(t *testing.T) {
		out, err := ping(nsCli, "-c", "3", "-i", "0.2", internet)
		if err != nil {
			t.Fatalf("ping через туннель: %v\n%s", err, out)
		}
		if !strings.Contains(out, "3 received") {
			t.Fatalf("потери:\n%s", out)
		}
	})
	t.Run("ping-gateway", func(t *testing.T) {
		if out, err := ping(nsCli, "-c", "1", gateway); err != nil {
			t.Fatalf("шлюз туннеля недоступен: %v\n%s", err, out)
		}
	})
	t.Run("curl", func(t *testing.T) {
		if out := curl(t, "http://"+internet+":8080/"); out != "hello from internet\n" {
			t.Fatalf("got %q", out)
		}
	})
	t.Run("nat", func(t *testing.T) {
		// «Интернет» видит адрес сервера, а не туннельный адрес клиента.
		if out := strings.TrimSpace(curl(t, "http://"+internet+":8080/whoami")); out != "203.0.113.1" {
			t.Fatalf("внешний адрес клиента: %q, ожидался адрес сервера", out)
		}
	})
	t.Run("udp", func(t *testing.T) {
		out := mustNS(t, nsCli, "bash", "-c",
			"exec 3<>/dev/udp/"+internet+"/7; printf 'udp-through-tunnel' >&3; timeout 3 head -c 18 <&3")
		if out != "udp-through-tunnel" {
			t.Fatalf("UDP-эхо: %q", out)
		}
	})
	t.Run("tcp-download-20MB", func(t *testing.T) { checkDownload(t, 20<<20) })
	t.Run("tcp-upload-20MB", func(t *testing.T) { checkUpload(t, 20<<20) })
	t.Run("parallel", func(t *testing.T) {
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); checkDownload(t, 2<<20) }()
		}
		wg.Wait()
	})

	t.Run("shutdown-cleans-up", func(t *testing.T) {
		s.client.stop(t)
		rules := mustNS(t, nsCli, "ip", "rule")
		if strings.Contains(rules, "7443") || strings.Contains(rules, "0x7443") {
			t.Fatalf("правила туннеля остались:\n%s", rules)
		}
		if out, _ := nsRun(nsCli, "ip", "link", "show", "masquevpn0"); !strings.Contains(out, "does not exist") {
			t.Fatalf("интерфейс остался:\n%s", out)
		}
		if _, err := ping(nsCli, "-c", "1", internet); err == nil {
			t.Fatal("после остановки клиента интернет всё ещё доступен")
		}
	})
}

func TestTunnelQUIC(t *testing.T) { testTunnel(t, "quic") }
func TestTunnelUTLS(t *testing.T) { testTunnel(t, "utls") }

var pmtuRe = regexp.MustCompile(`mtu (\d+)`)

// cachedPMTU читает из ядра выясненный Path MTU до адреса.
func cachedPMTU(t *testing.T, ns, dst string) int {
	t.Helper()
	out := mustNS(t, ns, "ip", "route", "get", dst)
	m := pmtuRe.FindStringSubmatch(out)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

// TestMTUBlackHole — MTU интерфейсов ЗАВЕДОМО больше, чем помещается в
// датаграмму (1500 против ~1300), подрезка MSS выключена. Работать всё
// должно только за счёт ICMP, который туннель пишет обратно в TUN:
//
//   - вверх: ядро клиента получает Fragmentation Needed от своего TUN;
//   - вниз: внешний хост получает Fragmentation Needed через NAT сервера.
//
// Без ICMP-обратной связи TCP здесь устанавливается и виснет.
func TestMTUBlackHole(t *testing.T) {
	for _, tr := range []string{"quic", "utls"} {
		t.Run(tr, func(t *testing.T) {
			// Кадры выключены: здесь проверяется именно ICMP-обратная связь
			// старого пути. С кадрами крупный пакет режется и ICMP не нужен
			// (см. TestFramingRemovesMTUCeiling).
			newStand(t, opts{transport: tr, clientMTU: 1500, serverMTU: 1500, noClamp: true, noFraming: true})

			t.Run("ping-df-too-big", func(t *testing.T) {
				out, err := ping(nsCli, "-c", "1", "-M", "do", "-s", "1472", internet)
				if err == nil {
					t.Fatalf("пакет 1500 с DF прошёл — туннель не может его вместить:\n%s", out)
				}
				pmtu := cachedPMTU(t, nsCli, internet)
				if pmtu < 1280 || pmtu >= 1500 {
					t.Fatalf("ядро клиента не узнало MTU туннеля (pmtu=%d):\n%s", pmtu, out)
				}
				t.Logf("MTU туннеля по ICMP: %d", pmtu)
				// Пакет ровно в MTU проходит вверх. Проверяем UDP с ответом-длиной,
				// а не ping: эхо-ответ такого же размера упёрся бы в потолок
				// обратного направления, а он у сервера свой.
				payload := make([]byte, pmtu-28)
				copy(payload, "len?")
				f := filepath.Join(t.TempDir(), "probe")
				os.WriteFile(f, payload, 0o644)
				got := mustNS(t, nsCli, "bash", "-c",
					"exec 3<>/dev/udp/"+internet+"/7; cat "+f+" >&3; timeout 3 dd bs=64 count=1 status=none <&3")
				if got != strconv.Itoa(len(payload)) {
					t.Fatalf("UDP-пакет ровно в MTU (%d) не дошёл: ответ %q", pmtu, got)
				}
			})
			t.Run("upload", func(t *testing.T) {
				mustNS(t, nsCli, "ip", "route", "flush", "cache")
				checkUpload(t, 8<<20)
			})
			t.Run("download", func(t *testing.T) {
				// Кэш PMTU клиента от прошлых шагов уменьшил бы объявляемый MSS,
				// и крупных пакетов вниз не было бы вовсе. Сбрасываем.
				mustNS(t, nsCli, "ip", "route", "flush", "cache")
				mustNS(t, nsInet, "ip", "route", "flush", "cache")
				checkDownload(t, 8<<20)
				pmtu := cachedPMTU(t, nsInet, "203.0.113.1")
				if pmtu < 1280 || pmtu >= 1500 {
					t.Fatalf("внешний хост не получил ICMP через NAT (pmtu=%d)", pmtu)
				}
				t.Logf("внешний хост узнал MTU: %d", pmtu)
			})
		})
	}
}

// TestMSSClamp — с подрезкой MSS (по умолчанию) внешний хост сразу шлёт
// сегменты под MTU туннеля, ICMP вниз даже не требуется.
func TestMSSClamp(t *testing.T) {
	newStand(t, opts{serverMTU: 1280})
	checkDownload(t, 4<<20)
	if pmtu := cachedPMTU(t, nsInet, "203.0.113.1"); pmtu != 0 {
		t.Fatalf("внешнему хосту понадобился ICMP (pmtu=%d) — MSS не подрезан", pmtu)
	}
}

// TestRotationUnderLoad — ротация соединения каждые 2 с посреди длинной
// TCP-передачи: адрес сохраняется, передача не рвётся.
func TestRotationUnderLoad(t *testing.T) {
	s := newStand(t, opts{transport: "utls", extraCli: map[string]any{
		// Разброс срока выключен: тест считает число ротаций за отрезок.
		"rotation": map[string]any{"every": "1500ms", "jitter": -1},
	}})
	// Передача на 8 секунд при ротации каждые 2 с: ротаций заведомо
	// несколько, и тест не зависит от того, насколько быстра машина.
	checkDownload(t, 8<<20, "--limit-rate", "1M")
	n := strings.Count(s.server.Log(), "сессия открыта")
	if n < 4 {
		t.Fatalf("за передачу произошло %d подключений, ожидалось несколько ротаций", n)
	}
	if strings.Contains(s.client.Log(), "адрес сменился") {
		t.Fatalf("адрес при ротации сменился — соединения внутри туннеля порвались бы")
	}
	// Все сессии открылись СРАЗУ со своим адресом. Раньше новая сессия
	// получала временный адрес (прежний ещё держала старая) и выпрашивала
	// нужный капсулой после Grace — передача на это время вставала.
	opened := regexp.MustCompile(`сессия открыта" addr=\[([^\]]+)\]`).FindAllStringSubmatch(s.server.Log(), -1)
	if len(opened) != n {
		t.Fatalf("разобрано %d строк открытия из %d", len(opened), n)
	}
	for _, m := range opened {
		if m[1] != opened[0][1] {
			t.Fatalf("сессии открывались с разными адресами (%s и %s) — адрес не закреплён за клиентом",
				opened[0][1], m[1])
		}
	}
	t.Logf("сессий за передачу: %d, все с адресом %s", n, opened[0][1])
}

// TestReconnectAfterServerRestart — сервер перезапущен: клиент сам
// переподключается, туннель снова работает.
func TestReconnectAfterServerRestart(t *testing.T) {
	s := newStand(t, opts{transport: "quic"})
	if out, err := ping(nsCli, "-c", "1", internet); err != nil {
		t.Fatalf("до перезапуска: %v\n%s", err, out)
	}
	s.server.stop(t)
	s.startServer(t, opts{})
	// Быстро — потому что сервер закрывает сессии при остановке. Если этого
	// не делать, клиент узнает об остановке только по таймауту простоя QUIC
	// (десятки секунд): туннель всё это время молча не работает.
	begin := time.Now()
	s.client.waitLog(t, "соединение восстановлено", 30*time.Second)
	if took := time.Since(begin); took > 10*time.Second {
		t.Fatalf("клиент заметил остановку сервера только через %v — сервер не закрыл сессии", took.Round(time.Second))
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		out, err := ping(nsCli, "-c", "1", internet)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("после перезапуска сервера туннель не ожил:\n%s", out)
		}
		time.Sleep(200 * time.Millisecond)
	}
	checkDownload(t, 1<<20)
}

// TestWrongKeyRejected — клиент с чужим ключом не получает туннель, а сервер
// не тратит на него адрес.
func TestWrongKeyRejected(t *testing.T) {
	requireEnv(t)
	bin := buildBinaries(t)
	topology(t)
	s := &stand{dir: t.TempDir(), bin: bin}
	s.ca, s.cert, s.key = certs(t, s.dir)
	s.authKey = strings.TrimSpace(sh(t, filepath.Join(bin, "vpnserver"), "genkey"))
	s.startServer(t, opts{})
	other := strings.TrimSpace(sh(t, filepath.Join(bin, "vpnserver"), "genkey"))
	path := writeJSON(t, filepath.Join(s.dir, "bad.json"), map[string]any{
		"server": "10.0.0.1:443", "server_name": sni, "auth_key": other, "ca_file": s.ca,
		"transport": "utls", "no_reconnect": true,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", nsCli, filepath.Join(bin, "vpnclient-utls"), "-config", path)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("клиент с чужим ключом подключился:\n%s", out)
	}
	if !strings.Contains(string(out), "404") {
		t.Fatalf("ожидался ответ как у обычного сайта (404):\n%s", out)
	}
	if strings.Contains(s.server.Log(), "сессия открыта") {
		t.Fatal("сервер открыл сессию для чужого ключа")
	}
}

// TestNATRequired — контроль: без NAT на сервере ответы из «интернета» не
// возвращаются (у него нет маршрута к сети клиентов). Значит, в остальных
// тестах работает именно наш NAT.
func TestNATRequired(t *testing.T) {
	newStand(t, opts{extraSrv: map[string]any{"nat": map[string]any{"disabled": true}}})
	if out, err := ping(nsCli, "-c", "1", internet); err == nil {
		t.Fatalf("без NAT интернет доступен — стенд проверяет не то:\n%s", out)
	}
}

func TestThroughput(t *testing.T) {
	if os.Getenv("MASQUEVPN_BENCH") == "" {
		t.Skip("MASQUEVPN_BENCH=1")
	}
	for _, sh := range []string{"none", "cloud-gaming"} {
		for _, tr := range []string{"quic", "utls"} {
			t.Run(sh+"/"+tr, func(t *testing.T) {
				o := opts{transport: tr}
				if sh == "none" {
					o.extraCli = map[string]any{"shaping": "none"}
					o.extraSrv = map[string]any{"shaping": "none"}
				}
				newStand(t, o)
				const n = 50 << 20
				begin := time.Now()
				checkDownload(t, n)
				d := time.Since(begin)
				begin = time.Now()
				checkUpload(t, n)
				u := time.Since(begin)
				t.Logf("вниз %.1f Мбит/с, вверх %.1f Мбит/с", float64(n*8)/d.Seconds()/1e6, float64(n*8)/u.Seconds()/1e6)
			})
		}
	}
}

var dnsLineRe = regexp.MustCompile(`dns src=(\S+) name=(\S+) type=(\d+)`)

type dnsQuery struct {
	src, name string
	qtype     int
}

func dnsQueries(p *proc) []dnsQuery {
	var out []dnsQuery
	for _, m := range dnsLineRe.FindAllStringSubmatch(p.Log(), -1) {
		n, _ := strconv.Atoi(m[3])
		out = append(out, dnsQuery{src: m[1], name: m[2], qtype: n})
	}
	return out
}

// TestDNSCoverVisibleOutsideTunnel — признак «хост не делает DNS-запросов»
// закрыт: запросы реально уходят МИМО туннеля и видны наблюдателю на пути.
//
// Резолвер стоит на 10.0.0.1:53 — на том же отрезке сети, что и вход в
// туннель. Если бы прикрытие пошло внутрь туннеля, запросы пришли бы с
// туннельного адреса 10.66.0.x (или не пришли бы вовсе).
func TestDNSCoverVisibleOutsideTunnel(t *testing.T) {
	domains := []string{"www.example.com", "cdn.example.net", "example.org"}
	s := newStand(t, opts{transport: "utls", dnsResolver: true, extraCli: map[string]any{
		"dns_cover": map[string]any{
			"servers":       []string{ispResolver},
			"domains":       domains,
			"mean_interval": "120ms",
		},
	}})
	s.client.waitLog(t, "прикрытие DNS включено", 10*time.Second)

	// Заодно через туннель идёт настоящий трафик: прикрытие не должно ему мешать.
	checkDownload(t, 2<<20)

	deadline := time.Now().Add(15 * time.Second)
	var got []dnsQuery
	for {
		got = dnsQueries(s.dns)
		if len(got) >= 20 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("наблюдатель на пути увидел лишь %d DNS-запросов — признак не закрыт", len(got))
		}
		time.Sleep(100 * time.Millisecond)
	}

	names := map[string]int{}
	types := map[int]int{}
	for _, q := range got {
		if q.src != "10.0.0.2" {
			t.Fatalf("запрос пришёл с %s, а не с настоящего адреса клиента %s: прикрытие ушло ВНУТРЬ туннеля", q.src, "10.0.0.2")
		}
		if !slices.Contains(domains, q.name) && q.name != sni {
			t.Fatalf("спрошено имя не из списка: %q", q.name)
		}
		names[q.name]++
		types[q.qtype]++
	}
	if types[1] == 0 || types[28] == 0 {
		t.Fatalf("нет пары A/AAAA: %v", types)
	}
	// Домен своего сервера тоже спрашивается: обычный клиент резолвит имя,
	// к которому подключается, а не ходит сразу на IP.
	if names[sni] == 0 {
		t.Fatalf("имя сервера %q ни разу не спрошено: %v", sni, names)
	}
	t.Logf("снаружи видно %d DNS-запросов, имена: %v", len(got), names)

	// Туннель при этом продолжает работать.
	if out, err := ping(nsCli, "-c", "1", internet); err != nil {
		t.Fatalf("после прикрытия DNS туннель сломался: %v\n%s", err, out)
	}
}

// TestDNSCoverDisabled — выключенное прикрытие не шлёт ничего: значение по
// умолчанию можно отменить, и тогда возвращается прежнее поведение.
func TestDNSCoverDisabled(t *testing.T) {
	s := newStand(t, opts{dnsResolver: true}) // dns_cover отключён в startClient
	checkDownload(t, 1<<20)
	time.Sleep(2 * time.Second)
	if got := dnsQueries(s.dns); len(got) != 0 {
		t.Fatalf("при выключенном прикрытии ушло %d запросов: %v", len(got), got[0])
	}
}

// txPackets — сколько пакетов ушло с интерфейса (счётчики ядра, то есть
// ровно то, что видно наблюдателю на проводе).
func txPackets(t *testing.T, ns, iface string) int {
	t.Helper()
	out := mustNS(t, ns, "ip", "-s", "-j", "link", "show", iface)
	var links []struct {
		Stats64 struct {
			TX struct {
				Packets int `json:"packets"`
			} `json:"tx"`
		} `json:"stats64"`
	}
	if err := json.Unmarshal([]byte(out), &links); err != nil || len(links) == 0 {
		t.Fatalf("счётчики %s: %v\n%s", iface, err, out)
	}
	return links[0].Stats64.TX.Packets
}

// TestFramingRemovesMTUCeiling — с кадрами (C2) MTU туннеля больше не
// упирается в размер QUIC-пакета: крупный пакет режется на куски и
// собирается обратно. MTU 1500 при потолке датаграммы ~1300 работает, и
// ICMP при этом не нужен вовсе — ядро клиента не узнаёт никакого
// уменьшенного MTU.
func TestFramingRemovesMTUCeiling(t *testing.T) {
	for _, tr := range []string{"quic", "utls"} {
		t.Run(tr, func(t *testing.T) {
			s := newStand(t, opts{transport: tr, clientMTU: 1500, serverMTU: 1500, noClamp: true})
			s.client.waitLog(t, "кадры=true", 15*time.Second)
			mustNS(t, nsCli, "ip", "route", "flush", "cache")
			mustNS(t, nsInet, "ip", "route", "flush", "cache")

			// Пакет в полный MTU проходит с установленным DF.
			if out, err := ping(nsCli, "-c", "2", "-M", "do", "-s", "1472", internet); err != nil {
				t.Fatalf("пакет 1500 байт с DF не прошёл:\n%s", out)
			}
			checkUpload(t, 8<<20)
			checkDownload(t, 8<<20)

			if pmtu := cachedPMTU(t, nsCli, internet); pmtu != 0 {
				t.Fatalf("ядро клиента узнало MTU %d — значит, был ICMP, а с кадрами он не нужен", pmtu)
			}
			if pmtu := cachedPMTU(t, nsInet, "203.0.113.1"); pmtu != 0 {
				t.Fatalf("внешний хост узнал MTU %d — значит, был ICMP", pmtu)
			}
		})
	}
}

// TestPacingShapesStreamE2E — с расписанием профиля поток датаграмм идёт
// своим ритмом и в простое тоже: снаружи не видно, что внутри туннеля тихо.
// Считаем пакеты счётчиками ядра на интерфейсе клиента.
func TestPacingShapesStreamE2E(t *testing.T) {
	const idle = 2 * time.Second

	measure := func(t *testing.T, o opts) int {
		s := newStand(t, o)
		s.client.waitLog(t, "кадры=true", 15*time.Second)
		if out, err := ping(nsCli, "-c", "1", internet); err != nil {
			t.Fatalf("туннель не работает: %v\n%s", err, out)
		}
		time.Sleep(300 * time.Millisecond) // дать улечься трафику от ping
		before := txPackets(t, nsCli, "cli0")
		time.Sleep(idle)
		return txPackets(t, nsCli, "cli0") - before
	}

	var withPace, without int
	t.Run("с расписанием", func(t *testing.T) {
		withPace = measure(t, opts{transport: "utls", extraCli: map[string]any{
			"packing": map[string]any{"pace": "cloud-gaming-up"},
		}})
		t.Logf("за %v простоя ушло %d пакетов", idle, withPace)
	})
	t.Run("без расписания", func(t *testing.T) {
		without = measure(t, opts{transport: "utls"})
		t.Logf("за %v простоя ушло %d пакетов", idle, without)
	})

	// Профиль — около 60 датаграмм в секунду; без него в простое идут только
	// редкие cover-датаграммы и keep-alive.
	if withPace < 60 {
		t.Fatalf("с расписанием за %v ушло %d пакетов — профиль не держится", idle, withPace)
	}
	if without >= withPace/2 {
		t.Fatalf("без расписания %d пакетов против %d с ним — разницы нет", without, withPace)
	}
}

// TestServerFingerprintProfile — отпечаток серверной стороны (C1) виден
// снаружи: подключаемся к своему же серверу обычным QUIC-клиентом и
// читаем транспортные параметры, которые он объявляет.
func TestServerFingerprintProfile(t *testing.T) {
	// Профиль задан явно: с 29.09 по умолчанию стоит stock (легенда Caddy),
	// а снятый с Cloudflare остался выбираемым — его и проверяем.
	s := newStand(t, opts{extraSrv: map[string]any{"server_profile": "cloudflare"}})
	s.server.waitLog(t, "профиль=", 10*time.Second)

	out := mustNS(t, nsCli, filepath.Join(s.bin, "fpserver"), "-probe", "10.0.0.1:443", "-sni", sni, "-insecure")

	// Ожидаемое считаем ИЗ профиля, а не вписываем числами: профиль по
	// умолчанию уже менялся (эвристика → снятое с www.cloudflare.com), и
	// вписанные числа превращают тест в ложно-красный — он падал, хотя
	// сервер объявлял ровно то, что в профиле.
	p := fingerprint.Captured()
	idle := time.Duration(p.MaxIdleTimeoutMS) * time.Millisecond
	for _, want := range []string{
		fmt.Sprintf("max_idle_timeout              %v", idle),
		fmt.Sprintf("initial_max_data              %d", p.InitialMaxData),
		fmt.Sprintf("initial_max_streams bidi/uni  %d / %d", p.MaxBidiStreams, p.MaxUniStreams),
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("сервер объявляет не то, что в профиле: нет %q\n%s", want, out)
		}
	}
	// Датаграммы обязаны быть объявлены — без них CONNECT-IP невозможен.
	if strings.Contains(out, "max_datagram_frame_size       0") {
		t.Fatalf("датаграммы не объявлены:\n%s", out)
	}
	t.Logf("параметры сервера снаружи:\n%s", out)
}

// TestServerStockProfile — контроль: с "stock" сервер отвечает умолчаниями
// quic-go, по которым он и узнаётся. Значит, профиль действительно меняет
// то, что видно снаружи.
func TestServerStockProfile(t *testing.T) {
	s := newStand(t, opts{extraSrv: map[string]any{"server_profile": "stock"}})
	out := mustNS(t, nsCli, filepath.Join(s.bin, "fpserver"), "-probe", "10.0.0.1:443", "-sni", sni, "-insecure")

	// Сравниваем со значениями ТЕКУЩЕГО профиля: вписанное число устаревает
	// вместе с профилем, и проверка тихо превращается в пустую.
	p := fingerprint.Captured()
	for _, profileOnly := range []string{
		fmt.Sprintf("initial_max_data              %d", p.InitialMaxData),
		fmt.Sprintf("max_idle_timeout              %v", time.Duration(p.MaxIdleTimeoutMS)*time.Millisecond),
	} {
		if strings.Contains(out, profileOnly) {
			t.Fatalf("с server_profile=stock параметры остались профильными (%q):\n%s", profileOnly, out)
		}
	}
}

// TestSessionResumptionOnRotation — при ротации клиент возобновляет
// TLS-сессию по билету, а не проводит полное рукопожатие каждый раз.
// Полное рукопожатие на каждом подключении — заметная аномалия: браузеры
// так себя не ведут.
func TestSessionResumptionOnRotation(t *testing.T) {
	s := newStand(t, opts{transport: "quic", extraCli: map[string]any{
		"rotation": map[string]any{"every": "1s"},
	}})
	s.client.waitLog(t, "TLS-сессия возобновлена по билету", 20*time.Second)
}

// TestServerAnswersOverTCP — домен отвечает и по TCP, и заголовком Alt-Svc
// сообщает про HTTP/3. Без этого получался домен, у которого HTTP/3 есть, а
// обычного HTTPS нет: аномалия, видимая одним curl, и браузеру неоткуда
// узнать про HTTP/3.
func TestServerAnswersOverTCP(t *testing.T) {
	s := newStand(t, opts{})
	s.server.waitLog(t, "TCP-слушатель запущен", 10*time.Second)

	out := mustNS(t, nsCli, "curl", "-sS", "-i", "--noproxy", "*", "--max-time", "10",
		"--cacert", s.ca, "--resolve", sni+":443:10.0.0.1", "https://"+sni+"/")
	if !strings.Contains(out, "200") || !strings.Contains(out, "сайт-прикрытие") {
		t.Fatalf("по TCP сайт не отдан:\n%s", out)
	}
	if !strings.Contains(strings.ToLower(out), "alt-svc: h3=") {
		t.Fatalf("нет заголовка Alt-Svc — браузер не узнает про HTTP/3:\n%s", out)
	}
	// А туннель при этом работает.
	if o, err := ping(nsCli, "-c", "1", internet); err != nil {
		t.Fatalf("туннель сломался: %v\n%s", err, o)
	}
}

// TestFallbackProxy — сайт-прикрытие можно проксировать на живой backend:
// пробер видит настоящий работающий сайт, а не статику из каталога.
func TestFallbackProxy(t *testing.T) {
	s := newStand(t, opts{extraSrv: map[string]any{
		"fallback_proxy": "http://203.0.113.2:8080",
	}})
	// backend — обычный HTTP-сервер в соседнем namespace.
	start(t, nsInet, "backend", filepath.Join(s.bin, "inetsrv"), "-addr", "203.0.113.2:8080", "-udp", "")
	deadline := time.Now().Add(10 * time.Second)
	for {
		out, err := nsRun(nsCli, "curl", "-sS", "--noproxy", "*", "--max-time", "5", "--cacert", s.ca,
			"--resolve", sni+":443:10.0.0.1", "https://"+sni+"/")
		if err == nil && strings.Contains(out, "hello from internet") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("прокси не отдал ответ backend'а: %v\n%s", err, out)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// probeTCP — один запрос к домену по TCP «как посторонний», с заголовками
// ответа.
func probeTCP(t *testing.T, s *stand, method, path string) string {
	t.Helper()
	return mustNS(t, nsCli, "curl", "-sS", "-i", "--noproxy", "*", "--max-time", "10",
		"--cacert", s.ca, "--resolve", sni+":443:10.0.0.1", "-X", method, "https://"+sni+path)
}

// TestProbeOverTCPGetsNoDocument — простукивание по TCP.
//
// По TCP сайт стоит без нашего обработчика CONNECT-IP, а http.FileServer на
// метод не смотрит: «curl -X CONNECT https://домен/» получал 200 и страницу.
// Обычный сервер документ на CONNECT не отдаёт никогда — это был признак,
// видимый одним запросом.
func TestProbeOverTCPGetsNoDocument(t *testing.T) {
	s := newStand(t, opts{}) // стенд со статикой в fallback_dir
	s.server.waitLog(t, "TCP-слушатель запущен", 10*time.Second)

	if out := probeTCP(t, s, "GET", "/"); !strings.Contains(out, "сайт-прикрытие") {
		t.Fatalf("обычный GET перестал отдавать сайт:\n%s", out)
	}
	out := probeTCP(t, s, "CONNECT", "/")
	if strings.Contains(out, "сайт-прикрытие") {
		t.Fatalf("на CONNECT пришла страница сайта:\n%s", out)
	}
	if !strings.Contains(out, "405") {
		t.Fatalf("на CONNECT ответ не 405:\n%s", out)
	}
}

// TestBuiltinCoverSite — встроенный сайт: без fallback_dir и fallback_proxy
// домен всё равно отвечает связанными страницами, а не 404. Голый 404
// отличим от VPN не лучше, чем брошенный домен.
func TestBuiltinCoverSite(t *testing.T) {
	seedDir := t.TempDir()
	seedFile := filepath.Join(seedDir, "site-seed")
	s := newStand(t, opts{extraSrv: map[string]any{
		"fallback_dir": "",
		// Seed — в каталог теста, а не в /var/lib/masquevpn машины, где
		// идёт стенд.
		"fallback_site": map[string]any{"seed_file": seedFile},
	}})
	s.server.waitLog(t, "TCP-слушатель запущен", 10*time.Second)

	// Seed создан сам, и сервер об этом сказал.
	s.server.waitLog(t, "создан seed сайта-прикрытия", 5*time.Second)
	if b, err := os.ReadFile(seedFile); err != nil || len(strings.TrimSpace(string(b))) != 32 {
		t.Fatalf("seed-файл: %q, %v", b, err)
	}

	home := probeTCP(t, s, "GET", "/")
	for _, want := range []string{"200", "<title>", "/status", "alt-svc: h3="} {
		if !strings.Contains(strings.ToLower(home), strings.ToLower(want)) {
			t.Fatalf("на главной нет %q:\n%s", want, home)
		}
	}
	// Название выведено из домена сертификата (vpn.example.test → Example).
	if !strings.Contains(home, "Example") {
		t.Fatalf("название не выведено из домена:\n%s", home)
	}
	// Пути документации и фида зависят от seed'а — берём их со страниц.
	paths := []string{"/status", "/robots.txt", "/favicon.ico", "/sitemap.xml"}
	for _, m := range regexp.MustCompile(`(?:href|src)="(/[^"]*)"`).FindAllStringSubmatch(home, -1) {
		paths = append(paths, m[1])
	}
	feed := regexp.MustCompile(`Machine-readable feed: <a href="(/[^"]+)"`).FindStringSubmatch(probeTCP(t, s, "GET", "/status"))
	if feed == nil {
		t.Fatal("на странице статуса нет ссылки на фид")
	}
	paths = append(paths, feed[1])
	for _, p := range paths {
		if out := probeTCP(t, s, "GET", p); !strings.Contains(out, " 200") {
			t.Fatalf("%s не отдан:\n%s", p, out)
		}
	}
	// Документация рассказывает то, что видно в протоколе у этого же
	// сервера: WebTransport (его объявляют SETTINGS) и UDP-порт, на котором
	// отвечает HTTP/3 (см. internal/site/legends.go).
	docsSeen := false
	for _, p := range paths {
		out := probeTCP(t, s, "GET", p)
		if !strings.Contains(out, "Network requirements") {
			continue
		}
		docsSeen = true
		for _, want := range []string{"new WebTransport(", "UDP port 443", "no TCP fallback"} {
			if !strings.Contains(out, want) {
				t.Fatalf("в документации %s нет %q:\n%s", p, want, out)
			}
		}
	}
	if !docsSeen {
		t.Fatal("не нашлась страница документации с требованиями к сети")
	}
	if out := probeTCP(t, s, "GET", feed[1]); !strings.Contains(out, `"components"`) {
		t.Fatalf("фид статуса %s:\n%s", feed[1], out)
	}
	if out := probeTCP(t, s, "GET", "/no-such-page"); !strings.Contains(out, "404") {
		t.Fatalf("несуществующая страница не дала 404:\n%s", out)
	}
	if out := probeTCP(t, s, "CONNECT", "/"); !strings.Contains(out, "405") {
		t.Fatalf("CONNECT не дал 405:\n%s", out)
	}
	// И туннель при этом работает.
	if o, err := ping(nsCli, "-c", "1", internet); err != nil {
		t.Fatalf("туннель сломался: %v\n%s", err, o)
	}
}

// TestSurvivesBlockade — что происходит, когда наш трафик просто перестают
// пропускать: так ведёт себя фильтрующее оборудование, когда решает, что
// поток ему не нравится.
//
// Проверяем две вещи. Во-первых, клиент не устраивает шторм переподключений:
// частые одинаковые попытки сами по себе заметны и вдобавок бесполезны.
// Во-вторых, после снятия блокировки туннель оживает С ТЕМ ЖЕ адресом —
// иначе все соединения внутри туннеля порвались бы именно в тот момент,
// когда связь вернулась.
func TestSurvivesBlockade(t *testing.T) {
	s := newStand(t, opts{transport: "quic"})
	if out, err := ping(nsCli, "-c", "1", internet); err != nil {
		t.Fatalf("до блокировки: %v\n%s", err, out)
	}
	before := regexp.MustCompile(`сессия открыта" addr=\[([^\]]+)\]`).FindStringSubmatch(s.server.Log())
	if before == nil {
		t.Fatalf("не найден адрес первой сессии:\n%s", s.server.Log())
	}

	// Глушим путь к серверу на 12 секунд.
	mustNS(t, nsCli, "ip", "route", "add", "blackhole", "10.0.0.1/32")
	attemptsAt := strings.Count(s.client.Log(), "переподключение не удалось")
	time.Sleep(12 * time.Second)
	attempts := strings.Count(s.client.Log(), "переподключение не удалось") - attemptsAt
	mustNS(t, nsCli, "ip", "route", "del", "blackhole", "10.0.0.1/32")
	t.Logf("за 12 с блокировки попыток переподключения: %d", attempts)
	if attempts > 8 {
		t.Fatalf("%d попыток за 12 с — пауза между ними не растёт, это шторм", attempts)
	}

	s.client.waitLog(t, "соединение восстановлено", 60*time.Second)
	deadline := time.Now().Add(20 * time.Second)
	for {
		if out, err := ping(nsCli, "-c", "1", internet); err == nil {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("после снятия блокировки туннель не ожил:\n%s", out)
		}
		time.Sleep(300 * time.Millisecond)
	}
	opened := regexp.MustCompile(`сессия открыта" addr=\[([^\]]+)\]`).FindAllStringSubmatch(s.server.Log(), -1)
	last := opened[len(opened)-1]
	if last[1] != before[1] {
		t.Fatalf("после переподключения адрес сменился: %s → %s — соединения внутри туннеля порвались бы",
			before[1], last[1])
	}
	t.Logf("сессий всего %d, адрес сохранён: %s", len(opened), last[1])
}

// hostResolvUntouched проверяет после теста, что /etc/resolv.conf хоста
// остался прежним: стенд не имеет права менять сеть машины, на которой
// идёт (на раннере GitHub это обрывало связь агента с сервером).
func hostResolvUntouched(t *testing.T) {
	t.Helper()
	snap := func() string {
		target, _ := os.Readlink("/etc/resolv.conf")
		raw, _ := os.ReadFile("/etc/resolv.conf")
		return target + "\x00" + string(raw)
	}
	before := snap()
	t.Cleanup(func() {
		if after := snap(); after != before {
			t.Errorf("стенд изменил /etc/resolv.conf хоста:\nбыло:\n%s\nстало:\n%s", before, after)
		}
	})
}
