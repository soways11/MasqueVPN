package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/soways11/masquevpn/internal/acme/acmetest"
)

// newTestCA поднимает тестовый удостоверяющий центр на loopback.
func newTestCA(t *testing.T) *acmetest.CA {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	ca, err := acmetest.New("http://" + srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if testing.Verbose() {
		ca.Logf = t.Logf
	}
	srv.Config.Handler = ca.Handler()
	srv.Start()
	t.Cleanup(srv.Close)
	return ca
}

const testDomain = "vpn.example.test"

// startTLS поднимает слушатель TLS с нужными настройками и возвращает адрес.
// Это стенд для проверки tls-alpn-01: удостоверяющий центр приходит именно
// сюда.
func startTLS(t *testing.T, conf *tls.Config) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				tc := tls.Server(c, conf)
				_ = tc.HandshakeContext(context.Background())
				_ = tc.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

// selfSigned — сертификат «из файлов», который в бою задаётся cert_file/key_file.
func selfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: testDomain},
		DNSNames:     []string{testDomain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}, pool
}

// whoIssued подключается к слушателю как обычный клиент и возвращает имя
// издателя предъявленного сертификата, проверив цепочку доверием к roots.
func whoIssued(t *testing.T, addr string, roots *x509.CertPool) string {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName: testDomain, RootCAs: roots, MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("рукопожатие с сервером: %v", err)
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0].Issuer.CommonName
}

// cacheDir — каталог кэша ACME. Не t.TempDir: autocert продлевает сертификат
// из собственной горутины с собственным таймером, остановить которую снаружи
// нечем, и она пишет в кэш уже после конца теста. t.TempDir на этом падает с
// «directory not empty» — то есть тест изредка «краснеет» на уборке, ничего
// не проверив. Убираем сами и не считаем неудачу уборки провалом теста.
func cacheDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "masquevpn-acme-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func newManager(t *testing.T, ca *acmetest.CA, fallback *tls.Certificate) *Manager {
	t.Helper()
	m, err := New(Config{
		Domains:      []string{testDomain},
		Email:        "admin@" + testDomain,
		CacheDir:     cacheDir(t),
		DirectoryURL: ca.DirectoryURL(),
		Fallback:     fallback,
		// В тесте всё то же самое, только быстрее: рукопожатие не ждёт
		// ACME долго, зависшая попытка быстро уступает место новой.
		HandshakeWait:  500 * time.Millisecond,
		AttemptTimeout: time.Second,
		RetryCooldown:  30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// TestObtainsCertificateOverTLSALPN — весь обмен ACME целиком: каталог,
// аккаунт, заказ, ПРОВЕРКА ВЛАДЕНИЯ ДОМЕНОМ через наш же слушатель TCP,
// finalize и выдача. После этого сервер предъявляет клиентам именно
// выпущенный сертификат.
func TestObtainsCertificateOverTLSALPN(t *testing.T) {
	ca := newTestCA(t)
	m := newManager(t, ca, nil)
	addr := startTLS(t, m.TCPConfig())
	ca.SetTarget(addr)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := m.Obtain(ctx); err != nil {
		t.Fatalf("сертификат не получен: %v", err)
	}
	if n := ca.Issued(); n != 1 {
		t.Fatalf("выпущено сертификатов: %d", n)
	}
	// Обычный клиент видит выпущенный сертификат, и цепочка проверяется.
	if issuer := whoIssued(t, addr, ca.Roots()); issuer != "masquevpn test CA" {
		t.Fatalf("сервер предъявил сертификат от %q", issuer)
	}
	// Второй заход берёт из кэша, а не заказывает заново: у настоящего
	// удостоверяющего центра на заказы есть лимиты.
	if err := m.Obtain(ctx); err != nil {
		t.Fatal(err)
	}
	if n := ca.Issued(); n != 1 {
		t.Fatalf("повторный заказ при живом сертификате: выпущено %d", n)
	}
	// Тот же сертификат отдаётся и для HTTP/3 (та же функция выдачи).
	if m.QUICConfig().GetCertificate == nil {
		t.Fatal("для QUIC не задана выдача сертификата")
	}
}

// TestSurvivesACMEOutage — отказ удостоверяющего центра не должен ронять
// сервер. Пока своего сертификата нет — отвечаем запасным из файлов; как
// только он получен — им; если ACME снова отвалился, продолжаем на прежнем.
func TestSurvivesACMEOutage(t *testing.T) {
	ca := newTestCA(t)
	fallback, fallbackRoots := selfSigned(t)
	m := newManager(t, ca, &fallback)
	addr := startTLS(t, m.TCPConfig())
	ca.SetTarget(addr)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 1. ACME недоступен с самого начала — работаем на запасном.
	ca.SetFail(true)
	octx, ocancel := context.WithTimeout(ctx, 10*time.Second)
	err := m.Obtain(octx)
	ocancel()
	if err == nil {
		t.Fatal("отказ удостоверяющего центра не замечен")
	}
	if issuer := whoIssued(t, addr, fallbackRoots); issuer != testDomain {
		t.Fatalf("при отказе ACME предъявлен сертификат от %q, а не запасной", issuer)
	}

	// 2. ACME ожил — переходим на выпущенный сертификат. Зависшая попытка
	// не должна мешать: у неё свой срок, после которого начинается новая.
	ca.SetFail(false)
	deadline := time.Now().Add(20 * time.Second)
	for {
		octx, ocancel := context.WithTimeout(ctx, 5*time.Second)
		err := m.Obtain(octx)
		ocancel()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("после восстановления ACME: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if issuer := whoIssued(t, addr, ca.Roots()); issuer != "masquevpn test CA" {
		t.Fatalf("после восстановления предъявлен сертификат от %q", issuer)
	}

	// 3. ACME снова отвалился — остаёмся на полученном, а не падаем.
	ca.SetFail(true)
	if issuer := whoIssued(t, addr, ca.Roots()); issuer != "masquevpn test CA" {
		t.Fatalf("после нового отказа предъявлен сертификат от %q", issuer)
	}
}

// TestNoCertificateAtAll — если ACME недоступен и запасного нет, сервер
// обязан сказать об этом прямо, а не отдавать пустоту.
func TestNoCertificateAtAll(t *testing.T) {
	ca := newTestCA(t)
	ca.SetFail(true)
	m := newManager(t, ca, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := m.Obtain(ctx); err == nil {
		t.Fatal("ошибки нет, хотя сертификата взять негде")
	}
}

// TestRenewsBeforeExpiry — продление без перезапуска. Удостоверяющий центр
// выдаёт короткий сертификат, и менеджер сам заказывает новый, не дожидаясь
// истечения и не требуя вмешательства.
func TestRenewsBeforeExpiry(t *testing.T) {
	ca := newTestCA(t)
	ca.Lifetime = 20 * 24 * time.Hour // меньше порога обновления autocert (30 дней)
	m := newManager(t, ca, nil)
	addr := startTLS(t, m.TCPConfig())
	ca.SetTarget(addr)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := m.Obtain(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for ca.Issued() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("сертификат не продлён: выпущено всего %d", ca.Issued())
		}
		_ = whoIssued(t, addr, ca.Roots()) // рукопожатия, как у живого сервера
		time.Sleep(200 * time.Millisecond)
	}
	// Сертификат продлён без перезапуска и без вмешательства. Счётчик тут
	// растёт дальше: срок 20 дней короче порога обновления (30), поэтому
	// autocert считает сертификат вечно устаревающим. В бою Let's Encrypt
	// выдаёт 90 дней, и обновление случается раз в 60; на короткие
	// сертификаты менеджер ругается в журнал.
	t.Logf("продление произошло, выпущено сертификатов: %d", ca.Issued())
}
