//go:build linux

// Проверка не загрузчика сертификатов, а того, что сервер им пользуется.
//
// Загрузчик протестирован отдельно (internal/certfile), но между ним и
// клиентом стоит certificates(): она решает, какие настройки TLS отдать
// слушателям. Ошибка здесь — вроде прочитанного один раз сертификата или
// копии настроек, застывшей на старой паре, — в юнит-тестах пакета не видна,
// а снаружи выглядит как домен, сломавшийся через три месяца.
//
// Поэтому тест идёт до конца: поднимает настоящий TLS-слушатель на тех
// настройках, которые вернула certificates(), и смотрит глазами клиента.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/soways11/masquevpn/internal/certfile"
	"github.com/soways11/masquevpn/internal/config"
)

func writeCertPair(t *testing.T, dir, cn string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath,
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// servedName поднимает TLS-слушатель на conf, подключается к нему обычным
// клиентом и возвращает имя из предъявленного сертификата — то самое, что
// увидел бы браузер.
func servedName(t *testing.T, conf *tls.Config) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", conf)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		io.Copy(io.Discard, c)
		c.Close()
	}()

	c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	certs := c.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		t.Fatal("сервер не предъявил сертификат")
	}
	return certs[0].Subject.CommonName
}

func fileCertConfig(t *testing.T) (*config.Server, string, string) {
	t.Helper()
	dir := t.TempDir()
	certPath, keyPath := writeCertPair(t, dir, "before.example")
	return &config.Server{
		Listen:   ":443",
		CertFile: certPath,
		KeyFile:  keyPath,
		Pool4:    "10.66.0.0/24",
	}, certPath, keyPath
}

// Главное: сертификат, переписанный certbot'ом на диске, доходит до клиента
// без перезапуска — и по QUIC, и по TCP. Раздельная проверка не случайна:
// настройки для двух слушателей создаются по отдельности, и застывшей может
// оказаться одна из них.
func TestServerPicksUpRenewedCertificate(t *testing.T) {
	saved := certfile.DefaultCheckInterval
	certfile.DefaultCheckInterval = 0
	defer func() { certfile.DefaultCheckInterval = saved }()

	cfg, _, _ := fileCertConfig(t)
	quicConf, tcpConf, mgr, host, err := certificates(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if mgr != nil {
		t.Fatal("без acme.domains создан менеджер ACME")
	}
	if host != "before.example" {
		t.Fatalf("домен из сертификата определён как %q", host)
	}
	if got := servedName(t, tcpConf); got != "before.example" {
		t.Fatalf("TCP предъявил %q", got)
	}

	writeCertPair(t, filepath.Dir(cfg.CertFile), "after.example")

	if got := servedName(t, tcpConf); got != "after.example" {
		t.Fatalf("после обновления TCP предъявил %q — сертификат не перечитан", got)
	}
	if got := servedName(t, quicConf); got != "after.example" {
		t.Fatalf("после обновления QUIC предъявил %q — сертификат не перечитан", got)
	}
}

// Слушатель TCP должен договариваться об h2: на этом домене снаружи виден
// обычный HTTPS-сайт, а сайт без h2 в 2026 году — сам по себе примета.
func TestFileCertificateNegotiatesHTTP2(t *testing.T) {
	cfg, _, _ := fileCertConfig(t)
	_, tcpConf, _, _, err := certificates(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tcpConf)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			io.Copy(io.Discard, c)
			c.Close()
		}
	}()

	c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := c.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("согласован протокол %q, ожидался h2", got)
	}
}

// Слушатель QUIC обязан требовать TLS 1.3: QUIC с более старой версией не
// работает вовсе, и лучше это знать здесь, чем по молчащим клиентам.
func TestFileCertificateRequiresTLS13ForQUIC(t *testing.T) {
	cfg, _, _ := fileCertConfig(t)
	quicConf, _, _, _, err := certificates(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if quicConf.MinVersion != tls.VersionTLS13 {
		t.Fatalf("минимальная версия TLS для QUIC: %#x", quicConf.MinVersion)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", quicConf)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			io.Copy(io.Discard, c)
			c.Close()
		}
	}()
	c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		MaxVersion:         tls.VersionTLS12,
	})
	if err == nil {
		c.Close()
		t.Fatal("клиент с TLS 1.2 принят")
	}
}

// Без сертификата и без ACME сервер бесполезен, и узнать об этом надо при
// запуске, а не от первого клиента.
func TestNoCertificateIsAStartupError(t *testing.T) {
	cfg := &config.Server{Listen: ":443", Pool4: "10.66.0.0/24"}
	if _, _, _, _, err := certificates(cfg, slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("сервер без сертификата и без ACME запустился бы")
	}
}
