package certfile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writePair кладёт самоподписанный сертификат на имя cn в пару файлов.
func writePair(t *testing.T, dir, cn string) (certPath, keyPath string) {
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

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func commonName(t *testing.T, r *Reloader) string {
	t.Helper()
	c := r.Certificate()
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf.Subject.CommonName
}

// Главное свойство: сертификат, обновлённый на диске кем-то другим
// (certbot, acme.sh, соседний nginx), подхватывается без перезапуска.
// Иначе через три месяца сервер отдаёт просроченный сертификат, и снаружи
// это выглядит как внезапно сломавшийся домен.
func TestPicksUpRenewedCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writePair(t, dir, "old.example")

	r, err := New(certPath, keyPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.every = 0 // в тесте проверяем файлы на каждом обращении
	if got := commonName(t, r); got != "old.example" {
		t.Fatalf("сначала отдан %q", got)
	}

	writePair(t, dir, "new.example") // «обновление» поверх тех же путей

	if got := commonName(t, r); got != "new.example" {
		t.Fatalf("после обновления отдан %q — сертификат не перечитан", got)
	}
	if r.Reloads() != 1 {
		t.Fatalf("перечитываний %d, ожидалось 1", r.Reloads())
	}
}

// Файлы не менялись — значит и перечитывать нечего: лишнее чтение с диска на
// каждое рукопожатие не нужно никому.
func TestDoesNotReloadUnchanged(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writePair(t, dir, "same.example")
	r, err := New(certPath, keyPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.every = 0
	for i := 0; i < 5; i++ {
		commonName(t, r)
	}
	if r.Reloads() != 0 {
		t.Fatalf("перечитываний %d при неизменных файлах", r.Reloads())
	}
}

// Обновление не атомарно: сертификат уже новый, ключ ещё старый. Такое
// чтение обязано оставить сервер на прежней паре, а не уронить его и не
// отдать несогласованную.
func TestKeepsOldCertificateWhenFilesAreInconsistent(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writePair(t, dir, "good.example")
	r, err := New(certPath, keyPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.every = 0

	// Подкладываем сертификат от другой пары ключей — ровно то, что видно
	// в середине обновления.
	other := t.TempDir()
	otherCert, _ := writePair(t, other, "half.example")
	raw, err := os.ReadFile(otherCert)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	if got := commonName(t, r); got != "good.example" {
		t.Fatalf("при рассогласованных файлах отдан %q, ожидался прежний", got)
	}

	// Когда обновление дописало ключ, новая пара подхватывается.
	otherKey := filepath.Join(other, "key.pem")
	raw, err = os.ReadFile(otherKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := commonName(t, r); got != "half.example" {
		t.Fatalf("после дописанного ключа отдан %q", got)
	}
}

// Исчезнувший файл — не повод падать: он мог пропасть на миг во время
// переименования.
func TestSurvivesMissingFile(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writePair(t, dir, "there.example")
	r, err := New(certPath, keyPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.every = 0
	if err := os.Remove(certPath); err != nil {
		t.Fatal(err)
	}
	if got := commonName(t, r); got != "there.example" {
		t.Fatalf("после пропажи файла отдан %q", got)
	}
}

func TestMissingAtStartIsAnError(t *testing.T) {
	if _, err := New("/нет/такого", "/и/такого", nil); err == nil {
		t.Fatal("отсутствующие файлы приняты при запуске")
	}
}

// Проверка файлов не должна происходить на каждом рукопожатии: интервал
// существует именно для этого.
func TestRespectsCheckInterval(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writePair(t, dir, "first.example")
	r, err := New(certPath, keyPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	r.now = func() time.Time { return now }
	r.every = time.Minute

	writePair(t, dir, "second.example")
	if got := commonName(t, r); got != "first.example" {
		t.Fatalf("перечитал раньше интервала: %q", got)
	}
	now = now.Add(2 * time.Minute)
	if got := commonName(t, r); got != "second.example" {
		t.Fatalf("после интервала отдан %q", got)
	}
}
