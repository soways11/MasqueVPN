//go:build utls

package utlsquic

import (
	"bytes"
	"context"
	"slices"
	"testing"
	"time"

	"github.com/soways11/masquevpn/internal/masque"
)

// Firefox 146 — второй член пула отпечатков и единственный не-Chromium: стек
// Gecko/NSS даёт ClientHello, реально отличный от Chrome на проводе (Chrome,
// Yandex, Edge между собой неразличимы — все BoringSSL). Профиль встроен в
// бинарник; ECH и домен съёма из SNI вычищены при встраивании.

func loadFirefox146(t *testing.T) *Fingerprint {
	t.Helper()
	fp, ok := embeddedFingerprint(ParrotFirefox146)
	if !ok {
		t.Fatal("встроенный профиль firefox-146 не читается")
	}
	return fp
}

// TestFirefox146Handshake — встроенный Firefox-профиль поднимает сессию, и
// поднимает каждый раз (ротация и переподключение дозваниваются заново).
func TestFirefox146Handshake(t *testing.T) {
	fp := loadFirefox146(t)
	e := startServer(t, masque.ServerConfig{})

	for i := 1; i <= 5; i++ {
		c, err := dial(t, e, func(cfg *Config) { cfg.CustomSpec = fp })
		if err != nil {
			t.Fatalf("дозвон %d: %v", i, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		pfx, err := c.WaitForAddress(ctx)
		cancel()
		if err != nil {
			t.Fatalf("дозвон %d: сессия не установилась: %v", i, err)
		}
		t.Logf("дозвон %d: адрес %s", i, pfx)
		c.Close()
	}
}

// TestFirefox146ByParrot — профиль выбирается по имени (как член пула
// fingerprint_pool), а не только через CustomSpec.
func TestFirefox146ByParrot(t *testing.T) {
	if err := ValidateParrot(ParrotFirefox146); err != nil {
		t.Fatalf("firefox-146 не проходит валидацию: %v", err)
	}
	e := startServer(t, masque.ServerConfig{})
	for i := 1; i <= 3; i++ {
		if _, err := dial(t, e, func(cfg *Config) { cfg.Parrot = ParrotFirefox146 }); err != nil {
			t.Fatalf("дозвон по имени %d: %v", i, err)
		}
	}
}

// TestFirefox146Replay — на провод уходит то же, что снято: тот же набор
// расширений, шифронаборы и транспортные параметры.
func TestFirefox146Replay(t *testing.T) {
	orig := loadFirefox146(t)

	pkts := captureFlight(t, 2, func(addr string) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, _ = Dial(ctx, Config{
			Addr: addr, ServerName: "localhost", InsecureSkipVerify: true,
			Authority: "localhost", CustomSpec: orig,
		})
	})
	got, err := CaptureFromPackets(pkts, "наш клиент")
	if err != nil {
		t.Fatalf("снятие с нашего клиента: %v", err)
	}

	a, b := sortedExtIDs(orig), sortedExtIDs(got)
	t.Logf("встроенный: %v", a)
	t.Logf("наш клиент: %v", b)
	if !slices.Equal(a, b) {
		t.Fatalf("набор расширений не совпал")
	}
	if !slices.Equal(orig.CipherSuites, got.CipherSuites) {
		t.Errorf("шифронаборы: %v против %v", got.CipherSuites, orig.CipherSuites)
	}
	if got.DestConnIDLen != orig.DestConnIDLen || got.SrcConnIDLen != orig.SrcConnIDLen {
		t.Errorf("длины Connection ID: %d/%d против %d/%d",
			got.DestConnIDLen, got.SrcConnIDLen, orig.DestConnIDLen, orig.SrcConnIDLen)
	}
	if got.DatagramSize != orig.DatagramSize {
		t.Errorf("размер датаграммы %d, в отпечатке %d", got.DatagramSize, orig.DatagramSize)
	}

	ta, tb := sortedTPIDs(orig), sortedTPIDs(got)
	t.Logf("транспортные параметры: встроенный %v, наш клиент %v", ta, tb)
	if !slices.Equal(ta, tb) {
		t.Fatalf("транспортные параметры не совпали")
	}
	origVals := map[uint64][]byte{}
	for _, p := range orig.TransportParams {
		origVals[p.ID] = p.Value
	}
	for _, p := range got.TransportParams {
		if p.ID == tpInitialSourceConnectionID {
			continue
		}
		if !slices.Equal(origVals[p.ID], p.Value) {
			t.Errorf("параметр %d: % x, в отпечатке % x", p.ID, p.Value, origVals[p.ID])
		}
	}
}

// TestFirefox146NoECH — во встроенном профиле ECH нет, и на провод он не
// уходит. У сырого Firefox-146 ECH был (ext 0xfe0d) — здесь он вычищен из
// файла и дополнительно выбрасывается при сборке.
func TestFirefox146NoECH(t *testing.T) {
	fp := loadFirefox146(t)
	if _, ok := extData(fp, extECH); ok {
		t.Fatal("во встроенном профиле firefox-146 остался ECH")
	}
	pkts := captureFlight(t, 2, func(addr string) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, _ = Dial(ctx, Config{
			Addr: addr, ServerName: "localhost", InsecureSkipVerify: true,
			Authority: "localhost", CustomSpec: fp,
		})
	})
	got, err := CaptureFromPackets(pkts, "наш клиент")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := extData(got, extECH); ok {
		t.Fatal("клиент отправил ECH — DPI отрежет такое соединение на рукопожатии")
	}
}

// TestFirefox146SNIFromConfig — домен съёма (fp.test) не зашит в профиль и не
// уходит на провод: SNI подставляется из конфигурации.
func TestFirefox146SNIFromConfig(t *testing.T) {
	fp := loadFirefox146(t)
	// В файле ext 0 (server_name) пуст — домена ловушки в нём нет.
	if data, ok := extData(fp, extSNI); ok && len(data) != 0 {
		t.Fatalf("в профиле остался SNI-данные: % x", data)
	}

	pkts := captureFlight(t, 2, func(addr string) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, _ = Dial(ctx, Config{
			Addr: addr, ServerName: "example.test", InsecureSkipVerify: true,
			Authority: "example.test", CustomSpec: fp,
		})
	})
	got, err := CaptureFromPackets(pkts, "наш клиент")
	if err != nil {
		t.Fatal(err)
	}
	data, ok := extData(got, extSNI)
	if !ok {
		t.Fatal("на проводе нет SNI")
	}
	if bytes.Contains(data, []byte("fp.test")) {
		t.Fatalf("на проводе утёк домен съёма fp.test: % x", data)
	}
	if !bytes.Contains(data, []byte("example.test")) {
		t.Fatalf("в SNI не подставилось имя из конфигурации: % x", data)
	}
}
