//go:build utls

package utlsquic

import (
	"context"
	"slices"
	"sort"
	"testing"
	"time"

	uquic "github.com/refraction-networking/uquic"
	"github.com/soways11/masquevpn/internal/masque"
)

// Отпечаток настоящего браузера, снятый fpcapture на боевом сервере.
// Ценен тем, что ClientHello у него НЕ ПОМЕЩАЕТСЯ в одну датаграмму:
// постквантовый key_share (1258 байт), ECH (218) и trust_anchors (186) дают
// около 1916 байт при датаграмме 1250. Браузер шлёт его двумя
// Initial-пакетами, и это ровно тот случай, на котором конвейер отпечатка
// разваливался.
const chrome153 = "testdata/chrome153.json"

func loadChrome153(t *testing.T) *Fingerprint {
	t.Helper()
	fp, err := LoadFingerprint(chrome153)
	if err != nil {
		t.Fatal(err)
	}
	return fp
}

// TestChrome153Handshake — снятый с браузера отпечаток работает: сессия
// поднимается, и поднимается КАЖДЫЙ раз, а не только первый.
//
// Повтор здесь не для красоты. Клиент дозванивается заново при каждой ротации
// соединения и при каждом обрыве; профиль, годный на один раз, означал бы
// «первая сессия есть, после ротации клиент мёртв», причём проявилось бы это
// не сразу, а через десятки минут работы.
func TestChrome153Handshake(t *testing.T) {
	fp := loadChrome153(t)
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

// TestChrome153InitialFlight — форма первого вылета: столько же датаграмм и
// такого же размера, как у браузера.
//
// Размер первой датаграммы наблюдатель читает без всякой расшифровки, и он
// постоянный у любого браузера. Пока криптоданные набирались «под завязку»,
// перекладывание их в свои CRYPTO/PING/PADDING-кадры раздувало пакет, добивать
// его было уже нечем, и размер плавал: замерено 1252–1295 вместо 1250.
func TestChrome153InitialFlight(t *testing.T) {
	fp := loadChrome153(t)

	for run := 1; run <= 5; run++ {
		pkts := captureFlight(t, 2, func(addr string) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, _ = Dial(ctx, Config{
				Addr: addr, ServerName: "localhost", InsecureSkipVerify: true,
				Authority: "localhost", CustomSpec: fp,
			})
		})
		if len(pkts) < 2 {
			t.Fatalf("прогон %d: ClientHello уехал в %d датаграмме — он не помещается в одну", run, len(pkts))
		}
		for i, p := range pkts[:2] {
			if len(p) != fp.DatagramSize {
				t.Errorf("прогон %d: датаграмма %d — %d байт, в отпечатке %d",
					run, i, len(p), fp.DatagramSize)
			}
			h := parseInitial(t, p)
			if h.DCIDLen != fp.DestConnIDLen || h.SCIDLen != fp.SrcConnIDLen {
				t.Errorf("прогон %d: датаграмма %d — DCID=%d SCID=%d, в отпечатке %d/%d",
					run, i, h.DCIDLen, h.SCIDLen, fp.DestConnIDLen, fp.SrcConnIDLen)
			}
		}
	}
}

// TestChrome153Replay — то, что уходит на провод, совпадает со снятым с
// браузера: тот же ClientHello и те же транспортные параметры.
//
// Снимаем отпечаток со своего же клиента тем же кодом, каким снимали с
// браузера, и сверяем с исходной записью.
func TestChrome153Replay(t *testing.T) {
	orig := loadChrome153(t)

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

	// Набор расширений. Порядок не сверяем: uTLS перемешивает его на каждое
	// соединение — и настоящий Chrome тоже. ECH из сверки исключён: он
	// сознательно не отправляется (см. TestChrome153NoECH).
	a, b := withoutECH(sortedExtIDs(orig)), sortedExtIDs(got)
	t.Logf("браузер:    %v", a)
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
	if got.InitPacketNumber != orig.InitPacketNumber {
		t.Errorf("номер первого пакета %d, в отпечатке %d", got.InitPacketNumber, orig.InitPacketNumber)
	}
	if got.DatagramSize != orig.DatagramSize {
		t.Errorf("размер датаграммы %d, в отпечатке %d", got.DatagramSize, orig.DatagramSize)
	}

	// Транспортные параметры — вторая ось отпечатка, видимая тому, кто
	// доведёт рукопожатие до конца.
	ta, tb := sortedTPIDs(orig), sortedTPIDs(got)
	t.Logf("транспортные параметры: браузер %v, наш клиент %v", ta, tb)
	if !slices.Equal(ta, tb) {
		t.Fatalf("транспортные параметры не совпали")
	}

	// Значения переносятся байт в байт — кроме initial_source_connection_id,
	// который у каждого соединения свой.
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

// TestChrome153NoECH — ECH не уходит на провод, хотя в записи он есть.
//
// Российский DPI режет соединения с encrypted_client_hello по самому факту
// наличия расширения, поэтому точное повторение браузера здесь означало бы не
// пройти вовсе. Проекту ECH и не нужен: SNI открыт по решению от 2026-09-17.
//
// Тест берёт запись с настоящим ECH от Chrome 153 — то есть проверяет именно
// выбрасывание, а не отсутствие расширения в исходных данных.
func TestChrome153NoECH(t *testing.T) {
	orig := loadChrome153(t)
	if _, ok := extData(orig, extECH); !ok {
		t.Fatal("в записи нет ECH — тест перестал проверять выбрасывание")
	}

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
		t.Fatal(err)
	}
	if _, ok := extData(got, extECH); ok {
		t.Fatal("клиент отправил ECH — DPI отрежет такое соединение на рукопожатии")
	}

	// И встроенного профиля это касается тоже.
	fp, ok := embeddedFingerprint(ParrotChrome153)
	if !ok {
		t.Fatal("встроенный профиль не читается")
	}
	if _, ok := extData(fp, extECH); ok {
		t.Fatal("во встроенном профиле остался ECH")
	}
	t.Logf("в записи ECH есть, на проводе его нет; расширений у нас %d", len(got.Extensions))
}

func extData(fp *Fingerprint, id uint16) ([]byte, bool) {
	for _, e := range fp.Extensions {
		if e.ID == id {
			return e.Data, true
		}
	}
	return nil, false
}

func withoutECH(ids []uint16) []uint16 {
	out := make([]uint16, 0, len(ids))
	for _, id := range ids {
		if id != extECH {
			out = append(out, id)
		}
	}
	return out
}

// TestChrome153SpecIsSingleUse закрепляет причину, по которой профиль
// собирается заново на каждый дозвон: объекты расширений uTLS одноразовые.
// Если это когда-нибудь перестанет быть так, тест об этом скажет.
func TestChrome153SpecIsSingleUse(t *testing.T) {
	fp := loadChrome153(t)
	e := startServer(t, masque.ServerConfig{})

	spec, err := fp.Spec()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dial(t, e, func(cfg *Config) { cfg.CustomSpec = spec }); err != nil {
		t.Fatalf("первый дозвон готовым профилем: %v", err)
	}
	if _, err := dial(t, e, func(cfg *Config) { cfg.CustomSpec = spec }); err == nil {
		t.Log("готовый профиль пережил второй дозвон — uTLS перестал дописывать в него состояние")
	} else {
		t.Logf("второй дозвон тем же объектом: %v (поэтому CustomSpec принимает *Fingerprint)", err)
	}

	// А запись переживает сколько угодно.
	for i := 1; i <= 3; i++ {
		if _, err := dial(t, e, func(cfg *Config) { cfg.CustomSpec = fp }); err != nil {
			t.Fatalf("дозвон записью %d: %v", i, err)
		}
	}
}

// TestChrome153LoadSpec — путь из конфигурации клиента (fingerprint_file).
func TestChrome153LoadSpec(t *testing.T) {
	v, err := LoadSpec(chrome153)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := v.(*Fingerprint); !ok {
		t.Fatalf("LoadSpec вернул %T — профиль должен пересобираться на каждый дозвон", v)
	}
	e := startServer(t, masque.ServerConfig{})
	for i := 1; i <= 3; i++ {
		if _, err := dial(t, e, func(cfg *Config) { cfg.CustomSpec = v }); err != nil {
			t.Fatalf("дозвон %d: %v", i, err)
		}
	}
}

// TestChrome153Reserve — запас под заголовки кадров доходит до профиля.
func TestChrome153Reserve(t *testing.T) {
	spec, err := loadChrome153(t).Spec()
	if err != nil {
		t.Fatal(err)
	}
	s, ok := any(spec).(*uquic.QUICSpec)
	if !ok {
		t.Fatalf("Spec вернул %T", spec)
	}
	if s.InitialPacketSpec.FrameOverheadReserve <= 0 {
		t.Fatal("запас под заголовки кадров не задан — размер первого пакета поплывёт")
	}
	t.Logf("запас под заголовки кадров: %d байт", s.InitialPacketSpec.FrameOverheadReserve)
}

func sortedExtIDs(fp *Fingerprint) []uint16 {
	out := extIDs(fp.Extensions)
	out = normalizeGREASE(out)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedTPIDs(fp *Fingerprint) []uint64 {
	out := tpIDs(fp.TransportParams)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
