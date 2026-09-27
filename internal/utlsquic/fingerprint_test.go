//go:build utls

package utlsquic

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net"
	"path/filepath"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/gaukas/clienthellod"
	"github.com/soways11/masquevpn/internal/fingerprint"
	"github.com/soways11/masquevpn/internal/masque"
)

// initialHeader — поля первого Initial-пакета, которые DPI читает БЕЗ расшифровки:
// они лежат в открытом long header (RFC 9000, 17.2).
type initialHeader struct {
	DatagramSize int
	Version      uint32
	DCIDLen      int
	SCIDLen      int
}

func parseInitial(t *testing.T, p []byte) initialHeader {
	t.Helper()
	if len(p) < 7 || p[0]&0x80 == 0 {
		t.Fatalf("не long header: % x", p[:minInt(8, len(p))])
	}
	h := initialHeader{DatagramSize: len(p), Version: binary.BigEndian.Uint32(p[1:5])}
	h.DCIDLen = int(p[5])
	off := 6 + h.DCIDLen
	if off >= len(p) {
		t.Fatal("обрезанный заголовок")
	}
	h.SCIDLen = int(p[off])
	return h
}

// captureFlight ловит первые пакеты клиента на UDP-«воронку». Соединение
// не устанавливается — нужен только первый вылет (flight).
func captureFlight(t *testing.T, want int, dial func(addr string)) [][]byte {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	got := make(chan [][]byte, 1)
	go func() {
		var pkts [][]byte
		buf := make([]byte, 2048)
		for len(pkts) < want {
			_ = pc.SetReadDeadline(time.Now().Add(10 * time.Second))
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				break
			}
			cp := make([]byte, n)
			copy(cp, buf[:n])
			pkts = append(pkts, cp)
		}
		got <- pkts
	}()

	go dial(pc.LocalAddr().String())

	select {
	case pkts := <-got:
		if len(pkts) == 0 {
			t.Fatal("клиент не отправил ни одного пакета")
		}
		return pkts
	case <-time.After(40 * time.Second):
		t.Fatal("клиент не отправил первый вылет")
		return nil
	}
}

// clientHelloFrom расшифровывает Initial-пакеты и собирает из их CRYPTO-фреймов
// TLS ClientHello. Ключи Initial выводятся из открытого DCID, поэтому это
// доступно любому наблюдателю на пути — ровно то, что делает DPI.
func clientHelloFrom(pkts [][]byte) (*clienthellod.QUICClientHello, error) {
	var frames []clienthellod.Frame
	for _, p := range pkts {
		hdr, err := clienthellod.DecodeQUICHeaderAndFrames(p)
		if err != nil {
			continue // не Initial-пакет
		}
		frames = append(frames, hdr.Frames()...)
	}
	if len(frames) == 0 {
		return nil, fmt.Errorf("не найдено ни одного QUIC-фрейма")
	}
	crypto := reassembleCrypto(frames)
	if len(crypto) == 0 {
		return nil, fmt.Errorf("нет CRYPTO-фреймов")
	}
	return clienthellod.ParseQUICClientHello(crypto)
}

// reassembleCrypto склеивает CRYPTO-фреймы по смещению. Сервер в тесте не
// отвечает, поэтому клиент повторяет Initial-пакеты — дубли по одному смещению
// отбрасываем (штатный ReassembleCRYPTOFrames на них спотыкается).
func reassembleCrypto(frames []clienthellod.Frame) []byte {
	byOffset := make(map[uint64][]byte)
	for _, f := range frames {
		c, ok := f.(*clienthellod.CRYPTO)
		if !ok {
			continue
		}
		if _, seen := byOffset[c.Offset]; !seen {
			byOffset[c.Offset] = c.Data
		}
	}
	var out []byte
	for {
		chunk, ok := byOffset[uint64(len(out))]
		if !ok {
			return out
		}
		out = append(out, chunk...)
	}
}

func dialStock(addr string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prof := fingerprint.Chrome()
	_, _ = masque.Dial(ctx, masque.ClientConfig{
		Addr:       addr,
		TLSConfig:  prof.TLSConfig(&tls.Config{ServerName: "localhost", RootCAs: x509.NewCertPool()}),
		QUICConfig: prof.QUICConfig(),
		Authority:  "localhost",
	})
}

func dialUTLS(addr string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _ = Dial(ctx, Config{
		Addr: addr, ServerName: "localhost", RootCAs: x509.NewCertPool(),
		Authority: "localhost", Parrot: ParrotChrome115,
	})
}

// TestInitialPacketShape — что видно БЕЗ расшифровки: размер датаграммы и
// длины Connection ID в открытом заголовке.
func TestInitialPacketShape(t *testing.T) {
	a := parseInitial(t, captureFlight(t, 1, dialStock)[0])
	b := parseInitial(t, captureFlight(t, 1, dialUTLS)[0])
	t.Logf("quic-go : размер=%d version=%#x DCID=%d SCID=%d", a.DatagramSize, a.Version, a.DCIDLen, a.SCIDLen)
	t.Logf("uTLS    : размер=%d version=%#x DCID=%d SCID=%d", b.DatagramSize, b.Version, b.DCIDLen, b.SCIDLen)

	if a.Version != b.Version {
		t.Errorf("версии QUIC разошлись: %#x vs %#x — оба должны быть v1", a.Version, b.Version)
	}
	// Chrome использует 8-байтовый DCID в первом Initial.
	if b.DCIDLen != 8 {
		t.Errorf("попугай Chrome: DCID=%d, ожидалось 8", b.DCIDLen)
	}
	// RFC 9000, 14.1: первый пакет дополняется минимум до 1200 байт.
	if b.DatagramSize < 1200 {
		t.Errorf("первый пакет %d байт — меньше обязательных 1200", b.DatagramSize)
	}
}

// TestClientHelloFingerprint — главное доказательство: сравниваем НАСТОЯЩИЙ
// TLS ClientHello стокового quic-go и попугая Chrome, расшифровав Initial-пакеты
// ровно так, как это сделал бы DPI.
func TestClientHelloFingerprint(t *testing.T) {
	stockPkts := captureFlight(t, 3, dialStock)
	utlsPkts := captureFlight(t, 3, dialUTLS)
	t.Logf("первый вылет: quic-go=%d пакетов, uTLS=%d пакетов", len(stockPkts), len(utlsPkts))

	chStock, err := clientHelloFrom(stockPkts)
	if err != nil {
		t.Fatalf("ClientHello quic-go: %v", err)
	}
	chUTLS, err := clientHelloFrom(utlsPkts)
	if err != nil {
		t.Fatalf("ClientHello uTLS: %v", err)
	}

	t.Logf("quic-go: расширений=%d, порядок=%v", len(chStock.Extensions), chStock.Extensions)
	t.Logf("uTLS   : расширений=%d, порядок=%v", len(chUTLS.Extensions), chUTLS.Extensions)
	t.Logf("quic-go: cipher_suites=%v ALPN=%v", chStock.CipherSuites, chStock.ALPN)
	t.Logf("uTLS   : cipher_suites=%v ALPN=%v", chUTLS.CipherSuites, chUTLS.ALPN)
	t.Logf("отпечаток ClientHello: quic-go=%s  uTLS=%s",
		chStock.FingerprintID(false), chUTLS.FingerprintID(false))

	// 1. Отпечатки обязаны различаться — иначе мимикрия бессмысленна.
	if chStock.FingerprintID(false) == chUTLS.FingerprintID(false) {
		t.Fatal("отпечатки ClientHello совпали — uTLS ничего не изменил")
	}

	has := func(xs []uint16, v uint16) bool {
		for _, x := range xs {
			if x == v {
				return true
			}
		}
		return false
	}

	// 2. Характерные расширения Chrome, которых Go-клиент не отправляет никогда:
	//    application_settings (ALPS, 17513) и compress_certificate (27).
	for _, ext := range []struct {
		id   uint16
		name string
	}{{17513, "application_settings (ALPS)"}, {27, "compress_certificate"}} {
		if !has(chUTLS.Extensions, ext.id) {
			t.Errorf("у попугая Chrome нет расширения %s (%d)", ext.name, ext.id)
		}
		if has(chStock.Extensions, ext.id) {
			t.Logf("неожиданно: стоковый quic-go тоже прислал %s", ext.name)
		}
	}

	// 3. «Подпись Go»: расширения, которые шлёт crypto/tls и не шлёт Chrome.
	//    Их наличие — прямая улика, что клиент написан на Go.
	for _, ext := range []struct {
		id   uint16
		name string
	}{{65281, "renegotiation_info"}, {23, "extended_master_secret"}, {11, "ec_point_formats"}} {
		if has(chUTLS.Extensions, ext.id) {
			t.Errorf("попугай Chrome прислал %s (%d) — выдаёт Go-клиента", ext.name, ext.id)
		}
	}

	// 4. Маскировка не должна ломать протокол: ALPN остаётся h3.
	if len(chUTLS.ALPN) == 0 || chUTLS.ALPN[0] != "h3" {
		t.Errorf("ALPN попугая = %v, ожидался h3", chUTLS.ALPN)
	}

	// 5. Порядок расширений должен отличаться от стокового Go.
	if fmt.Sprint(chStock.Extensions) == fmt.Sprint(chUTLS.Extensions) {
		t.Error("порядок расширений не изменился")
	}
}

// TestClientHelloHasGREASE — GREASE на месте.
//
// Найдено аудитом: встроенный профиль Chrome 115 из uquic GREASE не содержал
// вовсе. «Клиент TLS 1.3 без GREASE» — признак, который виден одним взглядом
// на ClientHello и не зависит ни от порядка расширений, ни от версии
// браузера: так не выглядит НИ ОДИН браузер на BoringSSL, то есть ни Chrome,
// ни Edge, ни Opera, ни Яндекс.Браузер.
//
// Разборщик приводит GREASE-значения к 0x0a0a (так делает и любой сборщик
// отпечатков), поэтому сравниваем с ним.
func TestClientHelloHasGREASE(t *testing.T) {
	const greasePlaceholder = 0x0a0a

	withG, err := clientHelloFrom(captureFlight(t, 3, dialUTLS))
	if err != nil {
		t.Fatal(err)
	}
	without, err := clientHelloFrom(captureFlight(t, 3, func(addr string) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _ = Dial(ctx, Config{
			Addr: addr, ServerName: "localhost", RootCAs: x509.NewCertPool(),
			Authority: "localhost", Parrot: ParrotChrome115NoGREASE,
		})
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("с GREASE : расширения=%v cipher=%v", withG.Extensions, withG.CipherSuites)
	t.Logf("как в uquic: расширения=%v cipher=%v", without.Extensions, without.CipherSuites)

	count := func(xs []uint16, v uint16) int {
		n := 0
		for _, x := range xs {
			if x == v {
				n++
			}
		}
		return n
	}
	// Два GREASE-расширения, по краям списка, — так их ставит BoringSSL.
	if n := count(withG.Extensions, greasePlaceholder); n != 2 {
		t.Errorf("GREASE-расширений %d, у Chrome их два", n)
	}
	if len(withG.Extensions) > 0 &&
		(withG.Extensions[0] != greasePlaceholder || withG.Extensions[len(withG.Extensions)-1] != greasePlaceholder) {
		t.Errorf("GREASE не по краям списка: %v", withG.Extensions)
	}
	// GREASE-набор первым в списке шифронаборов.
	if len(withG.CipherSuites) == 0 || withG.CipherSuites[0] != greasePlaceholder {
		t.Errorf("шифронаборы без GREASE: %v", withG.CipherSuites)
	}
	// И контроль: профиль uquic как есть — без GREASE вообще.
	if count(without.Extensions, greasePlaceholder) != 0 || count(without.CipherSuites, greasePlaceholder) != 0 {
		t.Errorf("контрольный профиль внезапно с GREASE: %v / %v", without.Extensions, without.CipherSuites)
	}
	if withG.FingerprintID(false) == without.FingerprintID(false) {
		t.Error("отпечатки с GREASE и без совпали")
	}
}

// normalizeGREASE приводит GREASE-значения к 0x0a0a: они случайны на каждом
// соединении, и сравнивать их напрямую бессмысленно.
func normalizeGREASE(v []uint16) []uint16 {
	out := make([]uint16, len(v))
	for i, x := range v {
		if isGREASE(x) {
			x = 0x0a0a
		}
		out[i] = x
	}
	return out
}

func hasGREASEValue(v []uint16) bool {
	for _, x := range v {
		if isGREASE(x) {
			return true
		}
	}
	return false
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ---------- снятие отпечатка и его воспроизведение ----------

// TestFingerprintRoundTrip — доказательство работоспособности всего конвейера
// «перехват → разбор → JSON → восстановление профиля → подключение».
//
// Браузера в контейнере разработки нет, поэтому источником служит наш же
// клиент: снимаем отпечаток с его Initial-пакета, собираем из записи профиль,
// подключаемся с ним и сверяем, что отпечаток совпал. Если круг замкнулся, то
// подмена источника на настоящий Chrome — это смена входных данных, а не логики.
func TestFingerprintRoundTrip(t *testing.T) {
	// 1. Снимаем отпечаток со встроенного профиля.
	pkts := captureFlight(t, 3, dialUTLS)
	fp, err := CaptureFromPackets(pkts, "masquevpn utls-клиент (профиль chrome-115)")
	if err != nil {
		t.Fatalf("снятие отпечатка: %v", err)
	}
	t.Logf("снято: расширений=%d, транспортных параметров=%d, датаграмма=%d байт, DCID=%d SCID=%d",
		len(fp.Extensions), len(fp.TransportParams), fp.DatagramSize, fp.DestConnIDLen, fp.SrcConnIDLen)
	if len(fp.TransportParams) == 0 {
		t.Fatal("транспортные параметры не сняты — профиль будет нерабочим")
	}

	// 2. Через файл: отпечаток должен переживать сохранение и чтение.
	path := filepath.Join(t.TempDir(), "fp.json")
	if err := SaveFingerprint(path, fp); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadFingerprint(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Extensions) != len(fp.Extensions) || len(loaded.TransportParams) != len(fp.TransportParams) {
		t.Fatalf("после чтения из файла отпечаток изменился: %d/%d против %d/%d",
			len(loaded.Extensions), len(loaded.TransportParams), len(fp.Extensions), len(fp.TransportParams))
	}

	// 3. Восстанавливаем профиль и подключаемся им к настоящему серверу.
	spec, err := loaded.Spec()
	if err != nil {
		t.Fatalf("сборка профиля: %v", err)
	}
	e := startServer(t, masque.ServerConfig{})
	c, err := dial(t, e, func(cfg *Config) { cfg.CustomSpec = spec })
	if err != nil {
		t.Fatalf("подключение восстановленным профилем: %v", err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := c.WaitForAddress(ctx); err != nil {
		t.Fatalf("сессия не установилась: %v", err)
	}

	// 4. Сверяем отпечаток восстановленного профиля с исходным.
	replayed := captureFlight(t, 3, func(addr string) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _ = Dial(ctx, Config{
			Addr: addr, ServerName: "localhost", RootCAs: x509.NewCertPool(),
			Authority: "localhost", CustomSpec: spec,
		})
	})
	fp2, err := CaptureFromPackets(replayed, "восстановленный профиль")
	if err != nil {
		t.Fatalf("повторное снятие: %v", err)
	}

	// GREASE-значения браузер разыгрывает на КАЖДОЕ соединение (и uTLS тоже),
	// поэтому сравниваем их приведёнными к общему виду — ровно так поступает
	// любой сборщик отпечатков.
	origIDs := normalizeGREASE(extIDs(fp.Extensions))
	replIDs := normalizeGREASE(extIDs(fp2.Extensions))
	sort.Slice(origIDs, func(i, j int) bool { return origIDs[i] < origIDs[j] })
	sort.Slice(replIDs, func(i, j int) bool { return replIDs[i] < replIDs[j] })
	t.Logf("исходный набор расширений:      %v", origIDs)
	t.Logf("восстановленный набор:          %v", replIDs)
	if !slices.Equal(origIDs, replIDs) {
		t.Fatalf("набор расширений не воспроизвёлся: %v против %v", replIDs, origIDs)
	}
	if !slices.Equal(normalizeGREASE(fp.CipherSuites), normalizeGREASE(fp2.CipherSuites)) {
		t.Fatalf("шифронаборы не воспроизвелись: %v против %v", fp2.CipherSuites, fp.CipherSuites)
	}
	// И сам GREASE не потерялся при переносе.
	if !hasGREASEValue(fp2.CipherSuites) {
		t.Fatalf("в восстановленном профиле нет GREASE-набора: %v", fp2.CipherSuites)
	}

	tpOrig := tpIDs(fp.TransportParams)
	tpRepl := tpIDs(fp2.TransportParams)
	sort.Slice(tpOrig, func(i, j int) bool { return tpOrig[i] < tpOrig[j] })
	sort.Slice(tpRepl, func(i, j int) bool { return tpRepl[i] < tpRepl[j] })
	t.Logf("транспортные параметры: исходно %v, восстановлено %v", tpOrig, tpRepl)
	if !slices.Equal(tpOrig, tpRepl) {
		t.Fatalf("транспортные параметры не воспроизвелись")
	}
}

func extIDs(exts []Extension) []uint16 {
	out := make([]uint16, len(exts))
	for i, e := range exts {
		out[i] = e.ID
	}
	return out
}

func tpIDs(tps []TransportParam) []uint64 {
	out := make([]uint64, len(tps))
	for i, p := range tps {
		out[i] = p.ID
	}
	return out
}

func TestFingerprintRejectsIncomplete(t *testing.T) {
	// Без транспортных параметров профиль собирать нельзя: uquic его не примет.
	fp := &Fingerprint{Extensions: []Extension{{ID: 0}}}
	if _, err := fp.Spec(); err == nil {
		t.Fatal("профиль без quic_transport_parameters собран")
	}
	if _, err := CaptureFromPackets(nil, "пусто"); err == nil {
		t.Fatal("снятие из пустого списка пакетов прошло")
	}
	if _, err := CaptureFromPackets([][]byte{{0, 1, 2}}, "мусор"); err == nil {
		t.Fatal("снятие из мусора прошло")
	}
}
