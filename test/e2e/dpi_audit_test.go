//go:build e2e && linux

package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestDPIObservation — взгляд на собственный трафик глазами наблюдателя на
// канале: размеры, ритм, объёмы и открытая часть заголовков QUIC. Ничего не
// утверждает, а печатает отчёт — им и ведётся разбор признаков.
//
//	go test -tags e2e ./test/e2e/ -run TestDPIObservation -v
func TestDPIObservation(t *testing.T) {
	o := opts{transport: "utls"}
	s := newStand(t, o)
	// Слушать начинаем ДО подключения: рукопожатие — единственная часть
	// потока, которую наблюдатель видит незашифрованной.
	s.client.stop(t)
	tap := start(t, nsSrv, "dpitap", filepath.Join(s.bin, "dpitap"),
		"-iface", "srv0", "-port", "443", "-duration", "26s",
		"-json", filepath.Join(s.dir, "tap.json"))
	time.Sleep(500 * time.Millisecond)
	s.startClient(t, o)

	// Простой: туннель поднят, пользователь ничего не делает.
	time.Sleep(6 * time.Second)
	// Просмотр: 3 МБ на скорости 1 МБ/с — как поток видео.
	checkDownload(t, 3<<20, "--limit-rate", "1M")
	// Снова простой.
	time.Sleep(6 * time.Second)
	// Немного интерактивного трафика.
	for i := 0; i < 5; i++ {
		ping(nsCli, "-c", "1", "-W", "1", internet)
		time.Sleep(300 * time.Millisecond)
	}

	<-tap.done
	t.Logf("\n%s", tap.Log())

	// Открытая часть рукопожатия — единственное, что наблюдатель читает
	// как есть. Проверяем её числами.
	var pkts []tapPacket
	raw, err := os.ReadFile(filepath.Join(s.dir, "tap.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &pkts); err != nil {
		t.Fatal(err)
	}
	var cliInitial, srvInitial *tapPacket
	for i := range pkts {
		p := &pkts[i]
		if p.Form != "Initial" {
			continue
		}
		if p.Out && cliInitial == nil {
			cliInitial = p
		}
		if !p.Out && srvInitial == nil {
			srvInitial = p
		}
	}
	if cliInitial == nil || srvInitial == nil {
		t.Fatalf("рукопожатие не поймано: %d записей", len(pkts))
	}
	// Клиент — как Chrome: первый пакет 1250 байт, DCID 8 байт.
	if cliInitial.Len != 1250 || cliInitial.DCID != 8 {
		t.Errorf("первый пакет клиента: %d байт, DCID %d — у Chrome 1250 и 8",
			cliInitial.Len, cliInitial.DCID)
	}
	// Сервер: Connection ID не короче восьми байт. Умолчание quic-go — 4, и
	// эта длина видна в каждом пакете клиента (поле DCID), то есть узнаётся
	// одним рукопожатием.
	if srvInitial.SCID < 8 {
		t.Errorf("сервер выдал Connection ID длиной %d байт — так делает quic-go по умолчанию, живые HTTP/3-серверы берут 8 и больше",
			srvInitial.SCID)
	}
	if cliInitial.Ver != 1 || srvInitial.Ver != 1 {
		t.Errorf("версии QUIC: клиент 0x%08x, сервер 0x%08x", cliInitial.Ver, srvInitial.Ver)
	}
	t.Logf("рукопожатие: клиент %d байт DCID=%d, сервер %d байт SCID=%d",
		cliInitial.Len, cliInitial.DCID, srvInitial.Len, srvInitial.SCID)
}

// tapPacket — запись наблюдателя (см. test/e2e/dpitap).
type tapPacket struct {
	At   int64  `json:"t"`
	Len  int    `json:"len"`
	Out  bool   `json:"out"`
	Form string `json:"form"`
	DCID int    `json:"dcid"`
	SCID int    `json:"scid"`
	Ver  uint32 `json:"ver"`
}
