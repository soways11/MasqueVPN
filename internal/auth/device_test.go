package auth

import (
	"encoding/base64"
	"net/http"
	"testing"
)

// Устройство в токене: один ключ на несколько устройств.
//
// Сервер закрепляет туннельный адрес за парой клиент+устройство. Клиент —
// это запись в реестре ключей, и у ноутбука с телефоном она одна; отличить
// устройства можно только по полю device. Если оно потеряется (не поедет в
// токене, не попадёт под подпись, окажется одинаковым у разных установок),
// сервер снова выдаст обоим один адрес — и работать будет только то
// устройство, что подключилось последним.

// TestDeviceIDTravelsAndIsSigned — псевдоним устройства доезжает до сервера и
// защищён подписью: подменить его в пути нельзя.
func TestDeviceIDTravelsAndIsSigned(t *testing.T) {
	cli, _ := newTestAuth(t, Options{ClientID: []byte("узел"), DeviceID: []byte("ноутбук")})
	srv, clk := newTestAuth(t, Options{})
	cli.now = clk.now

	tok, err := cli.Token()
	if err != nil {
		t.Fatal(err)
	}
	client, device, ok := srv.verify(tok)
	if !ok {
		t.Fatal("свой токен не принят")
	}
	if client != cli.ClientID() {
		t.Fatalf("клиент опознан как %q, а он %q", client, cli.ClientID())
	}
	if device != cli.DeviceID() {
		t.Fatalf("устройство опознано как %q, а оно %q", device, cli.DeviceID())
	}

	// Подмена байта устройства ломает подпись. Иначе поле было бы
	// украшением: сосед по ключу мог бы назваться чужим устройством и
	// отобрать у него адрес.
	//
	// Портим СВЕЖИЙ токен, а не проверенный выше: у того nonce уже в кэше
	// повторов, и отказ пришёл бы оттуда — проверка подписи осталась бы
	// непроверенной.
	fresh, err := cli.Token()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(fresh)
	if err != nil {
		t.Fatal(err)
	}
	raw[9+clientIDLen] ^= 0x01
	if _, _, ok := srv.verify(base64.RawURLEncoding.EncodeToString(raw)); ok {
		t.Fatal("токен с подменённым устройством принят")
	}
	// И убеждаемся, что отказ был именно из-за подписи: тот же токен без
	// правки проходит.
	again, err := cli.Token()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := srv.verify(again); !ok {
		t.Fatal("целый токен не принят — предыдущий отказ был не из-за подписи")
	}
}

// TestSameClientDifferentDevices — две установки одного доступа (ссылка одна,
// значит client_id один) различаются по устройству.
func TestSameClientDifferentDevices(t *testing.T) {
	id := make([]byte, ClientIDLen)
	for i := range id {
		id[i] = byte(i + 1)
	}
	laptop, clk := newTestAuth(t, Options{ClientIDExact: id, DeviceID: []byte("ноутбук")})
	phone, _ := newTestAuth(t, Options{ClientIDExact: id, DeviceID: []byte("телефон")})
	srv, _ := newTestAuth(t, Options{})
	phone.now, srv.now = clk.now, clk.now

	hl, _ := laptop.Header()
	hp, _ := phone.Header()
	cl, dl, ok := srv.Identify(&http.Request{Header: hl})
	if !ok {
		t.Fatal("токен ноутбука не принят")
	}
	cp, dp, ok := srv.Identify(&http.Request{Header: hp})
	if !ok {
		t.Fatal("токен телефона не принят")
	}
	if cl != cp {
		t.Fatalf("один доступ опознан как два клиента: %q и %q", cl, cp)
	}
	if dl == dp {
		t.Fatalf("у обоих устройств один псевдоним %q — сервер выдаст им один адрес", dl)
	}
}

// TestDeviceIDStableAndRandomWhenAbsent — постоянное значение даёт постоянный
// псевдоним (адрес сохраняется через перезапуск), а его отсутствие — случайный
// у каждой установки (одновременная работа не ломается и без файла).
func TestDeviceIDStableAndRandomWhenAbsent(t *testing.T) {
	a, _ := newTestAuth(t, Options{DeviceID: []byte("одно и то же")})
	b, _ := newTestAuth(t, Options{DeviceID: []byte("одно и то же")})
	if a.DeviceID() != b.DeviceID() {
		t.Fatalf("псевдоним не постоянен: %q и %q — после перезапуска адрес сменится", a.DeviceID(), b.DeviceID())
	}

	c, _ := newTestAuth(t, Options{})
	d, _ := newTestAuth(t, Options{})
	if c.DeviceID() == d.DeviceID() {
		t.Fatal("без значения псевдоним не случаен — два устройства поделят адрес")
	}
	if c.DeviceID() == "" {
		t.Fatal("псевдоним устройства пуст")
	}
}

// TestLegacyTokenAcceptedWithoutDevice — сервер принимает токен версии 2 (без
// устройства), а клиент умеет его выпустить. На этом держится обновление
// вразнобой: клиент новой сборки, встретив сервер старой, повторяет попытку
// таким токеном вместо того, чтобы молча не подключаться.
func TestLegacyTokenAcceptedWithoutDevice(t *testing.T) {
	cli, clk := newTestAuth(t, Options{ClientID: []byte("узел"), DeviceID: []byte("ноутбук")})
	srv, _ := newTestAuth(t, Options{})
	srv.now = clk.now

	h, err := cli.HeaderLegacy()
	if err != nil {
		t.Fatal(err)
	}
	client, device, ok := srv.Identify(&http.Request{Header: h})
	if !ok {
		t.Fatal("токен версии 2 не принят — клиент не сможет подключиться к серверу прошлой сборки")
	}
	if client != cli.ClientID() {
		t.Fatalf("клиент опознан как %q, а он %q", client, cli.ClientID())
	}
	if device != "" {
		t.Fatalf("в токене версии 2 нашлось устройство %q", device)
	}
}
