package client

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/soways11/masquevpn/internal/masque"
)

// tokenVersionOf — номер версии выданного токена. Смотрим прямо в байты:
// версия — это то, что решает, поймёт ли нас сервер.
func tokenVersionOf(t *testing.T, h http.Header) byte {
	t.Helper()
	v := h.Get("Authorization")
	const bearer = "Bearer "
	if len(v) <= len(bearer) {
		t.Fatalf("в заголовке нет токена: %q", v)
	}
	raw, err := base64.RawURLEncoding.DecodeString(v[len(bearer):])
	if err != nil || len(raw) == 0 {
		t.Fatalf("токен не разбирается: %v", err)
	}
	return raw[0]
}

// TestTokenCarriesDeviceUntilServerRefuses — обычно клиент выпускает токен с
// устройством (без него два устройства одного ключа делят адрес и работает
// только последнее), а встретив сервер прошлой сборки, переходит на прежний
// формат и остаётся на нём.
func TestTokenCarriesDeviceUntilServerRefuses(t *testing.T) {
	d, err := NewDialer(testClientConfig(), Options{DeviceID: "устройство"})
	if err != nil {
		t.Fatal(err)
	}
	h, err := d.tokenHeader()
	if err != nil {
		t.Fatal(err)
	}
	if got := tokenVersionOf(t, h); got != 3 {
		t.Fatalf("выпущен токен версии %d — устройство в него не попало", got)
	}

	// Отказ сервера, который такого токена не знает, выглядит как ответ
	// постороннему: 404.
	hdr, ok := d.legacyRetry(&masque.ResponseError{StatusCode: http.StatusNotFound})
	if !ok {
		t.Fatal("после отказа сервера повторной попытки старым токеном не будет — " +
			"обновление клиента раньше сервера всё сломает")
	}
	if got := tokenVersionOf(t, hdr); got != 2 {
		t.Fatalf("повтор идёт токеном версии %d, а нужен прежний формат", got)
	}

	// Повтор удался — дальше сразу старым токеном, без лишнего дозвона.
	d.legacy.Store(true)
	h2, err := d.tokenHeader()
	if err != nil {
		t.Fatal(err)
	}
	if got := tokenVersionOf(t, h2); got != 2 {
		t.Fatalf("после отката выпущен токен версии %d", got)
	}
	if _, ok := d.legacyRetry(&masque.ResponseError{StatusCode: http.StatusNotFound}); ok {
		t.Fatal("клиент повторяет попытку, уже работая старым токеном — лишний дозвон на каждом отказе")
	}
}

// TestNoLegacyRetryOnOtherFailures — откат к старому токену только по отказу
// доступа. Иначе он маскировал бы другие поломки: каждая неудача стоила бы
// двух дозвонов, а в журнале появлялось бы ложное «сервер старой сборки».
func TestNoLegacyRetryOnOtherFailures(t *testing.T) {
	d, err := NewDialer(testClientConfig(), Options{DeviceID: "устройство"})
	if err != nil {
		t.Fatal(err)
	}
	for name, e := range map[string]error{
		"таймаут":            errTimeoutStub{},
		"ответ 503":          &masque.ResponseError{StatusCode: http.StatusServiceUnavailable},
		"ответ 500":          &masque.ResponseError{StatusCode: http.StatusInternalServerError},
		"сервер занят (429)": &masque.ResponseError{StatusCode: http.StatusTooManyRequests},
	} {
		if _, ok := d.legacyRetry(e); ok {
			t.Errorf("%s: клиент решил, что сервер старой сборки", name)
		}
	}
}

// TestDialerUsesGivenDeviceID — псевдоним устройства берётся из постоянного
// значения, а не выдумывается заново.
//
// Если бы он был случайным на запуск, устройства всё равно не сталкивались бы,
// но адрес менялся бы после каждого перезапуска клиента — и соединения внутри
// туннеля рвались бы на ровном месте, ровно то, от чего заведена аренда
// адресов.
func TestDialerUsesGivenDeviceID(t *testing.T) {
	id := func(t *testing.T, device string) string {
		t.Helper()
		d, err := NewDialer(testClientConfig(), Options{DeviceID: device})
		if err != nil {
			t.Fatal(err)
		}
		return d.auth.DeviceID()
	}
	first := id(t, "это устройство")
	if second := id(t, "это устройство"); second != first {
		t.Fatalf("при том же устройстве псевдоним разный: %q и %q — адрес сменится после перезапуска", first, second)
	}
	if other := id(t, "другое устройство"); other == first {
		t.Fatalf("у разных устройств один псевдоним %q — работать будет только одно", other)
	}
}

type errTimeoutStub struct{}

func (errTimeoutStub) Error() string { return "timeout: no recent network activity" }
