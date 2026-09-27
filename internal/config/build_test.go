package config

import (
	"errors"
	"strings"
	"testing"
)

const testKey = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="

// TestBuildClientMinimal — три значения дают рабочую конфигурацию, и к ней
// применяются те же умолчания, что и к прочитанной из файла.
func TestBuildClientMinimal(t *testing.T) {
	c, err := BuildClient("vpn.example.com:443", testKey, "66bbb6180401ba34")
	if err != nil {
		t.Fatal(err)
	}
	if c.Server != "vpn.example.com:443" || string(c.AuthKey) != testKey {
		t.Errorf("значения не долетели: %+v", c)
	}
	if c.ClientID != "66bbb6180401ba34" {
		t.Errorf("идентификатор потерян: %q", c.ClientID)
	}
	// Умолчания: без них конфигурация была бы неполной, а окно показывало
	// бы аварийное отключение выключенным при полном туннеле.
	if c.KillSwitch == nil || c.FullTunnel == nil {
		t.Error("умолчания не применились")
	}
	if err := c.Validate(); err != nil {
		t.Errorf("собранная конфигурация не проходит проверку: %v", err)
	}

	// Идентификатор необязателен: сервер выдаст адрес и без него.
	if _, err := BuildClient("vpn.example.com:443", testKey, ""); err != nil {
		t.Errorf("без идентификатора не собралось: %v", err)
	}
	// Пробелы по краям человек приносит вместе со вставкой из мессенджера.
	c, err = BuildClient("  vpn.example.com:443 ", " "+testKey+"\n", " 66bbb6180401ba34 ")
	if err != nil {
		t.Fatalf("пробелы по краям сломали разбор: %v", err)
	}
	if c.Server != "vpn.example.com:443" {
		t.Errorf("пробелы остались в адресе: %q", c.Server)
	}
}

// TestBuildClientRejects — негодные значения отвергаются, а не доезжают до
// подключения: ошибка при добавлении понятнее, чем обрыв через минуту.
func TestBuildClientRejects(t *testing.T) {
	cases := map[string][3]string{
		"без адреса":     {"", testKey, ""},
		"без ключа":      {"vpn.example.com:443", "", ""},
		"ключ не base64": {"vpn.example.com:443", "это точно не ключ!!", ""},
		"короткий ключ":  {"vpn.example.com:443", "YWJj", ""},
		"порт не число":  {"vpn.example.com:абв", testKey, ""},
	}
	for name, v := range cases {
		if _, err := BuildClient(v[0], v[1], v[2]); err == nil {
			t.Errorf("%s: конфигурация собралась", name)
		}
	}
}

// TestWithDefaultPort — домен без порта дополняется, а всё остальное
// остаётся как есть.
func TestWithDefaultPort(t *testing.T) {
	cases := map[string]string{
		"vpn.example.com":      "vpn.example.com:443",
		"vpn.example.com:443":  "vpn.example.com:443",
		"vpn.example.com:8443": "vpn.example.com:8443",
		"203.0.113.10":         "203.0.113.10:443",
		"2001:db8::1":          "[2001:db8::1]:443", // голый IPv6 — в скобки
		"[2001:db8::1]":        "[2001:db8::1]:443",
		"[2001:db8::1]:443":    "[2001:db8::1]:443",
		"":                     "",
	}
	for in, want := range cases {
		if got := WithDefaultPort(in); got != want {
			t.Errorf("WithDefaultPort(%q) = %q, ожидалось %q", in, got, want)
		}
	}
	// И результат обязан разбираться: дописывать порт, после которого адрес
	// перестаёт быть адресом, хуже, чем не дописывать вовсе.
	for in := range cases {
		if in == "" {
			continue
		}
		if _, err := BuildClient(in, testKey, ""); err != nil {
			t.Errorf("адрес %q после дополнения не прошёл проверку: %v", in, err)
		}
	}
}

// TestFieldOfError — ошибка привязывается к полю, чтобы подсветить именно
// его: «неверный ключ» без подсветки заставляет перечитывать всю форму.
func TestFieldOfError(t *testing.T) {
	_, err := BuildClient("vpn.example.com:443", "мусор", "")
	if got := FieldOfError(err); got != 2 {
		t.Errorf("ошибка ключа отнесена к полю %d, ожидалось 2 (%v)", got, err)
	}
	_, err = BuildClient("не адрес:и не порт", testKey, "")
	if got := FieldOfError(err); got != 1 {
		t.Errorf("ошибка адреса отнесена к полю %d, ожидалось 1 (%v)", got, err)
	}
	if got := FieldOfError(nil); got != 0 {
		t.Errorf("пустая ошибка отнесена к полю %d", got)
	}
	if got := FieldOfError(errors.New("что-то совсем другое")); got != 0 {
		t.Errorf("чужая ошибка отнесена к полю %d", got)
	}
}

// TestBuildMatchesLink — конфигурация, собранная руками из трёх значений, и
// та же конфигурация, пришедшая ссылкой, должны совпадать. Иначе добавление
// вручную и вставка ссылки давали бы разные профили.
func TestBuildMatchesLink(t *testing.T) {
	built, err := BuildClient("vpn.example.com:443", testKey, "66bbb6180401ba34")
	if err != nil {
		t.Fatal(err)
	}
	link, err := EncodeLink(built, "")
	if err != nil {
		t.Fatal(err)
	}
	fromLink, _, err := DecodeLink(link)
	if err != nil {
		t.Fatal(err)
	}
	if fromLink.Server != built.Server || string(fromLink.AuthKey) != string(built.AuthKey) ||
		fromLink.ClientID != built.ClientID {
		t.Errorf("ручной ввод и ссылка разошлись:\n%+v\n%+v", built, fromLink)
	}
	if !strings.HasPrefix(link, LinkScheme+"://") {
		t.Errorf("ссылка собрана не с той схемой: %q", link)
	}
}
