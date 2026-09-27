package config

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func sampleClient() *Client {
	c := &Client{
		Server:   "vpn.example.com:443",
		AuthKey:  "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
		ClientID: "66bbb6180401ba34",
	}
	c.Defaults()
	return c
}

// TestLinkRoundTrip — ссылка переживает кодирование и разбор, и разобранная
// конфигурация работоспособна.
func TestLinkRoundTrip(t *testing.T) {
	want := sampleClient()
	link, err := EncodeLink(want, "домашний")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(link, LinkScheme+"://") {
		t.Fatalf("ссылка без схемы: %s", link)
	}
	t.Logf("ссылка: %s", link)

	got, name, err := DecodeLink(link)
	if err != nil {
		t.Fatal(err)
	}
	if name != "домашний" {
		t.Errorf("имя профиля %q, ожидалось «домашний»", name)
	}
	if got.Server != want.Server || got.AuthKey != want.AuthKey || got.ClientID != want.ClientID {
		t.Errorf("конфигурация не совпала: %+v", got)
	}
	if err := got.Validate(); err != nil {
		t.Errorf("разобранная конфигурация негодна: %v", err)
	}
}

// TestLinkCarriesMinimalConfig — в ссылку кладётся ровно то, что нужно.
//
// Смысл минимальной конфигурации в том, что остальное подставляется
// умолчаниями; если ссылка начнёт тащить всё подряд, она разбухнет и
// перестанет помещаться в QR-код разумной плотности.
func TestLinkCarriesMinimalConfig(t *testing.T) {
	c := &Client{
		Server:   "vpn.example.com:443",
		AuthKey:  "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
		ClientID: "66bbb6180401ba34",
	}
	link, err := EncodeLink(c, "")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(link, LinkScheme+"://"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	t.Logf("в ссылке %d полей, длина строки %d: %v", len(m), len(link), keys(m))
	for _, k := range []string{"server", "auth_key", "client_id"} {
		if _, ok := m[k]; !ok {
			t.Errorf("в ссылке нет поля %q", k)
		}
	}
	if len(m) > 3 {
		t.Errorf("ссылка несёт лишние поля: %v", keys(m))
	}
	// QR-код версии 10 с коррекцией M держит около 270 символов — держимся
	// в этих пределах, иначе код станет неразборчивым для телефона.
	if len(link) > 270 {
		t.Errorf("ссылка длиной %d символов не поместится в QR разумной плотности", len(link))
	}
}

// TestLinkTolerantToMessengers — ссылка переживает то, что с ней делают по
// дороге: перенос строки, пробел, лишний слэш в конце, набивку base64.
func TestLinkTolerantToMessengers(t *testing.T) {
	link, err := EncodeLink(sampleClient(), "рабочий")
	if err != nil {
		t.Fatal(err)
	}
	mid := len(link) / 2
	for name, damaged := range map[string]string{
		"перенос строки": link[:mid] + "\n" + link[mid:],
		"пробел":         link[:mid] + " " + link[mid:],
		"слэш в конце":   strings.Replace(link, "#", "/#", 1),
		"пробелы вокруг": "  " + link + "  ",
	} {
		if _, _, err := DecodeLink(damaged); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestLinkRejectsGarbage — понятный отказ вместо загадочного.
func TestLinkRejectsGarbage(t *testing.T) {
	cases := map[string]string{
		"пустая строка":     "",
		"не ссылка":         "C:\\Users\\user\\client.json",
		"чужая схема":       "vless://abc",
		"мусор внутри":      LinkScheme + "://!!!!",
		"не конфигурация":   LinkScheme + "://" + base64.RawURLEncoding.EncodeToString([]byte(`{"foo":1}`)),
		"нет адреса":        LinkScheme + "://" + base64.RawURLEncoding.EncodeToString([]byte(`{"auth_key":"AAA"}`)),
		"обрезанная строка": LinkScheme + "://eyJzZXJ2ZXIiOiJ2cG4uZXhhbXBsZS5jb20",
	}
	for name, s := range cases {
		if _, _, err := DecodeLink(s); err == nil {
			t.Errorf("%s: принято как ссылка", name)
		} else {
			t.Logf("%s → %v", name, err)
		}
	}
}

// TestEncodeLinkNeedsServer — пустая конфигурация не превращается в ссылку.
func TestEncodeLinkNeedsServer(t *testing.T) {
	if _, err := EncodeLink(&Client{}, ""); err == nil {
		t.Error("конфигурация без сервера закодирована")
	}
	if _, err := EncodeLink(nil, ""); err == nil {
		t.Error("nil закодирован")
	}
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestLinkKeepsNonDefaults — обратная сторона минимизации: всё, что
// отличается от умолчаний, обязано доехать.
//
// Урезать ссылку до трёх полей полезно ровно до тех пор, пока она не начала
// терять настройки. Выключенный kill switch, свой резолвер, раздельный
// туннель — если такое потеряется, человек получит не ту конфигурацию, что
// ему выдали, и узнает об этом в лучшем случае по поведению.
func TestLinkKeepsNonDefaults(t *testing.T) {
	no := false
	c := &Client{
		Server:          "vpn.example.com:443",
		AuthKey:         "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
		ClientID:        "66bbb6180401ba34",
		KillSwitch:      &no,
		KillSwitchAllow: []string{"203.0.113.7"},
		DNS:             []string{"9.9.9.9"},
		Parrot:          "chrome-115",
	}
	link, err := EncodeLink(c, "")
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := DecodeLink(link)
	if err != nil {
		t.Fatal(err)
	}
	if got.KillSwitch == nil || *got.KillSwitch {
		t.Error("выключенный kill switch не доехал — человек получит включённый")
	}
	if len(got.KillSwitchAllow) != 1 || got.KillSwitchAllow[0] != "203.0.113.7" {
		t.Errorf("исключения не доехали: %v", got.KillSwitchAllow)
	}
	if len(got.DNS) != 1 || got.DNS[0] != "9.9.9.9" {
		t.Errorf("свой резолвер не доехал: %v", got.DNS)
	}
	if got.Parrot != "chrome-115" {
		t.Errorf("профиль отпечатка не доехал: %q", got.Parrot)
	}
	t.Logf("длина ссылки с настройками: %d", len(link))
}

// TestDecodeLegacyScheme — ссылки, выданные до переименования проекта,
// обязаны продолжать работать: они лежат в переписках и напечатанных
// QR-кодах, а доступ за ними — настоящий.
func TestDecodeLegacyScheme(t *testing.T) {
	link, err := EncodeLink(sampleClient(), "домашний")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(link, LinkScheme+"://") {
		t.Fatalf("выдаётся ссылка со старой схемой: %q", link)
	}
	old := legacyScheme + "://" + strings.TrimPrefix(link, LinkScheme+"://")

	c, name, err := DecodeLink(old)
	if err != nil {
		t.Fatalf("старая ссылка не разобралась: %v", err)
	}
	if name != "домашний" || c.Server != sampleClient().Server {
		t.Errorf("старая ссылка разобралась неверно: %q → %+v", name, c)
	}
	if err := c.Validate(); err != nil {
		t.Errorf("конфигурация из старой ссылки негодна: %v", err)
	}

	// А вот чужая схема остаётся ошибкой — иначе в профиль попадёт что
	// угодно, лишь бы оно было в base64.
	if _, _, err := DecodeLink("vless://" + strings.TrimPrefix(link, LinkScheme+"://")); err == nil {
		t.Error("ссылка чужой схемы принята")
	}

	if !IsLink(old) || !IsLink(link) {
		t.Error("IsLink не опознаёт одну из схем")
	}
	if IsLink(`C:\Users\Пользователь\client.json`) {
		t.Error("путь к файлу опознан как ссылка")
	}
}
