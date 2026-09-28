package config

import (
	"strings"
	"testing"
)

// Правила формы общие для трёх клиентов, поэтому проверяются здесь, а не в
// окнах: раньше они жили в окнах и тестов не имели вовсе.

const sampleKey = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="

func TestBuildFormBlamesTheRightField(t *testing.T) {
	cases := []struct {
		name            string
		server, key, id string
		field           int
		mustMention     string
	}{
		{"пустой адрес", "  ", sampleKey, "", FieldServer, "адрес сервера"},
		{"пустой ключ", "vpn.example.com", "", "", FieldAuthKey, "ключа"},
		{"битый ключ", "vpn.example.com", "не-base64", "", FieldAuthKey, ""},
		{"порт не число", "vpn.example.com:абв", sampleKey, "", FieldServer, ""},
	}
	for _, c := range cases {
		_, err := BuildForm(c.server, c.key, c.id)
		if err == nil {
			t.Fatalf("%s: ошибки нет", c.name)
		}
		field, msg := FormErrorOf(err)
		if field != c.field {
			t.Errorf("%s: подсвечено поле %d вместо %d (%s)", c.name, field, c.field, msg)
		}
		if strings.Contains(msg, "\n") {
			t.Errorf("%s: сообщение в несколько строк — под формой видна будет одна: %q", c.name, msg)
		}
		if c.mustMention != "" && !strings.Contains(msg, c.mustMention) {
			t.Errorf("%s: в сообщении %q нет подсказки %q", c.name, msg, c.mustMention)
		}
	}
}

func TestBuildFormAcceptsBareDomain(t *testing.T) {
	c, err := BuildForm(" vpn.example.com ", " "+sampleKey+" ", "66bbb6180401ba34")
	if err != nil {
		t.Fatal(err)
	}
	if c.Server != "vpn.example.com:443" {
		t.Fatalf("адрес %q — порт по умолчанию не дописан или пробелы не сняты", c.Server)
	}
}

// Вставка понимает всё, чем пересылают доступ, и отличает «скопировал не
// то» от «ссылка повреждена».
func TestParseShared(t *testing.T) {
	link, err := EncodeLink(sampleClient(), "дача")
	if err != nil {
		t.Fatal(err)
	}
	c, name, err := ParseShared("  " + link + "\n")
	if err != nil {
		t.Fatalf("ссылка не принята: %v", err)
	}
	if name != "дача" {
		t.Fatalf("имя из ссылки потеряно: %q", name)
	}
	if c.Server != "vpn.example.com:443" {
		t.Fatalf("адрес %q", c.Server)
	}

	legacy := "govpn://" + strings.TrimPrefix(link, LinkScheme+"://")
	if _, _, err := ParseShared(legacy); err != nil {
		t.Fatalf("старая ссылка govpn:// не принята: %v", err)
	}

	if _, _, err := ParseShared(`{"server":"vpn.example.com:443","auth_key":"` + sampleKey + `"}`); err != nil {
		t.Fatalf("содержимое client.json не принято: %v", err)
	}

	for text, hint := range map[string]string{
		"":                   "пусто",
		"привет":             "не ссылка",
		`[1,2,3]`:            "JSON",
		`{"server":""}`:      "",
		LinkScheme + "://!!": "повреждена",
	} {
		_, _, err := ParseShared(text)
		if err == nil {
			t.Errorf("%q принят как доступ", text)
			continue
		}
		if hint != "" && !strings.Contains(err.Error(), hint) {
			t.Errorf("%q: сообщение %q не объясняет, в чём дело (ждали %q)", text, err, hint)
		}
	}
}

// Правка профиля: выбранный остаётся выбранным, место в списке не меняется,
// чужой профиль переименованием не затирается.
func TestProfilesUpdate(t *testing.T) {
	p := &Profiles{}
	if _, err := p.Add("дом", sampleClient()); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Add("работа", sampleClient()); err != nil {
		t.Fatal(err)
	}
	if err := p.Select("дом"); err != nil {
		t.Fatal(err)
	}

	other, err := BuildForm("other.example.com", sampleKey, "")
	if err != nil {
		t.Fatal(err)
	}
	pr, err := p.Update("дом", "квартира", other)
	if err != nil {
		t.Fatal(err)
	}
	if pr.Name != "квартира" || pr.Config.Server != "other.example.com:443" {
		t.Fatalf("правка не применилась: %+v", pr)
	}
	if p.Current != "квартира" {
		t.Fatalf("выбран %q — переименование выбранного профиля сбило выбор", p.Current)
	}
	if p.List[0].Name != "квартира" {
		t.Fatalf("профиль переехал в списке: %v", names(p))
	}

	// Пустое имя — оставить прежнее.
	if pr, err := p.Update("квартира", "  ", sampleClient()); err != nil || pr.Name != "квартира" {
		t.Fatalf("пустое имя не сохранило прежнее: %+v %v", pr, err)
	}

	// Переименование в имя соседа — отказ, а не молчаливая замена.
	if _, err := p.Update("квартира", "РАБОТА", sampleClient()); err == nil {
		t.Fatal("переименование в чужое имя прошло — соседний профиль затёрт")
	}
	if len(p.List) != 2 {
		t.Fatalf("профилей %d вместо двух", len(p.List))
	}

	if _, err := p.Update("нет такого", "", sampleClient()); err == nil {
		t.Fatal("правка несуществующего профиля прошла")
	}
	if _, err := p.Rename("работа", ""); err == nil {
		t.Fatal("переименование в пустое имя прошло")
	}
	if pr, err := p.Rename("работа", "офис"); err != nil || pr.Name != "офис" {
		t.Fatalf("переименование не прошло: %+v %v", pr, err)
	}
}

// Профили переживают сохранение в JSON и разбор — на телефоне они живут
// строкой в хранилище приложения, а не файлом.
func TestProfilesMarshalRoundTrip(t *testing.T) {
	p := &Profiles{}
	p.Add("дом", sampleClient())
	p.Add("работа", sampleClient())
	p.Select("работа")
	raw, err := p.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseProfiles(raw)
	if err != nil {
		t.Fatal(err)
	}
	if back.Current != "работа" || len(back.List) != 2 || back.List[1].Config.Server != "vpn.example.com:443" {
		t.Fatalf("после разбора: %+v", back)
	}

	if empty, err := ParseProfiles(nil); err != nil || len(empty.List) != 0 {
		t.Fatalf("пустое хранилище — не первый запуск: %+v %v", empty, err)
	}
	// Запись без конфигурации выбрасывается, а не роняет клиент потом.
	broken, err := ParseProfiles([]byte(`{"profiles":[{"name":"пустой"},{"name":"ok","config":{"server":"a.b:443","auth_key":"` + sampleKey + `"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(broken.List) != 1 || broken.List[0].Name != "ok" {
		t.Fatalf("запись без конфигурации осталась: %v", names(broken))
	}
}

func names(p *Profiles) []string {
	var out []string
	for _, pr := range p.List {
		out = append(out, pr.Name)
	}
	return out
}

// Правка адреса не должна выключать защиту: форма знает три поля, а у
// профиля их больше — аварийное отключение, полный туннель, исключения.
func TestProfilesUpdateKeepsSettings(t *testing.T) {
	p := &Profiles{}
	base := sampleClient()
	on, off := true, false
	base.KillSwitch = &on
	base.FullTunnel = &off
	base.Routes = []string{"10.0.0.0/8"} // без маршрутов неполный туннель недопустим
	base.KillSwitchAllow = []string{"192.168.1.10"}
	if _, err := p.Add("дом", base); err != nil {
		t.Fatal(err)
	}
	fixed, err := BuildForm("fixed.example.com", sampleKey, "")
	if err != nil {
		t.Fatal(err)
	}
	pr, err := p.Update("дом", "", fixed)
	if err != nil {
		t.Fatal(err)
	}
	c := pr.Config
	if c.Server != "fixed.example.com:443" {
		t.Fatalf("адрес не исправлен: %q", c.Server)
	}
	if c.KillSwitch == nil || !*c.KillSwitch {
		t.Fatal("исправление адреса выключило аварийное отключение")
	}
	if c.FullTunnel == nil || *c.FullTunnel {
		t.Fatal("исправление адреса вернуло полный туннель, выключенный человеком")
	}
	if len(c.KillSwitchAllow) != 1 || len(c.Routes) != 1 {
		t.Fatalf("исключения или маршруты потеряны: %v %v", c.KillSwitchAllow, c.Routes)
	}
}

// TestProfilesDropBrokenSplitTunnel — профиль, где переключатель «весь
// трафик через VPN» выключили, а сетей не задали, не подключался вовсе.
// Переключателя больше нет, и такой профиль возвращается в полный туннель;
// настоящий раздельный туннель со списком сетей остаётся как был.
func TestProfilesDropBrokenSplitTunnel(t *testing.T) {
	raw := []byte(`{"profiles":[
		{"name":"сломанный","config":{"server":"a.b:443","auth_key":"` + sampleKey + `","full_tunnel":false}},
		{"name":"раздельный","config":{"server":"a.b:443","auth_key":"` + sampleKey + `","full_tunnel":false,"routes":["10.0.0.0/8"]}}]}`)
	p, err := ParseProfiles(raw)
	if err != nil {
		t.Fatal(err)
	}
	broken, split := p.List[0].Config, p.List[1].Config
	if !*broken.FullTunnel || broken.Validate() != nil {
		t.Fatalf("сломанный профиль не починен: full_tunnel=%v err=%v", *broken.FullTunnel, broken.Validate())
	}
	if !*broken.KillSwitch {
		t.Error("у починенного профиля не включилось аварийное отключение")
	}
	if *split.FullTunnel || len(split.Routes) != 1 {
		t.Errorf("раздельный туннель со списком сетей изменён: %v %v", *split.FullTunnel, split.Routes)
	}
}
