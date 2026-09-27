package core

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/soways11/masquevpn/internal/config"
)

// Здесь проверяется договор с Kotlin: какие ключи лежат в ответах и что они
// значат. Правила формы как таковые проверены в internal/config — тут важно,
// что они доезжают до телефона, не теряя поля, которое надо подсветить.

const testKey = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="

type result struct {
	OK       bool   `json:"ok"`
	Name     string `json:"name"`
	Error    string `json:"error"`
	Field    int    `json:"field"`
	Server   string `json:"server"`
	AuthKey  string `json:"auth_key"`
	ClientID string `json:"client_id"`
}

func decode(t *testing.T, s string) result {
	t.Helper()
	var r result
	if err := json.Unmarshal([]byte(s), &r); err != nil {
		t.Fatalf("ответ не JSON (%v): %s", err, s)
	}
	return r
}

func TestProfilesFormContract(t *testing.T) {
	p, err := LoadProfiles("")
	if err != nil {
		t.Fatal(err)
	}
	if p.Count() != 0 || p.Current() != "" || p.CurrentConfig() != "" {
		t.Fatal("первый запуск — а профили уже есть")
	}

	// Ошибка приписана полю: экран подсветит именно его.
	r := decode(t, p.Add("vpn.example.com", "", "", ""))
	if r.OK || r.Field != FieldAuthKey || r.Error == "" {
		t.Fatalf("пустой ключ: %+v", r)
	}
	r = decode(t, p.Add("", testKey, "", ""))
	if r.OK || r.Field != FieldServer {
		t.Fatalf("пустой адрес: %+v", r)
	}

	r = decode(t, p.Add("vpn.example.com", testKey, "66bbb6180401ba34", ""))
	if !r.OK || r.Name != "vpn.example.com" {
		t.Fatalf("добавление: %+v — имя по умолчанию должно быть доменом", r)
	}
	if p.Current() != "vpn.example.com" {
		t.Fatalf("первый профиль не выбран: %q", p.Current())
	}
	r = decode(t, p.Add("second.example.com:8443", testKey, "", "дача"))
	if !r.OK || r.Name != "дача" {
		t.Fatalf("второй профиль: %+v", r)
	}
	if p.Current() != "vpn.example.com" {
		t.Fatal("добавление второго профиля переключило выбранный — туннель ушёл бы на другой сервер")
	}

	// Список — то, что рисует экран.
	var rows []struct {
		Name, Server, Host string
		Current            bool
	}
	if err := json.Unmarshal([]byte(p.ListJSON()), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || !rows[0].Current || rows[1].Current {
		t.Fatalf("список: %+v", rows)
	}
	if rows[1].Host != "second.example.com" || rows[1].Server != "second.example.com:8443" {
		t.Fatalf("в строке списка %q / %q — хост без порта, сервер с портом", rows[1].Host, rows[1].Server)
	}

	// Конфигурация для туннеля — полная и рабочая.
	cfg, err := config.ParseClient([]byte(p.CurrentConfig()))
	if err != nil {
		t.Fatalf("конфигурация выбранного не разбирается: %v", err)
	}
	if cfg.Server != "vpn.example.com:443" || cfg.ClientID != "66bbb6180401ba34" {
		t.Fatalf("конфигурация: %+v", cfg)
	}

	// Правка выбранного с переименованием — выбор сохраняется.
	var f result
	json.Unmarshal([]byte(p.FieldsJSON("vpn.example.com")), &f)
	if f.AuthKey != testKey || f.Name != "vpn.example.com" {
		t.Fatalf("поля для правки: %+v", f)
	}
	r = decode(t, p.Update("vpn.example.com", "fixed.example.com", f.AuthKey, f.ClientID, "дом"))
	if !r.OK || r.Name != "дом" || p.Current() != "дом" {
		t.Fatalf("правка: %+v, выбран %q", r, p.Current())
	}
	r = decode(t, p.Update("дом", "fixed.example.com", "битый", "", ""))
	if r.OK || r.Field != FieldAuthKey {
		t.Fatalf("правка с битым ключом: %+v", r)
	}

	// Сохранение и повторная загрузка — так профили переживают перезапуск.
	back, err := LoadProfiles(p.JSON())
	if err != nil {
		t.Fatal(err)
	}
	if back.Count() != 2 || back.Current() != "дом" {
		t.Fatalf("после перезапуска: %d профилей, выбран %q", back.Count(), back.Current())
	}

	if err := back.Rename("дача", "дача-2"); err != nil {
		t.Fatal(err)
	}
	if err := back.Remove("дом"); err != nil {
		t.Fatal(err)
	}
	if back.Current() != "дача-2" {
		t.Fatalf("удалён выбранный — выбран %q, а должен остаться единственный", back.Current())
	}
}

func TestParseSharedForForm(t *testing.T) {
	c, err := config.BuildForm("vpn.example.com", testKey, "66bbb6180401ba34")
	if err != nil {
		t.Fatal(err)
	}
	link, err := config.EncodeLink(c, "работа")
	if err != nil {
		t.Fatal(err)
	}
	if !IsLink(link) {
		t.Fatal("своя ссылка не опознана")
	}
	r := decode(t, ParseShared(link))
	if !r.OK || r.Server != "vpn.example.com:443" || r.AuthKey != testKey ||
		r.ClientID != "66bbb6180401ba34" || r.Name != "работа" {
		t.Fatalf("ссылка разложена по полям неверно: %+v", r)
	}
	// Ссылка из профиля — та же, что разобрали: перенос с устройства на
	// устройство не теряет ни ключа, ни имени.
	p, _ := LoadProfiles("")
	decode(t, p.Add(c.Server, string(c.AuthKey), c.ClientID, "работа"))
	again, err := p.LinkFor("РАБОТА")
	if err != nil {
		t.Fatal(err)
	}
	if r2 := decode(t, ParseShared(again)); !r2.OK || r2.AuthKey != testKey || r2.Name != "работа" {
		t.Fatalf("ссылка из профиля: %+v", r2)
	}
	if _, err := p.LinkFor("нет такого"); err == nil {
		t.Fatal("ссылка на несуществующий профиль")
	}
	r = decode(t, ParseShared("скопировал не то"))
	if r.OK || !strings.Contains(r.Error, "не ссылка") {
		t.Fatalf("мусор из буфера: %+v", r)
	}
}
