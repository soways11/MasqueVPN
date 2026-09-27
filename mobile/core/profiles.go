package core

// Профили на телефоне и всё, что форма «добавить сервер» решает по существу.
//
// # Почему здесь, а не в Kotlin
//
// Те же правила уже есть в окнах Windows и Linux — и живут они в
// internal/config, а не в окнах: что считать ошибкой, к какому полю её
// приписать, как понять вставленную ссылку, как переименовать выбранный
// профиль, не сбив выбор. Написать это на Kotlin заново значило бы завести
// третью копию, которая разойдётся с двумя другими при первой же правке.
//
// Хранит профили приложение (строка в SharedPreferences): файла «рядом с
// программой» на Android нет. Ядро получает строку, работает и отдаёт её
// обратно методом JSON.
//
// # Почему ответы — JSON
//
// gomobile переносит ошибку Go в исключение Java только с текстом, а форме
// нужно ещё и поле, которое подсветить. Поэтому операции формы возвращают
// строку вида {"ok":false,"error":"…","field":2} — одно значение, которое
// не теряет ничего по дороге.

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/soways11/masquevpn/internal/config"
	"github.com/soways11/masquevpn/internal/gui"
)

// Номера полей формы — те же, что в config (с единицы; 0 — ни к какому).
const (
	FieldNone     = config.FieldNone
	FieldServer   = config.FieldServer
	FieldAuthKey  = config.FieldAuthKey
	FieldClientID = config.FieldClientID
)

// Profiles — доступы, сохранённые на телефоне.
type Profiles struct {
	p *config.Profiles
}

// LoadProfiles разбирает сохранённую строку. Пустая строка — первый запуск.
func LoadProfiles(stored string) (*Profiles, error) {
	p, err := config.ParseProfiles([]byte(stored))
	if err != nil {
		return nil, err
	}
	return &Profiles{p: p}, nil
}

// JSON — строка для сохранения.
func (p *Profiles) JSON() string {
	raw, err := p.p.Marshal()
	if err != nil {
		return ""
	}
	return string(raw)
}

// Count — число профилей.
func (p *Profiles) Count() int { return len(p.p.List) }

// Current — имя выбранного профиля или пустая строка.
func (p *Profiles) Current() string {
	pr, ok := p.p.Active()
	if !ok {
		return ""
	}
	return pr.Name
}

// profileRow — строка списка профилей на экране.
type profileRow struct {
	Name    string `json:"name"`
	Server  string `json:"server"`
	Host    string `json:"host"`
	Current bool   `json:"current"`
}

// ListJSON — профили для экрана: [{"name","server","host","current"}].
// host — домен без порта: в строке списка порт почти всегда 443 и только
// занимает место (так же, как в окне).
func (p *Profiles) ListJSON() string {
	cur := p.Current()
	rows := make([]profileRow, 0, len(p.p.List))
	for _, pr := range p.p.List {
		rows = append(rows, profileRow{
			Name:    pr.Name,
			Server:  pr.Config.Server,
			Host:    gui.Host(pr.Config.Server),
			Current: strings.EqualFold(pr.Name, cur),
		})
	}
	return mustJSON(rows)
}

// Select выбирает профиль.
func (p *Profiles) Select(name string) error { return p.p.Select(name) }

// Remove удаляет профиль.
func (p *Profiles) Remove(name string) error { return p.p.Remove(name) }

// Rename меняет имя профиля. Выбранный остаётся выбранным.
func (p *Profiles) Rename(old, name string) error {
	_, err := p.p.Rename(old, name)
	return err
}

// formResult — ответ операции формы.
type formResult struct {
	OK    bool   `json:"ok"`
	Name  string `json:"name,omitempty"`
	Error string `json:"error,omitempty"`
	Field int    `json:"field,omitempty"`
}

func formFail(err error) string {
	field, msg := config.FormErrorOf(err)
	return mustJSON(formResult{Error: msg, Field: field})
}

// Add добавляет профиль из полей формы. Пустое имя — назвать по домену.
// Ответ: {"ok":true,"name":"…"} или {"ok":false,"error":"…","field":N}.
func (p *Profiles) Add(server, authKey, clientID, name string) string {
	c, err := config.BuildForm(server, authKey, clientID)
	if err != nil {
		return formFail(err)
	}
	pr, err := p.p.Add(name, c)
	if err != nil {
		return formFail(err)
	}
	return mustJSON(formResult{OK: true, Name: pr.Name})
}

// Update заменяет профиль old значениями формы. Пустое имя — оставить
// прежнее. Ответ — как у Add.
func (p *Profiles) Update(old, server, authKey, clientID, name string) string {
	c, err := config.BuildForm(server, authKey, clientID)
	if err != nil {
		return formFail(err)
	}
	// Настройки, которых в форме нет, Update сохраняет сам.
	pr, err := p.p.Update(old, name, c)
	if err != nil {
		return formFail(err)
	}
	return mustJSON(formResult{OK: true, Name: pr.Name})
}

// formFields — значения полей формы для правки профиля.
type formFields struct {
	Server   string `json:"server"`
	AuthKey  string `json:"auth_key"`
	ClientID string `json:"client_id"`
	Name     string `json:"name"`
}

// FieldsJSON — значения полей формы для профиля name, чтобы его править:
// {"server","auth_key","client_id","name"}. Нет профиля — пустая строка.
func (p *Profiles) FieldsJSON(name string) string {
	for _, pr := range p.p.List {
		if strings.EqualFold(pr.Name, name) {
			return mustJSON(formFields{
				Server:   pr.Config.Server,
				AuthKey:  string(pr.Config.AuthKey),
				ClientID: pr.Config.ClientID,
				Name:     pr.Name,
			})
		}
	}
	return ""
}

// CurrentConfig — полная конфигурация выбранного профиля для
// Tunnel.Connect. Нет профилей — пустая строка.
func (p *Profiles) CurrentConfig() string {
	pr, ok := p.p.Active()
	if !ok {
		return ""
	}
	raw, err := json.Marshal(pr.Config)
	if err != nil {
		return ""
	}
	return string(raw)
}

// LinkFor — ссылка masquevpn:// на профиль, чтобы перенести его на другое
// устройство. В ссылке ключ доступа: экран обязан сказать об этом, прежде
// чем класть её в буфер обмена.
func (p *Profiles) LinkFor(name string) (string, error) {
	for _, pr := range p.p.List {
		if strings.EqualFold(pr.Name, name) {
			return config.EncodeLink(pr.Config, pr.Name)
		}
	}
	return "", errors.New("нет такого профиля")
}

// ParseShared разбирает то, чем пересылают доступ: ссылку masquevpn:// или
// содержимое client.json. Ответ раскладывается по полям формы:
// {"ok":true,"server","auth_key","client_id","name"} или
// {"ok":false,"error":"…"}.
//
// Не добавляет профиль сам: форма показывает значения, чтобы человек видел,
// к какому серверу подключится, — как в окне.
func ParseShared(text string) string {
	c, name, err := config.ParseShared(text)
	if err != nil {
		return formFail(err)
	}
	return mustJSON(struct {
		OK bool `json:"ok"`
		formFields
	}{true, formFields{
		Server:   c.Server,
		AuthKey:  string(c.AuthKey),
		ClientID: c.ClientID,
		Name:     name,
	}})
}

// IsLink — похожа ли строка на ссылку доступа. Нужна экрану, чтобы решить,
// предлагать ли «вставить ссылку из буфера».
func IsLink(text string) bool { return config.IsLink(text) }

func mustJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return `{"ok":false,"error":"внутренняя ошибка: ` + strings.ReplaceAll(err.Error(), `"`, `'`) + `"}`
	}
	return string(raw)
}
