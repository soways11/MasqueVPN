package config

// Правила формы «добавить сервер» — одни на все клиенты.
//
// Форма есть в окне Windows, в окне Linux и на телефоне. До этого файла её
// правила жили в самих окнах, и в двух местах были написаны одинаково —
// ровно до первой правки, которую внесли бы в одно. Телефон стал бы третьей
// копией. Здесь то, что форма решает по существу: что считать ошибкой, к
// какому полю её приписать, что человеку сказать, как понять вставленный
// текст и как переименовать профиль при правке. Окну остаётся нарисовать.

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Поля формы. Номера с единицы: ноль означает «ошибка ни к какому полю не
// относится». Совпадают с тем, что возвращает FieldOfError.
const (
	FieldNone     = 0
	FieldServer   = 1
	FieldAuthKey  = 2
	FieldClientID = 3
)

// FormError — ошибка формы, приписанная полю. Msg — для человека, одной
// строкой: в окне под формой места ровно на неё.
type FormError struct {
	Field int
	Msg   string
}

func (e *FormError) Error() string { return e.Msg }

// FormErrorOf достаёт поле и сообщение из любой ошибки: FormError отдаёт
// своё, прочие — первую строку и поле по тексту.
func FormErrorOf(err error) (field int, msg string) {
	if err == nil {
		return FieldNone, ""
	}
	var fe *FormError
	if errors.As(err, &fe) {
		return fe.Field, fe.Msg
	}
	return FieldOfError(err), firstLine(err.Error())
}

// BuildForm собирает конфигурацию из полей формы.
//
// От BuildClient отличается тем, что говорит с человеком: пустой адрес и
// пустой ключ — не «server: пусто», а объяснение, что вписать и где это
// взять. Ошибка всегда *FormError: окно подсвечивает поле, не разбирая текст.
func BuildForm(server, authKey, clientID string) (*Client, error) {
	server = strings.TrimSpace(server)
	authKey = strings.TrimSpace(authKey)
	switch {
	case server == "":
		return nil, &FormError{FieldServer, "Укажите адрес сервера — например, vpn.example.com"}
	case authKey == "":
		return nil, &FormError{FieldAuthKey, "Без ключа доступа сервер не пустит: его выдаёт clients add"}
	}
	c, err := BuildClient(server, authKey, clientID)
	if err != nil {
		// Ошибку приписываем полю, из-за которого она возникла: «неверный
		// ключ» без подсветки заставляет перечитывать всю форму.
		return nil, &FormError{FieldOfError(err), firstLine(err.Error())}
	}
	return c, nil
}

// ParseShared понимает то, чем доступ пересылают: ссылку masquevpn:// (и
// старую govpn://) или содержимое client.json. Возвращает конфигурацию и
// имя профиля, если оно было в ссылке.
//
// Сообщения — для человека, нажавшего «вставить»: он не обязан знать, что
// такое base64, но должен понять, что скопировал не то.
func ParseShared(text string) (*Client, string, error) {
	text = strings.TrimSpace(text)
	switch {
	case text == "":
		return nil, "", errors.New("в буфере обмена пусто — скопируйте ссылку и попробуйте ещё раз")
	case IsLink(text):
		return DecodeLink(text)
	case strings.HasPrefix(text, "{"):
		c, err := ParseClient([]byte(text))
		if err != nil {
			return nil, "", err
		}
		if err := c.Validate(); err != nil {
			return nil, "", err
		}
		return c, "", nil
	case json.Valid([]byte(text)):
		return nil, "", errors.New("это похоже на JSON, но не на конфигурацию клиента")
	}
	return nil, "", fmt.Errorf("это не ссылка %s:// и не содержимое client.json", LinkScheme)
}

// ParseProfiles разбирает профили из JSON — того же вида, что profiles.json.
// Пустой текст — не ошибка: это первый запуск.
func ParseProfiles(raw []byte) (*Profiles, error) {
	p := &Profiles{}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return p, nil
	}
	if err := json.Unmarshal(raw, p); err != nil {
		return nil, err
	}
	// Записи без конфигурации (файл правили руками) выбрасываем: иначе
	// они всплыли бы разыменованием nil в самом неожиданном месте.
	kept := p.List[:0]
	for _, pr := range p.List {
		if pr.Config == nil {
			continue
		}
		pr.Config.Defaults()
		kept = append(kept, pr)
	}
	p.List = kept
	return p, nil
}

// Marshal — профили в JSON для хранения.
func (p *Profiles) Marshal() ([]byte, error) { return json.MarshalIndent(p, "", "  ") }

// Update заменяет профиль old новой конфигурацией и, возможно, новым именем.
//
// Правка — не «удалить и добавить»: выбранный профиль должен остаться
// выбранным, иначе переименование того, через что человек подключён,
// молча переключило бы его на другой сервер. Пустое имя значит «не
// переименовывать». Переименование в имя другого существующего профиля
// отвергается — иначе тот был бы тихо затёрт. Из c берутся только три поля
// формы, остальные настройки профиля сохраняются (см. keepExtras).
func (p *Profiles) Update(old, name string, c *Client) (Profile, error) {
	idx := -1
	for i, pr := range p.List {
		if strings.EqualFold(pr.Name, old) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return Profile{}, errors.New("профиль исчез, пока его правили")
	}
	if c == nil {
		return Profile{}, errors.New("config: пустая конфигурация")
	}
	if err := c.Validate(); err != nil {
		return Profile{}, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = p.List[idx].Name
	}
	for i, pr := range p.List {
		if i != idx && strings.EqualFold(pr.Name, name) {
			return Profile{}, fmt.Errorf("профиль «%s» уже есть — выберите другое имя", pr.Name)
		}
	}
	wasSelected := strings.EqualFold(p.Current, p.List[idx].Name)
	p.List[idx] = Profile{Name: name, Config: keepExtras(p.List[idx].Config, c)}
	if wasSelected {
		p.Current = name
	}
	return p.List[idx], nil
}

// keepExtras переносит в новую конфигурацию всё, кроме трёх полей формы.
//
// Форма правит адрес, ключ и идентификатор — и только их. Аварийное
// отключение, полный туннель, исключения, DNS и прочее, что включали
// переключателем или правили файлом, при исправлении опечатки в адресе
// теряться не должно: иначе правка молча выключала бы защиту.
func keepExtras(old, fresh *Client) *Client {
	if old == nil || old == fresh {
		return fresh
	}
	c := *old
	c.Server, c.AuthKey, c.ClientID = fresh.Server, fresh.AuthKey, fresh.ClientID
	return &c
}

// Rename меняет только имя профиля.
func (p *Profiles) Rename(old, name string) (Profile, error) {
	for _, pr := range p.List {
		if strings.EqualFold(pr.Name, old) {
			if strings.TrimSpace(name) == "" {
				return Profile{}, errors.New("имя не может быть пустым")
			}
			return p.Update(old, name, pr.Config)
		}
	}
	return Profile{}, errors.New("профиль исчез, пока его правили")
}

// firstLine — первая строка многострочной ошибки: errors.Join склеивает
// их переводами строки, а в окне строка одна.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
