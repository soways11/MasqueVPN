package config

// Ссылка для импорта: вся конфигурация одной строкой.
//
// # Зачем
//
// Доступ выдают человеку, а не машине. Файл надо куда-то положить, не
// перепутать и не потерять; ключ, напечатанный в терминал, остаётся в его
// истории и в буфере обмена. Строка, которую можно переслать и вставить, —
// то, чем люди пользуются на самом деле, и то, из чего делается QR-код для
// телефона.
//
// # Формат
//
//	masquevpn://<base64url от JSON конфигурации>#<имя профиля>
//
// Внутри — та же конфигурация клиента, что и в файле, без отступов. Base64
// в варианте url без набивки: строка переживает пересылку в мессенджере,
// вставку в адресную строку и печать в QR без экранирования.
//
// Имя профиля вынесено во фрагмент после #: оно нужно человеку («домашний»,
// «рабочий»), не участвует в подключении и не должно влиять на то, что
// разберёт клиент. Фрагмент URL для этого и предназначен.
//
// # Чего здесь нет
//
// Шифрования. Ссылка несёт ключ доступа в открытом виде — как и файл
// конфигурации. Пересылать её через недоверенный канал так же опасно, как
// пересылать файл, и клиент об этом предупреждает при выдаче. Добавлять
// пароль поверх значило бы выдумывать свой формат хранилища ключей ради
// ощущения безопасности: тот, кто перехватил ссылку, перехватит и пароль.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"strings"
)

// LinkScheme — схема ссылки импорта.
const LinkScheme = "masquevpn"

// legacyScheme — как схема называлась до переименования проекта.
//
// Разбор принимает обе: ссылка живёт в переписке и в QR-кодах, которые уже
// напечатаны, и переименование не повод отключать выданный доступ. Выдаётся
// при этом только новая — иначе старая не исчезнет никогда.
const legacyScheme = "govpn"

// IsLink сообщает, похожа ли строка на ссылку импорта.
//
// Нужна там, где ссылку надо отличить от пути к файлу. Знание о том, что
// схем две, живёт здесь: иначе каждый вызывающий проверял бы одну, и
// старые ссылки переставали бы опознаваться по-разному в разных местах.
func IsLink(s string) bool {
	s = strings.TrimSpace(s)
	return strings.HasPrefix(s, LinkScheme+"://") || strings.HasPrefix(s, legacyScheme+"://")
}

// EncodeLink собирает ссылку из конфигурации. name — необязательное имя
// профиля для человека.
func EncodeLink(c *Client, name string) (string, error) {
	if c == nil {
		return "", fmt.Errorf("config: пустая конфигурация")
	}
	if c.Server == "" {
		return "", fmt.Errorf("config: в конфигурации нет адреса сервера")
	}
	m, err := minimalFields(c)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	link := LinkScheme + "://" + base64.RawURLEncoding.EncodeToString(raw)
	if name != "" {
		link += "#" + url.PathEscape(name)
	}
	return link, nil
}

// DecodeLink разбирает ссылку и возвращает конфигурацию и имя профиля.
//
// Умолчания применяются сразу: ссылка, как и файл, может нести три поля,
// а клиент должен получить полную конфигурацию.
func DecodeLink(link string) (*Client, string, error) {
	s := strings.TrimSpace(link)
	switch {
	case strings.HasPrefix(s, LinkScheme+"://"):
		s = strings.TrimPrefix(s, LinkScheme+"://")
	case strings.HasPrefix(s, legacyScheme+"://"):
		s = strings.TrimPrefix(s, legacyScheme+"://")
	default:
		// Отдельное сообщение: чаще всего сюда попадает обрезанная строка
		// или путь к файлу, и «не удалось разобрать base64» ничего не
		// объясняет.
		return nil, "", fmt.Errorf("config: это не ссылка %s://…", LinkScheme)
	}

	var name string
	if i := strings.IndexByte(s, '#'); i >= 0 {
		var err error
		if name, err = url.PathUnescape(s[i+1:]); err != nil {
			name = s[i+1:]
		}
		s = s[:i]
	}
	// Мессенджеры любят дописывать слэш в конец и резать строку переносами.
	s = strings.TrimSuffix(s, "/")
	s = strings.Join(strings.FieldsFunc(s, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ' ' || r == '\t'
	}), "")

	raw, err := decodeBase64(s)
	if err != nil {
		return nil, "", fmt.Errorf("config: ссылка повреждена: %w", err)
	}
	var c Client
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, "", fmt.Errorf("config: в ссылке не конфигурация masquevpn: %w", err)
	}
	c.Defaults()
	if err := c.Validate(); err != nil {
		return nil, "", err
	}
	return &c, name, nil
}

// decodeBase64 принимает оба варианта base64url — с набивкой и без. Сами мы
// пишем без неё, но ссылка может прийти и от другого инструмента.
func decodeBase64(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

// minimalFields оставляет в конфигурации только то, что отличается от
// умолчаний.
//
// Иначе ссылка тащит всё, что подставил Defaults: резолверы, параметры TUN,
// ротацию. Это не ошибка, но строка разбухает втрое и перестаёт помещаться
// в QR-код разумной плотности, а человек, открывший её, видит десяток полей
// вместо трёх и не понимает, какие из них важны. Поймано тестом.
//
// Сравнение идёт с эталоном — той же конфигурацией, собранной из одних
// обязательных полей и прогнанной через Defaults. Так список умолчаний не
// приходится перечислять руками: он не разъедется с самим Defaults.
func minimalFields(c *Client) (map[string]any, error) {
	// Вход приводим к тому же виду, в котором его увидит клиент: иначе
	// конфигурация, не прошедшая через Defaults, отличается от эталона
	// нулями там, где у эталона умолчания, и они попадают в ссылку.
	norm := *c
	norm.Defaults()
	full, err := toMap(&norm)
	if err != nil {
		return nil, err
	}
	base := &Client{Server: c.Server, AuthKey: c.AuthKey, ClientID: c.ClientID}
	base.Defaults()
	def, err := toMap(base)
	if err != nil {
		return nil, err
	}
	keep := map[string]bool{"server": true, "auth_key": true, "client_id": true}
	for k, v := range full {
		if keep[k] {
			continue
		}
		if d, ok := def[k]; ok && reflect.DeepEqual(v, d) {
			delete(full, k)
		}
	}
	return full, nil
}

func toMap(c *Client) (map[string]any, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}
