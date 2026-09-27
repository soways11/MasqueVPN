package config

// Сборка конфигурации из того, что человек вводит руками.
//
// Минимальная конфигурация — адрес, ключ и идентификатор; остальное
// подставляют умолчания. Именно эти три значения показывает форма
// добавления сервера в окне клиента, и именно их выдаёт `clients add`.
//
// Живёт здесь, а не в окне, по двум причинам. Во-первых, это те же правила,
// что и для конфигурации из файла, и держать их порознь — значит однажды
// разойтись. Во-вторых, Android-клиенту предстоит та же форма, и правила
// должны быть общими, а не написанными заново.

import (
	"encoding/json"
	"strings"
)

// DefaultPort — порт, который дописывается к адресу без порта.
//
// Человек вводит домен, потому что именно его ему называют; требовать
// «:443» значило бы отвергать верное по сути значение из-за формальности.
// А 443 — единственный осмысленный выбор: сервер живёт на нём, чтобы
// сливаться с обычным HTTPS.
const DefaultPort = "443"

// BuildClient собирает клиентскую конфигурацию из трёх значений.
//
// Через JSON, а не присваиванием полей: так применяются те же умолчания и
// та же проверка, что и к конфигурации из файла. Структура, собранная
// руками, рано или поздно разошлась бы с ними — и разошлась бы молча.
func BuildClient(server, authKey, clientID string) (*Client, error) {
	m := map[string]string{
		"server":   WithDefaultPort(strings.TrimSpace(server)),
		"auth_key": strings.TrimSpace(authKey),
	}
	if id := strings.TrimSpace(clientID); id != "" {
		m["client_id"] = id
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	c, err := ParseClient(raw)
	if err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// WithDefaultPort дописывает порт по умолчанию, если его не указали.
//
// Адрес IPv6 без порта отличается от «хост:порт» тем, что двоеточий в нём
// больше одного и он не взят в скобки: 2001:db8::1 — это адрес целиком, а
// не «хост 2001 и порт db8::1».
func WithDefaultPort(server string) string {
	if server == "" {
		return ""
	}
	if strings.HasPrefix(server, "[") {
		if strings.Contains(server, "]:") {
			return server
		}
		return server + ":" + DefaultPort
	}
	switch strings.Count(server, ":") {
	case 0:
		return server + ":" + DefaultPort
	case 1:
		return server
	default: // голый IPv6 — оборачиваем в скобки, иначе порт не отделить
		return "[" + server + "]:" + DefaultPort
	}
}

// FieldOfError подсказывает, к какому из трёх полей относится ошибка
// проверки: 1 — адрес, 2 — ключ, 3 — идентификатор, 0 — ни к какому.
//
// Нужна интерфейсу, чтобы подсветить именно то поле, где ошибка: «неверный
// ключ» без подсветки заставляет перечитывать всю форму.
func FieldOfError(err error) int {
	if err == nil {
		return 0
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "auth_key"):
		return 2
	case strings.Contains(s, "server"):
		return 1
	case strings.Contains(s, "client_id"):
		return 3
	}
	return 0
}
