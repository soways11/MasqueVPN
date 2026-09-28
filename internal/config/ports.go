package config

// Запасные UDP-порты.
//
// # Зачем
//
// Провайдеры режут UDP по номеру порта, не глядя в содержимое: 25.09 у
// домашнего подключения UDP/443 не проходил вовсе, а 4443 — проходил.
// Браузер от такой блокировки откатывается на TCP, нам откатываться некуда:
// транспорт — только QUIC. Ответ в рамках MASQUE один — другой UDP-порт.
// Поэтому сервер слушает несколько портов, а клиент перебирает их сам.
//
// # Где порты у клиента
//
// Прямо в адресе сервера: «vpn.example.com:8443,2053,2083». Первый — тот,
// с которого начинать, остальные — запасные по порядку. Не отдельным полем
// сознательно: адрес — единственное, что форма «добавить сервер» показывает
// и правит во всех трёх клиентах (окно Windows, окно Linux, телефон), и
// отдельное поле терялось бы при каждой вставке ссылки и правке профиля.
// Так же адрес переживает ссылку masquevpn:// и файл профилей без единой
// новой строки кода в окнах — и порты можно поправить руками.
//
// Клиент прежних версий такой адрес не разберёт («порт должен быть
// числом») — ссылки с несколькими портами нужны клиенту 0.4.0 и новее.

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// DefaultPorts — стандартный набор: 443 и HTTPS-порты, которые Cloudflare
// принимает для проксируемых сайтов. Для наблюдателя это обычные порты
// HTTPS, а не случайные числа.
var DefaultPorts = []int{443, 8443, 2053, 2083, 2087, 2096}

// ParsePorts разбирает список портов: «8443,2053 2083» или «default».
// Повторы и числа вне 1–65535 — ошибка: в списке, который человек набрал
// сам, это почти всегда опечатка.
func ParsePorts(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	if strings.EqualFold(s, "default") {
		return append([]int(nil), DefaultPorts...), nil
	}
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' || r == '\t' })
	if len(fields) == 0 {
		return nil, errors.New("список портов пуст")
	}
	seen := map[int]bool{}
	out := make([]int, 0, len(fields))
	for _, f := range fields {
		n, err := strconv.Atoi(f)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("%q — порт должен быть числом от 1 до 65535", f)
		}
		if seen[n] {
			return nil, fmt.Errorf("порт %d указан дважды", n)
		}
		seen[n] = true
		out = append(out, n)
	}
	return out, nil
}

// SplitServer разбирает адрес сервера клиента: «host:порт» или
// «host:порт,порт,…». Возвращает хост и порты в порядке перебора.
func SplitServer(server string) (host string, ports []string, err error) {
	s := strings.TrimSpace(server)
	head, tail, multi := strings.Cut(s, ",")
	host, first, err := splitHostPort("server", strings.TrimSpace(head))
	if err != nil {
		return "", nil, err
	}
	ports = []string{first}
	if !multi {
		return host, ports, nil
	}
	rest, err := ParsePorts(tail)
	if err != nil {
		return "", nil, fmt.Errorf("server: запасные порты: %w", err)
	}
	for _, p := range rest {
		ps := strconv.Itoa(p)
		if ps == first {
			return "", nil, fmt.Errorf("server: порт %s указан дважды", ps)
		}
		ports = append(ports, ps)
	}
	return host, ports, nil
}

// JoinServer собирает адрес сервера клиента из хоста и портов.
func JoinServer(host string, ports []int) string {
	if len(ports) == 0 {
		return net.JoinHostPort(host, DefaultPort)
	}
	var b strings.Builder
	b.WriteString(net.JoinHostPort(host, strconv.Itoa(ports[0])))
	for _, p := range ports[1:] {
		b.WriteByte(',')
		b.WriteString(strconv.Itoa(p))
	}
	return b.String()
}

// UDPPorts — все порты, которые слушает сервер: сначала основной из listen,
// затем запасные.
func (c *Server) UDPPorts() ([]int, error) {
	_, p, err := splitHostPort("listen", c.Listen)
	if err != nil {
		return nil, err
	}
	first, _ := strconv.Atoi(p)
	out := []int{first}
	seen := map[int]bool{first: true}
	for _, a := range c.AltPorts {
		if a < 1 || a > 65535 {
			return nil, fmt.Errorf("alt_ports: %d — порт должен быть от 1 до 65535", a)
		}
		if seen[a] {
			return nil, fmt.Errorf("alt_ports: порт %d повторяется (или совпадает с listen)", a)
		}
		seen[a] = true
		out = append(out, a)
	}
	return out, nil
}

// UDPAddrs — адреса UDP-слушателей: хост из listen с каждым из портов.
func (c *Server) UDPAddrs() ([]string, error) {
	host, _, err := splitHostPort("listen", c.Listen)
	if err != nil {
		return nil, err
	}
	ports, err := c.UDPPorts()
	if err != nil {
		return nil, err
	}
	out := make([]string, len(ports))
	for i, p := range ports {
		out[i] = net.JoinHostPort(host, strconv.Itoa(p))
	}
	return out, nil
}
