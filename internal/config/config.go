// Package config — единый формат конфигурации masquevpn (JSON).
//
// Один и тот же формат клиента используется на всех платформах: desktop
// читает его из файла, мобильные обёртки передают ту же строку JSON в ядро.
// Платформа влияет только на то, какие поля имеют смысл (например, tun.name
// и full_tunnel на Android игнорируются — сеть настраивает система).
package config

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/soways11/masquevpn/internal/masque"
	"github.com/soways11/masquevpn/internal/obfuscation"
)

// Duration — time.Duration в JSON строкой ("30s", "5m").
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("длительность должна быть строкой вида \"30s\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// D возвращает значение как time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// TUN — параметры интерфейса.
type TUN struct {
	// Name — имя интерфейса; по умолчанию masquevpn0.
	Name string `json:"name,omitempty"`
	// MTU — по умолчанию 1280 (минимум для IPv6).
	MTU int `json:"mtu,omitempty"`
}

func (t *TUN) defaults() {
	if t.Name == "" {
		t.Name = "masquevpn0"
	}
	if t.MTU == 0 {
		t.MTU = 1280
	}
}

func (t *TUN) validate() error {
	if len(t.Name) > 15 {
		return fmt.Errorf("tun.name длиннее 15 символов: %q", t.Name)
	}
	if t.MTU < 576 || t.MTU > 65535 {
		return fmt.Errorf("tun.mtu вне диапазона: %d", t.MTU)
	}
	return nil
}

// Key — общий ключ аутентификации: base64 (обычный или URL-safe) либо
// ссылка на файл «file:/путь».
type Key string

// Bytes декодирует ключ.
func (k Key) Bytes() ([]byte, error) {
	s := strings.TrimSpace(string(k))
	if s == "" {
		return nil, errors.New("не задан auth_key")
	}
	if path, ok := strings.CutPrefix(s, "file:"); ok {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("auth_key: %w", err)
		}
		s = strings.TrimSpace(string(b))
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			if len(b) < 32 {
				return nil, fmt.Errorf("auth_key: %d байт, нужно не меньше 32", len(b))
			}
			return b, nil
		}
	}
	return nil, errors.New("auth_key: не base64")
}

// ShapingProfile строит Shaping по имени профиля.
//
//	none | chrome | cloud-gaming-up | cloud-gaming-down
func ShapingProfile(name string) (*masque.Shaping, error) {
	switch name {
	case "", "none":
		return nil, nil
	case "chrome":
		return obfuscation.New(obfuscation.ChromeLike()), nil
	case "cloud-gaming-up":
		return obfuscation.New(obfuscation.CloudGamingUpstream()), nil
	case "cloud-gaming-down":
		return obfuscation.New(obfuscation.CloudGamingDownstream()), nil
	}
	return nil, fmt.Errorf("неизвестный профиль shaping %q (none, chrome, cloud-gaming-up, cloud-gaming-down)", name)
}

// Packing — упаковка датаграмм (пункт C2): агрегация мелких пакетов,
// фрагментация крупных и, при желании, расписание отправки.
//
// Работает, только если другая сторона подтвердила поддержку кадров, — со
// старой версией на том конце обмен идёт по-прежнему.
type Packing struct {
	// Disabled выключает кадрирование целиком.
	Disabled bool `json:"disabled,omitempty"`
	// Window — окно агрегации: сколько ждать попутные пакеты. Это прямая
	// прибавка к задержке, поэтому значения микросекундные. 0 — 300µs.
	Window Duration `json:"window,omitempty"`
	// Pace — профиль расписания: none (по умолчанию), cloud-gaming-up,
	// cloud-gaming-down. С расписанием поток датаграмм задаётся профилем, а
	// не трафиком внутри туннеля; цена — постоянный фоновый трафик.
	Pace string `json:"pace,omitempty"`
	// PaceInterval переопределяет средний интервал профиля.
	PaceInterval Duration `json:"pace_interval,omitempty"`
	// PaceIdle переопределяет «слать и в простое».
	PaceIdle *bool `json:"pace_idle,omitempty"`
	// Burst — порог очереди в байтах, после которого расписание уступает
	// пропускной способности.
	Burst int `json:"burst,omitempty"`
}

// DefaultAggregationWindow — окно агрегации по умолчанию.
const DefaultAggregationWindow = 300 * time.Microsecond

// Options строит masque.Packing; nil — кадрирование выключено.
func (p *Packing) Options() (*masque.Packing, error) {
	if p != nil && p.Disabled {
		return nil, nil
	}
	out := &masque.Packing{Window: DefaultAggregationWindow}
	if p == nil {
		return out, nil
	}
	if p.Window > 0 {
		out.Window = p.Window.D()
	}
	pc, err := pacingProfile(p.Pace)
	if err != nil {
		return nil, err
	}
	if pc != nil {
		if p.PaceInterval > 0 {
			pc.MeanInterval = p.PaceInterval.D()
		}
		if p.PaceIdle != nil {
			pc.Idle = *p.PaceIdle
		}
		if p.Burst > 0 {
			pc.Burst = p.Burst
		}
		out.Pace = obfuscation.NewPacing(*pc)
	}
	return out, nil
}

func pacingProfile(name string) (*obfuscation.PacingConfig, error) {
	switch name {
	case "", "none":
		return nil, nil
	case "cloud-gaming-up":
		c := obfuscation.CloudGamingPacingUpstream()
		return &c, nil
	case "cloud-gaming-down":
		c := obfuscation.CloudGamingPacingDownstream()
		return &c, nil
	}
	return nil, fmt.Errorf("неизвестный профиль packing.pace %q (none, cloud-gaming-up, cloud-gaming-down)", name)
}

// Protocol переводит имя в значение :protocol.
func Protocol(name string) (string, error) {
	switch name {
	case "", "webtransport":
		return masque.ProtocolWebTransport, nil
	case "connect-ip":
		return masque.ProtocolConnectIP, nil
	}
	return "", fmt.Errorf("неизвестный protocol %q (webtransport, connect-ip)", name)
}

// decodeStrict разбирает JSON, отвергая неизвестные поля: опечатка в имени
// поля не должна молча превращаться в значение по умолчанию.
func decodeStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("лишние данные после объекта")
	}
	return nil
}

func readFile(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := decodeStrict(b, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func parsePrefix(field, s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%s: %w", field, err)
	}
	return p, nil
}

func splitHostPort(field, s string) (host, port string, err error) {
	host, port, err = net.SplitHostPort(s)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w (нужно host:port)", field, err)
	}
	// net.SplitHostPort разбирает «vpn.example.com:абв» без возражений: он
	// только делит строку. Порт проверяем сами — иначе негодное значение
	// доедет до подключения и упадёт там, где причину уже не видно.
	//
	// Пустой хост при этом законен: ":443" в настройках сервера означает
	// «слушать на всех интерфейсах».
	n, convErr := strconv.Atoi(port)
	if convErr != nil || n < 1 || n > 65535 {
		return "", "", fmt.Errorf("%s: %q — порт должен быть числом от 1 до 65535", field, port)
	}
	return host, port, nil
}
