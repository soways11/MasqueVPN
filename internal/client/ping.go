package client

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/soways11/masquevpn/internal/config"
	"github.com/soways11/masquevpn/internal/tunping"
)

// Пинг профиля: работает ли VPN через этот сервер и насколько быстро.
//
// Меряется путь целиком, как его видит приложение: поднимается настоящая
// сессия CONNECT-IP (тот же транспорт, отпечаток, токен и перебор портов,
// что при подключении), и через неё уходит HTTP GET на example.com (см.
// internal/tunping). Время — от SYN до первых байтов ответа; установка сессии
// и разрешение имени в него не входят.
//
// Сессия пинга открывается под ОТДЕЛЬНЫМ псевдонимом устройства (свой +
// «/ping»): сервер закрепляет адрес за парой клиент+устройство, и под тем же
// псевдонимом пинг профиля, через который сейчас подключены, отнял бы адрес
// у живой сессии. Под своим — получает соседний адрес и отдаёт его, закрыв
// сессию.

// DefaultPingTarget — куда идёт запрос пинга: хост[:порт], по умолчанию порт 80.
const DefaultPingTarget = "example.com"

// fallbackDNS — чем разрешать имя, если в профиле нет DNS IPv4 (раздельный
// туннель без своего DNS). Запрос всё равно идёт через туннель.
var fallbackDNS = netip.MustParseAddr("1.1.1.1")

// PingResult — итог проверки.
type PingResult struct {
	// RTT — от SYN до первых байтов HTTP-ответа через туннель.
	RTT time.Duration
	// Port — порт сервера, на котором поднялась сессия.
	Port string
	// Target — куда ходил запрос (example.com).
	Target string
	// Status — строка статуса ответа («HTTP/1.1 200 OK»).
	Status string
	// Addr — адрес, который сервер выдал сессии пинга. У живой сессии того
	// же профиля он свой (отдельный псевдоним устройства).
	Addr netip.Addr
}

// tunnelConn — то, что пингу нужно от сессии (masque.Conn).
type tunnelConn interface {
	tunping.PacketConn
	WaitForAddress(ctx context.Context) ([]netip.Prefix, error)
	Close() error
}

// Подменяются в тестах.
var (
	pingDial = func(ctx context.Context, d *Dialer) (tunnelConn, error) { return d.Dial(ctx) }
	pingGet  = tunping.Get
)

// Ping поднимает сессию по профилю cfg и делает через неё GET на target
// (пусто — DefaultPingTarget). Конфигурация не меняется: Dialer дописывает в
// неё выбранный транспорт, поэтому работаем с копией.
func Ping(ctx context.Context, cfg *config.Client, opt Options, target string) (PingResult, error) {
	if target == "" {
		target = DefaultPingTarget
	}
	host, port, err := splitTarget(target)
	if err != nil {
		return PingResult{}, err
	}
	c := *cfg
	opt.DeviceID = deviceID(opt) + "/ping"
	opt.Ports = nil // пинг не меняет запомненный порт подключения
	d, err := NewDialer(&c, opt)
	if err != nil {
		return PingResult{}, err
	}
	conn, err := pingDial(ctx, d)
	if err != nil {
		return PingResult{}, err
	}
	defer conn.Close()
	res := PingResult{Port: d.ports[int(d.cur.Load())%len(d.ports)], Target: target}

	prefixes, err := conn.WaitForAddress(ctx)
	if err != nil {
		return res, fmt.Errorf("сервер не выдал адрес: %w", err)
	}
	var src netip.Addr
	for _, p := range prefixes {
		if a := p.Addr().Unmap(); a.Is4() {
			src = a
			break
		}
	}
	if !src.IsValid() {
		return res, tunping.ErrNoIPv4
	}
	res.Addr = src
	dns, err := c.DNSServers()
	if err != nil {
		return res, err
	}
	dns = append(dns, fallbackDNS)

	r, err := pingGet(ctx, conn, src, dns, host, port, "/")
	if err != nil {
		return res, fmt.Errorf("%s через туннель: %w", host, err)
	}
	res.RTT, res.Status = r.RTT, r.Status
	return res, nil
}

// splitTarget разбирает «хост[:порт]».
func splitTarget(t string) (string, uint16, error) {
	host, ps, err := net.SplitHostPort(t)
	if err != nil {
		return t, 80, nil
	}
	p, err := strconv.ParseUint(ps, 10, 16)
	if err != nil || p == 0 {
		return "", 0, fmt.Errorf("пинг: неверный порт в %q", t)
	}
	return host, uint16(p), nil
}
