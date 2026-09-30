package client

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/soways11/masquevpn/internal/tunping"
)

// fakeTunnel — сессия, выдавшая адреса prefixes.
type fakeTunnel struct {
	prefixes []netip.Prefix
	closed   bool
}

func (f *fakeTunnel) ReadPacket([]byte) (int, error) { select {} }
func (f *fakeTunnel) WritePacket([]byte) error       { return nil }
func (f *fakeTunnel) WaitForAddress(context.Context) ([]netip.Prefix, error) {
	return f.prefixes, nil
}
func (f *fakeTunnel) Close() error { f.closed = true; return nil }

type getCall struct {
	src  netip.Addr
	dns  []netip.Addr
	host string
	port uint16
}

func stubPing(t *testing.T, tun *fakeTunnel, dialErr error) (*[]*Dialer, *getCall) {
	t.Helper()
	oldDial, oldGet := pingDial, pingGet
	t.Cleanup(func() { pingDial, pingGet = oldDial, oldGet })
	var dialers []*Dialer
	call := &getCall{}
	pingDial = func(ctx context.Context, d *Dialer) (tunnelConn, error) {
		dialers = append(dialers, d)
		if dialErr != nil {
			return nil, dialErr
		}
		return tun, nil
	}
	pingGet = func(ctx context.Context, pc tunping.PacketConn, src netip.Addr, dns []netip.Addr, host string, port uint16, path string) (tunping.Result, error) {
		*call = getCall{src, dns, host, port}
		return tunping.Result{RTT: 87 * time.Millisecond, Status: "HTTP/1.1 200 OK"}, nil
	}
	return &dialers, call
}

func TestPingThroughSession(t *testing.T) {
	tun := &fakeTunnel{prefixes: []netip.Prefix{
		netip.MustParsePrefix("fd00::5/128"),
		netip.MustParsePrefix("10.66.0.5/32"),
	}}
	dialers, call := stubPing(t, tun, nil)
	cfg := testClientConfig()
	cfg.Server = "192.0.2.10:8443,2053"
	cfg.DNS = []string{"2001:db8::53", "9.9.9.9"}
	cfg.Transport = ""
	before := *cfg

	res, err := Ping(t.Context(), cfg, Options{DeviceID: "phone"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Addr != netip.MustParseAddr("10.66.0.5") {
		t.Fatalf("адрес сессии пинга %v", res.Addr)
	}
	if res.RTT != 87*time.Millisecond || res.Status != "HTTP/1.1 200 OK" || res.Target != "example.com" || res.Port != "8443" {
		t.Fatalf("итог %+v", res)
	}
	// GET — на example.com:80, с IPv4-адреса туннеля, DNS профиля, затем запасной.
	if call.host != "example.com" || call.port != 80 || call.src != netip.MustParseAddr("10.66.0.5") {
		t.Fatalf("запрос %+v", call)
	}
	if len(call.dns) != 3 || call.dns[1] != netip.MustParseAddr("9.9.9.9") || call.dns[2] != fallbackDNS {
		t.Fatalf("DNS %v", call.dns)
	}
	if !tun.closed {
		t.Error("сессия пинга не закрыта — адрес остался бы занят")
	}
	// Отдельный псевдоним устройства: под своим пинг отнял бы адрес у
	// живой сессии того же профиля.
	d := (*dialers)[0]
	if d.opt.DeviceID != "phone/ping" {
		t.Fatalf("псевдоним устройства пинга %q", d.opt.DeviceID)
	}
	if d.opt.Ports != nil {
		t.Error("пинг меняет запомненный порт подключения")
	}
	if cfg.Transport != before.Transport || cfg.Server != before.Server {
		t.Fatalf("пинг изменил профиль: %+v", cfg)
	}
}

func TestPingTargetAndErrors(t *testing.T) {
	tun := &fakeTunnel{prefixes: []netip.Prefix{netip.MustParsePrefix("10.66.0.5/32")}}
	_, call := stubPing(t, tun, nil)
	cfg := testClientConfig()
	if _, err := Ping(t.Context(), cfg, Options{DeviceID: "x"}, "test.example:8080"); err != nil {
		t.Fatal(err)
	}
	if call.host != "test.example" || call.port != 8080 {
		t.Fatalf("цель %+v", call)
	}
	if _, err := Ping(t.Context(), cfg, Options{DeviceID: "x"}, "test.example:0"); err == nil {
		t.Fatal("порт 0 принят")
	}

	// Только IPv6 в туннеле.
	tun.prefixes = []netip.Prefix{netip.MustParsePrefix("fd00::5/128")}
	if _, err := Ping(t.Context(), cfg, Options{DeviceID: "x"}, ""); !errors.Is(err, tunping.ErrNoIPv4) {
		t.Fatalf("без IPv4: %v", err)
	}

	// Сессия не поднялась — ошибка дозвона как есть.
	stubPing(t, nil, errors.New("порты 443 не отвечают"))
	if _, err := Ping(t.Context(), cfg, Options{DeviceID: "x"}, ""); err == nil || !strings.Contains(err.Error(), "не отвечают") {
		t.Fatalf("ошибка дозвона: %v", err)
	}
}
