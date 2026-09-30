package core

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/soways11/masquevpn/internal/client"
	"github.com/soways11/masquevpn/internal/config"
)

func TestPingJSON(t *testing.T) {
	old := pingFn
	defer func() { pingFn = old }()

	var gotOpt client.Options
	var gotTarget string
	pingFn = func(ctx context.Context, cfg *config.Client, opt client.Options, target string) (client.PingResult, error) {
		gotTarget = target
		gotOpt = opt
		if _, ok := ctx.Deadline(); !ok {
			t.Error("пинг без срока: мог бы висеть вечно")
		}
		if cfg.Server == "down.example.com:443" {
			return client.PingResult{}, context.DeadlineExceeded
		}
		return client.PingResult{RTT: 38 * time.Millisecond, Port: "8443", Target: target, Status: "HTTP/1.1 200 OK"}, nil
	}

	var r pingResult
	if err := json.Unmarshal([]byte(Ping(testConfig(""), "a1b2c3")), &r); err != nil {
		t.Fatal(err)
	}
	if !r.OK || r.RTTMs != 38 || r.Text != "38 мс" || r.Port != "8443" {
		t.Fatalf("ответ %+v", r)
	}
	// Без Protect клиент не возьмёт Resolvers, а своего DNS у Go на Android нет.
	if gotOpt.Protect == nil {
		t.Error("нет зацепки Protect — резолверы телефона не применятся")
	}
	// Псевдоним телефона (client.Ping допишет «/ping»): без него клиент
	// полез бы за файлом рядом с программой, которого на Android нет.
	if gotOpt.DeviceID != "a1b2c3" {
		t.Errorf("псевдоним устройства %q", gotOpt.DeviceID)
	}
	if gotTarget != client.DefaultPingTarget || r.Target != "example.com" || r.Status != "HTTP/1.1 200 OK" {
		t.Errorf("цель %q, ответ %+v", gotTarget, r)
	}

	cfg := parseCfg(t, "")
	cfg.Server = "down.example.com:443"
	raw, _ := json.Marshal(cfg)
	r = pingResult{}
	if err := json.Unmarshal([]byte(Ping(string(raw), "a1b2c3")), &r); err != nil {
		t.Fatal(err)
	}
	if r.OK || r.Text != "нет" || r.Error != "время вышло" {
		t.Fatalf("ответ %+v", r)
	}

	r = pingResult{}
	_ = json.Unmarshal([]byte(Ping(`{"битая`, "a1b2c3")), &r)
	if r.OK || r.Error == "" {
		t.Fatalf("битая конфигурация: %+v", r)
	}
}

func TestConfigFor(t *testing.T) {
	p, err := LoadProfiles("")
	if err != nil {
		t.Fatal(err)
	}
	if res := p.Add("vpn.example.com:443", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "", "Дом"); !json.Valid([]byte(res)) {
		t.Fatal(res)
	}
	got := p.ConfigFor("дом")
	cfg, err := config.ParseClient([]byte(got))
	if err != nil {
		t.Fatalf("%v: %s", err, got)
	}
	if cfg.Server != "vpn.example.com:443" {
		t.Fatalf("сервер %q", cfg.Server)
	}
	if p.ConfigFor("нет такого") != "" {
		t.Error("конфигурация несуществующего профиля")
	}
}
