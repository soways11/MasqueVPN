package core

import (
	"context"
	"encoding/json"
	"strings"
	"syscall"

	"github.com/soways11/masquevpn/internal/client"
	"github.com/soways11/masquevpn/internal/clientrun"
	"github.com/soways11/masquevpn/internal/config"
	"github.com/soways11/masquevpn/internal/gui"
)

// Пинг профиля на телефоне — тот же client.Ping, что в окнах Windows и
// Linux: настоящая сессия CONNECT-IP (под псевдонимом устройства + «/ping»,
// чтобы не отнять адрес у живой сессии) и HTTP GET на example.com через неё.
//
// Сокет не защищается через VpnService.protect: приложение само выведено из
// своего туннеля (addDisallowedApplication в MasqueService), так что его
// сокеты и так идут мимо. Пустая зацепка Protect всё равно нужна — только с
// ней клиент берёт резолверы из Resolvers, а своего списка DNS у Go на
// Android нет (см. bootstrapResolvers).

// pingResult — ответ Ping для экрана.
type pingResult struct {
	OK    bool   `json:"ok"`
	RTTMs int64  `json:"rtt_ms,omitempty"`
	Port  string `json:"port,omitempty"`
	// Target и Status — куда ходил запрос и что ответили (для журнала).
	Target string `json:"target,omitempty"`
	Status string `json:"status,omitempty"`
	// Text — надпись на кнопке: «38 мс» или «нет».
	Text string `json:"text"`
	// Error — причина неудачи для журнала.
	Error string `json:"error,omitempty"`
}

// pingFn — сама проверка; подменяется в тестах.
var pingFn = client.Ping

// Ping поднимает сессию по профилю и делает через неё GET на example.com.
// Блокирует до ответа (не дольше clientrun.PingTimeout) — звать из фонового
// потока. configJSON — как для Tunnel.Connect (Profiles.ConfigFor +
// Store.withSystemResolvers), deviceID — тот же, что Tunnel.SetDeviceID.
// Ответ: {"ok":true,"rtt_ms":142,"port":"443","target":"example.com",
// "status":"HTTP/1.1 200 OK","text":"142 мс"} или
// {"ok":false,"text":"нет","error":"…"}.
func Ping(configJSON, deviceID string) string {
	fail := func(msg string) string { return mustJSON(pingResult{Text: "нет", Error: msg}) }
	cfg, err := config.ParseClient([]byte(configJSON))
	if err != nil {
		return fail("конфигурация: " + err.Error())
	}
	opt := client.Options{
		DeviceID:  deviceID, // client.Ping допишет «/ping»
		Protect:   func(syscall.RawConn) error { return nil },
		Resolvers: bootstrapResolvers(cfg),
	}
	ctx, cancel := context.WithTimeout(context.Background(), clientrun.PingTimeout)
	defer cancel()
	res, err := pingFn(ctx, cfg, opt, client.DefaultPingTarget)
	if err != nil {
		return fail(clientrun.PingReason(err))
	}
	return mustJSON(pingResult{OK: true, RTTMs: res.RTT.Milliseconds(), Port: res.Port,
		Target: res.Target, Status: res.Status, Text: gui.FormatRTT(res.RTT)})
}

// ConfigFor — полная конфигурация профиля name (для Ping). Нет такого —
// пустая строка.
func (p *Profiles) ConfigFor(name string) string {
	for _, pr := range p.p.List {
		if pr.Config != nil && strings.EqualFold(pr.Name, name) {
			raw, err := json.Marshal(pr.Config)
			if err != nil {
				return ""
			}
			return string(raw)
		}
	}
	return ""
}
