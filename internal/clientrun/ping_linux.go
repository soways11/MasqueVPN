//go:build linux

package clientrun

import (
	"os"
	"syscall"

	"github.com/soways11/masquevpn/internal/client"
	"github.com/soways11/masquevpn/internal/config"
	"github.com/soways11/masquevpn/internal/netsetup"
)

// PingOptions — сокет сессии пинга (QUIC к серверу) помечается той же
// меткой, что и сокет подключения. Тогда он идёт МИМО уже поднятого туннеля
// (правило маршрутизации по метке) и проходит аварийную блокировку (она
// пропускает помеченное): пинг другого сервера не заворачивается в текущий.
// Метку ставить может только root; без него — обычный сокет.
func PingOptions(cfg *config.Client) client.Options {
	if os.Geteuid() != 0 {
		return client.Options{}
	}
	mark := cfg.FwMark // та же, что возьмёт Run для этого профиля
	if mark == 0 {
		mark = netsetup.DefaultFwMark
	}
	return client.Options{Protect: func(rc syscall.RawConn) error {
		return netsetup.MarkSocket(rc, mark)
	}}
}
