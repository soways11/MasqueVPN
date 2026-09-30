//go:build !linux

package clientrun

import (
	"github.com/soways11/masquevpn/internal/client"
	"github.com/soways11/masquevpn/internal/config"
)

// PingOptions — на Windows сокет не помечается: текущий сервер выведен из
// туннеля маршрутом, а сессия пинга к другому серверу при поднятом туннеле
// идёт через него (время тогда больше настоящего).
func PingOptions(*config.Client) client.Options { return client.Options{} }
