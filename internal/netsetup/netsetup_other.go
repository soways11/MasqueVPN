//go:build !linux && !windows

// Package netsetup — системная настройка сети для туннеля. На этой платформе
// пока не реализована.
package netsetup

import (
	"errors"
	"net/netip"
	"runtime"
	"syscall"
)

// ErrUnsupported — настройка сети на этой платформе не реализована.
var ErrUnsupported = errors.New("netsetup: платформа " + runtime.GOOS + " пока не поддерживается")

func IPv6Available() bool                                           { return false }
func ConfigureInterface(string, int, []netip.Prefix) error          { return ErrUnsupported }
func ReplaceAddresses(string, []netip.Prefix, []netip.Prefix) error { return ErrUnsupported }
func MarkSocket(syscall.RawConn, uint32) error                      { return ErrUnsupported }

// FullTunnel — см. реализацию для Linux.
type FullTunnel struct {
	Iface    string
	Table    int
	FwMark   uint32
	Priority int
	IPv6     bool
}

func (*FullTunnel) Up() error   { return ErrUnsupported }
func (*FullTunnel) Down() error { return nil }

func SetDNS([]netip.Addr) (func() error, error) { return nil, ErrUnsupported }
func AddRoutes(string, []netip.Prefix) error    { return ErrUnsupported }

func SystemResolvers() ([]netip.Addr, error) { return nil, ErrUnsupported }

// KillSwitchOff — заглушка: аварийное отключение есть только на Windows.
func KillSwitchOff() error { return nil }

// CleanupReport — см. реализацию для Windows.
type CleanupReport struct {
	KillSwitch bool
	NRPT       bool
	Routes     int
}

func (r CleanupReport) Empty() bool { return true }

func (r CleanupReport) String() string { return "следов прошлого запуска нет" }

// Cleanup — заглушка: следы, переживающие процесс (правило разрешения имён,
// блокировка файрвола), есть только на Windows. На Linux маршруты и правила
// живут в своей таблице и снимаются при выходе, а после аварии их
// перезаписывает следующий запуск.
func Cleanup() (CleanupReport, error) { return CleanupReport{}, nil }
