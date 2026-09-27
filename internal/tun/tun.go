// Package tun — TUN-интерфейс: источник и приёмник IP-пакетов устройства.
//
// Два способа получить устройство:
//
//   - Open — открыть интерфейс самим (Linux: /dev/net/tun). Нужны права
//     CAP_NET_ADMIN.
//   - FromFD — принять уже открытый дескриптор. Так работают мобильные
//     платформы: Android VpnService и iOS NEPacketTunnelProvider создают
//     интерфейс сами и отдают приложению готовый fd. Ядро VPN не должно
//     знать, откуда дескриптор взялся.
//
// Устройство отдаёт «голые» IP-пакеты, без заголовка packet info (IFF_NO_PI).
// Адреса, маршруты и MTU этот пакет НЕ настраивает — это internal/netsetup
// (на мобильных платформах — система).
package tun

import (
	"errors"
	"os"
	"sync/atomic"
)

// Device — открытый TUN-интерфейс.
type Device interface {
	// Name — имя интерфейса (может быть пустым для принятого fd, если его
	// не сообщили).
	Name() string
	// MTU — MTU, с которым работает устройство.
	MTU() int
	// Read читает один IP-пакет. Буфер должен вмещать MTU.
	Read(b []byte) (int, error)
	// Write записывает один IP-пакет в систему.
	Write(b []byte) (int, error)
	// Close закрывает устройство; заблокированный Read возвращает ошибку.
	Close() error
}

// ErrClosed — устройство закрыто.
var ErrClosed = errors.New("tun: device closed")

// fileDevice — устройство поверх файлового дескриптора. Дескриптор переводится
// в неблокирующий режим и отдаётся поллеру рантайма Go: так Close надёжно
// прерывает заблокированный Read, а чтение не занимает поток ОС.
type fileDevice struct {
	f      *os.File
	name   string
	mtu    int
	closed atomic.Bool
}

func (d *fileDevice) Name() string { return d.name }
func (d *fileDevice) MTU() int     { return d.mtu }

func (d *fileDevice) Read(b []byte) (int, error) {
	n, err := d.f.Read(b)
	if err != nil && d.closed.Load() {
		return 0, ErrClosed
	}
	return n, err
}

func (d *fileDevice) Write(b []byte) (int, error) {
	n, err := d.f.Write(b)
	if err != nil && d.closed.Load() {
		return 0, ErrClosed
	}
	return n, err
}

func (d *fileDevice) Close() error {
	if d.closed.Swap(true) {
		return nil
	}
	return d.f.Close()
}

// DefaultMTU — MTU по умолчанию для туннеля.
//
// 1280 — минимум, который IPv6 требует от любого канала (RFC 8200). Меньше
// ставить нельзя: IPv6-стеки игнорируют сообщения Packet Too Big ниже 1280, и
// IPv6 внутри туннеля просто перестал бы работать. Больше — можно, если
// QUIC-путь позволяет (см. README, «MTU»); лишнее разрешится через ICMP.
const DefaultMTU = 1280
