//go:build linux

package tun

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Open создаёт (или подключается к существующему) TUN-интерфейсу name.
// Пустое name — ядро выберет имя само (tunN). Интерфейс создаётся
// выключенным и без адресов: поднять и настроить его — задача netsetup.
//
// mtu запоминается для Device.MTU; 0 — DefaultMTU.
func Open(name string, mtu int) (Device, error) {
	if len(name) >= unix.IFNAMSIZ {
		return nil, fmt.Errorf("tun: имя интерфейса длиннее %d байт: %q", unix.IFNAMSIZ-1, name)
	}
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("tun: open /dev/net/tun: %w", err)
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tun: %w", err)
	}
	// IFF_NO_PI — без 4-байтового заголовка packet info: читаем и пишем
	// голые IP-пакеты, как их отдаёт VpnService на Android.
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tun: TUNSETIFF %q: %w", name, err)
	}
	return newFileDevice(fd, ifr.Name(), mtu)
}

// FromFD оборачивает уже открытый TUN-дескриптор (Android VpnService.establish
// → ParcelFileDescriptor.detachFd). Дескриптор должен отдавать голые
// IP-пакеты (без packet info) — так работает Android. Устройство становится
// владельцем fd: Close его закроет.
//
// name необязателен — он нужен только для журналов и netsetup; на мобильных
// платформах сеть настраивает система, и имя не требуется.
func FromFD(fd int, name string, mtu int) (Device, error) {
	if fd < 0 {
		return nil, fmt.Errorf("tun: некорректный дескриптор %d", fd)
	}
	if name == "" {
		// На Linux имя можно узнать у самого дескриптора.
		if ifr, err := unix.NewIfreq(""); err == nil {
			if err := unix.IoctlIfreq(fd, unix.TUNGETIFF, ifr); err == nil {
				name = ifr.Name()
			}
		}
	}
	return newFileDevice(fd, name, mtu)
}

func newFileDevice(fd int, name string, mtu int) (Device, error) {
	if mtu <= 0 {
		mtu = DefaultMTU
	}
	// Неблокирующий режим ДО os.NewFile: тогда файл попадает в поллер
	// рантайма, и Close прерывает заблокированный Read.
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tun: set nonblock: %w", err)
	}
	f := os.NewFile(uintptr(fd), "tun:"+name)
	return &fileDevice{f: f, name: name, mtu: mtu}, nil
}
