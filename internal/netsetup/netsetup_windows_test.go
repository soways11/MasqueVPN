//go:build windows

package netsetup

import (
	"net/netip"
	"testing"
	"unsafe"
)

// TestStructLayout — раскладка структур IP Helper API должна совпадать с
// netioapi.h байт в байт. Ошибка здесь не вызвала бы отказа: система просто
// прочитала бы не те поля и испортила память, поэтому размеры проверяются
// явно.
func TestStructLayout(t *testing.T) {
	for _, c := range []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"MIB_UNICASTIPADDRESS_ROW", unsafe.Sizeof(mibUnicastIPAddressRow{}), 72},
		{"IP_ADDRESS_PREFIX", unsafe.Sizeof(ipAddressPrefix{}), 32},
		{"MIB_IPFORWARD_ROW2", unsafe.Sizeof(mibIPForwardRow2{}), 104},
		{"MIB_IPINTERFACE_ROW", unsafe.Sizeof(mibIPInterfaceRow{}), 168},
		{"SOCKADDR_INET", unsafe.Sizeof(sockaddrInet{}), 28},
	} {
		if c.got != c.want {
			t.Errorf("%s: размер %d, ожидался %d", c.name, c.got, c.want)
		}
	}
	// Смещения полей, которые заполняем вручную.
	var row mibIPForwardRow2
	base := uintptr(unsafe.Pointer(&row))
	for _, c := range []struct {
		name string
		off  uintptr
		want uintptr
	}{
		{"InterfaceIndex", uintptr(unsafe.Pointer(&row.InterfaceIndex)) - base, 8},
		{"DestinationPrefix", uintptr(unsafe.Pointer(&row.DestinationPrefix)) - base, 12},
		{"NextHop", uintptr(unsafe.Pointer(&row.NextHop)) - base, 44},
		{"Metric", uintptr(unsafe.Pointer(&row.Metric)) - base, 84},
	} {
		if c.off != c.want {
			t.Errorf("MIB_IPFORWARD_ROW2.%s: смещение %d, ожидалось %d", c.name, c.off, c.want)
		}
	}
	var ifr mibIPInterfaceRow
	ibase := uintptr(unsafe.Pointer(&ifr))
	for _, c := range []struct {
		name string
		off  uintptr
		want uintptr
	}{
		{"InterfaceLUID", uintptr(unsafe.Pointer(&ifr.InterfaceLUID)) - ibase, 8},
		{"SitePrefixLength", uintptr(unsafe.Pointer(&ifr.SitePrefixLength)) - ibase, 144},
		{"NlMtu", uintptr(unsafe.Pointer(&ifr.NlMtu)) - ibase, 152},
	} {
		if c.off != c.want {
			t.Errorf("MIB_IPINTERFACE_ROW.%s: смещение %d, ожидалось %d", c.name, c.off, c.want)
		}
	}
}

// TestSockaddr — кодирование адресов в SOCKADDR_INET: семейство и сам адрес
// должны лечь туда, где их ждёт система.
func TestSockaddr(t *testing.T) {
	for _, s := range []string{"10.66.0.2", "192.168.1.1", "fd00::2", "2001:db8::1"} {
		a := netip.MustParseAddr(s)
		got, ok := fromSockaddr(toSockaddr(a))
		if !ok || got != a {
			t.Errorf("%s → %v (ok=%v)", s, got, ok)
		}
	}
	// IPv4 лежит со смещения 4 (после семейства и порта), IPv6 — с 8.
	v4 := toSockaddr(netip.MustParseAddr("1.2.3.4"))
	if v4[0] != afINET || v4[4] != 1 || v4[7] != 4 {
		t.Errorf("IPv4: % x", v4[:8])
	}
	v6 := toSockaddr(netip.MustParseAddr("::1"))
	if v6[0] != afINET6 || v6[23] != 1 {
		t.Errorf("IPv6: % x", v6[:24])
	}
}
