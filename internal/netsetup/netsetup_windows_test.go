//go:build windows

package netsetup

import (
	"net/netip"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
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

// TestFilterPlanCoversPacketLayers — набор фильтров должен стоять и на слоях
// ALE (решение при установлении соединения), и на пакетных (решение на каждый
// пакет). Без пакетных слоёв блокировка не видит соединений, открытых ДО её
// включения: они продолжают идти мимо туннеля открытым текстом.
//
// Мутация: убрать пакетные слои из плана — тест краснеет.
func TestFilterPlanCoversPacketLayers(t *testing.T) {
	const luid = 0x1234
	allow := []netip.Prefix{
		netip.MustParsePrefix("203.0.113.7/32"),
		netip.MustParsePrefix("2001:db8::7/128"),
	}
	type counts struct{ permit, block int }
	byLayer := map[windows.GUID]*counts{}
	for _, spec := range append(filterPlan(luid, allow), packetFilterPlan(luid, allow)...) {
		c := byLayer[spec.layer]
		if c == nil {
			c = &counts{}
			byLayer[spec.layer] = c
		}
		switch spec.action {
		case actionPermit:
			c.permit++
		case actionBlock:
			c.block++
		default:
			t.Errorf("%s: неизвестное действие %#x", spec.name, spec.action)
		}
	}
	for _, l := range []struct {
		name  string
		layer windows.GUID
	}{
		{"ALE v4", layerAleAuthConnectV4},
		{"ALE v6", layerAleAuthConnectV6},
		{"пакетный v4", layerOutboundIPPacketV4},
		{"пакетный v6", layerOutboundIPPacketV6},
	} {
		c := byLayer[l.layer]
		if c == nil {
			t.Errorf("слой %s не покрыт фильтрами: трафик этого слоя не перехватывается", l.name)
			continue
		}
		if c.block != 1 {
			t.Errorf("слой %s: блокирующих фильтров %d, нужен ровно один", l.name, c.block)
		}
		// Разрешения: туннель, локальные диапазоны и один адрес из allow
		// своей семьи. Без них блокировка отрезала бы и сам туннель.
		if want := len(localPrefixes(l.layer == layerAleAuthConnectV6 || l.layer == layerOutboundIPPacketV6)) + 2; c.permit != want {
			t.Errorf("слой %s: разрешающих фильтров %d, ожидалось %d", l.name, c.permit, want)
		}
	}
}

// TestPacketPlanMirrorsALE — пакетный набор повторяет набор ALE один в один,
// только на других слоях: разрешения обязаны совпадать, иначе блокировка на
// пакетном слое отрежет то, что ALE пропускает (например сам туннель).
func TestPacketPlanMirrorsALE(t *testing.T) {
	const luid = 0x1234
	allow := []netip.Prefix{netip.MustParsePrefix("203.0.113.7/32")}
	ale, pkt := filterPlan(luid, allow), packetFilterPlan(luid, allow)
	if len(ale) != len(pkt) {
		t.Fatalf("фильтров ALE %d, пакетных %d — наборы разошлись", len(ale), len(pkt))
	}
	for i := range ale {
		if ale[i].name != pkt[i].name || ale[i].action != pkt[i].action ||
			len(ale[i].conditions) != len(pkt[i].conditions) {
			t.Errorf("фильтр %d: %q/%#x против %q/%#x", i,
				ale[i].name, ale[i].action, pkt[i].name, pkt[i].action)
		}
		if ale[i].layer == pkt[i].layer {
			t.Errorf("фильтр %d стоит на том же слое — пакетный набор не добавляет ничего", i)
		}
	}
}
