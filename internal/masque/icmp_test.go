package masque

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// TestICMPv4FragNeeded — ответ должен быть корректным ICMPv4 с указанием MTU
// и вложенной копией исходного пакета, иначе стек отправителя его проигнорирует.
func TestICMPv4FragNeeded(t *testing.T) {
	src := netip.MustParseAddr("10.8.0.2")
	dst := netip.MustParseAddr("1.1.1.1")
	orig := buildIPv4(src, dst, 6, make([]byte, 1400))

	icmp := buildICMPTooBig(orig, 1200, netip.Addr{})
	if icmp == nil {
		t.Fatal("ICMP не построен")
	}
	info, err := parsePacket(icmp)
	if err != nil {
		t.Fatalf("получился неразбираемый пакет: %v", err)
	}
	// Идёт обратно отправителю исходного пакета.
	if info.Dst != src {
		t.Fatalf("адресован %v, ожидался %v", info.Dst, src)
	}
	// По умолчанию «от имени» получателя исходного пакета.
	if info.Src != dst {
		t.Fatalf("отправитель %v, ожидался %v", info.Src, dst)
	}
	if info.Proto != protoICMPv4 {
		t.Fatalf("протокол %d, ожидался ICMP", info.Proto)
	}

	body := icmp[20:]
	if body[0] != icmpv4DestUnreachable || body[1] != icmpv4CodeFragNeeded {
		t.Fatalf("тип/код = %d/%d, ожидалось 3/4", body[0], body[1])
	}
	if mtu := binary.BigEndian.Uint16(body[6:8]); mtu != 1200 {
		t.Fatalf("MTU в сообщении = %d, ожидалось 1200", mtu)
	}
	// Вложены заголовок исходного пакета и 8 байт данных — по ним стек находит
	// нужное соединение.
	if len(body) < 8+20+8 {
		t.Fatalf("вложено слишком мало: %d байт", len(body)-8)
	}
	if string(body[8:8+20]) != string(orig[:20]) {
		t.Fatal("вложенный заголовок не совпадает с исходным")
	}
	// Контрольные суммы должны сходиться.
	if got := checksum(icmp[:20]); got != 0 {
		t.Fatalf("контрольная сумма IP не сходится: %#x", got)
	}
	if got := checksum(body); got != 0 {
		t.Fatalf("контрольная сумма ICMP не сходится: %#x", got)
	}
}

func TestICMPv6PacketTooBig(t *testing.T) {
	src := netip.MustParseAddr("fd00::2")
	dst := netip.MustParseAddr("2001:db8::1")
	orig := buildIPv6(src, dst, 6, make([]byte, 1400))

	icmp := buildICMPTooBig(orig, 1280, netip.Addr{})
	if icmp == nil {
		t.Fatal("ICMP не построен")
	}
	info, err := parsePacket(icmp)
	if err != nil {
		t.Fatalf("неразбираемый пакет: %v", err)
	}
	if info.Dst != src || info.Proto != protoICMPv6 {
		t.Fatalf("адресат %v, протокол %d", info.Dst, info.Proto)
	}
	body := icmp[40:]
	if body[0] != icmpv6PacketTooBig {
		t.Fatalf("тип %d, ожидался 2", body[0])
	}
	if mtu := binary.BigEndian.Uint32(body[4:8]); mtu != 1280 {
		t.Fatalf("MTU = %d", mtu)
	}
	// Весь пакет не должен превышать минимальный MTU IPv6.
	if len(icmp) > 1280 {
		t.Fatalf("ответ %d байт — больше минимального MTU IPv6", len(icmp))
	}
	if got := icmpv6Checksum(info.Src, info.Dst, body); got != 0 {
		t.Fatalf("контрольная сумма ICMPv6 не сходится: %#x", got)
	}
}

// TestICMPNoLoop — на ICMP-ошибку нельзя отвечать ICMP-ошибкой, иначе два узла
// начнут гонять сообщения по кругу.
func TestICMPNoLoop(t *testing.T) {
	orig := buildIPv4(netip.MustParseAddr("10.8.0.2"), netip.MustParseAddr("1.1.1.1"), 6, make([]byte, 100))
	errPkt := buildICMPTooBig(orig, 1200, netip.Addr{})
	if errPkt == nil {
		t.Fatal("первый ICMP не построен")
	}
	if again := buildICMPTooBig(errPkt, 1000, netip.Addr{}); again != nil {
		t.Fatal("на ICMP-ошибку построен ещё один ICMP — это петля")
	}

	// А на ping (echo request) отвечать можно: это не ошибка.
	ping := buildIPv4(netip.MustParseAddr("10.8.0.2"), netip.MustParseAddr("1.1.1.1"), protoICMPv4, nil)
	ping = append(ping, 8, 0, 0, 0, 0, 0, 0, 0) // тип 8 = echo request
	binary.BigEndian.PutUint16(ping[2:4], uint16(len(ping)))
	if buildICMPTooBig(ping, 1200, netip.Addr{}) == nil {
		t.Fatal("на echo request ICMP не построен, хотя это не ошибка")
	}
}

func TestICMPCustomSource(t *testing.T) {
	gw := netip.MustParseAddr("10.8.0.1")
	orig := buildIPv4(netip.MustParseAddr("10.8.0.2"), netip.MustParseAddr("1.1.1.1"), 6, make([]byte, 100))
	icmp := buildICMPTooBig(orig, 1200, gw)
	info, _ := parsePacket(icmp)
	if info.Src != gw {
		t.Fatalf("отправитель %v, ожидался шлюз %v", info.Src, gw)
	}
}

func TestICMPGarbageIgnored(t *testing.T) {
	for name, pkt := range map[string][]byte{
		"пусто":   nil,
		"мусор":   {0xff, 0xff},
		"обрывок": {0x45, 0x00},
	} {
		if buildICMPTooBig(pkt, 1200, netip.Addr{}) != nil {
			t.Errorf("%s: построен ICMP на неразбираемый пакет", name)
		}
	}
}
