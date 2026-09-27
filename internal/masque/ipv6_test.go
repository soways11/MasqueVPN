package masque

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

// ipv6WithExt собирает IPv6-пакет с цепочкой extension-заголовков.
// ext — список пар (тип этого заголовка, его длина в байтах).
func ipv6WithExt(upper uint8, ext []struct {
	typ uint8
	len int
}) []byte {
	var chain []byte
	// собираем с конца: последний заголовок указывает на upper
	next := upper
	for i := len(ext) - 1; i >= 0; i-- {
		e := ext[i]
		h := make([]byte, e.len)
		h[0] = next
		if e.typ == 44 { // fragment: фиксированные 8 байт, offset=0
			binary.BigEndian.PutUint16(h[2:4], 0)
		} else if e.typ == 51 { // AH: (len+2)*4
			h[1] = byte(e.len/4 - 2)
		} else {
			h[1] = byte(e.len/8 - 1)
		}
		chain = append(h, chain...)
		next = e.typ
	}
	b := make([]byte, 40+len(chain)+8)
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:6], uint16(len(chain)+8))
	b[6] = next
	b[7] = 64
	s := netip.MustParseAddr("fd00::1").As16()
	d := netip.MustParseAddr("fd00::2").As16()
	copy(b[8:], s[:])
	copy(b[24:], d[:])
	copy(b[40:], chain)
	return b
}

type extHdr = struct {
	typ uint8
	len int
}

func TestIPv6ExtensionHeaderChain(t *testing.T) {
	cases := map[string]struct {
		ext  []extHdr
		want uint8
	}{
		"без расширений":           {nil, 17},
		"hop-by-hop":               {[]extHdr{{0, 8}}, 17},
		"routing":                  {[]extHdr{{43, 24}}, 17},
		"dest opts":                {[]extHdr{{60, 16}}, 17},
		"fragment (первый)":        {[]extHdr{{44, 8}}, 17},
		"AH":                       {[]extHdr{{51, 24}}, 17},
		"цепочка hop+routing+dest": {[]extHdr{{0, 8}, {43, 24}, {60, 8}}, 17},
		"mobility":                 {[]extHdr{{135, 8}}, 17},
	}
	for name, c := range cases {
		pkt := ipv6WithExt(c.want, c.ext)
		info, err := parsePacket(pkt)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if info.Proto != c.want {
			t.Errorf("%s: протокол %d, ожидался %d", name, info.Proto, c.want)
		}
		if info.Src.String() != "fd00::1" {
			t.Errorf("%s: src разобран неверно: %v", name, info.Src)
		}
	}
}

// TestIPv6ExtensionHeadersAffectPolicy — ради чего всё и делалось: с маршрутом,
// ограниченным протоколом, пакет с extension-заголовком раньше отбрасывался.
func TestIPv6ExtensionHeadersAffectPolicy(t *testing.T) {
	route := IPRoute{
		Start:      netip.MustParseAddr("fd00::"),
		End:        netip.MustParseAddr("fd00::ffff"),
		IPProtocol: 17, // только UDP
	}
	plain := ipv6WithExt(17, nil)
	withExt := ipv6WithExt(17, []extHdr{{0, 8}, {60, 16}})

	for name, pkt := range map[string][]byte{"без расширений": plain, "с расширениями": withExt} {
		info, err := parsePacket(pkt)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !route.Contains(info.Dst, info.Proto) {
			t.Errorf("%s: пакет отброшен маршрутом (протокол прочитан как %d)", name, info.Proto)
		}
	}

	// Чужой протокол по-прежнему не проходит — проверка не ослабла.
	tcp := ipv6WithExt(6, []extHdr{{0, 8}})
	info, _ := parsePacket(tcp)
	if route.Contains(info.Dst, info.Proto) {
		t.Errorf("TCP прошёл через маршрут, разрешающий только UDP (протокол=%d)", info.Proto)
	}
}

func TestIPv6MalformedExtensionChain(t *testing.T) {
	// Обрыв цепочки не должен приводить к панике или уходу за границы.
	pkt := ipv6WithExt(17, []extHdr{{0, 8}, {60, 16}})
	for cut := 40; cut < len(pkt); cut++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("паника на обрезке %d: %v", cut, r)
				}
			}()
			_, _ = parsePacket(pkt[:cut])
		}()
	}
	// Заголовок с нулевой длиной не должен зациклить обход.
	loop := make([]byte, 60)
	loop[0] = 0x60
	binary.BigEndian.PutUint16(loop[4:6], 20)
	loop[6] = 0 // hop-by-hop
	for i := 40; i < 60; i += 8 {
		loop[i] = 0 // снова hop-by-hop
		loop[i+1] = 0
	}
	done := make(chan uint8, 1)
	go func() { info, _ := parsePacket(loop); done <- info.Proto }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("обход цепочки зациклился")
	}
}
