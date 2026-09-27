package netsetup

import (
	"net/netip"
	"testing"
)

// Порядок байт — то место, где ошибка не видна глазом. FWP_V4_ADDR_AND_MASK
// ждёт UINT32 в порядке хоста; перепутать с сетевым — значит разрешить не ту
// подсеть, и разрешение «к серверу» откроет дорогу к чужому адресу, а не к
// нужному.
func TestBigEndianToHostOrder(t *testing.T) {
	got := beToHost(netip.MustParseAddr("1.2.3.4").As4())
	want := uint32(0x01020304)
	if got != want {
		t.Fatalf("beToHost = 0x%08x, ожидалось 0x%08x", got, want)
	}
	// 192.168.1.1 — частый адрес роутера, проверим и его.
	if got := beToHost(netip.MustParseAddr("192.168.1.1").As4()); got != 0xc0a80101 {
		t.Fatalf("192.168.1.1 → 0x%08x", got)
	}
}

// Маска очерчивает подсеть разрешающего фильтра. Слишком широкая — дыра,
// слишком узкая — отрезанная сеть.
func TestPrefixMask(t *testing.T) {
	cases := []struct {
		bits int
		mask uint32
	}{
		{0, 0x00000000},  // всё
		{8, 0xff000000},  // /8
		{12, 0xfff00000}, // /12 — как у 172.16/12
		{16, 0xffff0000}, // /16
		{24, 0xffffff00}, // /24
		{32, 0xffffffff}, // один адрес
	}
	for _, c := range cases {
		if got := prefixMask4(c.bits); got != c.mask {
			t.Errorf("prefixMask4(%d) = 0x%08x, ожидалось 0x%08x", c.bits, got, c.mask)
		}
	}
}

// Проверка согласованности: адрес под маской своего же префикса должен
// оставаться собой (маска не срезает значащих бит сети).
func TestAddrAndMaskAgree(t *testing.T) {
	for _, s := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"} {
		p := netip.MustParsePrefix(s)
		addr := beToHost(p.Addr().As4())
		mask := prefixMask4(p.Bits())
		if addr&mask != addr {
			t.Errorf("%s: адрес 0x%08x не выравнен по маске 0x%08x — фильтр очертит не ту сеть",
				s, addr, mask)
		}
	}
}
