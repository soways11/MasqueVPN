package masque

import (
	"bufio"
	"bytes"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/quic-go/quic-go/http3"
)

func TestAddressAssignRoundTrip(t *testing.T) {
	in := []AssignedAddress{
		{RequestID: 0, Prefix: netip.MustParsePrefix("10.8.0.2/32")},
		{RequestID: 7, Prefix: netip.MustParsePrefix("fd00:8::/64")},
		{RequestID: 1 << 40, Prefix: netip.MustParsePrefix("192.168.0.0/16")},
	}
	b := EncodeAddressAssign(in)
	out, err := ParseAddressAssign(b)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(in, out) {
		t.Fatalf("got %v, want %v", out, in)
	}
	// Точный размер: varint(0)=1 + ver 1 + 4 + len 1 = 7; varint(7)=1+1+16+1=19;
	// varint(2^40)=8 +1+4+1 = 14.
	if len(b) != 7+19+14 {
		t.Fatalf("encoded size %d, want 40", len(b))
	}
}

func TestAddressRequestValidation(t *testing.T) {
	good := []RequestedAddress{{RequestID: 1, Prefix: netip.MustParsePrefix("0.0.0.0/32")}}
	out, err := ParseAddressRequest(EncodeAddressRequest(good))
	if err != nil || !slices.Equal(out, good) {
		t.Fatalf("got %v %v", out, err)
	}
	zeroID := []RequestedAddress{{RequestID: 0, Prefix: netip.MustParsePrefix("0.0.0.0/32")}}
	if _, err := ParseAddressRequest(EncodeAddressRequest(zeroID)); !errors.Is(err, errMalformedCapsule) {
		t.Fatalf("request ID 0 must be rejected, got %v", err)
	}
	if _, err := ParseAddressRequest(nil); !errors.Is(err, errMalformedCapsule) {
		t.Fatalf("empty request must be rejected, got %v", err)
	}
}

func TestMalformedAddress(t *testing.T) {
	cases := map[string][]byte{
		"bad version":      {0x00, 5, 1, 2, 3, 4, 32},
		"truncated addr":   {0x00, 4, 1, 2},
		"missing len":      {0x00, 4, 1, 2, 3, 4},
		"prefix too long":  {0x00, 4, 1, 2, 3, 4, 33},
		"host bits set":    {0x00, 4, 10, 0, 0, 1, 24},
		"truncated varint": {0x40},
	}
	for name, b := range cases {
		if _, err := ParseAddressAssign(b); !errors.Is(err, errMalformedCapsule) {
			t.Errorf("%s: want errMalformedCapsule, got %v", name, err)
		}
	}
}

func TestRouteAdvertisement(t *testing.T) {
	full := FullRoutes()
	out, err := ParseRouteAdvertisement(EncodeRouteAdvertisement(full))
	if err != nil || !slices.Equal(out, full) {
		t.Fatalf("got %v %v", out, err)
	}
	if n := len(EncodeRouteAdvertisement(full)); n != (1+4+4+1)+(1+16+16+1) {
		t.Fatalf("encoded size %d", n)
	}

	r := func(s, e string, p uint8) IPRoute {
		return IPRoute{Start: netip.MustParseAddr(s), End: netip.MustParseAddr(e), IPProtocol: p}
	}
	bad := map[string][]IPRoute{
		"v6 before v4":   {full[1], full[0]},
		"overlap":        {r("10.0.0.0", "10.0.0.255", 0), r("10.0.0.255", "10.0.1.0", 0)},
		"unordered":      {r("10.0.1.0", "10.0.1.255", 0), r("10.0.0.0", "10.0.0.255", 0)},
		"proto decrease": {r("10.0.0.0", "10.0.0.255", 17), r("11.0.0.0", "11.0.0.255", 6)},
		"start > end":    {r("10.0.0.9", "10.0.0.1", 0)},
	}
	for name, routes := range bad {
		if _, err := ParseRouteAdvertisement(EncodeRouteAdvertisement(routes)); !errors.Is(err, errMalformedCapsule) {
			t.Errorf("%s: want errMalformedCapsule, got %v", name, err)
		}
	}
	// Одинаковые диапазоны с разными протоколами допустимы.
	ok := []IPRoute{r("10.0.0.0", "10.0.0.255", 6), r("10.0.0.0", "10.0.0.255", 17)}
	if _, err := ParseRouteAdvertisement(EncodeRouteAdvertisement(ok)); err != nil {
		t.Fatalf("same range, different protocols: %v", err)
	}
}

func TestRouteContains(t *testing.T) {
	rt := IPRoute{Start: netip.MustParseAddr("10.0.0.0"), End: netip.MustParseAddr("10.0.0.255"), IPProtocol: 17}
	if !rt.Contains(netip.MustParseAddr("10.0.0.5"), 17) {
		t.Fatal("должен содержать")
	}
	if rt.Contains(netip.MustParseAddr("10.0.0.5"), 6) {
		t.Fatal("другой протокол")
	}
	if rt.Contains(netip.MustParseAddr("10.0.1.0"), 17) {
		t.Fatal("вне диапазона")
	}
	if rt.Contains(netip.MustParseAddr("::ffff:10.0.0.5"), 17) == false {
		t.Fatal("4in6 должен разворачиваться")
	}
}

func TestCapsuleStreamFraming(t *testing.T) {
	var buf bytes.Buffer
	w := bytesWriter{new([]byte)}
	_ = http3.WriteCapsule(w, CapsuleAddressAssign, EncodeAddressAssign([]AssignedAddress{{Prefix: netip.MustParsePrefix("10.8.0.2/32")}}))
	_ = http3.WriteCapsule(w, 0x1234, []byte("unknown"))
	_ = http3.WriteCapsule(w, CapsuleRouteAdvertisement, EncodeRouteAdvertisement(FullRoutes()))
	buf.Write(*w.b)

	r := bufio.NewReader(&buf)
	var types []uint64
	for {
		ct, _, err := readCapsule(r)
		if err != nil {
			break
		}
		types = append(types, uint64(ct))
	}
	if !slices.Equal(types, []uint64{1, 0x1234, 3}) {
		t.Fatalf("types %v", types)
	}

	// Слишком большая капсула отвергается.
	big := bytesWriter{new([]byte)}
	_ = http3.WriteCapsule(big, 0x99, make([]byte, maxCapsuleSize+1))
	if _, _, err := readCapsule(bufio.NewReader(bytes.NewReader(*big.b))); err == nil {
		t.Fatal("oversized capsule accepted")
	}
}

func TestDatagramFraming(t *testing.T) {
	pkt := []byte{0x45, 1, 2, 3}
	d := appendIPDatagram(nil, pkt, 0)
	if d[0] != contextIDIPPacket || len(d) != len(pkt)+1 {
		t.Fatalf("datagram %x", d)
	}
	ctx, got, ok := parseDatagram(d)
	if !ok || ctx != contextIDIPPacket || !bytes.Equal(got, pkt) {
		t.Fatal("round trip failed")
	}

	// Паддинг: полезная нагрузка вырастает, но IP-длина указывает на исходный пакет.
	padded := appendIPDatagram(nil, pkt, 64)
	if len(padded) != 65 {
		t.Fatalf("padded len %d, want 65", len(padded))
	}
	_, pl, _ := parseDatagram(padded)
	if !bytes.Equal(pl[:len(pkt)], pkt) {
		t.Fatal("padding corrupted payload")
	}

	// Cover-датаграмма.
	cover := appendCoverDatagram(nil, 100)
	ctx, cpl, ok := parseDatagram(cover)
	if !ok || ctx != contextIDPadding || len(cpl) != 100 {
		t.Fatalf("cover framing: ctx=%d len=%d", ctx, len(cpl))
	}

	if _, _, ok := parseDatagram(nil); ok {
		t.Fatal("empty datagram accepted")
	}
}

func TestIPPacketLen(t *testing.T) {
	p4 := buildIPv4(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), 17, []byte("hello"))
	if got := ipPacketLen(append(p4, make([]byte, 50)...)); got != len(p4) {
		t.Fatalf("ipv4 trim: got %d, want %d", got, len(p4))
	}
	p6 := buildIPv6(netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::2"), 17, []byte("hi"))
	if got := ipPacketLen(append(p6, make([]byte, 30)...)); got != len(p6) {
		t.Fatalf("ipv6 trim: got %d, want %d", got, len(p6))
	}
	// Заявленная длина больше доступной — некорректно.
	bad := buildIPv4(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), 17, nil)
	if got := ipPacketLen(bad[:15]); got != 0 {
		t.Fatalf("truncated: got %d", got)
	}
}

func TestParsePacket(t *testing.T) {
	p4 := buildIPv4(netip.MustParseAddr("10.8.0.2"), netip.MustParseAddr("1.1.1.1"), 17, []byte("x"))
	info, err := parsePacket(p4)
	if err != nil || info.Src.String() != "10.8.0.2" || info.Dst.String() != "1.1.1.1" || info.Proto != 17 {
		t.Fatalf("%+v %v", info, err)
	}
	p6 := buildIPv6(netip.MustParseAddr("fd00::2"), netip.MustParseAddr("2001:db8::1"), 58, nil)
	info, err = parsePacket(p6)
	if err != nil || info.Src.String() != "fd00::2" || info.Proto != 58 {
		t.Fatalf("%+v %v", info, err)
	}
	for _, b := range [][]byte{nil, {0x45}, {0x60, 0}, {0x75, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, {0x41, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}} {
		if _, err := parsePacket(b); err == nil {
			t.Errorf("accepted malformed %x", b)
		}
	}
}
