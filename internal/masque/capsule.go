package masque

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

// Типы капсул CONNECT-IP (RFC 9484, раздел 4.7).
const (
	CapsuleAddressAssign      http3.CapsuleType = 0x01
	CapsuleAddressRequest     http3.CapsuleType = 0x02
	CapsuleRouteAdvertisement http3.CapsuleType = 0x03
	maxCapsuleSize                              = 1 << 16

	// CapsuleFramingSupport — наша капсула согласования расширений.
	// Значение вне диапазонов RFC 9484: «govp» в ASCII. Её шлёт каждая
	// сторона сразу после открытия сессии; та, что её не понимает, молча
	// игнорирует (RFC 9297, 3.2), и обмен идёт по-старому — Context ID 0,
	// пакет в датаграмме, без cover.
	//
	// Согласуются оба наших Context ID помимо нулевого: кадрирование (2) и
	// cover-датаграммы (1). RFC 9484 отводит под IP-пакеты только ноль,
	// остальные значения — под расширения, поэтому слать их, не
	// договорившись, нельзя: сторонняя реализация сочла бы это мусором.
	CapsuleFramingSupport http3.CapsuleType = 0x676f7670

	// framingVersion — версия формата кадров.
	framingVersion = 1
)

// Флаги капсулы согласования.
const (
	extFraming = 1 << iota // понимаю кадрированные датаграммы (Context ID 2)
	extCover               // принимаю cover-датаграммы (Context ID 1)
)

// EncodeFramingSupport собирает капсулу согласования.
func EncodeFramingSupport(framing, cover bool) []byte {
	var flags uint64
	if framing {
		flags |= extFraming
	}
	if cover {
		flags |= extCover
	}
	b := quicvarint.Append(nil, framingVersion)
	return quicvarint.Append(b, flags)
}

// ParseFramingSupport разбирает капсулу согласования: совместима ли версия
// и какие расширения принимает другая сторона.
func ParseFramingSupport(b []byte) (framing, cover bool, err error) {
	v, n, err := quicvarint.Parse(b)
	if err != nil {
		return false, false, errMalformedCapsule
	}
	if v != framingVersion {
		return false, false, nil
	}
	flags, _, err := quicvarint.Parse(b[n:])
	if err != nil {
		return false, false, errMalformedCapsule
	}
	return flags&extFraming != 0, flags&extCover != 0, nil
}

var errMalformedCapsule = errors.New("masque: malformed capsule")

// AssignedAddress — элемент капсулы ADDRESS_ASSIGN.
// RequestID = 0 означает незапрошенное (проактивное) назначение.
type AssignedAddress struct {
	RequestID uint64
	Prefix    netip.Prefix
}

// RequestedAddress — элемент капсулы ADDRESS_REQUEST.
// RequestID обязан быть ненулевым и уникальным в рамках сессии.
// Адрес из одних нулей означает «без предпочтений».
type RequestedAddress struct {
	RequestID uint64
	Prefix    netip.Prefix
}

// IPRoute — элемент капсулы ROUTE_ADVERTISEMENT: диапазон [Start, End]
// и IP-протокол (0 = любой).
type IPRoute struct {
	Start      netip.Addr
	End        netip.Addr
	IPProtocol uint8
}

// Contains сообщает, попадает ли адрес (и протокол) в маршрут.
func (r IPRoute) Contains(a netip.Addr, proto uint8) bool {
	if r.IPProtocol != 0 && r.IPProtocol != proto {
		return false
	}
	a = a.Unmap()
	return a.BitLen() == r.Start.BitLen() && r.Start.Compare(a) <= 0 && a.Compare(r.End) <= 0
}

// FullRoutes — маршруты «весь интернет» для IPv4 и IPv6.
func FullRoutes() []IPRoute {
	return []IPRoute{
		{Start: netip.IPv4Unspecified(), End: netip.AddrFrom4([4]byte{255, 255, 255, 255})},
		{Start: netip.IPv6Unspecified(), End: netip.AddrFrom16([16]byte{
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})},
	}
}

// ---------- кодирование ----------

func appendAddr(b []byte, a netip.Addr) []byte {
	if a.Is4() {
		b = append(b, 4)
	} else {
		b = append(b, 6)
	}
	return append(b, a.AsSlice()...)
}

func appendPrefix(b []byte, p netip.Prefix) []byte {
	b = appendAddr(b, p.Addr())
	return append(b, byte(p.Bits()))
}

// EncodeAddressAssign кодирует значение капсулы ADDRESS_ASSIGN.
func EncodeAddressAssign(addrs []AssignedAddress) []byte {
	var b []byte
	for _, a := range addrs {
		b = quicvarint.Append(b, a.RequestID)
		b = appendPrefix(b, a.Prefix)
	}
	return b
}

// EncodeAddressRequest кодирует значение капсулы ADDRESS_REQUEST.
func EncodeAddressRequest(reqs []RequestedAddress) []byte {
	var b []byte
	for _, r := range reqs {
		b = quicvarint.Append(b, r.RequestID)
		b = appendPrefix(b, r.Prefix)
	}
	return b
}

// EncodeRouteAdvertisement кодирует значение капсулы ROUTE_ADVERTISEMENT.
func EncodeRouteAdvertisement(routes []IPRoute) []byte {
	var b []byte
	for _, r := range routes {
		b = appendAddr(b, r.Start)
		b = append(b, r.End.AsSlice()...)
		b = append(b, r.IPProtocol)
	}
	return b
}

// ---------- декодирование ----------

func readAddr(r *bytes.Reader) (netip.Addr, byte, error) {
	ver, err := r.ReadByte()
	if err != nil {
		return netip.Addr{}, 0, errMalformedCapsule
	}
	var n int
	switch ver {
	case 4:
		n = 4
	case 6:
		n = 16
	default:
		return netip.Addr{}, 0, fmt.Errorf("%w: invalid IP version %d", errMalformedCapsule, ver)
	}
	return readRawAddr(r, n, ver)
}

func readRawAddr(r *bytes.Reader, n int, ver byte) (netip.Addr, byte, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return netip.Addr{}, 0, errMalformedCapsule
	}
	a, _ := netip.AddrFromSlice(buf)
	return a, ver, nil
}

func readPrefix(r *bytes.Reader) (netip.Prefix, error) {
	a, _, err := readAddr(r)
	if err != nil {
		return netip.Prefix{}, err
	}
	bits, err := r.ReadByte()
	if err != nil {
		return netip.Prefix{}, errMalformedCapsule
	}
	if int(bits) > a.BitLen() {
		return netip.Prefix{}, fmt.Errorf("%w: prefix length %d too long", errMalformedCapsule, bits)
	}
	p := netip.PrefixFrom(a, int(bits))
	if p.Masked() != p {
		return netip.Prefix{}, fmt.Errorf("%w: bits set beyond prefix length in %s", errMalformedCapsule, p)
	}
	return p, nil
}

func parseAddressList(b []byte) ([]AssignedAddress, error) {
	r := bytes.NewReader(b)
	var out []AssignedAddress
	for r.Len() > 0 {
		id, err := quicvarint.Read(r)
		if err != nil {
			return nil, errMalformedCapsule
		}
		p, err := readPrefix(r)
		if err != nil {
			return nil, err
		}
		out = append(out, AssignedAddress{RequestID: id, Prefix: p})
	}
	return out, nil
}

// ParseAddressAssign разбирает значение капсулы ADDRESS_ASSIGN.
func ParseAddressAssign(b []byte) ([]AssignedAddress, error) { return parseAddressList(b) }

// ParseAddressRequest разбирает значение капсулы ADDRESS_REQUEST.
func ParseAddressRequest(b []byte) ([]RequestedAddress, error) {
	l, err := parseAddressList(b)
	if err != nil {
		return nil, err
	}
	if len(l) == 0 {
		return nil, fmt.Errorf("%w: empty ADDRESS_REQUEST", errMalformedCapsule)
	}
	out := make([]RequestedAddress, len(l))
	for i, a := range l {
		if a.RequestID == 0 {
			return nil, fmt.Errorf("%w: request ID 0 in ADDRESS_REQUEST", errMalformedCapsule)
		}
		out[i] = RequestedAddress(a)
	}
	return out, nil
}

// ParseRouteAdvertisement разбирает значение ROUTE_ADVERTISEMENT и проверяет
// порядок диапазонов: по версии IP, затем по протоколу, затем без пересечений
// и по возрастанию (RFC 9484, 4.7.3).
func ParseRouteAdvertisement(b []byte) ([]IPRoute, error) {
	r := bytes.NewReader(b)
	var out []IPRoute
	for r.Len() > 0 {
		start, ver, err := readAddr(r)
		if err != nil {
			return nil, err
		}
		end, _, err := readRawAddr(r, start.BitLen()/8, ver)
		if err != nil {
			return nil, err
		}
		proto, err := r.ReadByte()
		if err != nil {
			return nil, errMalformedCapsule
		}
		if end.Less(start) {
			return nil, fmt.Errorf("%w: route start %s > end %s", errMalformedCapsule, start, end)
		}
		rt := IPRoute{Start: start, End: end, IPProtocol: proto}
		if n := len(out); n > 0 {
			if err := checkRouteOrder(out[n-1], rt); err != nil {
				return nil, err
			}
		}
		out = append(out, rt)
	}
	return out, nil
}

func checkRouteOrder(prev, cur IPRoute) error {
	pv, cv := prev.Start.BitLen(), cur.Start.BitLen()
	switch {
	case pv < cv:
		return nil
	case pv > cv:
		return fmt.Errorf("%w: routes not ordered by IP version", errMalformedCapsule)
	}
	switch {
	case prev.IPProtocol < cur.IPProtocol:
		return nil
	case prev.IPProtocol > cur.IPProtocol:
		return fmt.Errorf("%w: routes not ordered by IP protocol", errMalformedCapsule)
	}
	if cur.Start.Compare(prev.End) <= 0 {
		return fmt.Errorf("%w: overlapping or unordered routes", errMalformedCapsule)
	}
	return nil
}

// readCapsule читает одну капсулу целиком, ограничивая её размер.
func readCapsule(r quicvarint.Reader) (http3.CapsuleType, []byte, error) {
	ct, cr, err := http3.ParseCapsule(r)
	if err != nil {
		return 0, nil, err
	}
	lr := &io.LimitedReader{R: cr, N: maxCapsuleSize + 1}
	val, err := io.ReadAll(lr)
	if err != nil {
		return 0, nil, err
	}
	if len(val) > maxCapsuleSize {
		return 0, nil, fmt.Errorf("masque: capsule type %d too large", ct)
	}
	return ct, val, nil
}
