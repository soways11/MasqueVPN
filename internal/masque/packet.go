package masque

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

var errBadPacket = errors.New("masque: malformed IP packet")

// ipPacketLen возвращает истинную длину IP-пакета по полю длины в заголовке
// (Total Length для IPv4, 40 + Payload Length для IPv6). Используется, чтобы
// отбросить хвостовой паддинг. Возвращает 0, если длина некорректна или
// превышает доступные данные.
func ipPacketLen(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return 0
		}
		n := int(binary.BigEndian.Uint16(b[2:4]))
		if n < 20 || n > len(b) {
			return 0
		}
		return n
	case 6:
		if len(b) < 40 {
			return 0
		}
		n := 40 + int(binary.BigEndian.Uint16(b[4:6]))
		if n > len(b) {
			return 0
		}
		return n
	default:
		return 0
	}
}

// packetInfo — минимально нужные для проверок поля IP-заголовка.
type packetInfo struct {
	Src, Dst netip.Addr
	Proto    uint8
}

// parsePacket читает src/dst/протокол из IPv4- или IPv6-заголовка.
// Для IPv6 берётся поле Next Header без обхода цепочки extension-заголовков.
func parsePacket(b []byte) (packetInfo, error) {
	if len(b) == 0 {
		return packetInfo{}, errBadPacket
	}
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return packetInfo{}, errBadPacket
		}
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || len(b) < ihl {
			return packetInfo{}, errBadPacket
		}
		return packetInfo{
			Src:   netip.AddrFrom4([4]byte(b[12:16])),
			Dst:   netip.AddrFrom4([4]byte(b[16:20])),
			Proto: b[9],
		}, nil
	case 6:
		if len(b) < 40 {
			return packetInfo{}, errBadPacket
		}
		return packetInfo{
			Src:   netip.AddrFrom16([16]byte(b[8:24])),
			Dst:   netip.AddrFrom16([16]byte(b[24:40])),
			Proto: ipv6UpperProto(b),
		}, nil
	default:
		return packetInfo{}, errBadPacket
	}
}

// Типы IPv6 extension-заголовков, которые нужно пропустить, чтобы добраться до
// протокола верхнего уровня (RFC 8200, раздел 4).
const (
	extHopByHop  = 0
	extRouting   = 43
	extFragment  = 44
	extAuth      = 51 // AH: длина считается иначе
	extDestOpts  = 60
	extMobility  = 135
	extNoNextHdr = 59
)

// maxExtHeaders ограничивает обход цепочки: пакет с сотнями заголовков —
// это попытка вымотать разборщик, а не нормальный трафик.
const maxExtHeaders = 8

// ipv6UpperProto обходит цепочку extension-заголовков IPv6 и возвращает протокол
// верхнего уровня. Без этого обхода в поле протокола оказывался тип первого
// extension-заголовка, и проверка по маршрутам с указанным IPProtocol отбрасывала
// вполне легитимные пакеты (например, фрагментированные).
//
// Если цепочку разобрать не удалось (обрыв, шифрование ESP, слишком длинная
// цепочка) — возвращается тип последнего разобранного заголовка: политика тогда
// отработает консервативно, а не пропустит пакет мимо проверки.
func ipv6UpperProto(b []byte) uint8 {
	next := b[6]
	off := 40
	for i := 0; i < maxExtHeaders; i++ {
		switch next {
		case extHopByHop, extRouting, extDestOpts, extMobility:
			if off+2 > len(b) {
				return next
			}
			hlen := (int(b[off+1]) + 1) * 8
			if off+hlen > len(b) {
				return next
			}
			next = b[off]
			off += hlen
		case extFragment:
			if off+8 > len(b) {
				return next
			}
			nx := b[off]
			// У не первого фрагмента полезной нагрузки верхнего уровня нет;
			// отдаём тип, который заявлен, — дальше идти бессмысленно.
			if binary.BigEndian.Uint16(b[off+2:off+4])&0xfff8 != 0 {
				return nx
			}
			next = nx
			off += 8
		case extAuth:
			if off+2 > len(b) {
				return next
			}
			hlen := (int(b[off+1]) + 2) * 4
			if off+hlen > len(b) {
				return next
			}
			next = b[off]
			off += hlen
		case extNoNextHdr:
			return extNoNextHdr
		default:
			return next // протокол верхнего уровня
		}
	}
	return next
}
