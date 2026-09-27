//go:build utls

package utlsquic

import (
	"encoding/binary"
	"fmt"

	"github.com/gaukas/clienthellod"
)

// Снятие отпечатка с перехваченных Initial-пакетов.
//
// Ключи Initial выводятся из открытого Destination Connection ID, поэтому
// расшифровать эти пакеты может кто угодно на пути — и DPI, и мы. Мы этим
// пользуемся, чтобы записать отпечаток настоящего браузера.
//
// Разбираем ClientHello сами, а не берём разобранные поля из clienthellod:
// нужны СЫРЫЕ байты каждого расширения, иначе неизвестные расширения (ECH,
// GREASE, будущие) не перенести.

// CaptureFromPackets собирает отпечаток из перехваченных UDP-датаграмм первого
// вылета клиента. Пакеты можно передавать в любом порядке и с повторами.
func CaptureFromPackets(pkts [][]byte, source string) (*Fingerprint, error) {
	if len(pkts) == 0 {
		return nil, fmt.Errorf("utlsquic: не передано ни одного пакета")
	}

	var (
		frames    []clienthellod.Frame
		firstSeen bool
		fp        = &Fingerprint{Source: source, CapturedAt: nowStamp()}
	)
	for _, p := range pkts {
		hdr, err := clienthellod.DecodeQUICHeaderAndFrames(p)
		if err != nil {
			continue // не Initial-пакет
		}
		if !firstSeen {
			fp.DatagramSize = len(p)
			fp.DestConnIDLen = int(hdr.DCIDLength)
			fp.SrcConnIDLen = int(hdr.SCIDLength)
			fp.PacketNumberLen = len(hdr.PacketNumber)
			var pn uint64
			for _, b := range hdr.PacketNumber {
				pn = pn<<8 | uint64(b)
			}
			fp.InitPacketNumber = pn
			firstSeen = true
		}
		frames = append(frames, hdr.Frames()...)
	}
	if !firstSeen {
		return nil, fmt.Errorf("utlsquic: среди пакетов нет Initial")
	}

	hello := reassembleCryptoStream(frames)
	if len(hello) == 0 {
		return nil, fmt.Errorf("utlsquic: не удалось собрать ClientHello из CRYPTO-фреймов")
	}
	if err := fp.parseClientHello(hello); err != nil {
		return nil, err
	}
	return fp, nil
}

// reassembleCryptoStream склеивает CRYPTO-фреймы по смещению, отбрасывая повторы
// (клиент переотправляет Initial, если сервер молчит).
func reassembleCryptoStream(frames []clienthellod.Frame) []byte {
	byOffset := make(map[uint64][]byte)
	for _, f := range frames {
		c, ok := f.(*clienthellod.CRYPTO)
		if !ok {
			continue
		}
		if _, seen := byOffset[c.Offset]; !seen {
			byOffset[c.Offset] = c.Data
		}
	}
	var out []byte
	for {
		chunk, ok := byOffset[uint64(len(out))]
		if !ok {
			return out
		}
		out = append(out, chunk...)
	}
}

// parseClientHello разбирает handshake-сообщение ClientHello (RFC 8446, 4.1.2).
func (fp *Fingerprint) parseClientHello(b []byte) error {
	// Заголовок handshake: тип(1) + длина(3).
	if len(b) < 4 || b[0] != 1 {
		return fmt.Errorf("utlsquic: это не ClientHello")
	}
	l := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if 4+l > len(b) {
		return fmt.Errorf("utlsquic: ClientHello обрезан")
	}
	p := b[4 : 4+l]

	// legacy_version(2) + random(32)
	if len(p) < 34 {
		return fmt.Errorf("utlsquic: ClientHello слишком короткий")
	}
	p = p[34:]

	// legacy_session_id
	if len(p) < 1 {
		return fmt.Errorf("utlsquic: обрыв на session_id")
	}
	sidLen := int(p[0])
	if 1+sidLen > len(p) {
		return fmt.Errorf("utlsquic: обрыв session_id")
	}
	p = p[1+sidLen:]

	// cipher_suites
	if len(p) < 2 {
		return fmt.Errorf("utlsquic: обрыв на cipher_suites")
	}
	csLen := int(binary.BigEndian.Uint16(p[:2]))
	if 2+csLen > len(p) || csLen%2 != 0 {
		return fmt.Errorf("utlsquic: обрыв cipher_suites")
	}
	fp.CipherSuites = nil
	for i := 2; i < 2+csLen; i += 2 {
		fp.CipherSuites = append(fp.CipherSuites, binary.BigEndian.Uint16(p[i:i+2]))
	}
	p = p[2+csLen:]

	// legacy_compression_methods
	if len(p) < 1 {
		return fmt.Errorf("utlsquic: обрыв на compression_methods")
	}
	cmLen := int(p[0])
	if 1+cmLen > len(p) {
		return fmt.Errorf("utlsquic: обрыв compression_methods")
	}
	p = p[1+cmLen:]

	// extensions
	if len(p) < 2 {
		return fmt.Errorf("utlsquic: нет расширений")
	}
	extLen := int(binary.BigEndian.Uint16(p[:2]))
	if 2+extLen > len(p) {
		return fmt.Errorf("utlsquic: обрыв блока расширений")
	}
	ext := p[2 : 2+extLen]

	fp.Extensions = nil
	fp.TransportParams = nil
	for len(ext) >= 4 {
		id := binary.BigEndian.Uint16(ext[:2])
		dl := int(binary.BigEndian.Uint16(ext[2:4]))
		if 4+dl > len(ext) {
			return fmt.Errorf("utlsquic: обрыв расширения %d", id)
		}
		data := append([]byte(nil), ext[4:4+dl]...)
		fp.Extensions = append(fp.Extensions, Extension{ID: id, Data: data})
		if id == extQUICTransportParam {
			tps, err := parseTransportParams(data)
			if err != nil {
				return fmt.Errorf("utlsquic: транспортные параметры: %w", err)
			}
			fp.TransportParams = tps
		}
		ext = ext[4+dl:]
	}
	if len(fp.Extensions) == 0 {
		return fmt.Errorf("utlsquic: расширения не разобраны")
	}
	return nil
}

// parseTransportParams разбирает содержимое quic_transport_parameters:
// последовательность varint(id) + varint(len) + value, порядок сохраняется.
func parseTransportParams(b []byte) ([]TransportParam, error) {
	var out []TransportParam
	for len(b) > 0 {
		id, n := readVarint(b)
		if n == 0 {
			return nil, fmt.Errorf("обрыв идентификатора")
		}
		b = b[n:]
		l, n := readVarint(b)
		if n == 0 {
			return nil, fmt.Errorf("обрыв длины")
		}
		b = b[n:]
		if uint64(len(b)) < l {
			return nil, fmt.Errorf("обрыв значения параметра %d", id)
		}
		out = append(out, TransportParam{ID: id, Value: append([]byte(nil), b[:l]...)})
		b = b[l:]
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("список пуст")
	}
	return out, nil
}

// readVarint читает QUIC-варинт; возвращает значение и число съеденных байт.
func readVarint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	switch b[0] >> 6 {
	case 0:
		return uint64(b[0] & 0x3f), 1
	case 1:
		if len(b) < 2 {
			return 0, 0
		}
		return uint64(binary.BigEndian.Uint16(b[:2]) & 0x3fff), 2
	case 2:
		if len(b) < 4 {
			return 0, 0
		}
		return uint64(binary.BigEndian.Uint32(b[:4]) & 0x3fffffff), 4
	default:
		if len(b) < 8 {
			return 0, 0
		}
		return binary.BigEndian.Uint64(b[:8]) & 0x3fffffffffffffff, 8
	}
}
