package masque

import (
	"github.com/quic-go/quic-go/quicvarint"
)

// Context ID полезной нагрузки HTTP Datagram (RFC 9484, раздел 6).
const (
	// contextIDIPPacket — полный IP-пакет (единственный, определённый RFC 9484).
	// За пакетом могут идти байты паддинга — получатель обрезает их по длине
	// из IP-заголовка, поэтому формат остаётся совместимым.
	contextIDIPPacket = 0
	// contextIDPadding — cover-датаграмма: только паддинг, отбрасывается на приёме.
	// Context ID вне 0 по RFC согласуется отдельно; т.к. оба конца — наши,
	// используем зарезервированный нами идентификатор для маскирующего трафика.
	contextIDPadding = 1
)

// appendIPDatagram формирует датаграмму с IP-пакетом и, при padTo > len(pkt),
// добивает её нулями до padTo байт полезной нагрузки после Context ID.
func appendIPDatagram(b, pkt []byte, padTo int) []byte {
	b = quicvarint.Append(b, contextIDIPPacket)
	b = append(b, pkt...)
	if padTo > len(pkt) {
		b = appendZeros(b, padTo-len(pkt))
	}
	return b
}

// appendCoverDatagram формирует cover-датаграмму из size байт паддинга.
func appendCoverDatagram(b []byte, size int) []byte {
	b = quicvarint.Append(b, contextIDPadding)
	return appendZeros(b, size)
}

func appendZeros(b []byte, n int) []byte {
	for i := 0; i < n; i++ {
		b = append(b, 0)
	}
	return b
}

// parseDatagram разбирает полезную нагрузку HTTP Datagram на Context ID и остаток.
func parseDatagram(b []byte) (ctx uint64, payload []byte, ok bool) {
	id, n, err := quicvarint.Parse(b)
	if err != nil {
		return 0, nil, false
	}
	return id, b[n:], true
}
