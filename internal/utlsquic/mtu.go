//go:build utls

package utlsquic

import (
	"context"
	"net"
	"sync"
	"sync/atomic"

	uquic "github.com/refraction-networking/uquic"
	"github.com/refraction-networking/uquic/logging"
)

// Потолок датаграммы в uTLS-пути.
//
// uquic v0.0.6 сверяет датаграмму только с max_datagram_frame_size пира, а не
// с размером пакета: датаграмма крупнее пакета принимается SendDatagram и
// молча выбрасывается при упаковке (packet_packer.go). Для VPN это чёрная
// дыра MTU, поэтому потолок считаем сами.
//
// Размер пакета uquic не сообщает, а читать его внутренности из другой
// горутины — гонка. Зато трассировщик соединения видит каждый отправленный
// 1-RTT пакет и каждое подтверждение: текущий размер пакета у uquic — это
// начальный размер либо размер последней подтверждённой MTU-пробы, то есть
// максимум из подтверждённых пакетов. Трассировщик вызывается из горутины
// соединения, мы храним результат атомарно.
type mtuTracker struct {
	size    atomic.Int64 // текущий максимальный размер пакета
	dcidLen atomic.Int64 // длина Connection ID получателя

	mu      sync.Mutex
	pending map[logging.PacketNumber]int64 // пакеты крупнее текущего, ждут подтверждения
}

// uquic не экспортирует свои начальные размеры (internal/protocol/params.go).
const (
	uquicInitialPacketSizeIPv4 = 1252
	uquicInitialPacketSizeIPv6 = 1232
	maxConnIDLen               = 20
)

func newMTUTracker(raddr *net.UDPAddr) *mtuTracker {
	t := &mtuTracker{pending: map[logging.PacketNumber]int64{}}
	if raddr.IP.To4() != nil {
		t.size.Store(uquicInitialPacketSizeIPv4)
	} else {
		t.size.Store(uquicInitialPacketSizeIPv6)
	}
	t.dcidLen.Store(maxConnIDLen)
	return t
}

func (t *mtuTracker) configure(qconf *uquic.Config) {
	prev := qconf.Tracer
	qconf.Tracer = func(ctx context.Context, p logging.Perspective, id uquic.ConnectionID) *logging.ConnectionTracer {
		// uquic вызывает часть методов трассировщика без проверки на nil, а
		// мультиплексор заполняет все поля. Одиночный трассировщик он
		// возвращает как есть, поэтому добавляем пустой второй.
		tracers := []*logging.ConnectionTracer{t.tracer(), {}}
		if prev != nil {
			if pt := prev(ctx, p, id); pt != nil {
				tracers = append(tracers, pt)
			}
		}
		return logging.NewMultiplexedConnectionTracer(tracers...)
	}
}

func (t *mtuTracker) tracer() *logging.ConnectionTracer {
	return &logging.ConnectionTracer{
		SentShortHeaderPacket: func(h *logging.ShortHeader, size logging.ByteCount, _ logging.ECN, _ *logging.AckFrame, _ []logging.Frame) {
			t.dcidLen.Store(int64(h.DestConnectionID.Len()))
			if int64(size) <= t.size.Load() {
				return
			}
			t.mu.Lock()
			if len(t.pending) < 64 { // проб за соединение единицы
				t.pending[h.PacketNumber] = int64(size)
			}
			t.mu.Unlock()
		},
		AcknowledgedPacket: func(l logging.EncryptionLevel, pn logging.PacketNumber) {
			if l != logging.Encryption1RTT {
				return
			}
			t.mu.Lock()
			size, ok := t.pending[pn]
			delete(t.pending, pn)
			t.mu.Unlock()
			if ok && size > t.size.Load() {
				t.size.Store(size)
			}
		},
		LostPacket: func(l logging.EncryptionLevel, pn logging.PacketNumber, _ logging.PacketLossReason) {
			if l != logging.Encryption1RTT {
				return
			}
			t.mu.Lock()
			delete(t.pending, pn)
			t.mu.Unlock()
		},
	}
}

// maxDatagram — сколько байт данных кадра DATAGRAM (включая Quarter Stream ID)
// помещается в пакет. Номер пакета считаем худшим (4 байта).
func (t *mtuTracker) maxDatagram() int {
	n := t.size.Load() -
		1 - t.dcidLen.Load() - 4 - // заголовок короткого пакета
		16 - // AEAD-тег
		3 // тип кадра DATAGRAM + длина (varint до 2 байт)
	if n < 0 {
		return 0
	}
	return int(n)
}
