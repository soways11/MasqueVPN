package masque

import (
	"context"
	"errors"
	"io"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

// Stream — транспортная абстракция установленной CONNECT-IP сессии: поток для
// капсул плюс канал HTTP-датаграмм для IP-пакетов.
//
// Благодаря ей ядро (капсулы, политика адресов, паддинг, cover-трафик) не зависит
// от конкретной QUIC-реализации: поверх этого интерфейса работает и стандартный
// quic-go, и uTLS-транспорт (`internal/utlsquic`) с отпечатком Chrome.
//
// Коды ошибок — обычные uint64 (значения HTTP/3), чтобы не тянуть в интерфейс
// типы конкретной библиотеки.
type Stream interface {
	io.ReadWriteCloser
	// SendDatagram отправляет полезную нагрузку HTTP Datagram (без Quarter Stream ID —
	// его добавляет сама реализация).
	SendDatagram([]byte) error
	// ReceiveDatagram возвращает полезную нагрузку следующей HTTP-датаграммы этого потока.
	ReceiveDatagram(context.Context) ([]byte, error)
	CancelRead(errorCode uint64)
	CancelWrite(errorCode uint64)
	Context() context.Context
}

// NewClientConn поднимает клиентскую CONNECT-IP сессию поверх уже установленного
// потока (запрос отправлен, ответ 2xx получен). Используется транспортами,
// отличными от стандартного quic-go — см. Dial для обычного случая.
//
// closer вызывается при закрытии сессии (обычно закрывает QUIC-соединение).
func NewClientConn(str Stream, opt ClientConnOptions) *Conn {
	c := newConn(str, roleClient, opt.Closer)
	c.shaping = opt.Shaping
	c.packing = opt.Packing
	c.start()
	return c
}

// ClientConnOptions — параметры сессии поверх готового потока.
type ClientConnOptions struct {
	Shaping *Shaping
	Packing *Packing
	// Closer вызывается при закрытии сессии.
	Closer func() error
}

// ---------- адаптеры для quic-go ----------

// requestStream приводит *http3.RequestStream (клиент) к Stream: коды ошибок uint64.
type requestStream struct{ *http3.RequestStream }

func (s requestStream) SendDatagram(b []byte) error {
	return translateDatagramErr(s.RequestStream.SendDatagram(b), s.RequestStream.StreamID())
}

func (s requestStream) CancelRead(code uint64) {
	s.RequestStream.CancelRead(quic.StreamErrorCode(code))
}

func (s requestStream) CancelWrite(code uint64) {
	s.RequestStream.CancelWrite(quic.StreamErrorCode(code))
}

// serverStream приводит *http3.Stream (сервер) к Stream.
type serverStream struct{ *http3.Stream }

func (s serverStream) SendDatagram(b []byte) error {
	return translateDatagramErr(s.Stream.SendDatagram(b), s.Stream.StreamID())
}

func (s serverStream) CancelRead(code uint64) {
	s.Stream.CancelRead(quic.StreamErrorCode(code))
}

func (s serverStream) CancelWrite(code uint64) {
	s.Stream.CancelWrite(quic.StreamErrorCode(code))
}

var (
	_ Stream = requestStream{}
	_ Stream = serverStream{}
)

// quicGoOverheadFix — поправка на ошибку quic-go v0.59: после первого ACK
// MaxDatagramPayloadSize равен СЫРОМУ размеру пакета (connection.go,
// handleAckFrame: currentMTUEstimate.Store(mtu) без estimateMaxPayloadSize).
// Вычитаем худший случай накладных расходов: тип (1) + Connection ID (до 20)
// + номер пакета (до 4) + AEAD-тег (16) + заголовок кадра DATAGRAM (до 3).
// До первого ACK оценка честная, и поправка лишь слегка занижает потолок.
// Проверяется тестом TestDatagramCapacityIsHonest: если quic-go исправят,
// тест покажет, что поправку можно убрать.
const quicGoOverheadFix = 1 + 20 + 4 + 16 + 3

// translateDatagramErr переводит ошибку размера quic-go в DatagramTooLargeError.
//
// quic-go сообщает потолок датаграммы QUIC целиком, а в ней перед нашей
// полезной нагрузкой ещё стоит Quarter Stream ID (RFC 9297) — 1–2 байта.
// Без поправки ядро считало бы, что помещается на эти байты больше, и
// пакет ровно на границе снова не проходил бы.
func translateDatagramErr(err error, id quic.StreamID) error {
	var q *quic.DatagramTooLargeError
	if err == nil || !errors.As(err, &q) {
		return err
	}
	n := int(q.MaxDatagramPayloadSize) - quicGoOverheadFix - quicvarint.Len(uint64(id)/4)
	if n < 0 {
		n = 0
	}
	return &DatagramTooLargeError{MaxPayload: n}
}
