//go:build utls

package utlsquic

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go/quicvarint"
	uquic "github.com/refraction-networking/uquic"
	"github.com/soways11/masquevpn/internal/masque"
)

// Минимальный клиентский HTTP/3 (RFC 9114) ровно под одну задачу: установить
// Extended CONNECT (RFC 9220) с :protocol=connect-ip и гонять по нему капсулы и
// HTTP-датаграммы (RFC 9297).
//
// Почему свой, а не http3 из uquic: http3 внутри uquic написан под qpack v0.4,
// а наш quic-go v0.59 требует qpack v0.6 — вместе в одном модуле они не живут.
// Поэтому от uquic берётся ТОЛЬКО QUIC-слой (он qpack не использует), а HTTP/3
// поверх него — этот файл. Заодно в uquic/http3 вообще нет HTTP-датаграмм,
// без которых CONNECT-IP невозможен.
const (
	frameTypeData     = 0x00
	frameTypeHeaders  = 0x01
	frameTypeSettings = 0x04

	streamTypeControl      = 0x00
	streamTypeQPACKEncoder = 0x02
	streamTypeQPACKDecoder = 0x03

	settingExtendedConnect = 0x08
	settingH3Datagram      = 0x33

	maxHeaderBytes = 1 << 16
)

// h3Conn — клиентское HTTP/3 соединение поверх QUIC-соединения uquic.
type h3Conn struct {
	conn uquic.Connection
	mtu  *mtuTracker // nil — без проверки размера (только в тестах h3)

	receivedSettings chan struct{}
	settingsOnce     sync.Once
	extendedConnect  bool
	datagrams        bool

	mu     sync.Mutex
	queues map[uint64]chan []byte // quarter stream ID -> очередь датаграмм
}

func newH3Conn(ctx context.Context, conn uquic.Connection, extraSettings map[uint64]uint64) (*h3Conn, error) {
	c := &h3Conn{
		conn:             conn,
		receivedSettings: make(chan struct{}),
		queues:           make(map[uint64]chan []byte),
	}

	// Управляющий поток: тип + SETTINGS с H3_DATAGRAM=1 (иначе сервер не примет
	// от нас датаграммы и откажет в CONNECT-IP).
	ctrl, err := conn.OpenUniStream()
	if err != nil {
		return nil, fmt.Errorf("utlsquic: open control stream: %w", err)
	}
	b := quicvarint.Append(nil, streamTypeControl)
	settings := quicvarint.Append(nil, settingH3Datagram)
	settings = quicvarint.Append(settings, 1)
	// Дополнительные SETTINGS (например, WebTransport) — порядок детерминирован,
	// чтобы не плодить лишний признак вариативностью.
	ids := make([]uint64, 0, len(extraSettings))
	for id := range extraSettings {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		settings = quicvarint.Append(settings, id)
		settings = quicvarint.Append(settings, extraSettings[id])
	}
	b = quicvarint.Append(b, frameTypeSettings)
	b = quicvarint.Append(b, uint64(len(settings)))
	b = append(b, settings...)
	if _, err := ctrl.Write(b); err != nil {
		return nil, fmt.Errorf("utlsquic: write SETTINGS: %w", err)
	}

	// QPACK-потоки: динамическую таблицу не используем, но потоки принято открывать.
	for _, t := range []uint64{streamTypeQPACKEncoder, streamTypeQPACKDecoder} {
		s, err := conn.OpenUniStream()
		if err != nil {
			return nil, fmt.Errorf("utlsquic: open qpack stream: %w", err)
		}
		if _, err := s.Write(quicvarint.Append(nil, t)); err != nil {
			return nil, fmt.Errorf("utlsquic: write qpack stream type: %w", err)
		}
	}

	go c.acceptUniStreams()
	go c.receiveDatagrams()

	select {
	case <-c.receivedSettings:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-conn.Context().Done():
		return nil, errors.New("utlsquic: connection closed before SETTINGS")
	}
	return c, nil
}

func (c *h3Conn) acceptUniStreams() {
	for {
		str, err := c.conn.AcceptUniStream(context.Background())
		if err != nil {
			return
		}
		go func() {
			br := bufio.NewReader(str)
			t, err := quicvarint.Read(br)
			if err != nil {
				return
			}
			if t != streamTypeControl {
				return // QPACK-потоки и push нам не нужны
			}
			c.readControlStream(br)
		}()
	}
}

func (c *h3Conn) readControlStream(br *bufio.Reader) {
	for {
		ft, flen, err := readFrameHeader(br)
		if err != nil {
			return
		}
		if ft != frameTypeSettings {
			if _, err := io.CopyN(io.Discard, br, int64(flen)); err != nil {
				return
			}
			continue
		}
		payload := make([]byte, flen)
		if _, err := io.ReadFull(br, payload); err != nil {
			return
		}
		c.parseSettings(payload)
	}
}

func (c *h3Conn) parseSettings(b []byte) {
	r := bufio.NewReader(newBytesReader(b))
	for {
		id, err := quicvarint.Read(r)
		if err != nil {
			break
		}
		val, err := quicvarint.Read(r)
		if err != nil {
			break
		}
		switch id {
		case settingExtendedConnect:
			c.extendedConnect = val == 1
		case settingH3Datagram:
			c.datagrams = val == 1
		}
	}
	c.settingsOnce.Do(func() { close(c.receivedSettings) })
}

// receiveDatagrams разбирает Quarter Stream ID и раскладывает датаграммы по потокам.
func (c *h3Conn) receiveDatagrams() {
	for {
		d, err := c.conn.ReceiveDatagram(context.Background())
		if err != nil {
			return
		}
		qsid, n, err := quicvarint.Parse(d)
		if err != nil {
			continue
		}
		c.mu.Lock()
		q := c.queues[qsid]
		c.mu.Unlock()
		if q == nil {
			continue // датаграмма для неизвестного потока — отбрасываем
		}
		payload := make([]byte, len(d)-n)
		copy(payload, d[n:])
		select {
		case q <- payload:
		default: // очередь переполнена — теряем, как и положено датаграмме
		}
	}
}

func (c *h3Conn) registerQueue(qsid uint64) chan []byte {
	q := make(chan []byte, 256)
	c.mu.Lock()
	c.queues[qsid] = q
	c.mu.Unlock()
	return q
}

func (c *h3Conn) unregisterQueue(qsid uint64) {
	c.mu.Lock()
	delete(c.queues, qsid)
	c.mu.Unlock()
}

// connectIP отправляет Extended CONNECT с :protocol=connect-ip и читает ответ.
// connectIP возвращает поток, код ответа и заголовок Date (по нему клиент
// проверяет, не разъехались ли часы, — см. masque.ResponseError).
func (c *h3Conn) connectIP(ctx context.Context, proto, authority, path string, hdr http.Header) (*h3Stream, int, string, error) {
	str, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, 0, "", fmt.Errorf("utlsquic: open request stream: %w", err)
	}
	qsid := uint64(str.StreamID()) / 4
	q := c.registerQueue(qsid) // до отправки запроса: ответные датаграммы не потеряются

	var headerBuf writeBuffer
	enc := qpack.NewEncoder(&headerBuf)
	fields := []qpack.HeaderField{
		{Name: ":method", Value: http.MethodConnect},
		{Name: ":protocol", Value: proto},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: authority},
		{Name: ":path", Value: path},
	}
	for k, vs := range hdr {
		for _, v := range vs {
			fields = append(fields, qpack.HeaderField{Name: lowerASCII(k), Value: v})
		}
	}
	for _, f := range fields {
		if err := enc.WriteField(f); err != nil {
			c.unregisterQueue(qsid)
			return nil, 0, "", err
		}
	}
	if err := enc.Close(); err != nil {
		c.unregisterQueue(qsid)
		return nil, 0, "", err
	}

	frame := quicvarint.Append(nil, frameTypeHeaders)
	frame = quicvarint.Append(frame, uint64(len(headerBuf.b)))
	frame = append(frame, headerBuf.b...)
	if _, err := str.Write(frame); err != nil {
		c.unregisterQueue(qsid)
		return nil, 0, "", fmt.Errorf("utlsquic: write HEADERS: %w", err)
	}

	br := bufio.NewReader(str)
	status, date, err := readResponseStatus(br)
	if err != nil {
		c.unregisterQueue(qsid)
		return nil, 0, "", err
	}
	return &h3Stream{h3: c, str: str, br: br, qsid: qsid, dgrams: q}, status, date, nil
}

func readResponseStatus(br *bufio.Reader) (int, string, error) {
	for {
		ft, flen, err := readFrameHeader(br)
		if err != nil {
			return 0, "", fmt.Errorf("utlsquic: read response: %w", err)
		}
		if ft != frameTypeHeaders {
			if _, err := io.CopyN(io.Discard, br, int64(flen)); err != nil {
				return 0, "", err
			}
			continue
		}
		if flen > maxHeaderBytes {
			return 0, "", errors.New("utlsquic: HEADERS frame too large")
		}
		block := make([]byte, flen)
		if _, err := io.ReadFull(br, block); err != nil {
			return 0, "", err
		}
		dec := qpack.NewDecoder()
		next := dec.Decode(block)
		code, date := 0, ""
		for {
			f, err := next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return 0, "", err
			}
			switch f.Name {
			case ":status":
				if _, err := fmt.Sscanf(f.Value, "%d", &code); err != nil {
					return 0, "", fmt.Errorf("utlsquic: bad :status %q", f.Value)
				}
			case "date":
				date = f.Value
			}
		}
		if code == 0 {
			return 0, "", errors.New("utlsquic: response without :status")
		}
		return code, date, nil
	}
}

// get выполняет обычный HTTP/3 GET по тому же соединению и вычитывает тело.
// Нужен для прикрытия потоками: сессия, состоящая из одного вечного потока и
// потока датаграмм, не похожа ни на один браузер.
func (c *h3Conn) get(ctx context.Context, authority, path string, maxBody int64) error {
	str, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	defer str.Close()

	var headerBuf writeBuffer
	enc := qpack.NewEncoder(&headerBuf)
	for _, f := range []qpack.HeaderField{
		{Name: ":method", Value: http.MethodGet},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: authority},
		{Name: ":path", Value: path},
	} {
		if err := enc.WriteField(f); err != nil {
			return err
		}
	}
	if err := enc.Close(); err != nil {
		return err
	}
	frame := quicvarint.Append(nil, frameTypeHeaders)
	frame = quicvarint.Append(frame, uint64(len(headerBuf.b)))
	frame = append(frame, headerBuf.b...)
	if _, err := str.Write(frame); err != nil {
		return err
	}
	if err := str.Close(); err != nil { // тела у GET нет
		return err
	}

	br := bufio.NewReader(str)
	if _, _, err := readResponseStatus(br); err != nil {
		return err
	}
	// Тело действительно вычитываем: по объёму видно, нужен ли кому-то ответ.
	_, err = io.Copy(io.Discard, io.LimitReader(&dataFrameReader{br: br}, maxBody))
	return err
}

// dataFrameReader отдаёт содержимое DATA-фреймов ответа.
type dataFrameReader struct {
	br        *bufio.Reader
	remaining uint64
}

func (r *dataFrameReader) Read(b []byte) (int, error) {
	for r.remaining == 0 {
		ft, flen, err := readFrameHeader(r.br)
		if err != nil {
			return 0, err
		}
		if ft == frameTypeData {
			r.remaining = flen
			break
		}
		if _, err := io.CopyN(io.Discard, r.br, int64(flen)); err != nil {
			return 0, err
		}
	}
	if uint64(len(b)) > r.remaining {
		b = b[:r.remaining]
	}
	n, err := r.br.Read(b)
	r.remaining -= uint64(n)
	return n, err
}

// h3Stream реализует masque.Stream поверх HTTP/3 потока uquic.
type h3Stream struct {
	h3   *h3Conn
	str  uquic.Stream
	br   *bufio.Reader
	qsid uint64

	dgrams chan []byte

	readMu    sync.Mutex
	remaining uint64 // непрочитанный остаток текущего DATA-фрейма

	writeMu sync.Mutex
}

// Read отдаёт содержимое DATA-фреймов (в них лежат капсулы).
func (s *h3Stream) Read(b []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	for s.remaining == 0 {
		ft, flen, err := readFrameHeader(s.br)
		if err != nil {
			return 0, err
		}
		if ft == frameTypeData {
			s.remaining = flen
			break
		}
		if _, err := io.CopyN(io.Discard, s.br, int64(flen)); err != nil {
			return 0, err
		}
	}
	if uint64(len(b)) > s.remaining {
		b = b[:s.remaining]
	}
	n, err := s.br.Read(b)
	s.remaining -= uint64(n)
	return n, err
}

// Write оборачивает данные в DATA-фрейм (одним вызовом, чтобы не разорвать кадр).
func (s *h3Stream) Write(b []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	buf := quicvarint.Append(nil, frameTypeData)
	buf = quicvarint.Append(buf, uint64(len(b)))
	buf = append(buf, b...)
	if _, err := s.str.Write(buf); err != nil {
		return 0, err
	}
	return len(b), nil
}

// SendDatagram добавляет Quarter Stream ID и отправляет QUIC-датаграмму.
func (s *h3Stream) SendDatagram(b []byte) error {
	if m := s.h3.mtu; m != nil {
		// uquic сам размер пакета не проверяет — см. mtu.go.
		limit := m.maxDatagram() - quicvarint.Len(s.qsid)
		if len(b) > limit {
			return &masque.DatagramTooLargeError{MaxPayload: max(limit, 0)}
		}
	}
	buf := quicvarint.Append(nil, s.qsid)
	buf = append(buf, b...)
	return s.h3.conn.SendDatagram(buf)
}

func (s *h3Stream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case d := <-s.dgrams:
		return d, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.str.Context().Done():
		return nil, io.EOF
	}
}

func (s *h3Stream) Close() error {
	s.h3.unregisterQueue(s.qsid)
	return s.str.Close()
}

func (s *h3Stream) CancelRead(code uint64)   { s.str.CancelRead(uquic.StreamErrorCode(code)) }
func (s *h3Stream) CancelWrite(code uint64)  { s.str.CancelWrite(uquic.StreamErrorCode(code)) }
func (s *h3Stream) Context() context.Context { return s.str.Context() }

// ---------- мелкие помощники ----------

func readFrameHeader(br *bufio.Reader) (ftype, flen uint64, err error) {
	ftype, err = quicvarint.Read(br)
	if err != nil {
		return 0, 0, err
	}
	flen, err = quicvarint.Read(br)
	if err != nil {
		return 0, 0, err
	}
	return ftype, flen, nil
}

type writeBuffer struct{ b []byte }

func (w *writeBuffer) Write(p []byte) (int, error) { w.b = append(w.b, p...); return len(p), nil }

type bytesReader struct {
	b []byte
	i int
}

func newBytesReader(b []byte) *bytesReader { return &bytesReader{b: b} }

func (r *bytesReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}

func lowerASCII(s string) string {
	out := []byte(s)
	for i, c := range out {
		if c >= 'A' && c <= 'Z' {
			out[i] = c + 32
		}
	}
	return string(out)
}

// startCoverBrowsing запускает фоновые GET-запросы к сайту-прикрытию, пока жива
// сессия. Зеркалит поведение quic-go пути: иначе маскировка потоками работала бы
// только там, где отпечаток и так хуже.
func (c *h3Conn) startCoverBrowsing(conn *masque.Conn, authority string, cb *masque.CoverBrowsing) {
	go func() {
		paths := cb.Paths
		if len(paths) == 0 {
			paths = []string{"/"}
		}
		maxBody := cb.MaxBodyBytes
		if maxBody <= 0 {
			maxBody = 64 << 10
		}
		for {
			d := 5*time.Second + time.Duration(rand.Int64N(int64(25*time.Second)))
			if cb.Next != nil {
				d = cb.Next()
			}
			select {
			case <-conn.Done():
				return
			case <-time.After(d):
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			err := c.get(ctx, authority, paths[rand.IntN(len(paths))], maxBody)
			cancel()
			if err == nil {
				conn.CountCoverRequest()
			}
		}
	}()
}
