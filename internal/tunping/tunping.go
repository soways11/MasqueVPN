// Package tunping — HTTP-запрос ВНУТРИ туннеля: пинг профиля.
//
// # Что меряем
//
// Пинг профиля отвечает на вопрос человека «работает ли VPN через этот
// сервер и насколько быстро» — поэтому меряется путь целиком: сессия
// CONNECT-IP поднята, и через неё, как обычное приложение, клиент открывает
// TCP-соединение к example.com:80 и шлёт GET. Время — от первого SYN до
// первых байтов ответа: два круга через туннель (рукопожатие TCP и сам
// запрос) плюс путь от сервера до сайта. Имя разрешается тоже через туннель
// (DNS из конфигурации профиля), но в время не входит: кэш резолвера сервера
// делал бы число случайным.
//
// # Почему свой маленький стек
//
// Туннель отдаёт и принимает целые IP-пакеты, а обычный net.Dial их не
// умеет. Полноценный стек (gVisor netstack) ради одного короткого запроса
// утяжелил бы ядро телефона на мегабайты. Здесь ровно то, что нужно для
// одного обмена: IPv4, UDP для DNS, TCP с рукопожатием, повтором SYN и
// запроса, приёмом первого сегмента ответа по порядку. После первых байтов
// соединение сбрасывается (RST) — тело не нужно.
package tunping

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// PacketConn — туннель: целые IP-пакеты в обе стороны (masque.Conn).
type PacketConn interface {
	ReadPacket(b []byte) (int, error)
	WritePacket(pkt []byte) error
}

// Result — итог запроса.
type Result struct {
	// RTT — от первого SYN до первых байтов HTTP-ответа.
	RTT time.Duration
	// Status — строка статуса ответа («HTTP/1.1 200 OK»).
	Status string
	// Addr — адрес, по которому разрешилось имя.
	Addr netip.Addr
	// DNS — сколько заняло разрешение имени (в RTT не входит).
	DNS time.Duration
}

// Ошибки, которые стоит показать человеку как есть.
var (
	ErrNoIPv4    = errors.New("в туннеле нет IPv4-адреса")
	ErrNoDNS     = errors.New("в профиле нет DNS-сервера IPv4 для разрешения имени")
	ErrReset     = errors.New("соединение сброшено сайтом")
	ErrClosed    = errors.New("сайт закрыл соединение, не ответив")
	ErrNotHTTP   = errors.New("ответ не похож на HTTP")
	errMalformed = errors.New("битый пакет")
)

// Get разрешает host через DNS-серверы dns (UDP/53 внутри туннеля),
// открывает TCP к host:port и шлёт GET path. src — адрес клиента в
// туннеле. Туннель pc закрывает вызывающий: фоновое чтение пакетов
// заканчивается вместе с ним.
func Get(ctx context.Context, pc PacketConn, src netip.Addr, dns []netip.Addr, host string, port uint16, path string) (Result, error) {
	var res Result
	if !src.Is4() {
		return res, ErrNoIPv4
	}
	s := newStack(pc, src)

	dst, err := netip.ParseAddr(host)
	if err != nil || !dst.Is4() {
		t0 := time.Now()
		dst, err = s.resolve(ctx, dns, host)
		if err != nil {
			return res, err
		}
		res.DNS = time.Since(t0)
	}
	res.Addr = dst

	if path == "" {
		path = "/"
	}
	hostHdr := host
	if port != 80 {
		hostHdr = fmt.Sprintf("%s:%d", host, port)
	}
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + hostHdr + "\r\n" +
		"User-Agent: Mozilla/5.0\r\n" +
		"Accept: */*\r\n" +
		"Connection: close\r\n\r\n"
	res.RTT, res.Status, err = s.get(ctx, dst, port, []byte(req))
	return res, err
}

// ---------- стек ----------

type stack struct {
	pc  PacketConn
	src netip.Addr
	in  chan []byte
	err chan error
}

func newStack(pc PacketConn, src netip.Addr) *stack {
	s := &stack{pc: pc, src: src, in: make(chan []byte, 64), err: make(chan error, 1)}
	go s.read()
	return s
}

// read перекладывает пакеты из туннеля в канал. Переполнение — сбрасываем:
// лишнее нам всё равно не нужно, а блокироваться на туннеле нельзя.
func (s *stack) read() {
	buf := make([]byte, 65536)
	for {
		n, err := s.pc.ReadPacket(buf)
		if err != nil {
			select {
			case s.err <- err:
			default:
			}
			return
		}
		p := append([]byte(nil), buf[:n]...)
		select {
		case s.in <- p:
		default:
		}
	}
}

// next ждёт следующий пакет не дольше d. nil без ошибки — время вышло.
func (s *stack) next(ctx context.Context, d time.Duration) ([]byte, error) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case p := <-s.in:
		return p, nil
	case err := <-s.err:
		return nil, fmt.Errorf("туннель закрыт: %w", err)
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.C:
		return nil, nil
	}
}

func randUint32() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
}

// ephemeralPort — случайный порт из динамического диапазона 49152–65535.
func ephemeralPort() uint16 { return 49152 + uint16(randUint32()%16384) }

// ---------- DNS ----------

// resolve спрашивает A-запись у каждого IPv4-сервера по очереди: запрос,
// повтор через секунду, ещё через две — затем следующий сервер.
func (s *stack) resolve(ctx context.Context, servers []netip.Addr, name string) (netip.Addr, error) {
	tried := false
	var lastErr error
	for _, srv := range servers {
		srv = srv.Unmap()
		if !srv.Is4() {
			continue
		}
		tried = true
		a, err := s.ask(ctx, srv, name)
		if err == nil {
			return a, nil
		}
		if ctx.Err() != nil {
			return netip.Addr{}, err
		}
		lastErr = err
	}
	if !tried {
		return netip.Addr{}, ErrNoDNS
	}
	return netip.Addr{}, lastErr
}

// ask — один DNS-сервер: запрос и один повтор.
func (s *stack) ask(ctx context.Context, srv netip.Addr, name string) (netip.Addr, error) {
	sport := ephemeralPort()
	id := uint16(randUint32())
	pkt := udpPacket(s.src, srv, sport, 53, dnsQuery(id, name))
	for _, wait := range []time.Duration{time.Second, 2 * time.Second} {
		if err := s.pc.WritePacket(pkt); err != nil {
			return netip.Addr{}, fmt.Errorf("DNS: %w", err)
		}
		deadline := time.Now().Add(wait)
		for {
			left := time.Until(deadline)
			if left <= 0 {
				break
			}
			p, err := s.next(ctx, left)
			if err != nil {
				return netip.Addr{}, err
			}
			if p == nil {
				break
			}
			ip, ok := parseIPv4(p)
			if !ok || ip.proto != protoUDP || ip.src != srv || ip.dst != s.src {
				continue
			}
			u, ok := parseUDP(ip.payload)
			if !ok || u.srcPort != 53 || u.dstPort != sport {
				continue
			}
			a, err := dnsAnswer(u.payload, id)
			if err == errNotOurs {
				continue
			}
			return a, err
		}
	}
	return netip.Addr{}, fmt.Errorf("DNS-сервер %s не ответил", srv)
}

var errNotOurs = errors.New("чужой ответ")

// dnsQuery — запрос A-записи с рекурсией.
func dnsQuery(id uint16, name string) []byte {
	b := make([]byte, 12, 12+len(name)+6)
	binary.BigEndian.PutUint16(b[0:], id)
	b[2] = 0x01                          // RD
	binary.BigEndian.PutUint16(b[4:], 1) // QDCOUNT
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0, 0, 1, 0, 1) // корень, QTYPE=A, QCLASS=IN
	return b
}

// dnsAnswer достаёт первую A-запись из ответа с идентификатором id.
func dnsAnswer(m []byte, id uint16) (netip.Addr, error) {
	if len(m) < 12 || binary.BigEndian.Uint16(m) != id || m[2]&0x80 == 0 {
		return netip.Addr{}, errNotOurs
	}
	switch rcode := m[3] & 0x0f; rcode {
	case 0:
	case 3:
		return netip.Addr{}, errors.New("DNS: такого имени нет")
	default:
		return netip.Addr{}, fmt.Errorf("DNS: сервер ответил ошибкой %d", rcode)
	}
	qd := int(binary.BigEndian.Uint16(m[4:]))
	an := int(binary.BigEndian.Uint16(m[6:]))
	off := 12
	var ok bool
	for i := 0; i < qd; i++ {
		if off, ok = skipName(m, off); !ok || off+4 > len(m) {
			return netip.Addr{}, errMalformed
		}
		off += 4
	}
	for i := 0; i < an; i++ {
		if off, ok = skipName(m, off); !ok || off+10 > len(m) {
			return netip.Addr{}, errMalformed
		}
		typ := binary.BigEndian.Uint16(m[off:])
		class := binary.BigEndian.Uint16(m[off+2:])
		rdlen := int(binary.BigEndian.Uint16(m[off+8:]))
		off += 10
		if off+rdlen > len(m) {
			return netip.Addr{}, errMalformed
		}
		if typ == 1 && class == 1 && rdlen == 4 {
			return netip.AddrFrom4([4]byte(m[off : off+4])), nil
		}
		off += rdlen
	}
	return netip.Addr{}, errors.New("DNS: у имени нет IPv4-адреса")
}

// skipName пропускает имя в сообщении DNS (с учётом сжатия указателями).
func skipName(m []byte, off int) (int, bool) {
	for off < len(m) {
		l := int(m[off])
		switch {
		case l == 0:
			return off + 1, true
		case l&0xc0 == 0xc0:
			return off + 2, off+2 <= len(m)
		case l&0xc0 != 0:
			return 0, false
		default:
			off += 1 + l
		}
	}
	return 0, false
}

// ---------- TCP ----------

const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpPSH = 0x08
	tcpACK = 0x10

	// synMSS — объявляемый MSS. Меньше обычного 1460: пакет идёт в
	// датаграмме QUIC, и крупный сегмент от сайта пришлось бы дробить.
	synMSS = 1200
)

// get — TCP-рукопожатие, запрос, первые байты ответа. Возвращает время от
// первого SYN до них и строку статуса.
func (s *stack) get(ctx context.Context, dst netip.Addr, dport uint16, req []byte) (time.Duration, string, error) {
	sport := ephemeralPort()
	iss := randUint32()
	send := func(flags byte, seq, ack uint32, payload []byte) error {
		return s.pc.WritePacket(tcpPacket(s.src, dst, sport, dport, seq, ack, flags, payload))
	}

	// Рукопожатие: SYN с повтором через 1, 2, 4 … с.
	start := time.Now()
	var irs uint32
	rto := time.Second
	established := false
	for !established {
		if err := send(tcpSYN, iss, 0, nil); err != nil {
			return 0, "", err
		}
		deadline := time.Now().Add(rto)
		for !established {
			seg, err := s.waitSeg(ctx, dst, dport, sport, deadline)
			if err != nil {
				return 0, "", err
			}
			if seg == nil {
				break // повторить SYN
			}
			switch {
			case seg.flags&tcpRST != 0:
				if seg.flags&tcpACK != 0 && seg.ack == iss+1 {
					return 0, "", ErrReset
				}
			case seg.flags&(tcpSYN|tcpACK) == tcpSYN|tcpACK && seg.ack == iss+1:
				irs = seg.seq
				established = true
			}
		}
		rto *= 2
	}

	// Запрос сразу с подтверждением SYN-ACK. Повтор, пока сайт его не
	// подтвердит или не ответит.
	sndNxt := iss + 1 + uint32(len(req))
	rcvNxt := irs + 1
	acked := false
	rto = time.Second
	for {
		if !acked {
			if err := send(tcpPSH|tcpACK, iss+1, rcvNxt, req); err != nil {
				return 0, "", err
			}
		}
		deadline := time.Now().Add(rto)
		for {
			seg, err := s.waitSeg(ctx, dst, dport, sport, deadline)
			if err != nil {
				return 0, "", err
			}
			if seg == nil {
				break
			}
			if seg.flags&tcpRST != 0 {
				return 0, "", ErrReset
			}
			if seg.flags&tcpACK != 0 && seqGE(seg.ack, sndNxt) {
				acked = true
			}
			if seg.flags&tcpSYN != 0 {
				// Наш ACK на SYN-ACK потерялся, сайт повторил: подтверждаем.
				_ = send(tcpACK, sndNxt, rcvNxt, nil)
				continue
			}
			if len(seg.payload) > 0 {
				if seg.seq != rcvNxt {
					_ = send(tcpACK, sndNxt, rcvNxt, nil) // не по порядку
					continue
				}
				rtt := time.Since(start)
				// Тело не нужно: сбрасываем соединение, чтобы сайт не слал
				// остальное в пустоту.
				_ = send(tcpRST|tcpACK, sndNxt, rcvNxt+uint32(len(seg.payload)), nil)
				status, err := statusLine(seg.payload)
				return rtt, status, err
			}
			if seg.flags&tcpFIN != 0 {
				_ = send(tcpRST|tcpACK, sndNxt, seg.seq+1, nil)
				return 0, "", ErrClosed
			}
		}
		if rto < 8*time.Second {
			rto *= 2
		}
	}
}

// waitSeg ждёт сегмент нашего соединения до срока. nil — срок вышел.
func (s *stack) waitSeg(ctx context.Context, dst netip.Addr, sport, dport uint16, deadline time.Time) (*tcpSeg, error) {
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return nil, nil
		}
		p, err := s.next(ctx, left)
		if err != nil || p == nil {
			return nil, err
		}
		ip, ok := parseIPv4(p)
		if !ok || ip.proto != protoTCP || ip.src != dst || ip.dst != s.src {
			continue
		}
		seg, ok := parseTCP(ip.payload)
		if !ok || seg.srcPort != sport || seg.dstPort != dport {
			continue
		}
		return seg, nil
	}
}

// seqGE — a ≥ b в арифметике последовательностей TCP.
func seqGE(a, b uint32) bool { return int32(a-b) >= 0 }

// statusLine — первая строка ответа, если это HTTP.
func statusLine(b []byte) (string, error) {
	line := string(b)
	if i := strings.IndexAny(line, "\r\n"); i >= 0 {
		line = line[:i]
	}
	if len(line) > 80 {
		line = line[:80]
	}
	if !strings.HasPrefix(line, "HTTP/") {
		return line, ErrNotHTTP
	}
	return line, nil
}

// ---------- пакеты ----------

const (
	protoTCP = 6
	protoUDP = 17
)

type ipv4 struct {
	proto    byte
	src, dst netip.Addr
	payload  []byte
}

// parseIPv4 разбирает заголовок IPv4. Фрагменты не собираются: ответ на
// наш короткий запрос в них не нуждается.
func parseIPv4(p []byte) (ipv4, bool) {
	if len(p) < 20 || p[0]>>4 != 4 {
		return ipv4{}, false
	}
	ihl := int(p[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(p[2:]))
	if ihl < 20 || total < ihl || total > len(p) {
		return ipv4{}, false
	}
	if frag := binary.BigEndian.Uint16(p[6:]); frag&0x3fff != 0 {
		return ipv4{}, false // MF или смещение
	}
	return ipv4{
		proto:   p[9],
		src:     netip.AddrFrom4([4]byte(p[12:16])),
		dst:     netip.AddrFrom4([4]byte(p[16:20])),
		payload: p[ihl:total],
	}, true
}

type udpDgram struct {
	srcPort, dstPort uint16
	payload          []byte
}

func parseUDP(b []byte) (udpDgram, bool) {
	if len(b) < 8 {
		return udpDgram{}, false
	}
	l := int(binary.BigEndian.Uint16(b[4:]))
	if l < 8 || l > len(b) {
		return udpDgram{}, false
	}
	return udpDgram{binary.BigEndian.Uint16(b), binary.BigEndian.Uint16(b[2:]), b[8:l]}, true
}

type tcpSeg struct {
	srcPort, dstPort uint16
	seq, ack         uint32
	flags            byte
	payload          []byte
}

func parseTCP(b []byte) (*tcpSeg, bool) {
	if len(b) < 20 {
		return nil, false
	}
	off := int(b[12]>>4) * 4
	if off < 20 || off > len(b) {
		return nil, false
	}
	return &tcpSeg{
		srcPort: binary.BigEndian.Uint16(b),
		dstPort: binary.BigEndian.Uint16(b[2:]),
		seq:     binary.BigEndian.Uint32(b[4:]),
		ack:     binary.BigEndian.Uint32(b[8:]),
		flags:   b[13],
		payload: b[off:],
	}, true
}

// ipv4Packet собирает пакет с заголовком без опций, TTL 64, DF.
func ipv4Packet(src, dst netip.Addr, proto byte, payload []byte) []byte {
	p := make([]byte, 20+len(payload))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	binary.BigEndian.PutUint16(p[4:], uint16(randUint32()))
	binary.BigEndian.PutUint16(p[6:], 0x4000) // DF
	p[8] = 64
	p[9] = proto
	s4, d4 := src.As4(), dst.As4()
	copy(p[12:16], s4[:])
	copy(p[16:20], d4[:])
	binary.BigEndian.PutUint16(p[10:], checksum(p[:20], 0))
	copy(p[20:], payload)
	return p
}

func udpPacket(src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	u := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(u, sport)
	binary.BigEndian.PutUint16(u[2:], dport)
	binary.BigEndian.PutUint16(u[4:], uint16(len(u)))
	copy(u[8:], payload)
	c := checksum(u, pseudoSum(src, dst, protoUDP, len(u)))
	if c == 0 {
		c = 0xffff // в UDP ноль значит «сумма не считалась»
	}
	binary.BigEndian.PutUint16(u[6:], c)
	return ipv4Packet(src, dst, protoUDP, u)
}

func tcpPacket(src, dst netip.Addr, sport, dport uint16, seq, ack uint32, flags byte, payload []byte) []byte {
	hl := 20
	if flags&tcpSYN != 0 {
		hl = 24 // опция MSS
	}
	t := make([]byte, hl+len(payload))
	binary.BigEndian.PutUint16(t, sport)
	binary.BigEndian.PutUint16(t[2:], dport)
	binary.BigEndian.PutUint32(t[4:], seq)
	binary.BigEndian.PutUint32(t[8:], ack)
	t[12] = byte(hl/4) << 4
	t[13] = flags
	binary.BigEndian.PutUint16(t[14:], 65535) // окно
	if hl == 24 {
		t[20], t[21] = 2, 4
		binary.BigEndian.PutUint16(t[22:], synMSS)
	}
	copy(t[hl:], payload)
	binary.BigEndian.PutUint16(t[16:], checksum(t, pseudoSum(src, dst, protoTCP, len(t))))
	return ipv4Packet(src, dst, protoTCP, t)
}

// pseudoSum — сумма псевдозаголовка IPv4 для UDP и TCP.
func pseudoSum(src, dst netip.Addr, proto byte, length int) uint32 {
	s4, d4 := src.As4(), dst.As4()
	var sum uint32
	for i := 0; i < 4; i += 2 {
		sum += uint32(s4[i])<<8 | uint32(s4[i+1])
		sum += uint32(d4[i])<<8 | uint32(d4[i+1])
	}
	return sum + uint32(proto) + uint32(length)
}

// checksum — интернет-контрольная сумма (RFC 1071) поверх начальной суммы.
func checksum(b []byte, sum uint32) uint16 {
	for len(b) >= 2 {
		sum += uint32(b[0])<<8 | uint32(b[1])
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
