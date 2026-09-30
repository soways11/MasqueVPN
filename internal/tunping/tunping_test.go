package tunping

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Проверка идёт против собеседника, собранного на gopacket, — чужом разборе
// и чужой сборке пакетов. Свой же разбор подтвердил бы свои же ошибки
// (перепутанный порядок байт, неверную контрольную сумму) — gopacket нет.

var (
	cliAddr = netip.MustParseAddr("10.66.0.4")
	dnsAddr = netip.MustParseAddr("10.66.0.1")
	webAddr = netip.MustParseAddr("93.184.215.14")
)

// peer — «интернет за туннелем»: резолвер и веб-сервер.
type peer struct {
	t     *testing.T
	delay time.Duration // задержка каждого ответа (путь через туннель)

	dropSYN   int  // сколько первых SYN «потерять»
	dropReq   int  // сколько первых запросов «потерять»
	rst       bool // на SYN — RST
	fin       bool // на запрос — FIN без данных
	nxdomain  bool
	dnsSilent bool

	mu      sync.Mutex
	out     chan []byte
	closed  bool
	sent    []*layers.TCP // что прислал клиент по TCP
	request []byte
	dnsQs   int
}

func newPeer(t *testing.T) *peer { return &peer{t: t, out: make(chan []byte, 64)} }

func (p *peer) ReadPacket(b []byte) (int, error) {
	pkt, ok := <-p.out
	if !ok {
		return 0, net.ErrClosed
	}
	return copy(b, pkt), nil
}

func (p *peer) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		p.closed = true
		close(p.out)
	}
}

func (p *peer) reply(ip *layers.IPv4, l gopacket.SerializableLayer, payload []byte) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	switch x := l.(type) {
	case *layers.TCP:
		_ = x.SetNetworkLayerForChecksum(ip)
	case *layers.UDP:
		_ = x.SetNetworkLayerForChecksum(ip)
	}
	if err := gopacket.SerializeLayers(buf, opts, ip, l, gopacket.Payload(payload)); err != nil {
		p.t.Error(err)
		return
	}
	pkt := append([]byte(nil), buf.Bytes()...)
	go func() {
		time.Sleep(p.delay)
		p.mu.Lock()
		defer p.mu.Unlock()
		if !p.closed {
			p.out <- pkt
		}
	}()
}

// checkSums сверяет контрольные суммы клиента с посчитанными gopacket.
func (p *peer) checkSums(pkt []byte, ip *layers.IPv4, l gopacket.SerializableLayer, payload []byte) {
	p.t.Helper()
	buf := gopacket.NewSerializeBuffer()
	cp := *ip
	switch x := l.(type) {
	case *layers.TCP:
		c := *x
		_ = c.SetNetworkLayerForChecksum(&cp)
		l = &c
	case *layers.UDP:
		c := *x
		_ = c.SetNetworkLayerForChecksum(&cp)
		l = &c
	}
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true}, &cp, l, gopacket.Payload(payload)); err != nil {
		p.t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), pkt) {
		p.t.Errorf("пакет клиента не совпал с пересобранным gopacket (контрольные суммы?)\nклиент:   %x\ngopacket: %x", pkt, buf.Bytes())
	}
}

func (p *peer) WritePacket(pkt []byte) error {
	pk := gopacket.NewPacket(pkt, layers.LayerTypeIPv4, gopacket.Default)
	ip, _ := pk.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ip == nil {
		p.t.Errorf("клиент прислал не IPv4: %x", pkt)
		return nil
	}
	if ip.TTL != 64 || ip.Flags&layers.IPv4DontFragment == 0 || !ip.SrcIP.Equal(cliAddr.AsSlice()) {
		p.t.Errorf("заголовок IPv4: ttl=%d flags=%v src=%v", ip.TTL, ip.Flags, ip.SrcIP)
	}
	if udp, _ := pk.Layer(layers.LayerTypeUDP).(*layers.UDP); udp != nil {
		p.checkSums(pkt, ip, udp, udp.Payload)
		p.dns(ip, udp)
		return nil
	}
	if tcp, _ := pk.Layer(layers.LayerTypeTCP).(*layers.TCP); tcp != nil {
		p.checkSums(pkt, ip, tcp, tcp.Payload)
		p.tcp(ip, tcp)
		return nil
	}
	p.t.Errorf("неожиданный протокол %v", ip.Protocol)
	return nil
}

func (p *peer) dns(ip *layers.IPv4, udp *layers.UDP) {
	p.mu.Lock()
	p.dnsQs++
	p.mu.Unlock()
	if udp.DstPort != 53 || !ip.DstIP.Equal(dnsAddr.AsSlice()) {
		p.t.Errorf("DNS-запрос не туда: %v:%d", ip.DstIP, udp.DstPort)
		return
	}
	var q layers.DNS
	if err := q.DecodeFromBytes(udp.Payload, gopacket.NilDecodeFeedback); err != nil {
		p.t.Errorf("gopacket не разобрал DNS-запрос: %v", err)
		return
	}
	if len(q.Questions) != 1 || string(q.Questions[0].Name) != "example.com" || q.Questions[0].Type != layers.DNSTypeA || !q.RD {
		p.t.Errorf("DNS-вопрос: %+v", q.Questions)
	}
	if p.dnsSilent {
		return
	}
	a := layers.DNS{ID: q.ID, QR: true, RD: true, RA: true, Questions: q.Questions}
	if p.nxdomain {
		a.ResponseCode = layers.DNSResponseCodeNXDomain
	} else {
		// CNAME впереди — ответ как у настоящих резолверов.
		a.Answers = []layers.DNSResourceRecord{
			{Name: []byte("example.com"), Type: layers.DNSTypeCNAME, Class: layers.DNSClassIN, TTL: 60, CNAME: []byte("edge.example.net")},
			{Name: []byte("edge.example.net"), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 60, IP: webAddr.AsSlice()},
		}
	}
	buf := gopacket.NewSerializeBuffer()
	if err := a.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: true}); err != nil {
		p.t.Fatal(err)
	}
	p.reply(&layers.IPv4{Version: 4, TTL: 60, Protocol: layers.IPProtocolUDP, SrcIP: ip.DstIP, DstIP: ip.SrcIP},
		&layers.UDP{SrcPort: 53, DstPort: udp.SrcPort}, buf.Bytes())
}

const iss = 777000

func (p *peer) tcp(ip *layers.IPv4, t *layers.TCP) {
	p.mu.Lock()
	cp := *t
	cp.Payload = append([]byte(nil), t.Payload...)
	p.sent = append(p.sent, &cp)
	p.mu.Unlock()

	back := &layers.IPv4{Version: 4, TTL: 60, Protocol: layers.IPProtocolTCP, SrcIP: ip.DstIP, DstIP: ip.SrcIP}
	seg := func(seq, ack uint32) *layers.TCP {
		return &layers.TCP{SrcPort: t.DstPort, DstPort: t.SrcPort, Seq: seq, Ack: ack, Window: 65535}
	}
	switch {
	case t.SYN:
		if p.dropSYN > 0 {
			p.dropSYN--
			return
		}
		s := seg(0, t.Seq+1)
		if p.rst {
			s.RST, s.ACK = true, true
		} else {
			s.Seq, s.SYN, s.ACK = iss, true, true
		}
		p.reply(back, s, nil)
	case len(t.Payload) > 0:
		p.mu.Lock()
		p.request = cp.Payload
		p.mu.Unlock()
		if p.dropReq > 0 {
			p.dropReq--
			return
		}
		next := t.Seq + uint32(len(t.Payload))
		if p.fin {
			s := seg(iss+1, next)
			s.FIN, s.ACK = true, true
			p.reply(back, s, nil)
			return
		}
		ack := seg(iss+1, next)
		ack.ACK = true
		p.reply(back, ack, nil)
		data := seg(iss+1, next)
		data.ACK, data.PSH = true, true
		p.reply(back, data, []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>"))
	}
}

func (p *peer) flags() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for _, t := range p.sent {
		var f []string
		for _, x := range []struct {
			on   bool
			name string
		}{{t.SYN, "S"}, {t.RST, "R"}, {t.PSH, "P"}, {t.FIN, "F"}, {t.ACK, "."}} {
			if x.on {
				f = append(f, x.name)
			}
		}
		out = append(out, strings.Join(f, ""))
	}
	return strings.Join(out, " ")
}

func get(t *testing.T, p *peer, timeout time.Duration) (Result, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	defer p.Close()
	return Get(ctx, p, cliAddr, []netip.Addr{netip.MustParseAddr("2001:db8::53"), dnsAddr}, "example.com", 80, "/")
}

func TestGetThroughTunnel(t *testing.T) {
	p := newPeer(t)
	p.delay = 30 * time.Millisecond
	res, err := get(t, p, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "HTTP/1.1 200 OK" || res.Addr != webAddr {
		t.Fatalf("итог %+v", res)
	}
	// Два круга через туннель: SYN → SYN-ACK и запрос → ответ. Меньше двух
	// задержек — значит, время меряется не от того места.
	if res.RTT < 2*p.delay || res.RTT > 2*p.delay+500*time.Millisecond {
		t.Fatalf("время %v при задержке %v на ответ", res.RTT, p.delay)
	}
	if res.DNS < p.delay {
		t.Fatalf("время DNS %v", res.DNS)
	}
	// SYN, запрос вместе с подтверждением, сброс после первых байтов.
	if got := p.flags(); got != "S P. R." {
		t.Fatalf("флаги клиента: %q", got)
	}
	syn := p.sent[0]
	if len(syn.Options) == 0 || syn.Options[0].OptionType != layers.TCPOptionKindMSS ||
		syn.Options[0].OptionData[0] != synMSS>>8 || syn.Options[0].OptionData[1] != synMSS&0xff {
		t.Errorf("в SYN нет MSS %d: %+v", synMSS, syn.Options)
	}
	if syn.SrcPort < 49152 || syn.DstPort != 80 {
		t.Errorf("порты %d → %d", syn.SrcPort, syn.DstPort)
	}
	req := string(p.request)
	for _, want := range []string{"GET / HTTP/1.1\r\n", "\r\nHost: example.com\r\n", "\r\n\r\n"} {
		if !strings.Contains(req, want) {
			t.Errorf("в запросе нет %q:\n%s", want, req)
		}
	}
	// Сброс подтверждает ответ целиком — иначе сайт слал бы его повторно.
	rst := p.sent[len(p.sent)-1]
	if rst.Ack != iss+1+uint32(len("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>")) {
		t.Errorf("RST подтверждает %d", rst.Ack)
	}
}

// Потери: SYN и запрос повторяются, а время честно включает ожидание.
func TestGetRetransmits(t *testing.T) {
	p := newPeer(t)
	p.dropSYN, p.dropReq = 1, 1
	res, err := get(t, p, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.flags(); got != "S S P. P. R." {
		t.Fatalf("флаги: %q", got)
	}
	if res.RTT < 2*time.Second {
		t.Fatalf("время %v не включает повторы (1 с на SYN + 1 с на запрос)", res.RTT)
	}
}

func TestGetFailures(t *testing.T) {
	for _, c := range []struct {
		name string
		set  func(*peer)
		want error
		msg  string
	}{
		{"сброс", func(p *peer) { p.rst = true }, ErrReset, ""},
		{"закрыл без ответа", func(p *peer) { p.fin = true }, ErrClosed, ""},
		{"нет имени", func(p *peer) { p.nxdomain = true }, nil, "такого имени нет"},
		{"резолвер молчит", func(p *peer) { p.dnsSilent = true }, nil, "не ответил"},
		{"сайт молчит", func(p *peer) { p.dropSYN = 100 }, context.DeadlineExceeded, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := newPeer(t)
			c.set(p)
			_, err := get(t, p, 4*time.Second)
			if err == nil {
				t.Fatal("ошибки нет")
			}
			if c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("ошибка %v, ждали %v", err, c.want)
			}
			if c.msg != "" && !strings.Contains(err.Error(), c.msg) {
				t.Fatalf("ошибка %q без %q", err, c.msg)
			}
		})
	}
	// Без IPv4 в туннеле и без DNS IPv4 — понятные ошибки сразу.
	p := newPeer(t)
	defer p.Close()
	if _, err := Get(context.Background(), p, netip.MustParseAddr("fd00::4"), nil, "example.com", 80, "/"); !errors.Is(err, ErrNoIPv4) {
		t.Fatalf("без IPv4: %v", err)
	}
	if _, err := Get(context.Background(), p, cliAddr, []netip.Addr{netip.MustParseAddr("2001:db8::1")}, "example.com", 80, "/"); !errors.Is(err, ErrNoDNS) {
		t.Fatalf("без DNS: %v", err)
	}
}

// Сжатые имена в ответе (как отдают почти все резолверы) — gopacket их не
// сжимает, поэтому этот случай собран руками.
func TestDNSAnswerCompressed(t *testing.T) {
	q := dnsQuery(0x1234, "example.com")
	m := append([]byte(nil), q...)
	m[2], m[3] = 0x81, 0x80                                                  // ответ, RD, RA
	m[7] = 1                                                                 // ANCOUNT
	m = append(m, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 215, 14) // имя — указатель на вопрос
	a, err := dnsAnswer(m, 0x1234)
	if err != nil || a != webAddr {
		t.Fatalf("%v %v", a, err)
	}
	if _, err := dnsAnswer(m, 0x9999); err != errNotOurs {
		t.Fatal("чужой идентификатор принят")
	}
	if _, err := dnsAnswer(m[:len(m)-3], 0x1234); err == nil {
		t.Fatal("обрезанный ответ принят")
	}
}
