// fpserverhello — пассивно снимает ServerHello живого HTTP/3-сервера и печатает
// legacy_version, выбранный cipher_suite и ПОРЯДОК расширений (для key_share —
// выбранную группу). Нужен, чтобы сверить наш ServerHello (crypto/tls) с чужим
// (Cloudflare = quiche/BoringSSL, Caddy = тот же crypto/tls).
//
//	fpserverhello -probe www.cloudflare.com:443
//
// Только stdlib. ClientHello делает crypto/tls.QUICClient (значит с
// X25519MLKEM768, как у Chrome), Initial-пакеты и расшифровку серверного
// Initial (ключи из открытого DCID, RFC 9001) собираем руками.
package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

var initialSaltV1 = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
}

const quicV1 = 0x00000001

func expandLabel(secret []byte, label string, length int) []byte {
	full := "tls13 " + label
	var info []byte
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0) // пустой context
	out, err := hkdf.Expand(sha256.New, secret, string(info), length)
	if err != nil {
		panic(err)
	}
	return out
}

type keys struct {
	key, iv, hp []byte
}

func initialKeys(dcid []byte) (client, server keys) {
	initial, err := hkdf.Extract(sha256.New, dcid, initialSaltV1)
	if err != nil {
		panic(err)
	}
	derive := func(who string) keys {
		s := expandLabel(initial, who, 32)
		return keys{
			key: expandLabel(s, "quic key", 16),
			iv:  expandLabel(s, "quic iv", 12),
			hp:  expandLabel(s, "quic hp", 16),
		}
	}
	return derive("client in"), derive("server in")
}

func aead(key []byte) cipher.AEAD {
	blk, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	a, err := cipher.NewGCM(blk)
	if err != nil {
		panic(err)
	}
	return a
}

func hpMask(hpKey, sample []byte) []byte {
	blk, err := aes.NewCipher(hpKey)
	if err != nil {
		panic(err)
	}
	out := make([]byte, 16)
	blk.Encrypt(out, sample[:16])
	return out
}

func nonce(iv []byte, pn uint64) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], pn)
	for i := range n {
		n[i] ^= iv[i]
	}
	return n
}

func varint(v uint64) []byte {
	switch {
	case v < 1<<6:
		return []byte{byte(v)}
	case v < 1<<14:
		return binary.BigEndian.AppendUint16(nil, uint16(v)|0x4000)
	case v < 1<<30:
		return binary.BigEndian.AppendUint32(nil, uint32(v)|0x80000000)
	default:
		return binary.BigEndian.AppendUint64(nil, v|0xc000000000000000)
	}
}

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
		return uint64(binary.BigEndian.Uint16(b) & 0x3fff), 2
	case 2:
		if len(b) < 4 {
			return 0, 0
		}
		return uint64(binary.BigEndian.Uint32(b) & 0x3fffffff), 4
	default:
		if len(b) < 8 {
			return 0, 0
		}
		return binary.BigEndian.Uint64(b) & 0x3fffffffffffffff, 8
	}
}

// buildClientHello поднимает crypto/tls.QUICClient и забирает байты ClientHello
// (уровень Initial) вместе с транспортными параметрами.
func buildClientHello(sni string, scid []byte) []byte {
	cfg := &tls.Config{
		ServerName: sni,
		NextProtos: []string{"h3"},
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}
	// Минимальные транспортные параметры. Длину каждого пишем как РЕАЛЬНУЮ
	// длину значения в QUIC-варинте, а не на глаз: varint(30000) — это 4 байта
	// (30000 > 2^14), и если объявить длину 2, живой сервер отвергнет
	// рукопожатие через CONNECTION_CLOSE в Initial.
	var tp []byte
	addTP := func(id, val uint64) {
		v := varint(val)
		tp = append(tp, varint(id)...)
		tp = append(tp, varint(uint64(len(v)))...)
		tp = append(tp, v...)
	}
	// initial_source_connection_id: значение — сырой SCID, не varint.
	tp = append(tp, varint(0x0f)...)
	tp = append(tp, varint(uint64(len(scid)))...)
	tp = append(tp, scid...)
	addTP(0x04, 1<<20) // initial_max_data
	addTP(0x01, 30000) // max_idle_timeout

	qc := tls.QUICClient(&tls.QUICConfig{TLSConfig: cfg})
	qc.SetTransportParameters(tp)
	if err := qc.Start(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "QUICClient.Start:", err)
		os.Exit(1)
	}
	var ch []byte
	for {
		ev := qc.NextEvent()
		if ev.Kind == tls.QUICNoEvent {
			break
		}
		if ev.Kind == tls.QUICWriteData && ev.Level == tls.QUICEncryptionLevelInitial {
			ch = append(ch, ev.Data...)
		}
	}
	qc.Close()
	return ch
}

// initialPacket собирает один Initial-пакет с CRYPTO(offset,data), дополняя
// PADDING до padTo байт всей датаграммы.
func initialPacket(dcid, scid, token []byte, pn uint32, cryptoOff uint64, cryptoData []byte, ck keys, padTo int) []byte {
	// frame CRYPTO
	frame := []byte{0x06}
	frame = append(frame, varint(cryptoOff)...)
	frame = append(frame, varint(uint64(len(cryptoData)))...)
	frame = append(frame, cryptoData...)

	pnLen := 4
	// header (public)
	hdr := []byte{0xc0 | byte(pnLen-1)} // long, Initial(00), pnlen
	hdr = binary.BigEndian.AppendUint32(hdr, quicV1)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, byte(len(scid)))
	hdr = append(hdr, scid...)
	hdr = append(hdr, varint(uint64(len(token)))...)
	hdr = append(hdr, token...)

	// payload перед padding
	payload := frame
	// сколько ещё PADDING нужно, чтобы датаграмма стала padTo
	// длина length-поля пока неизвестна (varint от pn+payload+16); берём 2 байта.
	// Оценим и добьём PADDING.
	overhead := len(hdr) + 2 /*length varint*/ + pnLen + 16 /*tag*/
	if pad := padTo - overhead - len(payload); pad > 0 {
		payload = append(payload, make([]byte, pad)...)
	}
	length := pnLen + len(payload) + 16
	lv := varint(uint64(length))
	// если оценка длины length-varint (2) не совпала — поправим padding
	if len(lv) != 2 {
		diff := 2 - len(lv)
		payload = append(payload, make([]byte, diff)...)
		length = pnLen + len(payload) + 16
		lv = varint(uint64(length))
	}
	hdr = append(hdr, lv...)
	pnOff := len(hdr)
	hdr = binary.BigEndian.AppendUint32(hdr, pn)

	// AEAD
	a := aead(ck.key)
	ct := a.Seal(nil, nonce(ck.iv, uint64(pn)), payload, hdr)
	pkt := append(append([]byte{}, hdr...), ct...)

	// header protection: sample с pnOff+4
	sample := pkt[pnOff+4 : pnOff+4+16]
	mask := hpMask(ck.hp, sample)
	pkt[0] ^= mask[0] & 0x0f
	for i := 0; i < pnLen; i++ {
		pkt[pnOff+i] ^= mask[1+i]
	}
	return pkt
}

type parsed struct {
	typ       byte // 0 Initial, 2 Handshake, 3 Retry
	crypto    map[uint64][]byte
	retrySCID []byte
	retryTok  []byte
	connClose bool
}

// decryptServerInitial разбирает одну датаграмму (возможно с несколькими
// пакетами), возвращает по каждому распознанному пакету результат.
func parseDatagram(dg []byte, sk keys, ourSCID []byte) []parsed {
	var out []parsed
	i := 0
	for i < len(dg) {
		b0 := dg[i]
		if b0&0x80 == 0 {
			break // короткий заголовок — не наш случай
		}
		typ := (b0 & 0x30) >> 4
		if i+5 > len(dg) {
			break
		}
		ver := binary.BigEndian.Uint32(dg[i+1 : i+5])
		p := i + 5
		if p >= len(dg) {
			break
		}
		dcidLen := int(dg[p])
		p++
		p += dcidLen
		if p >= len(dg) {
			break
		}
		scidLen := int(dg[p])
		p++
		scid := dg[p : p+scidLen]
		p += scidLen
		if ver == 0 { // version negotiation
			break
		}
		if typ == 3 { // Retry: остаток = token + 16б integrity tag
			rest := dg[p:]
			if len(rest) < 16 {
				break
			}
			out = append(out, parsed{typ: 3, retrySCID: append([]byte{}, scid...), retryTok: append([]byte{}, rest[:len(rest)-16]...)})
			return out
		}
		var tok []byte
		if typ == 0 { // Initial: token
			tl, n := readVarint(dg[p:])
			p += n
			tok = dg[p : p+int(tl)]
			_ = tok
			p += int(tl)
		}
		length, n := readVarint(dg[p:])
		if n == 0 {
			break
		}
		p += n
		pnOff := p
		if pnOff+int(length) > len(dg) {
			break
		}
		pktEnd := pnOff + int(length)
		// header protection removal (только для Initial, серверными ключами)
		if typ != 0 {
			i = pktEnd
			continue
		}
		sample := dg[pnOff+4 : pnOff+4+16]
		mask := hpMask(sk.hp, sample)
		first := b0 ^ (mask[0] & 0x0f)
		pnLen := int(first&0x03) + 1
		hdr := append([]byte{}, dg[i:pnOff]...)
		hdr[0] = first
		var pn uint64
		for k := 0; k < pnLen; k++ {
			bb := dg[pnOff+k] ^ mask[1+k]
			hdr = append(hdr, bb)
			pn = pn<<8 | uint64(bb)
		}
		ctStart := pnOff + pnLen
		ct := dg[ctStart:pktEnd]
		a := aead(sk.key)
		pt, err := a.Open(nil, nonce(sk.iv, pn), ct, hdr)
		if err != nil {
			out = append(out, parsed{typ: 0, crypto: nil})
			i = pktEnd
			continue
		}
		pr := parsed{typ: 0, crypto: map[uint64][]byte{}}
		parseFrames(pt, &pr)
		out = append(out, pr)
		i = pktEnd
	}
	return out
}

func parseFrames(pt []byte, pr *parsed) {
	i := 0
	for i < len(pt) {
		t := pt[i]
		switch {
		case t == 0x00: // PADDING
			i++
		case t == 0x01: // PING
			i++
		case t == 0x02 || t == 0x03: // ACK
			i++
			_, n := readVarint(pt[i:])
			i += n // largest
			_, n = readVarint(pt[i:])
			i += n // delay
			rc, n := readVarint(pt[i:])
			i += n // range count
			_, n = readVarint(pt[i:])
			i += n // first range
			for r := uint64(0); r < rc; r++ {
				_, n = readVarint(pt[i:])
				i += n
				_, n = readVarint(pt[i:])
				i += n
			}
			if t == 0x03 {
				for e := 0; e < 3; e++ {
					_, n = readVarint(pt[i:])
					i += n
				}
			}
		case t == 0x06: // CRYPTO
			i++
			off, n := readVarint(pt[i:])
			i += n
			ln, n := readVarint(pt[i:])
			i += n
			if i+int(ln) > len(pt) {
				return
			}
			pr.crypto[off] = append([]byte{}, pt[i:i+int(ln)]...)
			i += int(ln)
		case t == 0x1c || t == 0x1d: // CONNECTION_CLOSE
			pr.connClose = true
			return
		default:
			return // незнакомый фрейм — дальше не разобрать
		}
	}
}

func reassemble(m map[uint64][]byte) []byte {
	var out []byte
	for {
		c, ok := m[uint64(len(out))]
		if !ok {
			return out
		}
		out = append(out, c...)
	}
}

var extNames = map[uint16]string{
	0:      "server_name",
	10:     "supported_groups",
	13:     "signature_algorithms",
	43:     "supported_versions",
	51:     "key_share",
	41:     "pre_shared_key",
	42:     "early_data",
	44:     "cookie",
	0x39:   "quic_transport_parameters",
	0xff01: "renegotiation_info",
	16:     "application_layer_protocol_negotiation",
	5:      "status_request",
	65037:  "encrypted_client_hello",
}

var groupNames = map[uint16]string{
	0x001d: "X25519",
	0x0017: "secp256r1",
	0x0018: "secp384r1",
	0x0019: "secp521r1",
	0x11ec: "X25519MLKEM768",
	0x6399: "X25519Kyber768Draft00",
}

func parseServerHello(b []byte) {
	if len(b) < 4 || b[0] != 2 {
		fmt.Println("  (это не ServerHello, тип=", b[0], ")")
		return
	}
	l := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	p := b[4 : 4+l]
	ver := binary.BigEndian.Uint16(p[:2])
	fmt.Printf("  legacy_version   0x%04x\n", ver)
	p = p[34:] // version(2)+random(32)
	sidLen := int(p[0])
	p = p[1+sidLen:]
	cs := binary.BigEndian.Uint16(p[:2])
	fmt.Printf("  cipher_suite     0x%04x %s\n", cs, cipherName(cs))
	p = p[2:]
	p = p[1:] // compression
	extLen := int(binary.BigEndian.Uint16(p[:2]))
	ext := p[2 : 2+extLen]
	fmt.Println("  extensions (в порядке ServerHello):")
	order := 1
	for len(ext) >= 4 {
		id := binary.BigEndian.Uint16(ext[:2])
		dl := int(binary.BigEndian.Uint16(ext[2:4]))
		data := ext[4 : 4+dl]
		name := extNames[id]
		if name == "" {
			name = "?"
		}
		extra := ""
		switch id {
		case 51: // key_share
			if len(data) >= 2 {
				g := binary.BigEndian.Uint16(data[:2])
				gn := groupNames[g]
				if gn == "" {
					gn = "?"
				}
				extra = fmt.Sprintf("  group=0x%04x %s", g, gn)
			}
		case 43: // supported_versions
			if len(data) >= 2 {
				extra = fmt.Sprintf("  selected=0x%04x", binary.BigEndian.Uint16(data[:2]))
			}
		}
		fmt.Printf("    %d. 0x%04x %-38s len=%-4d%s\n", order, id, name, dl, extra)
		order++
		ext = ext[4+dl:]
	}
}

func cipherName(c uint16) string {
	switch c {
	case 0x1301:
		return "TLS_AES_128_GCM_SHA256"
	case 0x1302:
		return "TLS_AES_256_GCM_SHA384"
	case 0x1303:
		return "TLS_CHACHA20_POLY1305_SHA256"
	}
	return "?"
}

func main() {
	addr := flag.String("probe", "", "host:port")
	sni := flag.String("sni", "", "SNI (по умолчанию host из -probe)")
	timeout := flag.Duration("timeout", 8*time.Second, "таймаут")
	flag.Parse()
	if *addr == "" {
		fmt.Fprintln(os.Stderr, "нужен -probe host:port")
		os.Exit(2)
	}
	host := *addr
	if h, _, err := net.SplitHostPort(*addr); err == nil {
		host = h
	}
	name := *sni
	if name == "" {
		name = host
	}

	dcid := make([]byte, 8)
	scid := make([]byte, 8)
	rand.Read(dcid)
	rand.Read(scid)

	ch := buildClientHello(name, scid)
	fmt.Printf("проба %s (SNI %s), ClientHello %d байт, DCID %x\n", *addr, name, len(ch), dcid)

	ck, sk := initialKeys(dcid)

	uconn, err := net.Dial("udp", *addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dial:", err)
		os.Exit(1)
	}
	defer uconn.Close()

	sendFlight := func(dcid []byte, ck keys, token []byte) {
		// разбить ClientHello на пакеты по ~1100 байт CRYPTO
		const chunk = 1100
		var pn uint32
		for off := 0; off < len(ch); off += chunk {
			end := off + chunk
			if end > len(ch) {
				end = len(ch)
			}
			pkt := initialPacket(dcid, scid, token, pn, uint64(off), ch[off:end], ck, 1200)
			uconn.Write(pkt)
			pn++
		}
	}
	sendFlight(dcid, ck, nil)

	deadline := time.Now().Add(*timeout)
	uconn.SetReadDeadline(deadline)
	buf := make([]byte, 2048)
	got := map[uint64][]byte{}
	retried := false
	for time.Now().Before(deadline) {
		n, err := uconn.Read(buf)
		if err != nil {
			break
		}
		for _, pr := range parseDatagram(buf[:n], sk, scid) {
			if pr.typ == 3 && !retried {
				fmt.Printf("получен Retry (token %d байт) — повторяю с новым DCID\n", len(pr.retryTok))
				dcid = pr.retrySCID
				ck, sk = initialKeys(dcid)
				got = map[uint64][]byte{}
				retried = true
				sendFlight(dcid, ck, pr.retryTok)
				continue
			}
			if pr.connClose {
				fmt.Println("сервер прислал CONNECTION_CLOSE в Initial")
			}
			for o, d := range pr.crypto {
				if _, ok := got[o]; !ok {
					got[o] = d
				}
			}
		}
		if sh := reassemble(got); len(sh) >= 4 && sh[0] == 2 {
			hl := int(sh[1])<<16 | int(sh[2])<<8 | int(sh[3])
			if len(sh) >= 4+hl {
				fmt.Println("ServerHello снят:")
				parseServerHello(sh)
				return
			}
		}
	}
	if sh := reassemble(got); len(sh) >= 4 && sh[0] == 2 {
		fmt.Println("ServerHello снят (по таймауту):")
		parseServerHello(sh)
		return
	}
	fmt.Println("ServerHello собрать не удалось; собрано CRYPTO байт:", len(reassemble(got)))
	if strings.Contains(*addr, ":") {
		os.Exit(1)
	}
}
