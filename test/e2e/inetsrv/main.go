// Команда inetsrv — «интернет» для сквозного теста: HTTP-сервер во внешнем
// network namespace. Сообщает адрес, с которого пришёл запрос (проверка NAT),
// отдаёт и принимает крупные объёмы (проверка TCP и MTU).
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
)

// pattern — детерминированные данные: хеш можно посчитать на обеих сторонах.
type pattern struct{ off int64 }

func (p *pattern) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = byte((p.off*7 + p.off>>8) & 0xff)
		p.off++
	}
	return len(b), nil
}

func main() {
	addr := flag.String("addr", ":8080", "адрес HTTP (пусто — не поднимать)")
	udp := flag.String("udp", ":7", "адрес UDP-эха (пусто — не поднимать)")
	dns := flag.String("dns", "", "адрес DNS-резолвера: печатает каждый запрос")
	dnsA := flag.String("dns-a", "", "имя=IPv4: на A-запрос этого имени резолвер отвечает адресом")
	flag.Parse()

	if *dnsA != "" {
		name, ip, ok := strings.Cut(*dnsA, "=")
		a, err := netip.ParseAddr(ip)
		if !ok || err != nil || !a.Is4() {
			log.Fatalf("-dns-a: ожидалось имя=IPv4, получено %q", *dnsA)
		}
		answerName, answerIP = name, a
	}
	if *dns != "" {
		go serveDNS(*dns)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello from internet\n")
	})
	http.HandleFunc("/whoami", func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		fmt.Fprintln(w, host)
	})
	http.HandleFunc("/blob", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.ParseInt(r.URL.Query().Get("n"), 10, 64)
		w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
		io.CopyN(w, &pattern{}, n)
	})
	http.HandleFunc("/sink", func(w http.ResponseWriter, r *http.Request) {
		h := sha256.New()
		n, err := io.Copy(h, r.Body)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		fmt.Fprintf(w, "%d %s\n", n, hex.EncodeToString(h.Sum(nil)))
	})
	if *udp == "" {
		if *addr == "" {
			select {} // только DNS
		}
	} else {
		go serveUDPEcho(*udp)
	}
	log.Fatal(http.ListenAndServe(*addr, nil))
}

func serveUDPEcho(addr string) {
	{
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, 65536)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n >= 4 && string(buf[:4]) == "len?" {
				// Проверка одного направления: вместо эха — только длина.
				pc.WriteTo([]byte(strconv.Itoa(n)), from)
				continue
			}
			pc.WriteTo(buf[:n], from)
		}
	}
}

// answerName/answerIP — единственная запись, которую знает резолвер (-dns-a).
var (
	answerName string
	answerIP   netip.Addr
)

// serveDNS — минимальный резолвер для сквозного теста: печатает, КТО и ЧТО
// спросил, и отвечает пустым ответом. По этим строкам тест проверяет, что
// фоновые DNS-запросы видны снаружи туннеля и приходят с настоящего адреса
// клиента, а не с туннельного.
func serveDNS(addr string) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		host, _, _ := net.SplitHostPort(from.String())
		name, qtype, qend, ok := parseQuestion(buf[:n])
		if !ok {
			continue
		}
		fmt.Printf("dns src=%s name=%s type=%d\n", host, name, qtype)
		rsp := append([]byte(nil), buf[:n]...)
		rsp[2] |= 0x80 // QR
		if qtype == 1 && answerIP.IsValid() && strings.EqualFold(name, answerName) {
			// Ответ — заголовок и вопрос, затем одна запись A: имя ссылкой
			// на вопрос (0xC00C), класс IN, TTL 60, четыре байта адреса.
			// Всё после вопроса (EDNS0 OPT, который шлёт резолвер Go)
			// отрезается: запись после раздела «дополнительно» — битый
			// ответ, и резолвер его выбросит.
			rsp = rsp[:qend]
			binary.BigEndian.PutUint16(rsp[6:], 1)  // ANCOUNT
			binary.BigEndian.PutUint16(rsp[8:], 0)  // NSCOUNT
			binary.BigEndian.PutUint16(rsp[10:], 0) // ARCOUNT
			ip := answerIP.As4()
			rsp = append(rsp, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, ip[0], ip[1], ip[2], ip[3])
		}
		pc.WriteTo(rsp, from)
	}
}

// parseQuestion достаёт имя и тип из первого вопроса и где вопрос кончается.
func parseQuestion(b []byte) (string, uint16, int, bool) {
	if len(b) < 12 || binary.BigEndian.Uint16(b[4:]) != 1 {
		return "", 0, 0, false
	}
	p := 12
	var labels []string
	for {
		if p >= len(b) {
			return "", 0, 0, false
		}
		l := int(b[p])
		p++
		if l == 0 {
			break
		}
		if p+l > len(b) {
			return "", 0, 0, false
		}
		labels = append(labels, string(b[p:p+l]))
		p += l
	}
	if p+4 > len(b) {
		return "", 0, 0, false
	}
	return strings.Join(labels, "."), binary.BigEndian.Uint16(b[p:]), p + 4, true
}
