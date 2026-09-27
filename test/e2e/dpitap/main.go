//go:build linux

// Утилита dpitap — «пассивный DPI»: смотрит на наш трафик ровно тем, чем
// располагает наблюдатель на канале, и считает признаки.
//
// Наблюдателю доступны: время, длина и направление каждого пакета, адреса и
// порты, а из содержимого — только незашифрованная часть заголовка QUIC
// (форма заголовка, версия, длины и значения Connection ID у пакетов
// рукопожатия). Всё остальное зашифровано. Именно из этого набора и строятся
// признаки, по которым туннель отличают от браузера, поэтому и считаем ровно
// это, не подглядывая внутрь.
//
//	dpitap -iface srv0 -port 443 -duration 20s [-json файл]
package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type packet struct {
	At   time.Duration `json:"t"`
	Len  int           `json:"len"` // длина UDP-нагрузки (дейтаграмма QUIC)
	Out  bool          `json:"out"` // true — от клиента к серверу
	Form string        `json:"form,omitempty"`
	DCID int           `json:"dcid,omitempty"`
	SCID int           `json:"scid,omitempty"`
	Ver  uint32        `json:"ver,omitempty"`
}

func main() {
	iface := flag.String("iface", "", "интерфейс для прослушивания")
	port := flag.Int("port", 443, "UDP-порт сервера")
	dur := flag.Duration("duration", 20*time.Second, "сколько слушать")
	out := flag.String("json", "", "куда сложить сырые записи")
	flag.Parse()
	if *iface == "" {
		fmt.Fprintln(os.Stderr, "нужен -iface")
		os.Exit(2)
	}
	pkts, err := capture(*iface, *port, *dur)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *out != "" {
		b, _ := json.Marshal(pkts)
		if err := os.WriteFile(*out, b, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}
	report(pkts)
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func capture(iface string, port int, dur time.Duration) ([]packet, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("интерфейс %s: %w", iface, err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("AF_PACKET: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifi.Index,
	}); err != nil {
		return nil, fmt.Errorf("bind %s: %w", iface, err)
	}
	tv := unix.NsecToTimeval(int64(200 * time.Millisecond))
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	buf := make([]byte, 65536)
	var pkts []packet
	begin := time.Now()
	deadline := begin.Add(dur)
	for time.Now().Before(deadline) {
		select {
		case <-stop:
			return pkts, nil
		default:
		}
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			continue // таймаут
		}
		p, ok := parse(buf[:n], port)
		if !ok {
			continue
		}
		p.At = time.Since(begin)
		pkts = append(pkts, p)
	}
	return pkts, nil
}

// parse разбирает кадр Ethernet → IPv4/IPv6 → UDP и заголовок QUIC настолько,
// насколько он открыт наблюдателю.
func parse(b []byte, port int) (packet, bool) {
	if len(b) < 14 {
		return packet{}, false
	}
	et := binary.BigEndian.Uint16(b[12:14])
	b = b[14:]
	var payload []byte
	var src, dst uint16
	switch et {
	case 0x0800:
		if len(b) < 20 || b[0]>>4 != 4 || b[9] != 17 {
			return packet{}, false
		}
		ihl := int(b[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(b[2:4]))
		if total > len(b) || total < ihl+8 {
			return packet{}, false
		}
		u := b[ihl:total]
		src, dst = binary.BigEndian.Uint16(u[0:2]), binary.BigEndian.Uint16(u[2:4])
		payload = u[8:]
	case 0x86dd:
		if len(b) < 40 || b[6] != 17 {
			return packet{}, false
		}
		plen := int(binary.BigEndian.Uint16(b[4:6]))
		if 40+plen > len(b) || plen < 8 {
			return packet{}, false
		}
		u := b[40 : 40+plen]
		src, dst = binary.BigEndian.Uint16(u[0:2]), binary.BigEndian.Uint16(u[2:4])
		payload = u[8:]
	default:
		return packet{}, false
	}
	if int(src) != port && int(dst) != port {
		return packet{}, false
	}
	p := packet{Len: len(payload), Out: int(dst) == port}
	quicHeader(&p, payload)
	return p, true
}

func quicHeader(p *packet, b []byte) {
	if len(b) < 1 {
		return
	}
	if b[0]&0x80 == 0 {
		p.Form = "1-RTT"
		return
	}
	if len(b) < 7 {
		return
	}
	p.Ver = binary.BigEndian.Uint32(b[1:5])
	switch {
	case p.Ver == 0:
		p.Form = "version-negotiation"
	default:
		switch (b[0] >> 4) & 0x3 {
		case 0:
			p.Form = "Initial"
		case 1:
			p.Form = "0-RTT"
		case 2:
			p.Form = "Handshake"
		case 3:
			p.Form = "Retry"
		}
	}
	dl := int(b[5])
	if len(b) < 6+dl+1 {
		return
	}
	p.DCID = dl
	p.SCID = int(b[6+dl])
}

// ---------- отчёт ----------

func report(pkts []packet) {
	if len(pkts) == 0 {
		fmt.Println("пакетов не поймано")
		return
	}
	var up, down []packet
	for _, p := range pkts {
		if p.Out {
			up = append(up, p)
		} else {
			down = append(down, p)
		}
	}
	dur := pkts[len(pkts)-1].At
	fmt.Printf("поток: %v, пакетов %d (вверх %d, вниз %d)\n", dur.Round(time.Millisecond), len(pkts), len(up), len(down))
	fmt.Printf("байт: вверх %d, вниз %d, асимметрия %.2f\n", bytesOf(up), bytesOf(down), ratio(bytesOf(down), bytesOf(up)))

	fmt.Println("\n-- рукопожатие (то, что открыто наблюдателю) --")
	shown := 0
	for _, p := range pkts {
		if p.Form == "" || p.Form == "1-RTT" {
			continue
		}
		dir := "←"
		if p.Out {
			dir = "→"
		}
		fmt.Printf("  %6s %s %-20s len=%-5d version=0x%08x DCID=%d SCID=%d\n",
			p.At.Round(time.Microsecond), dir, p.Form, p.Len, p.Ver, p.DCID, p.SCID)
		if shown++; shown >= 12 {
			break
		}
	}

	quiet(pkts)

	for _, s := range []struct {
		name string
		set  []packet
	}{{"вверх (клиент→сервер)", up}, {"вниз (сервер→клиент)", down}} {
		fmt.Printf("\n-- %s --\n", s.name)
		sizes(s.set)
		timings(s.set)
	}
}

// quiet показывает, умолкает ли поток вообще. У браузера соединение то
// молчит, то оживает; у туннеля с cover-трафиком тишины не бывает — это
// отдельный признак, и его надо видеть числом.
func quiet(ps []packet) {
	fmt.Println("\n-- тишина и ритм потока --")
	var longest time.Duration
	var at time.Duration
	for i := 1; i < len(ps); i++ {
		if g := ps[i].At - ps[i-1].At; g > longest {
			longest, at = g, ps[i-1].At
		}
	}
	fmt.Printf("  самая длинная пауза: %v (на %v)\n", longest.Round(time.Millisecond), at.Round(time.Second))

	// Посекундно: сколько пакетов и байт. Видно, отличается ли простой от работы.
	total := int(ps[len(ps)-1].At/time.Second) + 1
	cnt := make([]int, total)
	vol := make([]int, total)
	for _, p := range ps {
		i := int(p.At / time.Second)
		cnt[i]++
		vol[i] += p.Len
	}
	fmt.Print("  пакетов/с: ")
	for _, c := range cnt {
		fmt.Printf("%d ", c)
	}
	fmt.Print("\n  КБ/с:      ")
	for _, v := range vol {
		fmt.Printf("%d ", v>>10)
	}
	fmt.Println()
}

func bytesOf(ps []packet) int {
	n := 0
	for _, p := range ps {
		n += p.Len
	}
	return n
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

func sizes(ps []packet) {
	if len(ps) == 0 {
		return
	}
	hist := map[int]int{}
	for _, p := range ps {
		hist[p.Len]++
	}
	type kv struct{ size, n int }
	var top []kv
	for s, n := range hist {
		top = append(top, kv{s, n})
	}
	sort.Slice(top, func(i, j int) bool { return top[i].n > top[j].n })
	fmt.Printf("  уникальных размеров: %d из %d пакетов\n", len(hist), len(ps))
	fmt.Print("  самые частые:")
	for i, t := range top {
		if i >= 5 {
			break
		}
		fmt.Printf(" %d×%d (%.0f%%)", t.size, t.n, 100*float64(t.n)/float64(len(ps)))
	}
	fmt.Println()
	// Доля пакетов «в потолок» — признак объёмной передачи.
	full := 0
	maxLen := 0
	for _, p := range ps {
		if p.Len > maxLen {
			maxLen = p.Len
		}
	}
	for _, p := range ps {
		if p.Len >= maxLen-8 {
			full++
		}
	}
	fmt.Printf("  максимум %d, пакетов у потолка %.0f%%\n", maxLen, 100*float64(full)/float64(len(ps)))
}

func timings(ps []packet) {
	if len(ps) < 3 {
		return
	}
	var gaps []float64
	for i := 1; i < len(ps); i++ {
		gaps = append(gaps, float64(ps[i].At-ps[i-1].At)/float64(time.Millisecond))
	}
	mean, cv := meanCV(gaps)
	uniq := map[int64]struct{}{}
	for _, g := range gaps {
		uniq[int64(g*10)] = struct{}{} // с точностью 0,1 мс
	}
	fmt.Printf("  интервалы: среднее %.2f мс, коэффициент вариации %.2f, уникальных %d из %d\n",
		mean, cv, len(uniq), len(gaps))
	// Периодичность: сколько интервалов попадает в 5% от медианы — метроном
	// виден именно так.
	sorted := append([]float64(nil), gaps...)
	sort.Float64s(sorted)
	med := sorted[len(sorted)/2]
	near := 0
	for _, g := range gaps {
		if math.Abs(g-med) <= 0.05*med {
			near++
		}
	}
	fmt.Printf("  медиана %.2f мс, в пределах ±5%% от неё %.0f%% интервалов\n",
		med, 100*float64(near)/float64(len(gaps)))
}

func meanCV(v []float64) (mean, cv float64) {
	for _, x := range v {
		mean += x
	}
	mean /= float64(len(v))
	var d float64
	for _, x := range v {
		d += (x - mean) * (x - mean)
	}
	if mean == 0 {
		return 0, 0
	}
	return mean, math.Sqrt(d/float64(len(v))) / mean
}
