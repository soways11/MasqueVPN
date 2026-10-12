//go:build linux

// Утилита leaktap — сторож утечек: смотрит на физический интерфейс клиента и
// перечисляет ВСЁ, что ушло с него наружу своим ходом.
//
// Зачем отдельный инструмент. Проверить «весь трафик идёт через туннель»
// изнутри туннеля нельзя: успех запроса говорит лишь о том, что ответ пришёл,
// но не о том, какой дорогой ушёл вопрос. А утечка — это именно дорога:
// пакет, который вышел на провод в открытом виде, минуя сессию CONNECT-IP.
// Увидеть это можно только на проводе, поэтому здесь сырой AF_PACKET и учёт
// по потокам: протокол, адреса, порты, счётчик.
//
// Считаются только ИСХОДЯЩИЕ кадры (PACKET_OUTGOING): входящие — это чужой
// трафик, за него туннель не отвечает.
//
//	leaktap -iface cli0 -duration 30s -json flows.json
//
// Политики у инструмента нет: он не знает, что «можно». Разрешённое
// перечисляет тест (трафик самого туннеля — это UDP к адресу сервера), а
// канальные адреса — multicast, broadcast, link-local — помечаются полем
// link: за пределы канала они не уходят и утечкой не считаются.
package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// flow — поток, увиденный на проводе. Ключ — всё, кроме счётчиков.
type flow struct {
	Proto string `json:"proto"`
	Src   string `json:"src"`
	Dst   string `json:"dst"`
	SPort int    `json:"sport,omitempty"`
	DPort int    `json:"dport,omitempty"`
	// Link — адресат за пределы канала не уходит (multicast, broadcast,
	// link-local). Такой пакет не утечка: соседям по сети мы видны и так.
	Link    bool `json:"link,omitempty"`
	Packets int  `json:"packets"`
	Bytes   int  `json:"bytes"`
}

type key struct {
	proto        string
	src, dst     string
	sport, dport int
	link         bool
}

func main() {
	iface := flag.String("iface", "", "интерфейс, за которым следить")
	dur := flag.Duration("duration", 30*time.Second, "сколько следить")
	out := flag.String("json", "", "куда сложить перечень потоков")
	flag.Parse()
	if *iface == "" {
		fmt.Fprintln(os.Stderr, "нужен -iface")
		os.Exit(2)
	}
	flows, err := watch(*iface, *dur)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *out != "" {
		b, _ := json.Marshal(flows)
		if err := os.WriteFile(*out, b, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	report(flows)
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func watch(iface string, dur time.Duration) ([]flow, error) {
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
	tv := unix.NsecToTimeval(int64(100 * time.Millisecond))
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	// Готовность печатаем до цикла: тест ждёт эту строку, иначе он успеет
	// пустить трафик раньше, чем сокет встанет на интерфейс.
	fmt.Fprintf(os.Stderr, "слежу за %s\n", iface)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	seen := map[key]*flow{}
	buf := make([]byte, 65536)
	deadline := time.Now().Add(dur)
	for time.Now().Before(deadline) {
		select {
		case <-stop:
			return collect(seen), nil
		default:
		}
		n, from, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			continue // таймаут приёма
		}
		ll, ok := from.(*unix.SockaddrLinklayer)
		if !ok || ll.Pkttype != unix.PACKET_OUTGOING {
			continue
		}
		k, size, ok := parse(buf[:n])
		if !ok {
			continue
		}
		f := seen[k]
		if f == nil {
			f = &flow{Proto: k.proto, Src: k.src, Dst: k.dst, SPort: k.sport, DPort: k.dport, Link: k.link}
			seen[k] = f
		}
		f.Packets++
		f.Bytes += size
	}
	return collect(seen), nil
}

func collect(seen map[key]*flow) []flow {
	out := make([]flow, 0, len(seen))
	for _, f := range seen {
		out = append(out, *f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Dst != out[j].Dst {
			return out[i].Dst < out[j].Dst
		}
		return out[i].DPort < out[j].DPort
	})
	return out
}

// parse разбирает кадр Ethernet → IPv4/IPv6 → TCP/UDP. Остальные протоколы
// (ICMP, ESP, что угодно ещё) учитываются по номеру: утечка — это любой
// пакет, а не только знакомого протокола.
func parse(b []byte) (key, int, bool) {
	if len(b) < 14 {
		return key{}, 0, false
	}
	et := binary.BigEndian.Uint16(b[12:14])
	b = b[14:]
	var (
		src, dst netip.Addr
		proto    uint8
		rest     []byte
	)
	switch et {
	case 0x0800:
		if len(b) < 20 || b[0]>>4 != 4 {
			return key{}, 0, false
		}
		ihl := int(b[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(b[2:4]))
		if ihl < 20 || total < ihl || total > len(b) {
			return key{}, 0, false
		}
		src, dst = netip.AddrFrom4([4]byte(b[12:16])), netip.AddrFrom4([4]byte(b[16:20]))
		proto, rest = b[9], b[ihl:total]
		// Фрагмент без первого куска портов не несёт — и это тоже утечка,
		// просто без портов.
		if binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
			rest = nil
		}
	case 0x86dd:
		if len(b) < 40 || b[0]>>4 != 6 {
			return key{}, 0, false
		}
		plen := int(binary.BigEndian.Uint16(b[4:6]))
		if 40+plen > len(b) {
			return key{}, 0, false
		}
		src, dst = netip.AddrFrom16([16]byte(b[8:24])), netip.AddrFrom16([16]byte(b[24:40]))
		proto, rest = b[6], b[40:40+plen]
	default:
		return key{}, 0, false // ARP и прочее не-IP: канальная служебка
	}

	k := key{proto: protoName(proto), src: src.String(), dst: dst.String(), link: linkScope(dst)}
	if (proto == 6 || proto == 17) && len(rest) >= 4 {
		k.sport = int(binary.BigEndian.Uint16(rest[0:2]))
		k.dport = int(binary.BigEndian.Uint16(rest[2:4]))
	}
	return k, len(b), true
}

// linkScope — адресат, дальше канала не уходящий. Такие пакеты видны только
// соседям по сегменту: сам факт их отправки туннель не нарушает.
func linkScope(a netip.Addr) bool {
	return a.IsMulticast() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a == netip.MustParseAddr("255.255.255.255")
}

func protoName(p uint8) string {
	switch p {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 58:
		return "icmp6"
	default:
		return fmt.Sprintf("ip-proto-%d", p)
	}
}

func report(flows []flow) {
	if len(flows) == 0 {
		fmt.Println("исходящих IP-пакетов не было")
		return
	}
	fmt.Printf("исходящие потоки (%d):\n", len(flows))
	for _, f := range flows {
		mark := ""
		if f.Link {
			mark = "  [канальный]"
		}
		fmt.Printf("  %-12s %s:%d → %s:%d  пакетов %d, байт %d%s\n",
			f.Proto, f.Src, f.SPort, f.Dst, f.DPort, f.Packets, f.Bytes, mark)
	}
}
