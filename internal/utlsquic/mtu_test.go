//go:build utls

package utlsquic

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/soways11/masquevpn/internal/masque"
)

func waitRoutes(t *testing.T, c *masque.Conn) {
	t.Helper()
	for i := 0; i < 500 && len(c.Routes()) == 0; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if len(c.Routes()) == 0 {
		t.Fatal("маршруты не получены")
	}
}

// TestUTLSCapacityIsHonest — в uTLS-пути отчёт о потолке датаграммы честный:
// пакет ровно в потолок доходит, на байт больше — ICMP. Без собственной
// проверки (mtu.go) uquic принимал бы крупные датаграммы и молча их терял.
//
// Заодно проверяется рост потолка: uquic выполняет Path MTU Discovery, на
// loopback пробы проходят, и потолок должен подняться выше стартового
// (1252 байта пакета — меньше, чем нужно IPv6-пакету в 1280).
func TestUTLSCapacityIsHonest(t *testing.T) {
	// Сервер отвечает коротким пакетом с длиной принятого: проверяем именно
	// направление клиент→сервер (у сервера на quic-go свой потолок).
	e := startServer(t, masque.ServerConfig{OnSession: func(ctx context.Context, c *masque.Conn, _ netip.Prefix) {
		buf := make([]byte, 20000)
		for {
			n, err := c.ReadPacket(buf)
			if err != nil {
				return
			}
			src := netip.AddrFrom4([4]byte(buf[16:20]))
			dst := netip.AddrFrom4([4]byte(buf[12:16]))
			c.WritePacket(ipv4(src, dst, binary.BigEndian.AppendUint16(nil, uint16(n))))
		}
	}})
	c, err := dial(t, e)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	waitRoutes(t, c)
	src := c.AssignedPrefixes()[0].Addr()
	dst := netip.MustParseAddr("1.1.1.1")
	buf := make([]byte, 20000)

	start := c.DatagramCapacity()
	if start <= 0 || start >= 1252 {
		t.Fatalf("стартовый потолок %d неправдоподобен", start)
	}
	// Даём PMTUD поработать: пробам нужен трафик и подтверждения.
	deadline := time.Now().Add(10 * time.Second)
	for c.DatagramCapacity() < 1280 && time.Now().Before(deadline) {
		c.WritePacket(ipv4(src, dst, []byte("tick")))
		readWithTimeout(c, buf, 200*time.Millisecond)
		time.Sleep(50 * time.Millisecond)
	}
	grown := c.DatagramCapacity()
	t.Logf("потолок IP-пакета: старт %d, после PMTUD %d", start, grown)
	if grown < 1280 {
		t.Fatalf("потолок не вырос до 1280 (%d): IPv6 в туннеле не заработает", grown)
	}

	for size := grown - 30; size <= grown; size++ {
		pkt := ipv4(src, dst, make([]byte, size-20))
		if err := c.WritePacket(pkt); err != nil {
			t.Fatalf("size=%d (потолок %d): %v", size, grown, err)
		}
		n, err := readWithTimeout(c, buf, 2*time.Second)
		if err != nil || n != 22 || int(binary.BigEndian.Uint16(buf[20:])) != size {
			t.Fatalf("size=%d (потолок %d): принят, но потерян — чёрная дыра (n=%d err=%v)", size, grown, n, err)
		}
	}
	err = c.WritePacket(ipv4(src, dst, make([]byte, grown+1-20)))
	if tl, ok := masque.AsPacketTooLarge(err); !ok || tl.ICMP == nil || tl.MaxSize != grown {
		t.Fatalf("пакет потолок+1: %v", err)
	}
}

// TestWarmUpReaches1280 — WarmUp сам (без внешнего трафика) доводит потолок
// до IPv6-минимума.
func TestWarmUpReaches1280(t *testing.T) {
	e := startServer(t, masque.ServerConfig{OnSession: echoSession})
	c, err := dial(t, e)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := c.DatagramCapacity()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	begin := time.Now()
	got := c.WarmUp(ctx, 1280)
	t.Logf("потолок %d → %d за %v", start, got, time.Since(begin).Round(time.Millisecond))
	if got < 1280 {
		t.Fatalf("WarmUp: %d", got)
	}
}
