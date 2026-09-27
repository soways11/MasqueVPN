//go:build linux

package tun_test

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/soways11/masquevpn/internal/netnstest"
	"github.com/soways11/masquevpn/internal/netsetup"
	"github.com/soways11/masquevpn/internal/tun"
)

func TestMain(m *testing.M) { netnstest.Main(m) }

func checksum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s > 0xffff {
		s = s>>16 + s&0xffff
	}
	return ^uint16(s)
}

// udp4 строит IPv4/UDP-пакет (контрольная сумма UDP = 0 — допустимо для IPv4).
func udp4(src, dst netip.AddrPort, payload []byte) []byte {
	p := make([]byte, 28+len(payload))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	p[8] = 64
	p[9] = unix.IPPROTO_UDP
	s, d := src.Addr().As4(), dst.Addr().As4()
	copy(p[12:], s[:])
	copy(p[16:], d[:])
	binary.BigEndian.PutUint16(p[10:], checksum(p[:20]))
	binary.BigEndian.PutUint16(p[20:], src.Port())
	binary.BigEndian.PutUint16(p[22:], dst.Port())
	binary.BigEndian.PutUint16(p[24:], uint16(8+len(payload)))
	copy(p[28:], payload)
	return p
}

// TestKernelRoundTrip — настоящий путь через ядро: сокет → маршрут → TUN →
// наш Read, и обратно: наш Write → TUN → ядро → сокет.
func TestKernelRoundTrip(t *testing.T) {
	netnstest.Require(t)
	dev, err := tun.Open("gvtest0", 1400)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	if dev.Name() != "gvtest0" || dev.MTU() != 1400 {
		t.Fatalf("name=%q mtu=%d", dev.Name(), dev.MTU())
	}
	local := netip.MustParsePrefix("10.99.0.1/24")
	if err := netsetup.ConfigureInterface(dev.Name(), dev.MTU(), []netip.Prefix{local}); err != nil {
		t.Fatal(err)
	}
	ifc, err := net.InterfaceByName("gvtest0")
	if err != nil || ifc.MTU != 1400 || ifc.Flags&net.FlagUp == 0 {
		t.Fatalf("интерфейс не настроен: %+v %v", ifc, err)
	}

	sock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(10, 99, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sock.Close()
	peer := netip.MustParseAddrPort("10.99.0.2:9999")
	if _, err := sock.WriteToUDPAddrPort([]byte("ping-out"), peer); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 2000)
	deadline := time.Now().Add(3 * time.Second)
	var me netip.AddrPort
	for {
		if time.Now().After(deadline) {
			t.Fatal("пакет из сокета не дошёл до TUN")
		}
		n, err := dev.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		p := buf[:n]
		if p[0]>>4 != 4 || p[9] != unix.IPPROTO_UDP {
			continue // IPv6-служебка и пр.
		}
		dst := netip.AddrFrom4([4]byte(p[16:20]))
		if dst != peer.Addr() || string(p[28:]) != "ping-out" {
			continue
		}
		me = netip.AddrPortFrom(netip.AddrFrom4([4]byte(p[12:16])), binary.BigEndian.Uint16(p[20:]))
		break
	}

	if _, err := dev.Write(udp4(peer, me, []byte("pong-in"))); err != nil {
		t.Fatal(err)
	}
	sock.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, from, err := sock.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("ответ, записанный в TUN, не дошёл до сокета: %v", err)
	}
	if string(buf[:n]) != "pong-in" || from != peer {
		t.Fatalf("got %q from %v", buf[:n], from)
	}
}

// TestCloseUnblocksRead — Close обязан прерывать заблокированный Read,
// иначе клиент не сможет корректно завершиться.
func TestCloseUnblocksRead(t *testing.T) {
	netnstest.Require(t)
	dev, err := tun.Open("", 0)
	if err != nil {
		t.Fatal(err)
	}
	if dev.MTU() != tun.DefaultMTU || dev.Name() == "" {
		t.Fatalf("name=%q mtu=%d", dev.Name(), dev.MTU())
	}
	done := make(chan error, 1)
	go func() {
		_, err := dev.Read(make([]byte, 1500))
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	dev.Close()
	select {
	case err := <-done:
		if err != tun.ErrClosed {
			t.Fatalf("err = %v, want ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Read не прервался после Close")
	}
}

// TestFromFD — путь мобильных платформ: дескриптор открыт кем-то другим.
func TestFromFD(t *testing.T) {
	netnstest.Require(t)
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	ifr, _ := unix.NewIfreq("gvfd0")
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		t.Fatal(err)
	}
	dev, err := tun.FromFD(fd, "", 1300)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	if dev.Name() != "gvfd0" {
		t.Fatalf("имя по дескриптору не определено: %q", dev.Name())
	}
	if err := netsetup.ConfigureInterface("gvfd0", 1300, []netip.Prefix{netip.MustParsePrefix("10.98.0.1/24")}); err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("udp4", "10.98.0.7:53")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("x"))
	buf := make([]byte, 1500)
	for i := 0; i < 20; i++ {
		n, err := dev.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if buf[0]>>4 == 4 && n == 29 && buf[28] == 'x' {
			return
		}
	}
	t.Fatal("пакет не получен через принятый дескриптор")
}
