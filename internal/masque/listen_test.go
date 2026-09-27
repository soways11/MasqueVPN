package masque

import (
	"crypto/rand"
	"net"
	"net/netip"
	"testing"
	"time"
)

// TestServerLooksLikeRealDeployment — то, что видно наблюдателю и проберу
// в обход всякой авторизации: длина Connection ID сервера и ответ на пакет
// с незнакомым Connection ID.
func TestServerLooksLikeRealDeployment(t *testing.T) {
	pool, err := NewIPPool(netip.MustParsePrefix("10.8.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHandler(ServerConfig{Pool: pool})
	if err != nil {
		t.Fatal(err)
	}
	stls, ctls := testTLS(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := NewHTTP3Server("", stls, h)
	go func() { _ = ServeUDP(srv, pc, DefaultConnectionIDLength) }()
	t.Cleanup(func() { _ = srv.Close(); _ = pc.Close() })
	addr := pc.LocalAddr().String()

	// 1. Сессия через такой слушатель по-прежнему работает.
	env := &testEnv{addr: addr, client: ctls, pool: pool}
	c := mustDial(t, env)
	if len(c.AssignedPrefixes()) == 0 {
		t.Fatal("адрес не выдан")
	}

	// 2. Пакет с незнакомым Connection ID: настоящий сервер отвечает
	// stateless reset, а не молчит.
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	pkt := make([]byte, 64)
	if _, err := rand.Read(pkt); err != nil {
		t.Fatal(err)
	}
	pkt[0] = 0x40 // короткий заголовок (fixed bit), дальше — «наш» CID и мусор
	if _, err := conn.Write(pkt); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("на пакет с незнакомым Connection ID сервер промолчал: %v", err)
	}
	// Stateless reset: короткий заголовок и не меньше 21 байта (RFC 9000, §10.3).
	if n < 21 || buf[0]&0x80 != 0 {
		t.Fatalf("ответ не похож на stateless reset: %d байт, первый байт 0x%02x", n, buf[0])
	}
	t.Logf("ответ на незнакомый Connection ID: %d байт", n)

	// 3. Пакет с неизвестной версией QUIC: настоящий сервер отвечает
	// Version Negotiation. Это тоже проверяют простукиванием.
	vn := make([]byte, 1250)
	if _, err := rand.Read(vn); err != nil {
		t.Fatal(err)
	}
	vn[0] = 0xc0                                  // long header
	copy(vn[1:5], []byte{0x0a, 0x0a, 0x0a, 0x0a}) // зарезервированная версия
	vn[5] = 8                                     // длина DCID
	vn[14] = 8                                    // длина SCID
	if _, err := conn.Write(vn); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatalf("на неизвестную версию QUIC сервер промолчал: %v", err)
	}
	if n < 7 || buf[0]&0x80 == 0 || buf[1]|buf[2]|buf[3]|buf[4] != 0 {
		t.Fatalf("ответ не Version Negotiation: %d байт, % x", n, buf[:minI(8, n)])
	}
	t.Logf("ответ на неизвестную версию: Version Negotiation, %d байт", n)
}

func minI(a, b int) int {
	if a < b {
		return a
	}
	return b
}
