package tunnel

import (
	"net/http"
	"net/netip"
	"testing"

	"github.com/soways11/masquevpn/internal/auth"
	"github.com/soways11/masquevpn/internal/masque"
)

// TestTwoDevicesOfOneKeyBothCarryTraffic — жалоба «по одному ключу с разных
// устройств работает только на одном» целиком.
//
// Ключ один, ссылка одна, значит и client_id у ноутбука с телефоном один.
// Пока адрес закреплялся только за клиентом, оба получали ОДИН туннельный
// адрес, а таблица маршрутизатора хранит одну запись на адрес: входящее
// уходило в последнюю подключившуюся сессию. Наружу пакеты шли с обоих
// устройств, ответы — только на одно, и выглядело это как «интернет умер».
//
// Проверяем именно доставку в обе стороны, а не только «адреса разные»:
// разойтись адреса могли бы, а маршрутизатор всё равно свести их в одну
// запись.
func TestTwoDevicesOfOneKeyBothCarryTraffic(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	srvAuth, err := auth.New(key, auth.Options{})
	if err != nil {
		t.Fatal(err)
	}
	s := startServer(t, func(c *masque.ServerConfig) { c.Identify = srvAuth.Identify })

	id := make([]byte, auth.ClientIDLen)
	for i := range id {
		id[i] = byte(0x11 * (i + 1))
	}
	header := func(device string) http.Header {
		t.Helper()
		a, err := auth.New(key, auth.Options{ClientIDExact: id, DeviceID: []byte(device)})
		if err != nil {
			t.Fatal(err)
		}
		h, err := a.Header()
		if err != nil {
			t.Fatal(err)
		}
		return h
	}

	devA, a, _ := s.clientAs(t, header("ноутбук"))
	devB, b, _ := s.clientAs(t, header("телефон"))
	addrA := a.AssignedPrefixes()[0].Addr()
	addrB := b.AssignedPrefixes()[0].Addr()
	if addrA == addrB {
		t.Fatalf("оба устройства получили %s — входящее уйдёт только в одну сессию", addrA)
	}

	// Наружу — с каждого устройства свой адрес источника.
	devA.in <- ipv4(addrA, internet, 17, []byte("from-laptop"))
	devB.in <- ipv4(addrB, internet, 17, []byte("from-phone"))
	for i := 0; i < 2; i++ {
		s.dev.expect(t, "пакеты обоих устройств на сервере", func(p []byte) bool {
			return dst4(p) == internet && (src4(p) == addrA || src4(p) == addrB)
		})
	}

	// Внутрь — каждому своё, и ни одно устройство не осталось без ответа.
	s.dev.in <- ipv4(internet, addrA, 17, []byte("to-laptop"))
	s.dev.in <- ipv4(internet, addrB, 17, []byte("to-phone"))
	pa := devA.expect(t, "ответ ноутбуку", func(p []byte) bool { return true })
	pb := devB.expect(t, "ответ телефону", func(p []byte) bool { return true })
	if string(pa[20:]) != "to-laptop" || string(pb[20:]) != "to-phone" {
		t.Fatalf("пакеты перепутаны: ноутбук=%q телефон=%q", pa[20:], pb[20:])
	}
}

// TestRotationOfOneDeviceKeepsAddress — обратная сторона того же: две сессии
// ОДНОГО устройства (ротация, make-before-break) обязаны делить адрес, иначе
// на каждой ротации рвались бы соединения внутри туннеля. Устройство в токене
// не должно это сломать.
func TestRotationOfOneDeviceKeepsAddress(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 7)
	}
	srvAuth, err := auth.New(key, auth.Options{})
	if err != nil {
		t.Fatal(err)
	}
	s := startServer(t, func(c *masque.ServerConfig) { c.Identify = srvAuth.Identify })

	// Одно устройство: один и тот же аутентификатор, как и в живом клиенте,
	// где Dialer переживает ротацию.
	id := make([]byte, auth.ClientIDLen)
	for i := range id {
		id[i] = byte(0x20 + i)
	}
	dev, err := auth.New(key, auth.Options{ClientIDExact: id, DeviceID: []byte("ноутбук")})
	if err != nil {
		t.Fatal(err)
	}
	head := func() http.Header {
		t.Helper()
		h, err := dev.Header()
		if err != nil {
			t.Fatal(err)
		}
		return h
	}

	first := s.dialAs(t, head())
	defer first.Close()
	second := s.dialAs(t, head()) // новая сессия при живой старой
	defer second.Close()

	var got, want netip.Addr = second.AssignedPrefixes()[0].Addr(), first.AssignedPrefixes()[0].Addr()
	if got != want {
		t.Fatalf("при ротации устройство получило %s вместо %s — пакеты с прежним адресом сервер отбросит", got, want)
	}
}
