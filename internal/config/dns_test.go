package config

import (
	"net/netip"
	"testing"
)

// Самое важное свойство во всём файле.
//
// Полный туннель без заданного резолвера — это не «настройка по вкусу», а
// утечка. Система продолжит спрашивать имена у резолвера локальной сети,
// обычно у домашнего роутера, до которого можно дотянуться напрямую, мимо
// туннеля. Байты пойдут через сервер, а список посещённых сайтов останется
// у провайдера: туннель есть, приватности нет, и снаружи это никак не
// проявляется — ни ошибки, ни строчки в журнале.
//
// Именно такую конфигурацию выдавал `vpnserver clients add`.
func TestFullTunnelNeverLeavesResolverUnset(t *testing.T) {
	c := &Client{Server: "example.test:443"}
	c.Defaults()

	if !*c.FullTunnel {
		t.Fatal("полный туннель по умолчанию выключен — тест проверяет не то")
	}
	if len(c.DNS) == 0 {
		t.Fatal("при полном туннеле резолвер не задан: имена уйдут мимо туннеля")
	}
	if !c.DNSByDefault {
		t.Error("подстановка резолвера не отмечена — о ней нечего будет сказать в журнале")
	}

	// Обе семьи: при живом IPv6 система предпочтёт его, и резолвер только
	// для IPv4 оставил бы ту же дыру.
	servers, err := c.DNSServers()
	if err != nil {
		t.Fatal(err)
	}
	var has4, has6 bool
	for _, s := range servers {
		if s.Unmap().Is4() {
			has4 = true
		} else {
			has6 = true
		}
	}
	if !has4 || !has6 {
		t.Errorf("подставлены резолверы только одной семьи: %v", servers)
	}
}

// Заданный вручную резолвер — выбор пользователя, и трогать его нельзя.
func TestExplicitResolverIsKept(t *testing.T) {
	c := &Client{Server: "example.test:443", DNS: []string{"9.9.9.9"}}
	c.Defaults()
	if len(c.DNS) != 1 || c.DNS[0] != "9.9.9.9" {
		t.Fatalf("заданный резолвер подменён: %v", c.DNS)
	}
	if c.DNSByDefault {
		t.Error("заданный вручную резолвер отмечен как подставленный")
	}
}

// Без полного туннеля через него идут только перечисленные маршруты, а имена
// система резолвит как обычно — навязывать ей свой резолвер незачем.
func TestSplitTunnelResolverIsNotImposed(t *testing.T) {
	no := false
	c := &Client{Server: "example.test:443", FullTunnel: &no, Routes: []string{"10.0.0.0/8"}}
	c.Defaults()
	if len(c.DNS) != 0 {
		t.Fatalf("при раздельном туннеле навязан резолвер: %v", c.DNS)
	}
}

func TestUsableDNSDropsFamiliesTheTunnelLacks(t *testing.T) {
	v4only := []netip.Prefix{netip.MustParsePrefix("10.66.0.2/32")}
	both := []netip.Prefix{
		netip.MustParsePrefix("10.66.0.2/32"),
		netip.MustParsePrefix("fd66::2/128"),
	}
	servers := []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("2606:4700:4700::1111"),
	}

	// Резолвер IPv6 на туннеле без адреса IPv6 не заработает, а система
	// будет ждать его ответа на каждом имени — это не «просто лишняя
	// запись», это задержка на всём, что открывает пользователь.
	got := UsableDNS(servers, v4only)
	if len(got) != 1 || !got[0].Is4() {
		t.Fatalf("на туннеле только с IPv4 оставлены резолверы %v", got)
	}

	if got := UsableDNS(servers, both); len(got) != 2 {
		t.Fatalf("на двухсемейном туннеле оставлены резолверы %v", got)
	}
}
