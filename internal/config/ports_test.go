package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParsePorts(t *testing.T) {
	for in, want := range map[string][]int{
		"default":         DefaultPorts,
		" DEFAULT ":       DefaultPorts,
		"8443":            {8443},
		"8443,2053 2083":  {8443, 2053, 2083},
		"443; 8443,,2096": {443, 8443, 2096},
	} {
		got, err := ParsePorts(in)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%q → %v, %v; ожидалось %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "0", "65536", "8443,abc", "8443,8443", "-1"} {
		if _, err := ParsePorts(bad); err == nil {
			t.Errorf("%q принят", bad)
		}
	}
	// Стандартный набор нельзя испортить через возвращённый срез.
	p, _ := ParsePorts("default")
	p[0] = 1
	if DefaultPorts[0] != 443 {
		t.Fatal("ParsePorts отдал сам DefaultPorts, а не копию")
	}
}

func TestSplitServer(t *testing.T) {
	type res struct {
		host  string
		ports []string
	}
	for in, want := range map[string]res{
		"vpn.example.com:443":            {"vpn.example.com", []string{"443"}},
		"vpn.example.com:8443,2053,2083": {"vpn.example.com", []string{"8443", "2053", "2083"}},
		"vpn.example.com:8443, 2053":     {"vpn.example.com", []string{"8443", "2053"}},
		"[2001:db8::1]:8443,2053":        {"2001:db8::1", []string{"8443", "2053"}},
		"203.0.113.7:443,8443":           {"203.0.113.7", []string{"443", "8443"}},
		" vpn.example.com:8443 ,2053 ":   {"vpn.example.com", []string{"8443", "2053"}},
	} {
		h, p, err := SplitServer(in)
		if err != nil || h != want.host || !reflect.DeepEqual(p, want.ports) {
			t.Errorf("%q → %q %v %v; ожидалось %+v", in, h, p, err, want)
		}
	}
	for _, bad := range []string{
		"vpn.example.com", "vpn.example.com:8443,8443", "vpn.example.com:8443,x",
		"vpn.example.com:8443,", "vpn.example.com:0,443",
	} {
		_, _, err := SplitServer(bad)
		if err == nil {
			t.Errorf("%q принят", bad)
			continue
		}
		// Ошибку форма приписывает полю по слову «server» — оно должно быть.
		if FieldOfError(err) != FieldServer {
			t.Errorf("%q: ошибка %q не привязана к полю адреса", bad, err)
		}
	}
	if got := JoinServer("vpn.example.com", []int{8443, 2053}); got != "vpn.example.com:8443,2053" {
		t.Errorf("JoinServer: %q", got)
	}
	if got := JoinServer("2001:db8::1", []int{443}); got != "[2001:db8::1]:443" {
		t.Errorf("JoinServer IPv6: %q", got)
	}
}

// TestMultiPortServerThroughForm — адрес с запасными портами проходит весь
// путь, которым идёт доступ: форма, ссылка, профиль. Отдельного поля нет
// как раз ради этого — проверяем, что по дороге порты не теряются.
func TestMultiPortServerThroughForm(t *testing.T) {
	const srv = "vpn.example.com:8443,2053,2083"
	c, err := BuildForm(srv, key, "")
	if err != nil {
		t.Fatal(err)
	}
	if c.Server != srv || c.Host() != "vpn.example.com" || !reflect.DeepEqual(c.ServerPorts(), []string{"8443", "2053", "2083"}) {
		t.Fatalf("форма: %q host=%q ports=%v", c.Server, c.Host(), c.ServerPorts())
	}
	link, err := EncodeLink(c, "дача")
	if err != nil {
		t.Fatal(err)
	}
	back, name, err := DecodeLink(link)
	if err != nil || back.Server != srv || name != "дача" {
		t.Fatalf("ссылка: %v %q %q", err, back.Server, name)
	}
	var p Profiles
	if _, err := p.Add("дача", back); err != nil {
		t.Fatal(err)
	}
	up, err := p.Update("дача", "", mustForm(t, "vpn.example.com:2053,8443", key))
	if err != nil || up.Config.Server != "vpn.example.com:2053,8443" {
		t.Fatalf("правка профиля: %v %q", err, up.Config.Server)
	}
	// Опечатка в запасных портах — ошибка поля адреса, а не общая.
	if _, err := BuildForm("vpn.example.com:8443,20x3", key, ""); err == nil {
		t.Fatal("опечатка в порту принята")
	} else if f, _ := FormErrorOf(err); f != FieldServer {
		t.Fatalf("ошибка приписана полю %d", f)
	}
}

func mustForm(t *testing.T, server, k string) *Client {
	t.Helper()
	c, err := BuildForm(server, k, "")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestServerAltPorts(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.json")
	base := `{"cert_file":"c","key_file":"k","auth_key":"` + key + `"`
	os.WriteFile(p, []byte(base+`,"listen":"0.0.0.0:8443","alt_ports":[2053,2083]}`), 0o600)
	c, err := LoadServer(p)
	if err != nil {
		t.Fatal(err)
	}
	addrs, _ := c.UDPAddrs()
	if !reflect.DeepEqual(addrs, []string{"0.0.0.0:8443", "0.0.0.0:2053", "0.0.0.0:2083"}) {
		t.Fatalf("UDPAddrs: %v", addrs)
	}
	// TCP остаётся на своём: запасные порты — только UDP.
	if c.TCPAddr() != "0.0.0.0:8443" {
		t.Fatalf("TCPAddr: %q", c.TCPAddr())
	}
	for _, bad := range []string{`[8443]`, `[2053,2053]`, `[70000]`} {
		os.WriteFile(p, []byte(base+`,"listen":":8443","alt_ports":`+bad+`}`), 0o600)
		if _, err := LoadServer(p); err == nil || !strings.Contains(err.Error(), "alt_ports") {
			t.Errorf("alt_ports %s: %v", bad, err)
		}
	}
}
