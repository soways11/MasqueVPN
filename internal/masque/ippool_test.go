package masque

import (
	"errors"
	"net/netip"
	"testing"
)

func TestIPPoolV4(t *testing.T) {
	p, err := NewIPPool(netip.MustParsePrefix("10.8.0.0/29")) // .0 сеть, .1 шлюз, .2–.6 клиенты, .7 broadcast
	if err != nil {
		t.Fatal(err)
	}
	if p.Gateway().String() != "10.8.0.1" {
		t.Fatalf("gateway %s", p.Gateway())
	}
	seen := map[netip.Addr]bool{}
	for i := 0; i < 5; i++ {
		a, err := p.Allocate(netip.Addr{})
		if err != nil {
			t.Fatal(err)
		}
		if a.Bits() != 32 || seen[a.Addr()] {
			t.Fatalf("bad/duplicate %s", a)
		}
		seen[a.Addr()] = true
	}
	for _, reserved := range []string{"10.8.0.0", "10.8.0.1", "10.8.0.7"} {
		if seen[netip.MustParseAddr(reserved)] {
			t.Fatalf("reserved %s allocated", reserved)
		}
	}
	if _, err := p.Allocate(netip.Addr{}); !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("want exhausted, got %v", err)
	}
	p.Release(netip.MustParsePrefix("10.8.0.4/32"))
	a, err := p.Allocate(netip.Addr{})
	if err != nil || a.Addr().String() != "10.8.0.4" {
		t.Fatalf("got %s %v", a, err)
	}
	if p.InUse() != 5 {
		t.Fatalf("in use %d", p.InUse())
	}
}

func TestIPPoolPreferred(t *testing.T) {
	p, _ := NewIPPool(netip.MustParsePrefix("10.8.0.0/24"))
	a, _ := p.Allocate(netip.MustParseAddr("10.8.0.77"))
	if a.Addr().String() != "10.8.0.77" {
		t.Fatalf("got %s", a)
	}
	b, _ := p.Allocate(netip.MustParseAddr("10.8.0.77")) // занят — любой другой
	if b.Addr() == a.Addr() {
		t.Fatal("duplicate")
	}
	c, _ := p.Allocate(netip.MustParseAddr("10.8.0.1")) // шлюз не выдаётся
	if c.Addr().String() == "10.8.0.1" {
		t.Fatal("gateway allocated")
	}
}

func TestIPPoolV6(t *testing.T) {
	p, err := NewIPPool(netip.MustParsePrefix("fd00:8::/64"))
	if err != nil {
		t.Fatal(err)
	}
	a, _ := p.Allocate(netip.Addr{})
	if a.String() != "fd00:8::2/128" {
		t.Fatalf("got %s", a)
	}
}

func TestIPPoolTooSmall(t *testing.T) {
	if _, err := NewIPPool(netip.MustParsePrefix("10.0.0.0/31")); err == nil {
		t.Fatal("/31 accepted")
	}
}
