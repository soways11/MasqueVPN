package masque

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
)

// ErrPoolExhausted — свободных адресов не осталось.
var ErrPoolExhausted = errors.New("masque: address pool exhausted")

// IPPool выдаёт клиентам хостовые адреса (/32 или /128) из префикса.
// Первый адрес после сетевого резервируется за сервером (шлюз туннеля),
// для IPv4 также исключается broadcast.
type IPPool struct {
	mu      sync.Mutex
	prefix  netip.Prefix
	gateway netip.Addr
	first   netip.Addr
	last    netip.Addr
	next    netip.Addr
	used    map[netip.Addr]struct{}
}

// NewIPPool создаёт пул. Для IPv4 префикс должен быть не длиннее /30.
func NewIPPool(prefix netip.Prefix) (*IPPool, error) {
	prefix = prefix.Masked()
	if !prefix.IsValid() {
		return nil, errors.New("masque: invalid pool prefix")
	}
	hostBits := prefix.Addr().BitLen() - prefix.Bits()
	if hostBits < 2 {
		return nil, fmt.Errorf("masque: pool prefix %s too small", prefix)
	}
	gw := prefix.Addr().Next()
	first := gw.Next()
	last := lastAddr(prefix)
	if prefix.Addr().Is4() {
		last = last.Prev() // broadcast
	}
	return &IPPool{
		prefix: prefix, gateway: gw, first: first, last: last, next: first,
		used: make(map[netip.Addr]struct{}),
	}, nil
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	bits := p.Bits()
	for i := range b {
		for j := 0; j < 8; j++ {
			if i*8+j >= bits {
				b[i] |= 0x80 >> j
			}
		}
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// Prefix — префикс пула.
func (p *IPPool) Prefix() netip.Prefix { return p.prefix }

// Gateway — адрес сервера внутри туннельной сети.
func (p *IPPool) Gateway() netip.Addr { return p.gateway }

func (p *IPPool) hostPrefix(a netip.Addr) netip.Prefix {
	return netip.PrefixFrom(a, a.BitLen())
}

// Allocate выдаёт свободный адрес. Если want валиден, свободен и принадлежит
// пулу — выдаётся именно он.
func (p *IPPool) Allocate(want netip.Addr) (netip.Prefix, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if want.IsValid() && p.inRange(want) {
		if _, busy := p.used[want]; !busy {
			p.used[want] = struct{}{}
			return p.hostPrefix(want), nil
		}
	}
	start := p.next
	a := start
	for {
		if _, busy := p.used[a]; !busy {
			p.used[a] = struct{}{}
			p.next = p.advance(a)
			return p.hostPrefix(a), nil
		}
		a = p.advance(a)
		if a == start {
			return netip.Prefix{}, ErrPoolExhausted
		}
	}
}

func (p *IPPool) inRange(a netip.Addr) bool {
	return p.first.Compare(a) <= 0 && a.Compare(p.last) <= 0
}

func (p *IPPool) advance(a netip.Addr) netip.Addr {
	if a == p.last {
		return p.first
	}
	return a.Next()
}

// Release возвращает адрес в пул.
func (p *IPPool) Release(pr netip.Prefix) {
	p.mu.Lock()
	delete(p.used, pr.Addr())
	p.mu.Unlock()
}

// InUse — число выданных адресов.
func (p *IPPool) InUse() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.used)
}
