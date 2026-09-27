package tunnel

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"

	"github.com/soways11/masquevpn/internal/masque"
	"github.com/soways11/masquevpn/internal/tun"
)

// Router — маршрутизатор сервера: пакеты из TUN раздаются сессиям по адресу
// получателя, пакеты сессий пишутся в TUN (дальше их маршрутизирует и
// NAT-ит ядро).
//
// У каждой сессии своя очередь и свой писатель: джиттер и паддинг одной
// сессии (а WritePacket может ждать) не должны тормозить остальных.
//
// Подключение к masque.ServerConfig:
//
//	OnSession:       router.Serve
//	OnAddressChange: router.AddressChanged
type Router struct {
	dev tun.Device
	log *slog.Logger
	cnt *Counters

	queueLen int

	mu    sync.RWMutex
	byIP  map[netip.Addr]*peer
	peers map[*masque.Conn]*peer
}

type peer struct {
	c     *masque.Conn
	out   chan []byte
	addrs []netip.Addr // под Router.mu
}

// RouterOptions — необязательные параметры NewRouter.
type RouterOptions struct {
	Logger   *slog.Logger
	Counters *Counters
	// QueueLen — длина очереди пакетов к одной сессии; по умолчанию 512.
	// При переполнении пакеты отбрасываются (как на любом маршрутизаторе).
	QueueLen int
}

// NewRouter создаёт маршрутизатор поверх открытого TUN.
func NewRouter(dev tun.Device, opt RouterOptions) *Router {
	r := &Router{
		dev:      dev,
		log:      opt.Logger,
		cnt:      opt.Counters,
		queueLen: opt.QueueLen,
		byIP:     map[netip.Addr]*peer{},
		peers:    map[*masque.Conn]*peer{},
	}
	if r.log == nil {
		r.log = slog.New(slog.DiscardHandler)
	}
	if r.cnt == nil {
		r.cnt = new(Counters)
	}
	if r.queueLen <= 0 {
		r.queueLen = 512
	}
	return r
}

// Counters возвращает счётчики маршрутизатора.
func (r *Router) Counters() *Counters { return r.cnt }

// Sessions — число активных сессий.
func (r *Router) Sessions() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.peers)
}

// Lookup возвращает сессию, которой принадлежит адрес.
func (r *Router) Lookup(a netip.Addr) (*masque.Conn, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.byIP[a]
	if !ok {
		return nil, false
	}
	return p.c, true
}

// Run читает пакеты из TUN и раздаёт их сессиям, пока TUN не закроется
// или не отменён ctx (тогда TUN закрывается).
func (r *Router) Run(ctx context.Context) error {
	stop := context.AfterFunc(ctx, func() { _ = r.dev.Close() })
	defer stop()
	buf := make([]byte, maxPacket)
	for {
		n, err := r.dev.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		dst, ok := dstAddr(buf[:n])
		if !ok {
			continue
		}
		r.mu.RLock()
		p := r.byIP[dst]
		r.mu.RUnlock()
		if p == nil {
			r.cnt.NoRoute.Add(1)
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		select {
		case p.out <- pkt:
		default:
			r.cnt.Overflow.Add(1)
		}
	}
}

// update приводит таблицу адресов сессии к её текущему состоянию. Читает
// адреса под блокировкой маршрутизатора, поэтому при любом порядке вызовов
// побеждает последнее состояние сессии.
func (r *Router) update(p *peer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.peers[p.c] != p {
		return // сессия уже снята
	}
	for _, a := range p.addrs {
		if r.byIP[a] == p {
			delete(r.byIP, a)
		}
	}
	p.addrs = p.addrs[:0]
	for _, pr := range p.c.AssignedPrefixes() {
		// Клиенту выдаётся адрес хоста (/32, /128). Префиксы короче в
		// таблицу не кладём: делегирование сетей пока не поддерживается.
		if !pr.IsSingleIP() {
			continue
		}
		a := pr.Addr()
		r.byIP[a] = p
		p.addrs = append(p.addrs, a)
	}
}

// AddressChanged — обработчик masque.ServerConfig.OnAddressChange.
func (r *Router) AddressChanged(c *masque.Conn, old, new []netip.Prefix) {
	r.mu.RLock()
	p := r.peers[c]
	r.mu.RUnlock()
	if p != nil {
		r.update(p)
		r.log.Info("адрес сессии изменён", "old", old, "new", new)
	}
}

// CloseAll закрывает все живые сессии.
//
// Нужно при остановке сервера: клиент должен узнать об этом сразу, по
// закрытому потоку, а не через десятки секунд по таймауту простоя QUIC.
// Полагаться тут на закрытие слушателя нельзя — quic-go в этом случае
// рвёт соединения локально, не посылая CONNECTION_CLOSE.
func (r *Router) CloseAll() {
	r.mu.RLock()
	conns := make([]*masque.Conn, 0, len(r.peers))
	for c := range r.peers {
		conns = append(conns, c)
	}
	r.mu.RUnlock()
	for _, c := range conns {
		c.Close()
	}
}

// Serve обслуживает сессию до её закрытия — обработчик
// masque.ServerConfig.OnSession.
func (r *Router) Serve(ctx context.Context, c *masque.Conn, addr netip.Prefix) {
	p := &peer{c: c, out: make(chan []byte, r.queueLen)}
	r.mu.Lock()
	r.peers[c] = p
	r.mu.Unlock()
	r.update(p)
	r.log.Info("сессия открыта", "addr", c.AssignedPrefixes())

	defer func() {
		r.mu.Lock()
		for _, a := range p.addrs {
			// Адрес мог уже перейти к другой сессии (возврат адреса после
			// ротации): чужую запись не трогаем.
			if r.byIP[a] == p {
				delete(r.byIP, a)
			}
		}
		delete(r.peers, c)
		r.mu.Unlock()
		st := c.Stats()
		r.log.Info("сессия закрыта", "addr", p.addrs,
			"pkts_in", st.PacketsIn, "pkts_out", st.PacketsOut,
			"bytes_in", st.BytesIn, "bytes_out", st.BytesOut)
	}()

	done := make(chan struct{})
	go func() { // очередь → клиент
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case pkt := <-p.out:
				err := c.WritePacket(pkt)
				if err == nil {
					r.cnt.ToTunnel.Add(1)
					continue
				}
				// ICMP уходит в TUN сервера, оттуда ядро (с учётом NAT)
				// доставляет его внешнему отправителю.
				if err := handleWriteErr(err, r.dev, r.cnt, r.log); err != nil {
					return
				}
			}
		}
	}()

	buf := make([]byte, maxPacket)
	for { // клиент → TUN
		n, err := c.ReadPacket(buf)
		if err != nil {
			break
		}
		if _, err := r.dev.Write(buf[:n]); err != nil {
			r.log.Debug("запись в TUN", "err", err)
			continue
		}
		r.cnt.FromTunnel.Add(1)
	}
	c.Close()
	<-done
}
