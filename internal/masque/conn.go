package masque

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/http3"
)

var (
	// ErrSessionClosed — сессия закрыта локально или удалённой стороной.
	ErrSessionClosed = errors.New("masque: session closed")
	// ErrPacketRejected — пакет не соответствует выданным адресам/маршрутам.
	ErrPacketRejected = errors.New("masque: packet rejected by address/route policy")
	// ErrIdleTimeout — сессия закрыта из-за простоя (лимит ресурсов).
	ErrIdleTimeout = errors.New("masque: session idle timeout")
	// ErrTooManyAddressRequests — клиент превысил потолок капсул ADDRESS_REQUEST.
	ErrTooManyAddressRequests = errors.New("masque: too many ADDRESS_REQUEST capsules")
)

type role uint8

const (
	roleClient role = iota
	roleServer
)

// Stats — счётчики сессии.
type Stats struct {
	PacketsIn, PacketsOut uint64
	BytesIn, BytesOut     uint64
	DroppedIn             uint64 // отброшено на приёме (политика, мусор, чужой контекст)
	RejectedOut           uint64 // не отправлено из-за политики
	CoverIn, CoverOut     uint64 // маскирующие датаграммы (принято/отправлено)
	TooLargeOut           uint64 // не отправлено из-за размера (отправителю ушёл ICMP)

	// Кадрирование (C2): по этим числам видно, насколько поток датаграмм
	// разошёлся с потоком IP-пакетов.
	DatagramsOut uint64 // отправлено датаграмм (при кадрировании)
	PackedOut    uint64 // пакетов, уехавших не в одиночку
	FragmentsOut uint64 // отправлено кусков крупных пакетов
	FragmentsIn  uint64 // принято кусков
	QueueDrop    uint64 // отброшено из-за переполнения очереди отправки
	ReasmDrop    uint64 // не собрано из кусков (потеря или таймаут)
	DroppedOut   uint64 // не отправлено (ошибка транспорта)
}

// Conn — установленная CONNECT-IP сессия. Безопасна для конкурентного
// использования: один читатель ReadPacket и любое число писателей WritePacket.
type Conn struct {
	str     Stream
	role    role
	closer  func() error
	shaping *Shaping // задаётся до start(), затем только читается

	ctx    context.Context
	cancel context.CancelFunc

	writeMu sync.Mutex // сериализует запись капсул в поток

	mu         sync.Mutex
	assigned   []netip.Prefix // адреса клиента (у клиента — полученные, у сервера — выданные)
	routes     []IPRoute      // маршруты сервера (у клиента — полученные, у сервера — объявленные)
	tunnelNets []netip.Prefix // сети туннеля, закрытые для клиента (изоляция клиентов)
	tunnelOpen []netip.Addr   // адреса внутри tunnelNets, открытые всем (шлюзы сервера)
	addrUpdate chan struct{}  // закрывается и пересоздаётся при каждом ADDRESS_ASSIGN
	nextReqID  uint64
	onAddrReq  func(*Conn, []RequestedAddress)
	closeErr   error

	closeOnce sync.Once

	rx     chan []byte
	rxDone chan struct{}
	rxErr  error    // пишется до закрытия rxDone
	ready  [][]byte // разобранные пакеты одной датаграммы; только для читателя

	packing     *Packing // задаётся до start(), затем только читается
	txq         chan []byte
	peerFraming atomic.Bool // другая сторона подтвердила поддержку кадров
	peerCover   atomic.Bool // другая сторона принимает cover-датаграммы
	reasm       *reassembler
	nextFragID  atomic.Uint64

	delayOnce sync.Once
	delayQ    chan delayedPacket
	delayMu   sync.Mutex
	lastDue   time.Time

	pktIn, pktOut, bytesIn, bytesOut, droppedIn, rejectedOut atomic.Uint64
	coverIn, coverOut                                        atomic.Uint64
	tooLargeOut                                              atomic.Uint64
	coverReqs                                                atomic.Uint64
	lastSendNanos, lastPktNanos                              atomic.Int64
	maxPacketSize                                            atomic.Int64 // известный потолок IP-пакета, 0 — ещё не известен
	dgramCap                                                 atomic.Int64 // выясненный потолок полезной нагрузки датаграммы
	dgramCapNanos                                            atomic.Int64 // когда он выяснен
	dgramOut, packedOut, fragOut, queueDrop, droppedOut      atomic.Uint64
	fragIn, reasmDrop                                        atomic.Uint64
	icmpSource                                               netip.Addr // от чьего имени слать ICMP (задаётся до start)
	addrReqs                                                 atomic.Int64
	maxAddrReqs                                              int
	unknownCaps                                              atomic.Int64
	resumed, used0RTT                                        bool // задаются до start()
	maxUnknownCaps                                           int
	limiter                                                  *rateLimiter
	idleTimeout                                              time.Duration
}

func newConn(str Stream, r role, closer func() error) *Conn {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Conn{
		str:        str,
		role:       r,
		closer:     closer,
		ctx:        ctx,
		cancel:     cancel,
		addrUpdate: make(chan struct{}),
		nextReqID:  1,
		rx:         make(chan []byte, rxQueueLen),
		rxDone:     make(chan struct{}),
		reasm:      newReassembler(),
	}
	c.nextFragID.Store(randomFragID())
	go func() {
		select {
		case <-str.Context().Done():
			c.closeWithError(ErrSessionClosed)
		case <-ctx.Done():
		}
	}()
	return c
}

// Приём датаграмм.
//
// quic-go держит на поток HTTP/3 лишь 32 непрочитанные датаграммы и
// остальные молча выбрасывает (http3/state_tracking_stream.go). Насос,
// который между чтениями ещё и пишет пакет в TUN, не успевает за залпом —
// хвост залпа теряется, и TCP внутри туннеля уходит в повторные передачи.
// Поэтому датаграммы выбираются отдельной горутиной, которая больше ничего не
// делает, в собственную очередь побольше.
const rxQueueLen = 1024

func (c *Conn) recvLoop() {
	defer close(c.rxDone)
	for {
		d, err := c.str.ReceiveDatagram(c.ctx)
		if err != nil {
			c.rxErr = err
			return
		}
		select {
		case c.rx <- d:
		default:
			c.droppedIn.Add(1) // очередь переполнена — как потеря в сети
		}
	}
}

func (c *Conn) start() {
	go c.recvLoop()
	if c.packing != nil {
		c.txq = make(chan []byte, c.packing.queueLen())
		go c.packLoop()
	}
	// Сообщаем, какие расширения понимаем. Ответная капсула включит их на
	// отправку; без неё шлём только то, что определено RFC.
	go func() {
		_ = c.writeCapsule(CapsuleFramingSupport, EncodeFramingSupport(c.packing != nil, true))
	}()
	c.recordPacket()
	go c.capsuleLoop()
	if c.idleTimeout > 0 {
		go c.idleWatchdog(c.idleTimeout)
	}
	if c.shaping != nil && c.shaping.Cover != nil {
		go c.coverLoop(*c.shaping.Cover)
	}
}

// ---------- капсулы ----------

func (c *Conn) capsuleLoop() {
	r := bufio.NewReader(c.str)
	for {
		ct, val, err := readCapsule(r)
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = ErrSessionClosed
			}
			c.closeWithError(err)
			return
		}
		if err := c.handleCapsule(ct, val); err != nil {
			c.closeWithError(err)
			return
		}
	}
}

func (c *Conn) handleCapsule(ct http3.CapsuleType, val []byte) error {
	switch ct {
	case CapsuleAddressAssign:
		if c.role != roleClient {
			return nil // сервер не принимает адреса от клиента
		}
		addrs, err := ParseAddressAssign(val)
		if err != nil {
			return err
		}
		prefixes := make([]netip.Prefix, len(addrs))
		for i, a := range addrs {
			prefixes[i] = a.Prefix
		}
		c.mu.Lock()
		c.assigned = prefixes
		close(c.addrUpdate)
		c.addrUpdate = make(chan struct{})
		c.mu.Unlock()
	case CapsuleAddressRequest:
		if c.role != roleServer {
			return nil
		}
		// Потолок на число запросов: иначе авторизованный, но враждебный клиент
		// может бесконечно гонять сервер по пулу адресов.
		if max := c.maxAddrReqs; max > 0 && int(c.addrReqs.Add(1)) > max {
			return ErrTooManyAddressRequests
		}
		reqs, err := ParseAddressRequest(val)
		if err != nil {
			return err
		}
		c.mu.Lock()
		h := c.onAddrReq
		c.mu.Unlock()
		if h != nil {
			h(c, reqs)
		}
	case CapsuleRouteAdvertisement:
		if c.role != roleClient {
			return nil
		}
		routes, err := ParseRouteAdvertisement(val)
		if err != nil {
			return err
		}
		c.mu.Lock()
		c.routes = routes
		c.mu.Unlock()
	case CapsuleFramingSupport:
		framing, cover, err := ParseFramingSupport(val)
		if err != nil {
			return err
		}
		if framing {
			c.peerFraming.Store(true)
		}
		if cover {
			c.peerCover.Store(true)
		}
	default:
		// Неизвестные капсулы игнорируются (RFC 9297, 3.2), но не бесконечно:
		// поток мусорных капсул — дешёвый способ занять чужой процессор,
		// а у честной стороны их не бывает вовсе.
		if max := c.maxUnknownCaps; max > 0 && int(c.unknownCaps.Add(1)) > max {
			return fmt.Errorf("masque: поток неизвестных капсул (больше %d)", max)
		}
	}
	return nil
}

func (c *Conn) writeCapsule(ct http3.CapsuleType, val []byte) error {
	if c.ctx.Err() != nil {
		return c.Err()
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	// Капсула целиком одним Write — одним DATA-кадром.
	buf := make([]byte, 0, len(val)+16)
	w := bytesWriter{&buf}
	if err := http3.WriteCapsule(w, ct, val); err != nil {
		return err
	}
	_, err := c.str.Write(buf)
	return err
}

type bytesWriter struct{ b *[]byte }

func (w bytesWriter) Write(p []byte) (int, error) { *w.b = append(*w.b, p...); return len(p), nil }
func (w bytesWriter) WriteByte(c byte) error      { *w.b = append(*w.b, c); return nil }

// AssignAddresses (сервер) выдаёт клиенту адреса, заменяя прежний набор.
// requestID != 0 — ответ на конкретный ADDRESS_REQUEST.
func (c *Conn) AssignAddresses(prefixes []netip.Prefix, requestIDs ...uint64) error {
	if c.role != roleServer {
		return errors.New("masque: AssignAddresses is server-only")
	}
	list := make([]AssignedAddress, len(prefixes))
	for i, p := range prefixes {
		list[i] = AssignedAddress{Prefix: p}
		if i < len(requestIDs) {
			list[i].RequestID = requestIDs[i]
		}
	}
	c.mu.Lock()
	c.assigned = slices.Clone(prefixes)
	c.mu.Unlock()
	return c.writeCapsule(CapsuleAddressAssign, EncodeAddressAssign(list))
}

// AdvertiseRoutes (сервер) объявляет клиенту доступные маршруты.
func (c *Conn) AdvertiseRoutes(routes []IPRoute) error {
	if c.role != roleServer {
		return errors.New("masque: AdvertiseRoutes is server-only")
	}
	for i := 1; i < len(routes); i++ {
		if err := checkRouteOrder(routes[i-1], routes[i]); err != nil {
			return err
		}
	}
	c.mu.Lock()
	c.routes = slices.Clone(routes)
	c.mu.Unlock()
	return c.writeCapsule(CapsuleRouteAdvertisement, EncodeRouteAdvertisement(routes))
}

// RequestAddresses (клиент) просит сервер выдать адреса.
// Невалидный (нулевой) префикс означает «любой IPv4».
func (c *Conn) RequestAddresses(prefixes ...netip.Prefix) error {
	if c.role != roleClient {
		return errors.New("masque: RequestAddresses is client-only")
	}
	c.mu.Lock()
	reqs := make([]RequestedAddress, len(prefixes))
	for i, p := range prefixes {
		if !p.IsValid() {
			p = netip.PrefixFrom(netip.IPv4Unspecified(), 32)
		}
		reqs[i] = RequestedAddress{RequestID: c.nextReqID, Prefix: p}
		c.nextReqID++
	}
	c.mu.Unlock()
	return c.writeCapsule(CapsuleAddressRequest, EncodeAddressRequest(reqs))
}

// AssignedPrefixes возвращает адреса клиента.
func (c *Conn) AssignedPrefixes() []netip.Prefix {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.assigned)
}

// Routes возвращает маршруты сервера.
func (c *Conn) Routes() []IPRoute {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.routes)
}

// WaitForAddress (клиент) ждёт, пока сервер выдаст хотя бы один адрес.
func (c *Conn) WaitForAddress(ctx context.Context) ([]netip.Prefix, error) {
	for {
		c.mu.Lock()
		if len(c.assigned) > 0 {
			p := slices.Clone(c.assigned)
			c.mu.Unlock()
			return p, nil
		}
		ch := c.addrUpdate
		c.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-c.ctx.Done():
			return nil, c.Err()
		}
	}
}

// ---------- политика ----------

func prefixesContain(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func routesContain(rs []IPRoute, a netip.Addr, proto uint8) bool {
	for _, r := range rs {
		if r.Contains(a, proto) {
			return true
		}
	}
	return false
}

// allowed проверяет пакет. outbound=true — пакет отправляется нами.
//
//	клиент → сервер: src ∈ assigned, dst ∈ routes
//	сервер → клиент: src ∈ routes,   dst ∈ assigned
func (c *Conn) allowed(pkt []byte, outbound bool) bool {
	info, err := parsePacket(pkt)
	if err != nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	clientToServer := (c.role == roleClient) == outbound
	if clientToServer {
		if !prefixesContain(c.assigned, info.Src) || !routesContain(c.routes, info.Dst, info.Proto) {
			return false
		}
		// Изоляция клиентов: внутрь туннельных сетей пускаем только пакеты,
		// адресованные самому себе. Маршруты по умолчанию — весь интернет,
		// а он включает и наши туннельные сети.
		if prefixesContain(c.tunnelNets, info.Dst) && !prefixesContain(c.assigned, info.Dst) &&
			!slices.Contains(c.tunnelOpen, info.Dst) {
			return false
		}
		return true
	}
	return routesContain(c.routes, info.Src, info.Proto) && prefixesContain(c.assigned, info.Dst)
}

// ---------- пакеты ----------

var datagramPool = sync.Pool{New: func() any { b := make([]byte, 0, 1600); return &b }}

// WritePacket отправляет один IP-пакет как HTTP Datagram, применяя паддинг и
// джиттер из Shaping (если заданы). Возвращает ErrPacketRejected, если пакет не
// проходит проверку политики, и *quic.DatagramTooLargeError, если пакет (с учётом
// паддинга) не помещается в QUIC-датаграмму.
func (c *Conn) WritePacket(pkt []byte) error {
	if c.ctx.Err() != nil {
		return c.Err()
	}
	if !c.allowed(pkt, true) {
		c.rejectedOut.Add(1)
		return ErrPacketRejected
	}
	if c.FramingActive() {
		// Дальше пакетом занимается упаковщик: он сложит его с попутными,
		// при необходимости порежет и выдержит профиль. Насос TUN не ждёт.
		c.enqueueForPacking(pkt)
		return nil
	}
	if d := c.shaping.delay(len(pkt)); d > 0 && c.enqueueDelayed(pkt, d) {
		return nil
	}
	return c.writeNow(pkt)
}

// Resumed сообщает, было ли TLS-соединение возобновлено по билету.
// Браузер возобновляет сессии постоянно; клиент, который каждый раз
// делает полное рукопожатие, этим и выделяется.
func (c *Conn) Resumed() bool { return c.resumed }

// Used0RTT сообщает, были ли отправлены ранние данные (0-RTT).
func (c *Conn) Used0RTT() bool { return c.used0RTT }

// FramingActive сообщает, идёт ли обмен кадрированными датаграммами: мы
// настроены на кадры И другая сторона подтвердила, что их понимает.
func (c *Conn) FramingActive() bool { return c.packing != nil && c.peerFraming.Load() }

// Джиттер без блокировки.
//
// Раньше WritePacket просто засыпал на время джиттера. Но пишет в сессию
// ОДИН насос TUN, и сон на каждом мелком пакете выстраивал их в очередь:
// при джиттере до 2 мс на TCP-подтверждениях клиент успевал отправить не
// больше ~1000 подтверждений в секунду, и скачивание упиралось в ~30 Мбит/с
// (измерено сквозным тестом: 30 против 220–310 без маскировки).
//
// Теперь задержанные пакеты уходят в очередь с отдельным отправителем, а
// насос сразу берёт следующий пакет. Порядок задержанных пакетов сохраняется:
// момент отправки не раньше предыдущего, и задержка всё равно не превышает
// заданного максимума.
type delayedPacket struct {
	due time.Time
	b   []byte
}

const delayQueueLen = 1024

func (c *Conn) enqueueDelayed(pkt []byte, d time.Duration) bool {
	c.delayOnce.Do(func() {
		c.delayQ = make(chan delayedPacket, delayQueueLen)
		go c.delayLoop()
	})
	c.delayMu.Lock()
	due := time.Now().Add(d)
	if due.Before(c.lastDue) {
		due = c.lastDue
	}
	c.lastDue = due
	c.delayMu.Unlock()
	select {
	case c.delayQ <- delayedPacket{due: due, b: append([]byte(nil), pkt...)}:
		return true
	default:
		return false // очередь полна — отправим без задержки
	}
}

func (c *Conn) delayLoop() {
	t := time.NewTimer(time.Hour)
	defer t.Stop()
	for {
		var p delayedPacket
		select {
		case <-c.ctx.Done():
			return
		case p = <-c.delayQ:
		}
		if w := time.Until(p.due); w > 0 {
			t.Reset(w)
			select {
			case <-c.ctx.Done():
				return
			case <-t.C:
			}
		}
		// Джиттер применяется к мелким пакетам, «слишком большой» для них
		// не бывает; прочие ошибки — сессия закрывается.
		_ = c.writeNow(p.b)
	}
}

// writeNow отправляет пакет, прошедший политику, без джиттера.
// sendFailed превращает отказ транспорта в ErrSessionClosed.
//
// Датаграмму транспорт отвергает всего по двум причинам: не влезла (это
// разбирается выше, по datagramCapacity) или отправлять уже некуда —
// поток запроса или всё соединение закрыты. Второе и есть конец сессии, но
// узнаёт о нём отправитель раньше, чем читатель успеет закрыть Conn: в этом
// окне ошибка приходила как есть («write on closed stream»), и сессия с
// переподключением принимала её за смертельную — насос туннеля завершал
// клиента вместо того, чтобы дождаться нового соединения.
func sendFailed(err error) error {
	if errors.Is(err, ErrSessionClosed) {
		return err
	}
	return fmt.Errorf("%w: %v", ErrSessionClosed, err)
}

func (c *Conn) writeNow(pkt []byte) error {
	c.limiter.wait(c.ctx, len(pkt))
	// Потолок проверяем ДО отправки: транспорт может принять датаграмму,
	// которая потом молча не влезет в пакет (см. capacity), — и отправитель
	// внутри туннеля никогда не узнал бы о потере.
	capacity := c.capacity()
	if capacity > 0 && len(pkt)+contextIDLen > capacity {
		return c.tooLarge(capacity, pkt)
	}
	padTo := c.clampPad(len(pkt), c.shaping.padTo(len(pkt)))
	err := c.sendIP(pkt, padTo)
	if err != nil {
		capacity, ok := datagramCapacity(err)
		if !ok {
			return sendFailed(err)
		}
		c.learnCapacity(capacity)
		if len(pkt)+contextIDLen > capacity {
			return c.tooLarge(capacity, pkt)
		}
		// Не влез только паддинг — отправляем с урезанным. Иначе «ведро»
		// крупнее пути превращало бы в ICMP пакеты, которые проходят.
		if err := c.sendIP(pkt, c.clampPad(len(pkt), padTo)); err != nil {
			return sendFailed(err)
		}
	}
	c.recordSend()
	c.recordPacket()
	c.pktOut.Add(1)
	c.bytesOut.Add(uint64(len(pkt)))
	return nil
}

func (c *Conn) sendIP(pkt []byte, padTo int) error {
	bp := datagramPool.Get().(*[]byte)
	b := appendIPDatagram((*bp)[:0], pkt, padTo)
	err := c.str.SendDatagram(b) // реализации копируют данные
	*bp = b[:0]
	datagramPool.Put(bp)
	return err
}

// contextIDLen — длина Context ID 0 в датаграмме (varint).
const contextIDLen = 1

// Потолок датаграммы.
//
// # Почему его надо узнавать заранее
//
// Оба наших транспорта умеют ПРИНЯТЬ датаграмму, которая не поместится в
// пакет, — и молча выбросить её при упаковке:
//
//   - quic-go v0.59 после первого ACK подменяет оценку потолка сырым размером
//     пакета, без вычета заголовка и AEAD-тега (connection.go, handleAckFrame);
//     адаптер потоков вносит поправку (stream.go);
//   - uquic v0.0.6 вообще сверяет датаграмму только с параметром пира, а не с
//     размером пакета; потолок считает наш HTTP/3 (utlsquic).
//
// Поэтому потолок узнаётся пробой: отправка заведомо огромной датаграммы
// всегда отклоняется транспортом ДО выхода в сеть, а ошибка несёт текущий
// потолок. Проба — cover-датаграмма (Context ID 1): даже если бы какой-то
// транспорт её пропустил, получатель её просто отбросит.
const (
	capacityTTL       = 2 * time.Second
	capacityProbeSize = 16 * 1024
)

var capacityProbe = appendCoverDatagram(nil, capacityProbeSize)

func (c *Conn) learnCapacity(n int) {
	c.dgramCap.Store(int64(n))
	c.dgramCapNanos.Store(time.Now().UnixNano())
}

// capacity возвращает текущий потолок полезной нагрузки датаграммы
// (0 — неизвестен), при устаревании обновляя его пробой.
func (c *Conn) capacity() int {
	last := c.dgramCapNanos.Load()
	now := time.Now().UnixNano()
	if now-last > int64(capacityTTL) && c.dgramCapNanos.CompareAndSwap(last, now) {
		if n, ok := datagramCapacity(c.str.SendDatagram(capacityProbe)); ok {
			c.learnCapacity(n)
		}
	}
	return int(c.dgramCap.Load())
}

func (c *Conn) refreshCapacity() int {
	c.dgramCapNanos.Store(time.Now().UnixNano())
	if n, ok := datagramCapacity(c.str.SendDatagram(capacityProbe)); ok {
		c.learnCapacity(n)
	}
	return int(c.dgramCap.Load())
}

// WarmUp ждёт, пока в датаграмму начнёт помещаться IP-пакет размером want,
// и возвращает достигнутый потолок (он может остаться меньше want, если
// путь не позволяет или вышло время).
//
// Зачем: в uTLS-пути стартовый размер QUIC-пакета мал (1252 байта, это
// зашито в uquic), и в датаграмму влезает ~1220 байт — меньше, чем нужно
// IPv6 (1280). Потолок растёт через Path MTU Discovery, но пробам нужен
// трафик: пока ждём, отправляем мелкие cover-датаграммы (получатель их
// отбрасывает).
func (c *Conn) WarmUp(ctx context.Context, want int) int {
	t := time.NewTicker(50 * time.Millisecond)
	defer t.Stop()
	for {
		if n := c.refreshCapacity() - contextIDLen; n >= want {
			return n
		}
		c.sendCover(32)
		select {
		case <-ctx.Done():
			return c.DatagramCapacity()
		case <-c.ctx.Done():
			return 0
		case <-t.C:
		}
	}
}

// DatagramCapacity возвращает, сколько байт IP-пакета сейчас помещается в
// одну датаграмму (0 — неизвестно). Слой TUN может по нему выбрать MTU.
func (c *Conn) DatagramCapacity() int {
	if n := c.capacity(); n > contextIDLen {
		return n - contextIDLen
	}
	return 0
}

// clampPad урезает паддинг до известного потолка датаграммы (но не ниже
// реального размера пакета).
func (c *Conn) clampPad(realLen, padTo int) int {
	if padTo <= realLen {
		return padTo
	}
	if lim := c.capacity() - contextIDLen; lim > 0 && padTo > lim {
		padTo = max(lim, realLen)
	}
	return padTo
}

// DatagramTooLargeError — ошибка «датаграмма не помещается» для транспортов,
// отличных от quic-go (у quic-go своя *quic.DatagramTooLargeError).
// MaxPayload — сколько байт полезной нагрузки HTTP Datagram (после Quarter
// Stream ID) помещается сейчас.
type DatagramTooLargeError struct {
	MaxPayload int
}

func (e *DatagramTooLargeError) Error() string {
	return fmt.Sprintf("masque: datagram too large (max payload %d)", e.MaxPayload)
}

// datagramCapacity извлекает потолок полезной нагрузки из ошибки отправки.
// Ошибки quic-go переводятся в DatagramTooLargeError адаптерами потоков
// (stream.go) — с поправкой на Quarter Stream ID.
func datagramCapacity(err error) (int, bool) {
	var m *DatagramTooLargeError
	if errors.As(err, &m) {
		return m.MaxPayload, true
	}
	return 0, false
}

func (c *Conn) recordSend() { c.lastSendNanos.Store(time.Now().UnixNano()) }

// tooLarge превращает отказ «пакет не помещается» в осмысленный ответ:
// сообщает предельный размер и готовит ICMP для отправителя внутри туннеля.
// Без этого пакет исчезал бы молча — см. комментарий в icmp.go.
func (c *Conn) tooLarge(capacity int, pkt []byte) error {
	// Паддинг в расчёт не входит: он урезается под потолок сам, отправителю
	// важен только размер IP-пакета.
	maxIP := capacity - contextIDLen
	if maxIP < 0 {
		maxIP = 0
	}
	c.maxPacketSize.Store(int64(maxIP))
	c.tooLargeOut.Add(1)
	return &PacketTooLargeError{
		MaxSize: maxIP,
		ICMP:    buildICMPTooBig(pkt, maxIP, c.icmpSource),
	}
}

// MaxPacketSize возвращает известный предельный размер IP-пакета для этой
// сессии или 0, если он ещё не выяснен. Значение уточняется после первой
// попытки отправить слишком большой пакет, поэтому MTU интерфейса TUN стоит
// задавать заранее с запасом, а не полагаться только на него.
func (c *Conn) MaxPacketSize() int { return int(c.maxPacketSize.Load()) }

// SetICMPSource задаёт адрес, от имени которого отправляются ICMP-сообщения об
// MTU. По умолчанию берётся получатель исходного пакета. Вызывать до start.
func (c *Conn) SetICMPSource(a netip.Addr) { c.icmpSource = a }

// coverLoop отправляет маскирующую датаграмму, если за случайную паузу не было
// отправок. Пауза случайная — постоянный период сам стал бы признаком.
func (c *Conn) coverLoop(cfg CoverConfig) {
	if cfg.Next == nil || cfg.Size == nil {
		return
	}
	c.recordSend()
	for {
		d := cfg.Next()
		if d <= 0 {
			d = time.Second
		}
		t := time.NewTimer(d)
		select {
		case <-c.ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		if cfg.Always || time.Since(time.Unix(0, c.lastSendNanos.Load())) >= d {
			c.sendCover(cfg.Size())
		}
	}
}

func (c *Conn) sendCover(size int) {
	if size < 0 || !c.peerCover.Load() {
		// Context ID 1 — наше расширение: без подтверждения другой стороны
		// это был бы мусор в её адрес.
		return
	}
	if lim := c.capacity() - contextIDLen; lim > 0 && size > lim {
		size = lim
	}
	bp := datagramPool.Get().(*[]byte)
	b := appendCoverDatagram((*bp)[:0], size)
	err := c.str.SendDatagram(b)
	*bp = b[:0]
	datagramPool.Put(bp)
	if err == nil {
		c.recordSend()
		c.coverOut.Add(1)
	} else if n, ok := datagramCapacity(err); ok {
		c.learnCapacity(n) // следующий cover уже поместится
	}
}

// ReadPacket блокируется до получения следующего допустимого IP-пакета
// и копирует его в b. Пакеты, не прошедшие проверку, отбрасываются.
//
// Читатель должен быть один: разобранные пакеты одной датаграммы (при
// кадрировании их может быть несколько) хранятся между вызовами.
func (c *Conn) ReadPacket(b []byte) (int, error) {
	for {
		for len(c.ready) > 0 {
			pkt := c.ready[0]
			c.ready = c.ready[1:]
			if n, ok := c.deliver(pkt, b); ok {
				return n, nil
			}
		}
		d, err := c.nextDatagram()
		if err != nil {
			return 0, err
		}
		c.dispatch(d)
	}
}

// nextDatagram отдаёт следующую принятую датаграмму.
func (c *Conn) nextDatagram() ([]byte, error) {
	select {
	case d := <-c.rx:
		return d, nil
	case <-c.rxDone:
		// Дочитываем то, что уже принято, и только потом сообщаем ошибку.
		select {
		case d := <-c.rx:
			return d, nil
		default:
			if c.ctx.Err() != nil {
				return nil, c.Err()
			}
			return nil, c.rxErr
		}
	}
}

// deliver проверяет пакет политикой и копирует его вызывающему.
func (c *Conn) deliver(pkt, b []byte) (int, bool) {
	if !c.allowed(pkt, false) || len(pkt) > len(b) {
		c.droppedIn.Add(1)
		return 0, false
	}
	c.recordPacket()
	c.pktIn.Add(1)
	c.bytesIn.Add(uint64(len(pkt)))
	return copy(b, pkt), true
}

// dispatch разбирает датаграмму и складывает готовые пакеты в c.ready.
func (c *Conn) dispatch(d []byte) {
	ctxID, payload, ok := parseDatagram(d)
	if !ok {
		c.droppedIn.Add(1)
		return
	}
	switch ctxID {
	case contextIDPadding:
		c.coverIn.Add(1) // cover-трафик — молча отбрасываем
	case contextIDIPPacket:
		// Обрезаем хвостовой паддинг по длине из IP-заголовка.
		n := ipPacketLen(payload)
		if n == 0 {
			c.droppedIn.Add(1)
			return
		}
		c.ready = append(c.ready, payload[:n])
	case contextIDFramed:
		before := len(c.ready)
		err := parseFrames(payload, func(f frame) error {
			switch f.typ {
			case frameTypePacket:
				c.ready = append(c.ready, f.payload)
			case frameTypeFragment, frameTypeFragmentFin:
				c.fragIn.Add(1)
				if pkt := c.reasm.add(f.id, f.off, f.payload, f.typ == frameTypeFragmentFin); pkt != nil {
					c.ready = append(c.ready, pkt)
				}
			}
			return nil
		})
		if err != nil {
			c.droppedIn.Add(1)
			return
		}
		if len(c.ready) == before {
			// Датаграмма без готовых пакетов — паддинг или кусок пакета.
			c.coverIn.Add(1)
		}
	default:
		c.droppedIn.Add(1)
	}
}

// Stats возвращает счётчики сессии.
func (c *Conn) Stats() Stats {
	return Stats{
		PacketsIn: c.pktIn.Load(), PacketsOut: c.pktOut.Load(),
		BytesIn: c.bytesIn.Load(), BytesOut: c.bytesOut.Load(),
		DroppedIn: c.droppedIn.Load(), RejectedOut: c.rejectedOut.Load(),
		CoverIn: c.coverIn.Load(), CoverOut: c.coverOut.Load(),
		TooLargeOut:  c.tooLargeOut.Load(),
		DatagramsOut: c.dgramOut.Load(), PackedOut: c.packedOut.Load(),
		FragmentsOut: c.fragOut.Load(), FragmentsIn: c.fragIn.Load(),
		QueueDrop: c.queueDrop.Load(), ReasmDrop: c.reasm.drops(),
		DroppedOut: c.droppedOut.Load(),
	}
}

// ---------- закрытие ----------

// Done закрывается при завершении сессии.
func (c *Conn) Done() <-chan struct{} { return c.ctx.Done() }

// Err возвращает причину закрытия (nil, пока сессия жива).
func (c *Conn) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeErr
}

// Close закрывает сессию.
func (c *Conn) Close() error {
	c.closeWithError(ErrSessionClosed)
	return nil
}

func (c *Conn) closeWithError(err error) {
	c.closeOnce.Do(func() {
		if err == nil {
			err = ErrSessionClosed
		} else if !errors.Is(err, ErrSessionClosed) {
			err = fmt.Errorf("%w: %w", ErrSessionClosed, err)
		}
		c.mu.Lock()
		c.closeErr = err
		c.mu.Unlock()
		c.cancel()
		c.str.CancelRead(uint64(http3.ErrCodeNoError))
		_ = c.str.Close()
		if c.closer != nil {
			_ = c.closer()
		}
	})
}
