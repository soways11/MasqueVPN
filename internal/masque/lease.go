package masque

import (
	"net/netip"
	"slices"
	"sync"
	"time"
)

// Аренда адресов за КЛИЕНТОМ, а не за сессией.
//
// Проблема, которую это решает. Адрес выдавался сессии и возвращался в пул,
// когда её обработчик завершался. При ротации (make-before-break) новая
// сессия открывается, пока старая ещё жива, — значит прежний адрес занят, и
// новая сессия получала другой. Клиент же продолжает слать пакеты со своим
// прежним адресом: сервер отбрасывал их как «src не из выданных», пока
// клиент не выпросит адрес обратно капсулой ADDRESS_REQUEST — то есть до
// конца Grace. На стенде с ротацией раз в 2 с передача почти вставала: 6,8 МБ
// из 8 за минуту.
//
// Ещё хуже было при обрыве. После смены сети клиент переподключается за
// полсекунды, а сервер держит адрес мёртвой сессии, пока QUIC не закроется по
// простою (десятки секунд). Клиент получал новый адрес — и все соединения
// внутри туннеля рвались, ради сохранения которых ротация и делалась.
//
// Решение: адрес закрепляется за псевдонимом клиента из токена (см. auth).
// Вернувшийся клиент получает СВОЙ адрес сразу, в первом же ADDRESS_ASSIGN,
// не спрашивая, — и во время ротации обе сессии законно работают с одним
// адресом (это один и тот же клиент). Маршрутизатор сервера направляет входящее
// в последнюю зарегистрированную сессию, а исходящее принимается от обеих.
// Аренда без единой живой сессии живёт ещё LeaseTTL и только потом
// возвращается в пул.
//
// # Почему в ключе ещё и устройство
//
// «Тот же клиент» — это запись в реестре ключей, а не железка: один ключ
// человек ставит и на ноутбук, и на телефон. Пока ключом аренды был только
// псевдоним клиента, оба устройства получали ОДИН адрес — то самое поведение,
// которое спасает ротацию, но для разных устройств означает, что работает
// только подключившееся последним: таблица маршрутизатора хранит одну запись
// на адрес, и входящий трафик уходит в последнюю сессию.
//
// Поэтому ключ — пара клиент+устройство. Ротация (две сессии одного
// устройства) по-прежнему делит адрес, а второе устройство получает своё.
// Общими на клиента остаются то, что и должно: ключ, полоса, квота, отзыв.

// DefaultAddressLeaseTTL — сколько адрес держится за ушедшим клиентом.
const DefaultAddressLeaseTTL = 2 * time.Minute

// addrLease — аренда набора адресов (по одному на пул) за одним устройством
// одного клиента.
type addrLease struct {
	// id — ключ аренды: клиент и устройство (см. leaseKey).
	id string
	// client — псевдоним клиента без устройства. Нужен отзыву: он закрывает
	// доступ клиенту целиком, со всеми его устройствами.
	client string
	addrs  []netip.Prefix
	// conns — сколько живых сессий этого клиента держат аренду. Больше
	// одной бывает во время ротации.
	conns  int
	idleAt time.Time
}

type leaseRegistry struct {
	mu    sync.Mutex
	pools []*IPPool
	ttl   time.Duration
	now   func() time.Time
	byID  map[string]*addrLease
}

func newLeaseRegistry(pools []*IPPool, ttl time.Duration) *leaseRegistry {
	if ttl <= 0 {
		ttl = DefaultAddressLeaseTTL
	}
	return &leaseRegistry{
		pools: pools,
		ttl:   ttl,
		now:   time.Now,
		byID:  map[string]*addrLease{},
	}
}

// leaseKey — ключ аренды. Разделитель невозможен внутри самих псевдонимов
// (они шестнадцатеричные), поэтому склейка однозначна.
func leaseKey(client, device string) string {
	if client == "" {
		return ""
	}
	if device == "" {
		// Клиент старой сборки: устройства в токене нет, и различить их
		// нечем — ведём себя как раньше, одна аренда на клиента.
		return client
	}
	return client + "/" + device
}

// acquire выдаёт адреса сессии устройства device клиента client. Вернувшееся
// устройство получает те же адреса, что и раньше. Пустой client (токен версии
// 1 или сервер без проверки) аренды не создаёт — поведение как было, адрес
// живёт ровно сессию.
func (r *leaseRegistry) acquire(client, device string) (*addrLease, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweepLocked()

	id := leaseKey(client, device)
	if id != "" {
		if l := r.byID[id]; l != nil {
			l.conns++
			l.idleAt = time.Time{}
			return l, nil
		}
	}
	addrs, err := r.allocLocked()
	if err != nil {
		// Пул исчерпан: сначала отдаём то, что держится за ушедшими
		// клиентами, и только потом отказываем.
		if !r.evictOldestLocked() {
			return nil, err
		}
		if addrs, err = r.allocLocked(); err != nil {
			return nil, err
		}
	}
	l := &addrLease{id: id, client: client, addrs: addrs, conns: 1}
	if id != "" {
		r.byID[id] = l
	}
	return l, nil
}

// release отпускает аренду одной сессией.
func (r *leaseRegistry) release(l *addrLease) {
	if l == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if l.conns > 0 {
		l.conns--
	}
	if l.conns > 0 {
		return
	}
	if l.id == "" {
		r.freeLocked(l)
		return
	}
	l.idleAt = r.now()
}

// setAddrs запоминает новые адреса аренды (клиент попросил другой адрес).
func (r *leaseRegistry) setAddrs(l *addrLease, addrs []netip.Prefix) {
	r.mu.Lock()
	l.addrs = slices.Clone(addrs)
	r.mu.Unlock()
}

// addrsOf — текущие адреса аренды.
func (r *leaseRegistry) addrsOf(l *addrLease) []netip.Prefix {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(l.addrs)
}

func (r *leaseRegistry) allocLocked() ([]netip.Prefix, error) {
	addrs := make([]netip.Prefix, 0, len(r.pools))
	for i, p := range r.pools {
		a, err := p.Allocate(netip.Addr{})
		if err != nil {
			for j, got := range addrs {
				r.pools[j].Release(got)
			}
			_ = i
			return nil, err
		}
		addrs = append(addrs, a)
	}
	return addrs, nil
}

func (r *leaseRegistry) freeLocked(l *addrLease) {
	for i, a := range l.addrs {
		if i < len(r.pools) {
			r.pools[i].Release(a)
		}
	}
	l.addrs = nil
	delete(r.byID, l.id)
}

func (r *leaseRegistry) sweepLocked() {
	now := r.now()
	for _, l := range r.byID {
		if l.conns == 0 && !l.idleAt.IsZero() && now.Sub(l.idleAt) > r.ttl {
			r.freeLocked(l)
		}
	}
}

// evictOldestLocked освобождает аренду клиента, который дольше всех не
// появлялся. Возвращает false, если освобождать нечего.
func (r *leaseRegistry) evictOldestLocked() bool {
	var oldest *addrLease
	for _, l := range r.byID {
		if l.conns != 0 || l.idleAt.IsZero() {
			continue
		}
		if oldest == nil || l.idleAt.Before(oldest.idleAt) {
			oldest = l
		}
	}
	if oldest == nil {
		return false
	}
	r.freeLocked(oldest)
	return true
}

// leases — число аренд в реестре (для тестов и статистики).
func (r *leaseRegistry) leases() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.byID)
}

// forget освобождает аренды клиента немедленно, не дожидаясь TTL.
// Нужен отзыву: держать адрес за тем, кому доступ закрыт, незачем — он не
// вернётся, а пул тем временем занят. Возвращает true, если хоть одна аренда
// была освобождена.
//
// Отзывается доступ клиента целиком, поэтому освобождаются аренды ВСЕХ его
// устройств: их у одного клиента несколько (см. заголовок файла), и оставить
// адрес за телефоном отозванного клиента — то же, что не отозвать.
//
// Аренда с живыми сессиями не трогается: адрес из-под работающей сессии
// выдёргивать нельзя. Отзыв сначала закрывает сессии, а освобождение
// происходит само, когда последняя отпустит аренду.
func (r *leaseRegistry) forget(client string) bool {
	if client == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	freed := false
	for _, l := range r.byID {
		if l.client != client || l.conns > 0 {
			continue
		}
		r.freeLocked(l)
		freed = true
	}
	return freed
}
