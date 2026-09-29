// Package core — ядро masquevpn для мобильных платформ: то, что вызывается из
// Kotlin (Android, VpnService) и Swift (iOS, NEPacketTunnelProvider).
//
// # Почему отдельный пакет, а не clientrun
//
// На desktop клиент всё делает сам: открывает TUN, назначает адреса, правит
// маршруты, подменяет DNS. На мобильных платформах ничего этого делать нельзя
// и не нужно — интерфейс создаёт система, она же назначает адреса и маршруты,
// а приложению выдаёт готовый файловый дескриптор. Половина clientrun там
// просто лишняя, а вторая половина (netsetup) невыполнима: прав нет.
//
// # Порядок вызовов и почему он именно такой
//
// На Android есть неприятность: VpnService.Builder требует АДРЕС ДО создания
// интерфейса, а наш адрес выдаёт сервер капсулой ADDRESS_ASSIGN уже внутри
// установленной сессии. Курица и яйцо. Поэтому запуск разделён надвое:
//
//  1. Connect  — открывает сессию БЕЗ интерфейса и возвращает JSON с тем,
//     что система должна настроить: адреса, маршруты, DNS, MTU.
//  2. Attach   — принимает дескриптор от VpnService.establish() и запускает
//     перекачку пакетов.
//
// Если сервер позже выдаст другой адрес (такое возможно, когда аренда
// истекла и прежний адрес ушёл в пул), ядро зовёт Events.OnRebind: интерфейс
// надо построить заново и отдать новый дескриптор в Rebind. Сессия при этом
// НЕ рвётся — соединения внутри туннеля переживают смену интерфейса.
//
// # Ограничения gomobile
//
// Наружу торчат только типы, которые умеет связывать gomobile: string, int,
// bool, error и интерфейсы, объявленные здесь же. Никаких срезов, карт,
// каналов, time.Duration и чужих структур в сигнатурах — иначе `gomobile
// bind` откажется собирать привязку, и узнается это только на машине со
// сборкой Android. Всё сложное едет через JSON.
package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/soways11/masquevpn/internal/client"
	"github.com/soways11/masquevpn/internal/clientrun"
	"github.com/soways11/masquevpn/internal/config"
	"github.com/soways11/masquevpn/internal/gui"
	"github.com/soways11/masquevpn/internal/session"
	"github.com/soways11/masquevpn/internal/tun"
	"github.com/soways11/masquevpn/internal/tunnel"
)

// Состояния туннеля. Строки, а не константы типа int, — их показывает
// приложение, и их же удобно печатать в журнал.
const (
	StateStopped    = "stopped"    // не запущен
	StateConnecting = "connecting" // идёт дозвон
	StateReady      = "ready"      // сессия есть, ждём дескриптор интерфейса
	StateRunning    = "running"    // туннель работает
	StateError      = "error"      // остановлен из-за ошибки
)

// Protector защищает сокет от попадания в туннель.
//
// На Android это VpnService.protect(fd): без него пакеты самого туннеля
// пойдут В туннель, и соединение замкнётся на себя. На Linux ту же роль
// играет метка сокета (SO_MARK).
//
// Возвращает false, если защитить не удалось, — тогда дозвон прерывается.
// Молча продолжать нельзя: незащищённый сокет означает неработающий туннель.
type Protector interface {
	Protect(fd int) bool
}

// Events — уведомления приложению. Вызываются из горутин ядра, так что
// приложение само отвечает за переход в свой поток интерфейса.
type Events interface {
	// OnState сообщает новое состояние (см. константы State*).
	OnState(state string)
	// OnLog — строка журнала: level = debug|info|warn|error.
	OnLog(level string, message string)
	// OnRebind зовётся, когда сервер выдал другие адреса и интерфейс надо
	// построить заново. Аргумент — тот же JSON, что вернул Connect.
	// Приложение строит интерфейс и вызывает Rebind с новым дескриптором.
	OnRebind(networkJSON string)
}

// network — то, что система должна настроить на интерфейсе. Наружу едет
// только как JSON: gomobile не умеет связывать срезы, поэтому тип
// намеренно не экспортирован — связывать нечего, и сломаться на чужой
// машине нечему.
type network struct {
	// Addresses — адреса интерфейса, "10.66.0.2/32".
	Addresses []string `json:"addresses"`
	// Routes — что заворачивать в туннель. При полном туннеле это "0.0.0.0/0"
	// (и "::/0", если есть адрес IPv6).
	Routes []string `json:"routes"`
	// DNS — адреса DNS-серверов для туннеля.
	DNS []string `json:"dns"`
	// MTU интерфейса.
	MTU int `json:"mtu"`
	// Bypass — адреса, трафик к которым НЕ должен идти в туннель: сам
	// сервер и резолверы прикрытия DNS. На Android это делается защитой
	// сокета, а не маршрутом, поэтому поле справочное — для журнала и для
	// платформ, где защиты сокета нет.
	Bypass []string `json:"bypass,omitempty"`
}

// Tunnel — туннель, которым управляет приложение.
type Tunnel struct {
	mu    sync.Mutex
	state string

	cfg    *config.Client
	log    *slog.Logger
	events Events

	sess   *session.Session
	cancel context.CancelFunc // отменяет всё: сессию, прикрытие DNS
	net    network

	inbound    chan []byte        // пакеты из сессии, общие для всех насосов
	pumpCancel context.CancelFunc // отменяет только насос (для Rebind)
	pumpDone   chan struct{}
	counters   *tunnel.Counters

	// deviceID — псевдоним этого телефона (см. SetDeviceID).
	deviceID string
	// stateDir — каталог приложения для служебных файлов (см. SetStateDir).
	stateDir string
	// meter считает скорость по нарастающим итогам; since — когда туннель
	// заработал (для «сессии» на экране).
	meter   *gui.Meter
	metered time.Time
	since   time.Time
}

// NewTunnel создаёт остановленный туннель.
//
// Имя не New специально: в Java «new» — зарезервированное слово, и gomobile
// переименовывает такую функцию по своим правилам. Проверить это здесь
// нечем (NDK нет), поэтому имя выбрано так, чтобы проверять было нечего.
func NewTunnel() *Tunnel { return &Tunnel{state: StateStopped} }

// SetDeviceID задаёт псевдоним этого устройства. Вызывать до Connect.
//
// Зачем. Ключ у человека один, а устройств несколько — телефон, ноутбук.
// Сервер закрепляет туннельный адрес за парой клиент+устройство; если
// устройство не назвать, псевдоним выйдет случайным на каждый запуск: работать
// одновременно с ноутбуком телефон всё равно будет, но при каждом
// перезапуске получит новый адрес, и соединения внутри туннеля порвутся.
//
// На desktop псевдоним берётся из файла рядом с программой. На Android такого
// файла нет, поэтому значение хранит приложение (случайная строка в своём
// хранилище, созданная один раз) и передаёт сюда.
func (t *Tunnel) SetDeviceID(id string) {
	t.mu.Lock()
	t.deviceID = strings.TrimSpace(id)
	t.mu.Unlock()
}

// SetStateDir задаёт каталог, где ядро хранит служебное — сейчас это
// удачный порт сервера (client.PortsFile). Вызывать до Connect; приложение
// передаёт свой filesDir.
//
// Без каталога порт помнится до конца процесса: переподключения и новые
// сессии начинают с удачного порта, а после перезапуска телефона — снова с
// первого в адресе.
func (t *Tunnel) SetStateDir(dir string) {
	t.mu.Lock()
	t.stateDir = strings.TrimSpace(dir)
	t.mu.Unlock()
}

// processPorts — память портов на время жизни процесса, общая для всех
// туннелей: служба VPN пересоздаёт Tunnel при каждом включении.
var processPorts = client.MemPortMemory()

// State — текущее состояние.
func (t *Tunnel) State() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.state
}

func (t *Tunnel) setState(s string) {
	t.mu.Lock()
	t.state = s
	ev := t.events
	t.mu.Unlock()
	if ev != nil {
		ev.OnState(s)
	}
}

// Connect открывает сессию без интерфейса и возвращает JSON с параметрами
// сети (см. Network), которые приложение должно применить перед тем, как
// создать интерфейс и вызвать Attach.
//
// configJSON — та же конфигурация клиента, что у desktop (см. internal/config).
func (t *Tunnel) Connect(configJSON string, p Protector, ev Events) (string, error) {
	t.mu.Lock()
	if t.state != StateStopped && t.state != StateError {
		st := t.state
		t.mu.Unlock()
		return "", fmt.Errorf("masquevpn: туннель уже в состоянии %q", st)
	}
	t.state = StateConnecting
	t.events = ev
	t.mu.Unlock()
	if ev != nil {
		ev.OnState(StateConnecting)
	}

	netJSON, err := t.connect(configJSON, p)
	if err != nil {
		t.fail(err)
		return "", err
	}
	t.setState(StateReady)
	return netJSON, nil
}

func (t *Tunnel) connect(configJSON string, p Protector) (string, error) {
	cfg, err := config.ParseClient([]byte(configJSON))
	if err != nil {
		return "", fmt.Errorf("конфигурация: %w", err)
	}
	log := slog.New(&eventHandler{t: t, level: levelOf(cfg.LogLevel)})

	opt, err := t.dialOptions(cfg, p, log)
	if err != nil {
		return "", err
	}

	dialer, err := client.NewDialer(cfg, opt)
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithCancel(context.Background())
	dctx, dcancel := context.WithTimeout(ctx, dialer.ConnectTimeout())
	defer dcancel()

	onRotate := func(old, new []netip.Prefix) {
		if sameAddrs(old, new) {
			return
		}
		log.Info("адрес сменился", "old", old, "new", new)
		t.rebindNeeded(new)
	}
	sess, err := dialer.OpenSession(dctx, onRotate)
	if err != nil {
		cancel()
		return "", fmt.Errorf("подключение: %w", err)
	}

	// Кадрирование согласуется не мгновенно; ждём немного, чтобы сообщить
	// приложению честный MTU.
	for i := 0; i < 20 && !sess.Current().FramingActive(); i++ {
		time.Sleep(50 * time.Millisecond)
	}

	nw := networkFor(cfg, sess.Prefixes(), dialer.ServerIP())
	log.Info("сессия установлена", "addrs", nw.Addresses,
		"capacity", sess.Current().DatagramCapacity(), "кадры", sess.Current().FramingActive())

	// Прикрытие DNS: запросы уходят МИМО туннеля тем же защищённым сокетом.
	// На Android список резолверов системы читать неоткуда, поэтому если
	// dns_cover.servers не задан, прикрытие просто не включится и скажет
	// об этом в журнал.
	if resolvers := clientrun.StartDNSCover(ctx, cfg, opt.Protect, log); len(resolvers) > 0 {
		for _, a := range resolvers {
			nw.Bypass = append(nw.Bypass, a.String())
		}
	}

	raw, err := json.Marshal(nw)
	if err != nil {
		sess.Close()
		cancel()
		return "", err
	}

	inbound := make(chan []byte, 256)
	go readLoop(sess, inbound)

	t.mu.Lock()
	t.cfg, t.log, t.sess, t.cancel, t.net = cfg, log, sess, cancel, nw
	t.counters = new(tunnel.Counters)
	t.inbound = inbound
	t.meter, t.metered, t.since = gui.NewMeter(1), time.Time{}, time.Time{}
	t.mu.Unlock()
	return string(raw), nil
}

// dialOptions — платформенные зацепки дозвона: защита сокета, журнал и
// псевдоним устройства.
func (t *Tunnel) dialOptions(cfg *config.Client, p Protector, log *slog.Logger) (client.Options, error) {
	t.mu.Lock()
	device, dir := t.deviceID, t.stateDir
	t.mu.Unlock()
	opt := client.Options{Logger: log, DeviceID: device, Ports: processPorts}
	if dir != "" {
		opt.Ports = client.FilePortMemory(filepath.Join(dir, client.PortsFile))
	}
	if p != nil {
		// Защита сокета — обязательна при полном туннеле: без неё пакеты
		// самого туннеля уйдут в туннель. Ошибку здесь не проглатываем.
		opt.Protect = protectFunc(p)
		opt.Resolvers = bootstrapResolvers(cfg)
	} else if *cfg.FullTunnel {
		return opt, errors.New("masquevpn: при полном туннеле нужен Protector — " +
			"иначе трафик туннеля замкнётся сам на себя")
	}
	return opt, nil
}

// bootstrapResolvers — чем разрешать имя сервера на телефоне.
//
// Своего списка резолверов у Go на Android нет (нет /etc/resolv.conf), и
// без явного списка каждое подключение по имени падало с «lookup …
// on [::1]:53: connection refused». Берём, по порядку:
//
//   - резолверы сети, которые приложение узнало у системы и положило в
//     dns_cover.servers (Store.withSystemResolvers) — те же, что у всех
//     остальных приложений телефона, запрос к ним ничем не выделяется;
//   - DNS из конфигурации (при полном туннеле по умолчанию 1.1.1.1) —
//     запасной вариант, если система резолверы не отдала.
//
// IPv4 вперёд: у части мобильных сетей IPv6 нет, и запрос к v6-резолверу
// первым съел бы таймаут.
func bootstrapResolvers(cfg *config.Client) []netip.AddrPort {
	var out []netip.AddrPort
	seen := map[netip.AddrPort]bool{}
	add := func(ap netip.AddrPort) {
		ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
		if !ap.IsValid() || ap.Addr().IsLoopback() || ap.Addr().IsUnspecified() || seen[ap] {
			return
		}
		seen[ap] = true
		out = append(out, ap)
	}
	if cover, err := cfg.DNSCoverServers(); err == nil {
		for _, ap := range cover {
			add(ap)
		}
	}
	if dns, err := cfg.DNSServers(); err == nil {
		for _, a := range dns {
			add(netip.AddrPortFrom(a, 53))
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Addr().Is4() && !out[j].Addr().Is4() })
	return out
}

// Attach принимает дескриптор интерфейса, созданного системой, и запускает
// перекачку пакетов. Дескриптор переходит во владение ядра: приложение не
// должно его закрывать (на Android — detachFd, а не getFd).
func (t *Tunnel) Attach(fd int) error {
	t.mu.Lock()
	if t.state != StateReady {
		st := t.state
		t.mu.Unlock()
		return fmt.Errorf("masquevpn: Attach в состоянии %q, ожидалось %q", st, StateReady)
	}
	t.mu.Unlock()
	if err := t.startPump(fd); err != nil {
		t.fail(err)
		return err
	}
	t.mu.Lock()
	t.since = time.Now()
	t.mu.Unlock()
	t.setState(StateRunning)
	return nil
}

// Rebind заменяет интерфейс, не разрывая сессию: приложение вызывает его
// после OnRebind, передав дескриптор заново созданного интерфейса.
// Соединения внутри туннеля при этом не рвутся.
func (t *Tunnel) Rebind(fd int) error {
	t.mu.Lock()
	if t.state != StateRunning {
		st := t.state
		t.mu.Unlock()
		return fmt.Errorf("masquevpn: Rebind в состоянии %q", st)
	}
	t.mu.Unlock()

	t.stopPump()
	if err := t.startPump(fd); err != nil {
		t.fail(err)
		return err
	}
	return nil
}

// startPump запускает насос TUN ⇄ сессия на новом дескрипторе.
func (t *Tunnel) startPump(fd int) error {
	t.mu.Lock()
	sess, log, mtu := t.sess, t.log, t.net.MTU
	cnt, inbound := t.counters, t.inbound
	t.mu.Unlock()
	if sess == nil {
		return errors.New("masquevpn: нет сессии")
	}

	dev, err := tun.FromFD(fd, "", mtu)
	if err != nil {
		return fmt.Errorf("дескриптор интерфейса: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	t.mu.Lock()
	t.pumpCancel, t.pumpDone = cancel, done
	t.mu.Unlock()

	go func() {
		defer close(done)
		// Насос владеет устройством и закрывает его на выходе. Сессию он
		// закрыть не может: она спрятана за обёрткой без Close — иначе
		// Rebind рвал бы то, ради сохранения чего он и нужен.
		err := tunnel.RunClient(ctx, dev, &sessionSide{in: inbound, s: sess, done: make(chan struct{})},
			tunnel.ClientOptions{Logger: log, Counters: cnt})
		if errors.Is(err, errPumpStopped) {
			err = nil // обычная остановка насоса, а не поломка
		}
		if err != nil && ctx.Err() == nil {
			t.fail(err)
		}
	}()
	return nil
}

func (t *Tunnel) stopPump() {
	t.mu.Lock()
	cancel, done := t.pumpCancel, t.pumpDone
	t.pumpCancel, t.pumpDone = nil, nil
	t.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	<-done
}

// Stop разбирает всё: насос, сессию, прикрытие DNS. Интерфейс закрывает
// насос, поэтому дескриптор трогать не надо.
func (t *Tunnel) Stop() {
	t.stopPump()
	t.mu.Lock()
	sess, cancel := t.sess, t.cancel
	t.sess, t.cancel, t.inbound = nil, nil, nil
	t.mu.Unlock()
	if sess != nil {
		sess.Close()
	}
	if cancel != nil {
		cancel()
	}
	t.setState(StateStopped)
}

// NetworkJSON — последние параметры сети (то же, что вернул Connect).
func (t *Tunnel) NetworkJSON() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	raw, err := json.Marshal(t.net)
	if err != nil {
		return "{}"
	}
	return string(raw)
}

// statsMinInterval — чаще этого скорость не пересчитывается. Экран
// опрашивает раз в секунду, но если опросов станет два (экран и
// уведомление), деление на крошечный промежуток дало бы пляшущие цифры.
const statsMinInterval = 500 * time.Millisecond

// StatsJSON — счётчики и готовые к показу строки.
//
// Байты считаются за всю жизнь туннеля (Session.Stats), а не текущего
// соединения: при ротации соединение меняется каждые несколько минут, и
// счётчики «Принято» и «Отправлено» обнулялись бы на глазах.
//
// Строки (*_text) форматирует ядро тем же кодом, что и окна Windows и
// Linux: «1,24 ГБ», «38 Мбит/с», «04:12». Иначе на телефоне те же числа
// читались бы по-другому.
func (t *Tunnel) StatsJSON() string {
	return t.statsAt(time.Now())
}

func (t *Tunnel) statsAt(now time.Time) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := map[string]any{}
	if t.counters != nil {
		s["to_tunnel"] = t.counters.ToTunnel.Load()
		s["from_tunnel"] = t.counters.FromTunnel.Load()
		s["icmp"] = t.counters.ICMP.Load()
		s["rejected"] = t.counters.Rejected.Load()
	}
	var in, out uint64
	if t.sess != nil {
		s["rotations"] = t.sess.Rotations()
		s["reconnects"] = t.sess.Reconnects()
		s["dropped"] = t.sess.Dropped()
		st := t.sess.Stats()
		in, out = st.BytesIn, st.BytesOut
		if c := t.sess.Current(); c != nil {
			s["capacity"] = c.DatagramCapacity()
		}
		if t.meter != nil && (t.metered.IsZero() || now.Sub(t.metered) >= statsMinInterval) {
			t.meter.Observe(in, out, now)
			t.metered = now
		}
	}
	var rateIn, rateOut float64
	if t.meter != nil && t.sess != nil {
		rateIn, rateOut = t.meter.Rates()
	}
	var session time.Duration
	if !t.since.IsZero() && t.state == StateRunning {
		session = now.Sub(t.since)
	}
	s["bytes_in"], s["bytes_out"] = in, out
	s["rate_in"], s["rate_out"] = rateIn, rateOut
	s["session_seconds"] = int64(session / time.Second)
	s["bytes_in_text"], s["bytes_out_text"] = gui.Bytes(in), gui.Bytes(out)
	s["rate_in_text"], s["rate_out_text"] = gui.Rate(rateIn), gui.Rate(rateOut)
	s["session_text"] = gui.Duration(session)
	raw, err := json.Marshal(s)
	if err != nil {
		return "{}"
	}
	return string(raw)
}

func (t *Tunnel) fail(err error) {
	t.mu.Lock()
	t.state = StateError
	ev := t.events
	t.mu.Unlock()
	if ev != nil {
		ev.OnLog("error", err.Error())
		ev.OnState(StateError)
	}
}

// rebindNeeded сообщает приложению, что интерфейс надо построить заново.
func (t *Tunnel) rebindNeeded(addrs []netip.Prefix) {
	t.mu.Lock()
	t.net.Addresses = prefixStrings(addrs)
	raw, _ := json.Marshal(t.net)
	ev := t.events
	t.mu.Unlock()
	if ev != nil {
		ev.OnRebind(string(raw))
	}
}

// sessionSide — сторона сессии для насоса.
//
// Насос владеет тем, что ему дали, и на выходе закрывает это. Для устройства
// так и надо, а сессию закрывать нельзя: при Rebind она должна пережить смену
// интерфейса — ради этого Rebind и существует. Но и просто спрятать Close
// нельзя: тогда на остановке насос повиснет в чтении сессии навсегда и
// Stop не вернётся. Проверено на стенде: имитатор не завершался по сигналу.
//
// Поэтому чтение идёт не прямо из сессии, а из общей очереди, которую
// наполняет одна долгоживущая горутина. Close закрывает только эту сторону:
// насос отпускает чтение, сессия остаётся жива.
type sessionSide struct {
	in   <-chan []byte
	s    *session.Session
	done chan struct{}
	once sync.Once
}

func (x *sessionSide) ReadPacket(b []byte) (int, error) {
	select {
	case p, ok := <-x.in:
		if !ok {
			return 0, errPumpStopped
		}
		return copy(b, p), nil
	case <-x.done:
		return 0, errPumpStopped
	}
}

func (x *sessionSide) WritePacket(pkt []byte) error { return x.s.WritePacket(pkt) }

func (x *sessionSide) Close() error {
	x.once.Do(func() { close(x.done) })
	return nil
}

var errPumpStopped = errors.New("masquevpn: насос остановлен")

// readLoop переносит пакеты из сессии в очередь. Живёт, пока жива сессия:
// смена интерфейса его не касается, поэтому пакеты не теряются между
// остановкой старого насоса и запуском нового.
func readLoop(sess *session.Session, out chan<- []byte) {
	defer close(out)
	for {
		buf := make([]byte, 65535)
		n, err := sess.ReadPacket(buf)
		if err != nil {
			return
		}
		out <- buf[:n]
	}
}

// protectFunc превращает Protector приложения в зацепку клиента.
func protectFunc(p Protector) func(syscall.RawConn) error {
	return func(rc syscall.RawConn) error {
		var ok bool
		if err := rc.Control(func(fd uintptr) { ok = p.Protect(int(fd)) }); err != nil {
			return err
		}
		if !ok {
			return errors.New("masquevpn: система отказалась защитить сокет")
		}
		return nil
	}
}

// eventHandler отправляет журнал ядра в приложение.
type eventHandler struct {
	t     *Tunnel
	level slog.Level
	attrs []slog.Attr
}

func (h *eventHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level }

func (h *eventHandler) Handle(_ context.Context, r slog.Record) error {
	msg := r.Message
	for _, a := range h.attrs {
		msg += fmt.Sprintf("  %s=%v", a.Key, a.Value)
	}
	r.Attrs(func(a slog.Attr) bool {
		msg += fmt.Sprintf("  %s=%v", a.Key, a.Value)
		return true
	})
	h.t.mu.Lock()
	ev := h.t.events
	h.t.mu.Unlock()
	if ev != nil {
		ev.OnLog(levelName(r.Level), msg)
	}
	return nil
}

func (h *eventHandler) WithAttrs(as []slog.Attr) slog.Handler {
	n := *h
	n.attrs = append(append([]slog.Attr(nil), h.attrs...), as...)
	return &n
}

func (h *eventHandler) WithGroup(string) slog.Handler { return h }

func levelName(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return "error"
	case l >= slog.LevelWarn:
		return "warn"
	case l >= slog.LevelInfo:
		return "info"
	default:
		return "debug"
	}
}

func levelOf(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
