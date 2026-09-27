// Package dnscover устраняет признак «хост не делает DNS-запросов».
//
// # Признак, который это закрывает
//
// Когда весь трафик уходит в туннель, вместе с ним уезжает и DNS. Снаружи
// получается машина, которая часами льёт объём на один IP-адрес и при этом
// почти не спрашивает имён. У обычного хоста наоборот: перед каждым новым
// соединением — запрос к резолверу провайдера, и таких запросов десятки в
// час. Отсутствие DNS — дешёвый и устойчивый признак: он виден на потоках
// даже там, где содержимое не разбирают, и не зависит от того, насколько
// хорош отпечаток рукопожатия.
//
// # Что делает пакет
//
// Периодически отправляет настоящие DNS-запросы МИМО туннеля — тем же
// способом, которым защищён сокет QUIC (SO_MARK на Linux,
// VpnService.protect на Android), — к тому резолверу, которым система
// пользовалась до подключения. Снаружи это выглядит как обычная работа
// стаб-резолвера: A и AAAA одной группой из одного сокета, иногда HTTPS RR,
// как у современных браузеров.
//
// # Чего он НЕ делает
//
//   - Не выносит наружу ничего из настоящего трафика: имена берутся только
//     из заданного списка, реальные обращения пользователя по-прежнему
//     резолвятся внутри туннеля.
//   - Не генерирует случайные поддомены. Случайная метка слева — это
//     признак DNS-туннеля, то есть мы бы заменили одну аномалию другой,
//     заметной ещё лучше. Запрашиваются только имена целиком из списка.
//   - Не использует ответы. Это прикрытие, а не резолвинг.
package dnscover

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// Типы записей DNS.
const (
	typeA     = 1
	typeAAAA  = 28
	typeHTTPS = 65 // современные браузеры спрашивают его вместе с адресами
	classIN   = 1

	// ednsUDPSize — размер буфера в OPT-записи. 1232 — общепринятое значение
	// (DNS Flag Day 2020), его ставят и systemd-resolved, и браузеры.
	ednsUDPSize = 1232
)

// DefaultDomains — список имён по умолчанию: ничем не примечательные адреса,
// которые и так спрашивает любая машина с браузером и обновлениями ОС.
var DefaultDomains = []string{
	"www.google.com",
	"www.gstatic.com",
	"fonts.googleapis.com",
	"www.youtube.com",
	"i.ytimg.com",
	"www.cloudflare.com",
	"cdn.jsdelivr.net",
	"github.com",
	"api.github.com",
	"www.microsoft.com",
	"login.live.com",
	"www.apple.com",
	"init.itunes.apple.com",
	"firefox.settings.services.mozilla.com",
	"detectportal.firefox.com",
	"www.wikipedia.org",
	"upload.wikimedia.org",
	"yandex.ru",
	"mc.yandex.ru",
	"vk.com",
}

// DefaultMeanInterval — средний интервал между группами запросов.
const DefaultMeanInterval = 45 * time.Second

// Config — параметры прикрытия.
type Config struct {
	// Servers — резолверы, которыми система пользовалась до туннеля.
	// Порт можно не указывать, по умолчанию 53. Пустой список — ошибка:
	// слать запросы некуда.
	Servers []netip.AddrPort
	// Domains — имена для запросов; пусто — DefaultDomains.
	Domains []string
	// Next возвращает паузу до следующей группы запросов; nil —
	// пуассоновские интервалы со средним DefaultMeanInterval.
	Next func() time.Duration
	// Protect помечает сокет, чтобы запрос ушёл мимо туннеля. nil — не
	// помечать (годится, когда туннель не полный).
	Protect func(syscall.RawConn) error
	// Timeout — сколько ждать ответы одной группы; 0 — 2 с.
	Timeout time.Duration
	Logger  *slog.Logger

	// allowLoopback снимает запрет на резолвер в loopback. Поле
	// неэкспортируемое: снаружи пакета его не выставить, оно нужно тестам,
	// где поддельный резолвер живёт на 127.0.0.1.
	allowLoopback bool
}

// Cover — фоновая отправка DNS-запросов.
type Cover struct {
	cfg     Config
	domains []string

	groups  atomic.Uint64
	queries atomic.Uint64
	answers atomic.Uint64
	errs    atomic.Uint64
}

// New проверяет конфигурацию и создаёт прикрытие.
func New(cfg Config) (*Cover, error) {
	if len(cfg.Servers) == 0 {
		return nil, errors.New("dnscover: не задан ни один резолвер")
	}
	for i, s := range cfg.Servers {
		if !s.Addr().IsValid() {
			return nil, fmt.Errorf("dnscover: некорректный резолвер %v", s)
		}
		if s.Port() == 0 {
			cfg.Servers[i] = netip.AddrPortFrom(s.Addr(), 53)
		}
		if cfg.Servers[i].Addr().IsLoopback() && !cfg.allowLoopback {
			// Заглушка вроде 127.0.0.53 пересылает запрос дальше по обычной
			// маршрутизации, то есть внутрь туннеля: снаружи не появится
			// ничего, и прикрытие окажется пустышкой.
			return nil, fmt.Errorf("dnscover: %v — локальная заглушка, снаружи запросов не будет", s)
		}
	}
	domains := cfg.Domains
	if len(domains) == 0 {
		domains = DefaultDomains
	}
	for _, d := range domains {
		if _, err := appendName(nil, d); err != nil {
			return nil, fmt.Errorf("dnscover: имя %q: %w", d, err)
		}
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}
	if cfg.Next == nil {
		cfg.Next = func() time.Duration { return expInterval(DefaultMeanInterval) }
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	c := &Cover{cfg: cfg, domains: append([]string(nil), domains...)}
	return c, nil
}

// expInterval — пауза из экспоненциального распределения (пуассоновский
// поток) с потолком 5·mean. Постоянный период сам был бы признаком.
func expInterval(mean time.Duration) time.Duration {
	d := time.Duration(rand.ExpFloat64() * float64(mean))
	if d > 5*mean {
		d = 5 * mean
	}
	if d <= 0 {
		d = time.Millisecond
	}
	return d
}

// Stats — счётчики прикрытия.
type Stats struct {
	Groups  uint64 // групп запросов отправлено
	Queries uint64 // отдельных запросов (A, AAAA, HTTPS)
	Answers uint64 // получено ответов
	Errors  uint64
}

// Stats возвращает счётчики.
func (c *Cover) Stats() Stats {
	return Stats{
		Groups: c.groups.Load(), Queries: c.queries.Load(),
		Answers: c.answers.Load(), Errors: c.errs.Load(),
	}
}

// Run шлёт группы запросов, пока не отменён ctx.
//
// Порядок имён — случайная перестановка списка, которая целиком
// проходится до повторов: так одно и то же имя не спрашивается дважды
// подряд (у резолверов есть кэш, и повтор через полминуты выглядел бы
// странно), но и редкие имена не простаивают.
func (c *Cover) Run(ctx context.Context) {
	order := rand.Perm(len(c.domains))
	i := 0
	last := -1
	t := time.NewTimer(c.cfg.Next())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if i >= len(order) {
			order = rand.Perm(len(c.domains))
			i = 0
			// На стыке перестановок имя могло бы повториться подряд —
			// единственное место, где кэш резолвера выдал бы неправдоподобный
			// повтор. Меняем первое имя местами с соседним.
			if len(order) > 1 && order[0] == last {
				order[0], order[1] = order[1], order[0]
			}
		}
		last = order[i]
		name := c.domains[order[i]]
		i++
		if err := c.query(ctx, name); err != nil {
			c.errs.Add(1)
			c.cfg.Logger.Debug("фоновый DNS-запрос не удался", "name", name, "err", err)
		}
		t.Reset(c.cfg.Next())
	}
}

// QueryOnce отправляет одну группу запросов немедленно — для тестов и для
// первого запроса сразу после подключения.
func (c *Cover) QueryOnce(ctx context.Context, name string) error { return c.query(ctx, name) }

// query отправляет группу запросов об одном имени из одного сокета — так же,
// как это делает стаб-резолвер системы или браузер: A и AAAA параллельно,
// иногда HTTPS RR.
func (c *Cover) query(ctx context.Context, name string) error {
	server := c.cfg.Servers[rand.IntN(len(c.cfg.Servers))]

	lc := net.ListenConfig{}
	if c.cfg.Protect != nil {
		lc.Control = func(_, _ string, rc syscall.RawConn) error { return c.cfg.Protect(rc) }
	}
	network := "udp4"
	if server.Addr().Is6() {
		network = "udp6"
	}
	pc, err := lc.ListenPacket(ctx, network, "")
	if err != nil {
		return err
	}
	defer pc.Close()

	types := []uint16{typeA, typeAAAA}
	if rand.IntN(2) == 0 {
		types = append(types, typeHTTPS)
	}
	dst := net.UDPAddrFromAddrPort(server)
	ids := make([]uint16, 0, len(types))
	for _, qt := range types {
		id := uint16(rand.IntN(1 << 16))
		msg, err := buildQuery(id, name, qt)
		if err != nil {
			return err
		}
		if _, err := pc.WriteTo(msg, dst); err != nil {
			return err
		}
		ids = append(ids, id)
		c.queries.Add(1)
	}
	c.groups.Add(1)

	// Ответы вычитываем: их всё равно пришлют, а прочитанный сокет ведёт
	// себя как настоящий резолвер (иначе в ответ полетит ICMP «порт
	// недоступен», чего у обычного хоста не бывает).
	_ = pc.SetReadDeadline(time.Now().Add(c.cfg.Timeout))
	buf := make([]byte, 1500)
	for range ids {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			break
		}
		if n >= 12 && buf[2]&0x80 != 0 {
			c.answers.Add(1)
		}
	}
	return nil
}

// buildQuery собирает DNS-запрос: заголовок, один вопрос и OPT-запись EDNS0
// (её шлёт любой современный резолвер, без неё запрос выглядел бы старым).
func buildQuery(id uint16, name string, qtype uint16) ([]byte, error) {
	b := make([]byte, 0, 64)
	b = binary.BigEndian.AppendUint16(b, id)
	b = binary.BigEndian.AppendUint16(b, 0x0100) // RD — рекурсия, как у стаба
	b = binary.BigEndian.AppendUint16(b, 1)      // QDCOUNT
	b = binary.BigEndian.AppendUint16(b, 0)      // ANCOUNT
	b = binary.BigEndian.AppendUint16(b, 0)      // NSCOUNT
	b = binary.BigEndian.AppendUint16(b, 1)      // ARCOUNT — OPT

	b, err := appendName(b, name)
	if err != nil {
		return nil, err
	}
	b = binary.BigEndian.AppendUint16(b, qtype)
	b = binary.BigEndian.AppendUint16(b, classIN)

	// OPT: имя — корень, тип 41, «класс» — размер буфера UDP.
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, 41)
	b = binary.BigEndian.AppendUint16(b, ednsUDPSize)
	b = binary.BigEndian.AppendUint32(b, 0) // расширенный код ответа и флаги
	b = binary.BigEndian.AppendUint16(b, 0) // RDLENGTH
	return b, nil
}

// appendName кодирует имя метками. Заодно это проверка списка доменов.
func appendName(b []byte, name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return nil, errors.New("пустое имя")
	}
	if len(name) > 253 {
		return nil, errors.New("имя длиннее 253 байт")
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return nil, fmt.Errorf("некорректная метка %q", label)
		}
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	return append(b, 0), nil
}
