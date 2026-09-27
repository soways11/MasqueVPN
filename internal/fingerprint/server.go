package fingerprint

import (
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

// Отпечаток серверной стороны (пункт C1 плана).
//
// # Признак, который это закрывает
//
// Клиент у нас выглядит как Chrome — с точностью до байта в ClientHello.
// А сервер до сих пор отвечал как стоковый quic-go: свои значения окон,
// своё время простоя, свои лимиты потоков. Рукопожатие состоит из двух
// половин, и вторая половина сводила на нет работу над первой: достаточно
// посмотреть, ЧТО отвечает сервер, чтобы отличить его от обычного
// веб-сервера, к которому мы прикидываемся.
//
// # Что здесь можно сделать, а что нельзя
//
// Через публичный API quic-go настраиваются: время простоя, окна приёма
// (из них выводятся initial_max_data и initial_max_stream_data_*), лимиты
// числа потоков, размер пакета, наличие ключа stateless reset и поддержка
// датаграмм. Этого хватает, чтобы набор транспортных параметров перестал
// быть узнаваемо-quic-go'шным.
//
// Не настраивается (и это честно записано как остаток C1): порядок и
// состав расширений ServerHello, выбор шифронабора TLS 1.3 (Go выбирает
// его сам по наличию AES-NI), ack_delay_exponent, max_ack_delay,
// active_connection_id_limit, disable_active_migration и
// max_udp_payload_size — их quic-go и crypto/tls наружу не отдают.
// Довести до конца можно либо патчем quic-go, либо форком.
//
// # Откуда брать значения
//
// Придумывать «как у Google» нельзя: получится химера, как и с клиентским
// отпечатком. Поэтому здесь два пути:
//
//   - CDNLike() — эвристический профиль: значения порядков величин, типичных
//     для крупных HTTP/3-развёртываний, но НЕ снятые с конкретного сервера;
//   - CaptureServer() — снятие параметров с живого сервера (`fpcapture
//     -probe cloudflare-quic.com:443`) и подстановка их файлом, без
//     перекомпиляции. Это то же, что мы делаем с браузером для клиента.

// ServerProfile — транспортные параметры, которые сервер объявляет клиенту.
// Значения длительностей — в миллисекундах, размеры — в байтах.
type ServerProfile struct {
	// Source — откуда снят профиль (для человека).
	Source string `json:"source,omitempty"`
	// CapturedAt — когда снят.
	CapturedAt string `json:"captured_at,omitempty"`

	MaxIdleTimeoutMS     int64  `json:"max_idle_timeout_ms"`
	InitialMaxData       uint64 `json:"initial_max_data"`
	InitialMaxStreamData uint64 `json:"initial_max_stream_data"`
	MaxBidiStreams       int64  `json:"initial_max_streams_bidi"`
	MaxUniStreams        int64  `json:"initial_max_streams_uni"`
	// InitialPacketSize — размер отправляемых пакетов (не транспортный
	// параметр, но виден на проводе сразу).
	InitialPacketSize uint16 `json:"initial_packet_size,omitempty"`
	// StatelessReset — был ли stateless_reset_token у сервера, с которого
	// снимали. Это НАБЛЮДЕНИЕ, а не настройка: свой токен мы отправляем
	// всегда (masque.ServeUDP), потому что молчание на пакет с незнакомым
	// Connection ID само по себе признак — пробер отличает нас одним
	// пакетом. Поле оставлено, чтобы снятые профили можно было сравнивать
	// между собой.
	StatelessReset bool `json:"stateless_reset,omitempty"`
	// ConnectionIDLength — длина Connection ID, которые выдаёт сервер.
	// Это не транспортный параметр, а то, что наблюдатель читает прямо из
	// заголовка: SCID в Initial-пакете сервера и дальше DCID в каждом пакете
	// клиента. У quic-go по умолчанию 4 байта, у живых HTTP/3-серверов 8 и
	// больше. 0 — masque.DefaultConnectionIDLength.
	ConnectionIDLength int `json:"connection_id_length,omitempty"`
}

// CIDLength — длина Connection ID профиля (0 — решает вызывающий).
func (p ServerProfile) CIDLength() int { return p.ConnectionIDLength }

//go:embed profiles/cloudflare.json
var cloudflareProfile []byte

// Captured — профиль, СНЯТЫЙ с живого сервера и встроенный в бинарник
// (www.cloudflare.com, 24.09.2026). Это умолчание: эвристика ниже оставлена
// только для сравнения.
//
// Почему обычный сайт, а не демо-стенд QUIC: его параметры видят миллионы
// клиентов Cloudflare по всему миру, и на их фоне мы растворяемся лучше.
// Почему не Google: у него начальное окно соединения 192 КиБ — объявлять
// такое можно, но раньше оно становилось ещё и потолком роста (см.
// QUICConfig), и туннель упирался бы в flow control.
func Captured() ServerProfile {
	var p ServerProfile
	if err := json.Unmarshal(cloudflareProfile, &p); err != nil {
		// Файл лежит рядом и проверяется тестом; сюда попасть можно только
		// сломав сборку.
		return CDNLike()
	}
	p.fillUncapturable()
	return p
}

// CDNLike — эвристический профиль сервера: окна и лимиты порядков величин,
// типичных для крупных HTTP/3-развёртываний, время простоя 30 с.
//
// Это НЕ снятый отпечаток конкретного сервера: точные значения берутся
// через CaptureServer. Но и такой профиль уже уводит параметры от
// умолчаний quic-go, по которым сервер узнаётся сразу.
func CDNLike() ServerProfile {
	return ServerProfile{
		Source:               "эвристика masquevpn (не снято с живого сервера; см. Captured)",
		MaxIdleTimeoutMS:     30_000,
		InitialMaxData:       15 * 1024 * 1024,
		InitialMaxStreamData: 6 * 1024 * 1024,
		MaxBidiStreams:       100,
		MaxUniStreams:        103,
		InitialPacketSize:    1350,
		StatelessReset:       true,
		ConnectionIDLength:   8,
	}
}

// Valid проверяет, что профиль заполнен.
func (p ServerProfile) Valid() error {
	switch {
	case p.MaxIdleTimeoutMS <= 0:
		return errors.New("fingerprint: не задан max_idle_timeout_ms")
	case p.InitialMaxData == 0 || p.InitialMaxStreamData == 0:
		return errors.New("fingerprint: не заданы окна приёма")
	case p.MaxBidiStreams < 0 || p.MaxUniStreams < 0:
		return errors.New("fingerprint: отрицательные лимиты потоков")
	}
	return nil
}

// QUICConfig собирает *quic.Config сервера по профилю. Датаграммы включены
// всегда — без них CONNECT-IP невозможен.
func (p ServerProfile) QUICConfig() *quic.Config {
	return &quic.Config{
		MaxIdleTimeout: time.Duration(p.MaxIdleTimeoutMS) * time.Millisecond,

		// НАЧАЛЬНЫЕ окна — из профиля: именно они едут в транспортных
		// параметрах и видны наблюдателю.
		InitialConnectionReceiveWindow: p.InitialMaxData,
		InitialStreamReceiveWindow:     p.InitialMaxStreamData,

		// ПОТОЛОК роста окна наружу не виден: он не объявляется, а
		// проявляется только в зашифрованных MAX_DATA. Занижать его по
		// профилю незачем, а вред прямой: у настоящих серверов начальные
		// окна бывают крошечными (у www.google.com — 192 КиБ на соединение),
		// и туннель, упёршись в такой потолок, отдавал бы десятки мегабит
		// вместо сотен. Берём максимум из профиля и своего минимума.
		MaxConnectionReceiveWindow: maxU64(p.InitialMaxData, defaultMaxConnWindow),
		MaxStreamReceiveWindow:     maxU64(p.InitialMaxStreamData, defaultMaxStreamWindow),

		MaxIncomingStreams:    p.MaxBidiStreams,
		MaxIncomingUniStreams: p.MaxUniStreams,
		InitialPacketSize:     p.InitialPacketSize,

		// Без датаграмм нет CONNECT-IP. Настоящие серверы их не объявляют
		// (ни Cloudflare, ни Google), поэтому из снятого профиля этот
		// параметр прийти не может — и включается он здесь, всегда.
		EnableDatagrams: true,
	}
}

// Потолки роста окна приёма. Наружу не видны (см. QUICConfig), поэтому
// выбраны по пропускной способности, а не по правдоподобию.
const (
	defaultMaxConnWindow   = 15 * 1024 * 1024
	defaultMaxStreamWindow = 6 * 1024 * 1024
)

func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

// SaveServerProfile сохраняет профиль в JSON.
func SaveServerProfile(path string, p ServerProfile) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// LoadServerProfile читает профиль из JSON (снятый с живого сервера).
func LoadServerProfile(path string) (ServerProfile, error) {
	var p ServerProfile
	b, err := os.ReadFile(path)
	if err != nil {
		return p, err
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return p, fmt.Errorf("%s: %w", path, err)
	}
	if err := p.Valid(); err != nil {
		return p, fmt.Errorf("%s: %w", path, err)
	}
	p.fillUncapturable()
	return p, nil
}

// fillUncapturable дозаполняет поля, которых в снятом профиле быть не может.
//
// Размер пакета и длина Connection ID — НЕ транспортные параметры: они не
// объявляются, а видны прямо на проводе, и снятию через qlog не поддаются.
// В файле от fpserver они поэтому нулевые, и без этой дозаправки подстановка
// профиля молча меняла бы поведение:
//
//   - размер пакета 0 означает умолчание quic-go — 1280 вместо наших 1350,
//     то есть потолок датаграммы падает примерно на 70 байт. Место тонкое:
//     на нём проект уже ловил чёрную дыру MTU;
//   - длина Connection ID 0 вернула бы 4 байта quic-go — ровно тот признак,
//     по которому сервер на quic-go отличается от живого CDN одним пакетом.
func (p *ServerProfile) fillUncapturable() {
	if p.InitialPacketSize == 0 {
		p.InitialPacketSize = DefaultInitialPacketSize
	}
	if p.ConnectionIDLength == 0 {
		p.ConnectionIDLength = DefaultConnectionIDLength
	}
}

// Значения для полей, которые со стороны клиента не снимаются.
const (
	DefaultInitialPacketSize  = 1350
	DefaultConnectionIDLength = 8
)

// ---------- снятие профиля с живого сервера ----------

// paramTrace — приёмник событий qlog, который ловит транспортные параметры,
// присланные ДРУГОЙ стороной. Это ровно то, что видит любой клиент.
type paramTrace struct{ ch chan qlog.ParametersSet }

func (t *paramTrace) AddProducer() qlogwriter.Recorder { return paramRecorder{t} }
func (t *paramTrace) SupportsSchemas(string) bool      { return true }

type paramRecorder struct{ t *paramTrace }

func (r paramRecorder) RecordEvent(e qlogwriter.Event) {
	p, ok := e.(qlog.ParametersSet)
	if !ok || p.Restore || p.Initiator != qlog.InitiatorRemote {
		return
	}
	select {
	case r.t.ch <- p:
	default:
	}
}

func (r paramRecorder) Close() error { return nil }

// CaptureServer подключается к серверу addr (host:port) и возвращает
// профиль его транспортных параметров — так же, как их видит обычный
// QUIC-клиент.
//
// serverName — SNI (пусто: host из addr). insecure отключает проверку
// сертификата: профиль снимается и с сервера, которому мы не доверяем.
func CaptureServer(ctx context.Context, addr, serverName string, insecure bool) (ServerProfile, error) {
	var out ServerProfile
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return out, fmt.Errorf("fingerprint: адрес %q: %w", addr, err)
	}
	if serverName == "" {
		serverName = host
	}
	tr := &paramTrace{ch: make(chan qlog.ParametersSet, 4)}
	conf := Chrome().QUICConfig()
	conf.Tracer = func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return tr }

	conn, err := quic.DialAddr(ctx, addr, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: insecure,
		NextProtos:         []string{"h3"},
	}, conf)
	if err != nil {
		return out, fmt.Errorf("fingerprint: подключение к %s: %w", addr, err)
	}
	defer conn.CloseWithError(0, "")

	select {
	case p := <-tr.ch:
		return profileFromParams(p, addr), nil
	case <-ctx.Done():
		return out, ctx.Err()
	case <-time.After(5 * time.Second):
		return out, errors.New("fingerprint: транспортные параметры не пришли")
	}
}

func profileFromParams(p qlog.ParametersSet, source string) ServerProfile {
	return ServerProfile{
		Source:               source,
		CapturedAt:           time.Now().UTC().Format(time.RFC3339),
		MaxIdleTimeoutMS:     p.MaxIdleTimeout.Milliseconds(),
		InitialMaxData:       uint64(p.InitialMaxData),
		InitialMaxStreamData: uint64(p.InitialMaxStreamDataBidiRemote),
		MaxBidiStreams:       p.InitialMaxStreamsBidi,
		MaxUniStreams:        p.InitialMaxStreamsUni,
		StatelessReset:       p.StatelessResetToken != nil,
	}
}

// CapturedParams — то, что реально пришло от другой стороны. Возвращается
// тестам и утилите снятия, чтобы можно было сравнить два сервера целиком,
// включая поля, которые мы настроить не можем.
type CapturedParams struct {
	MaxIdleTimeout                 time.Duration
	InitialMaxData                 uint64
	InitialMaxStreamDataBidiLocal  uint64
	InitialMaxStreamDataBidiRemote uint64
	InitialMaxStreamDataUni        uint64
	MaxBidiStreams                 int64
	MaxUniStreams                  int64
	MaxDatagramFrameSize           uint64
	ActiveConnectionIDLimit        uint64
	MaxAckDelay                    time.Duration
	AckDelayExponent               uint8
	MaxUDPPayloadSize              uint64
	DisableActiveMigration         bool
	HasStatelessResetToken         bool
}

// CaptureParams снимает полный набор параметров сервера.
func CaptureParams(ctx context.Context, addr, serverName string, insecure bool) (CapturedParams, error) {
	var out CapturedParams
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return out, fmt.Errorf("fingerprint: адрес %q: %w", addr, err)
	}
	if serverName == "" {
		serverName = host
	}
	tr := &paramTrace{ch: make(chan qlog.ParametersSet, 4)}
	conf := Chrome().QUICConfig()
	conf.Tracer = func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return tr }
	conn, err := quic.DialAddr(ctx, addr, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: insecure,
		NextProtos:         []string{"h3"},
	}, conf)
	if err != nil {
		return out, fmt.Errorf("fingerprint: подключение к %s: %w", addr, err)
	}
	defer conn.CloseWithError(0, "")

	select {
	case p := <-tr.ch:
		return CapturedParams{
			MaxIdleTimeout:                 p.MaxIdleTimeout,
			InitialMaxData:                 uint64(p.InitialMaxData),
			InitialMaxStreamDataBidiLocal:  uint64(p.InitialMaxStreamDataBidiLocal),
			InitialMaxStreamDataBidiRemote: uint64(p.InitialMaxStreamDataBidiRemote),
			InitialMaxStreamDataUni:        uint64(p.InitialMaxStreamDataUni),
			MaxBidiStreams:                 p.InitialMaxStreamsBidi,
			MaxUniStreams:                  p.InitialMaxStreamsUni,
			MaxDatagramFrameSize:           uint64(p.MaxDatagramFrameSize),
			ActiveConnectionIDLimit:        p.ActiveConnectionIDLimit,
			MaxAckDelay:                    p.MaxAckDelay,
			AckDelayExponent:               p.AckDelayExponent,
			MaxUDPPayloadSize:              uint64(p.MaxUDPPayloadSize),
			DisableActiveMigration:         p.DisableActiveMigration,
			HasStatelessResetToken:         p.StatelessResetToken != nil,
		}, nil
	case <-ctx.Done():
		return out, ctx.Err()
	case <-time.After(5 * time.Second):
		return out, errors.New("fingerprint: транспортные параметры не пришли")
	}
}
