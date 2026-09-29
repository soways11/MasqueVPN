//go:build utls

// Package utlsquic — клиентский транспорт CONNECT-IP с отпечатком настоящего
// браузера (пункт 2.7 плана). Собирается только с тегом `utls`:
//
//	go build -tags utls ./...
//
// Устройство:
//
//	uquic (форк quic-go с uTLS)         — QUIC + ClientHello как у Chrome,
//	                                      форма Initial-пакета, длина Connection ID
//	  └─ h3.go (наш минимальный HTTP/3) — SETTINGS, Extended CONNECT, DATA-фреймы,
//	                                      HTTP-датаграммы (RFC 9297)
//	       └─ masque.NewClientConn      — капсулы, политика адресов, паддинг, cover
//
// От uquic берётся только QUIC-слой: его собственный http3 написан под qpack v0.4
// (конфликтует с qpack v0.6 из quic-go v0.59) и вдобавок не умеет HTTP-датаграммы.
//
// Что это даёт против DPI сверх обычного клиента: TLS ClientHello с порядком
// расширений и cipher suites как у Chrome, форму первого пакета и GREASE —
// то, что стоковый quic-go воспроизвести не может. GREASE добавляется здесь
// же (см. withChromeGREASE): во встроенном профиле uquic его не было.
package utlsquic

import (
	"context"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	uquic "github.com/refraction-networking/uquic"
	utls "github.com/refraction-networking/utls"
	"github.com/soways11/masquevpn/internal/masque"
)

// Профили отпечатка (значения поля Config.Parrot). Профиль по умолчанию снят с
// живого Chrome утилитой fpcapture и встроен в бинарник; остальные достались от
// авторов uquic и устарели.
//
// # Почему свежий профиль пришлось снимать самим
//
// Проверено 2026-09-17. В uTLS v1.8.2 есть спеки Chrome 120/131/133, но они
// сделаны для TLS-over-TCP. Построить из них QUIC-профиль нельзя, и дело не в
// трудоёмкости: QUIC-профиль обязан нести список ТРАНСПОРТНЫХ ПАРАМЕТРОВ QUIC
// (uquic вызывает PopulateFromUQUIC над ним), а в TCP-спеке их нет и быть не
// может — у TLS поверх TCP таких параметров не существует. Это вторая, отдельная
// ось отпечатка, и вывести её из первой невозможно.
//
// Попытка довести вывод до рабочего состояния упирается в цепочку:
// версии TLS → ALPN (h2 вместо h3) → supported_versions (TLS 1.2 и GREASE) →
// отсутствующие транспортные параметры; а у Chrome 131/133 ClientHello вдобавок
// не помещается в компоновку Initial-пакета от Chrome 115 (ECH и постквантовый
// обмен ключами) — uquic отвечает «failed to reassemble CRYPTO frames».
//
// Каждая такая правка уводит дальше от настоящего браузера. Результатом был бы
// не «Chrome 133», а химера: TLS-расширения от 133, транспортные параметры от
// 115 — сочетание, которого нет ни у одного живого клиента. Отпечаток «почти
// Chrome» детекторы ловят лучше, чем точный отпечаток старой версии, поэтому
// такой профиль сознательно НЕ добавлен.
//
// Правильный путь — снять отпечаток с настоящего браузера и подставить его
// через Config.CustomSpec. См. README, раздел «Свежий отпечаток».
const (
	// ParrotChrome153 — отпечаток, снятый с живого Chrome 153 утилитой
	// fpcapture и встроенный в бинарник. В отличие от профилей ниже, он не
	// собран из кода uquic, а разобран из настоящего ClientHello, поэтому
	// несёт и то, чего в uquic нет вовсе: постквантовый key_share,
	// trust_anchors, новый номер ALPS. ECH из записи выбрасывается: его режет
	// DPI, а проекту он не нужен — SNI открыт (см. Fingerprint.Spec).
	ParrotChrome153     = "chrome-153"
	ParrotChrome115     = "chrome-115"
	ParrotChrome115IPv6 = "chrome-115-ipv6"
	ParrotFirefox116    = "firefox-116"
	// ParrotChrome115NoGREASE — профиль uquic как есть, без добавленного
	// GREASE (см. withChromeGREASE). Для сравнения в тестах.
	ParrotChrome115NoGREASE = "chrome-115-no-grease"
)

// DefaultParrot — профиль по умолчанию.
//
// Профиль Chrome 115 — это 2023 год, и трёхлетний браузер среди живых сам по
// себе примета. Умолчанием служит снятый отпечаток.
const DefaultParrot = ParrotChrome153

//go:embed profiles/chrome-153.json
var chrome153Profile []byte

// Available сообщает, собран ли бинарник с поддержкой uTLS.
func Available() bool { return true }

// Parrots возвращает список встроенных профилей отпечатка.
func Parrots() []string {
	return []string{ParrotChrome153, ParrotChrome115, ParrotChrome115IPv6, ParrotFirefox116, ParrotChrome115NoGREASE}
}

// embeddedFingerprint возвращает встроенную запись отпечатка, если профиль с
// таким именем снят с браузера, а не собран из кода uquic.
func embeddedFingerprint(name string) (*Fingerprint, bool) {
	if name != "" && name != ParrotChrome153 {
		return nil, false
	}
	var fp Fingerprint
	if err := json.Unmarshal(chrome153Profile, &fp); err != nil {
		return nil, false
	}
	return &fp, true
}

func parrotSpec(name string) (uquic.QUICSpec, error) {
	// Снятые отпечатки собираются из записи — заново на каждый дозвон.
	if fp, ok := embeddedFingerprint(name); ok {
		spec, err := fp.Spec()
		if err != nil {
			return uquic.QUICSpec{}, fmt.Errorf("utlsquic: встроенный профиль %s: %w", ParrotChrome153, err)
		}
		return *spec, nil
	}
	var id uquic.QUICID
	switch name {
	case ParrotChrome115:
		id = uquic.QUICChrome_115_IPv4
	case ParrotChrome115IPv6:
		id = uquic.QUICChrome_115_IPv6
	case ParrotFirefox116:
		id = uquic.QUICFirefox_116
	case ParrotChrome115NoGREASE:
		// Профиль ровно такой, какой отдаёт uquic, — без GREASE. Нужен
		// тестам (сравнение) и как запасной вариант, если добавленный
		// GREASE где-то помешает.
		return uquic.QUICID2Spec(uquic.QUICChrome_115_IPv4)
	default:
		return uquic.QUICSpec{}, fmt.Errorf("utlsquic: unknown parrot %q", name)
	}
	spec, err := uquic.QUICID2Spec(id)
	if err != nil {
		return spec, err
	}
	if id != uquic.QUICFirefox_116 {
		// Firefox собран не на BoringSSL, и GREASE у него другой — трогаем
		// только профили Chrome.
		spec = withChromeGREASE(spec)
	}
	return spec, nil
}

// resolveSpec выбирает профиль: снятый пользователем (CustomSpec) или встроенный.
//
// Профиль собирается на КАЖДЫЙ дозвон. Объекты расширений uTLS одноразовые:
// в них попадает состояние рукопожатия, и вторая попытка тем же объектом
// заканчивается «tls: internal error». Встроенные профили этим не страдали
// только потому, что parrotSpec каждый раз строит их заново.
func resolveSpec(cfg Config) (uquic.QUICSpec, error) {
	switch v := cfg.CustomSpec.(type) {
	case nil:
		return parrotSpec(cfg.Parrot)

	case *Fingerprint:
		// Снятая запись — источник, из которого профиль собирается заново.
		spec, err := v.Spec()
		if err != nil {
			return uquic.QUICSpec{}, err
		}
		return *spec, nil

	case *uquic.QUICSpec:
		if v.ClientHelloSpec == nil {
			return uquic.QUICSpec{}, fmt.Errorf("utlsquic: в CustomSpec не задан ClientHelloSpec")
		}
		// Готовый профиль пригоден ровно для одного подключения (см. Config).
		return *v, nil

	default:
		return uquic.QUICSpec{}, fmt.Errorf("utlsquic: CustomSpec должен быть *Fingerprint или *uquic.QUICSpec, получен %T", cfg.CustomSpec)
	}
}

// Config — параметры подключения. Набор полей одинаков в обеих сборках
// (с тегом utls и без), чтобы вызывающий код компилировался в любой.
type Config struct {
	// Addr — адрес сервера host:port (UDP).
	Addr string
	// ServerName — SNI; по умолчанию хост из Addr.
	ServerName string
	// RootCAs — доверенные корневые сертификаты (nil — системные).
	RootCAs *x509.CertPool
	// InsecureSkipVerify отключает проверку сертификата (только для тестов).
	InsecureSkipVerify bool
	// Authority — значение :authority; по умолчанию Addr.
	Authority string
	// Path — путь запроса; по умолчанию masque.DefaultPath.
	Path string
	// Header — дополнительные заголовки (например, токен аутентификации).
	Header http.Header
	// Shaping — маскировка трафика (паддинг, джиттер, cover).
	Shaping *masque.Shaping
	// Packing — упаковка датаграмм (агрегация, фрагментация, профиль потока).
	Packing *masque.Packing
	// CoverBrowsing — фоновые HTTP/3 GET к сайту-прикрытию по тому же
	// соединению. Без него сессия состоит из одного вечного потока и горы
	// датаграмм — поведение, которого у браузера не бывает.
	CoverBrowsing *masque.CoverBrowsing
	// Parrot — встроенный профиль отпечатка; по умолчанию DefaultParrot.
	Parrot string
	// CustomSpec, если задан, полностью заменяет встроенный профиль.
	// Это путь для отпечатка, снятого с настоящего браузера: встроенные
	// профили устаревают, а подставить свой можно без правки кода.
	//
	// Принимается *Fingerprint (снятая запись — LoadFingerprint/LoadSpec) или
	// готовый *uquic.QUICSpec. Поле объявлено как any, чтобы Config был
	// одинаков в обеих сборках.
	//
	// Предпочтителен *Fingerprint: профиль собирается ЗАНОВО на каждое
	// подключение. Готовый *uquic.QUICSpec переживает ровно один дозвон —
	// uTLS дописывает в объекты расширений состояние рукопожатия (ключи
	// key_share и прочее), и повторное подключение тем же объектом падает с
	// «tls: internal error». Для клиента это значило бы: первая сессия
	// поднялась, а после ротации или обрыва — уже никогда.
	CustomSpec any
	// Protocol — значение :protocol. По умолчанию masque.ProtocolConnectIP.
	// masque.ProtocolWebTransport маскирует сессию под WebTransport: вместе с
	// отпечатком Chrome это закрывает и рукопожатие, и семантику протокола.
	Protocol string
	// KeepAlivePeriod — период keep-alive QUIC; по умолчанию случайный
	// 10–20 с (постоянный период — метроном и признак сборки).
	KeepAlivePeriod time.Duration
	// ListenUDP, если задан, создаёт UDP-сокет соединения — чтобы пометить
	// его (SO_MARK на Linux, VpnService.protect на Android). Сокет закрывается
	// вместе с соединением.
	ListenUDP func() (*net.UDPConn, error)
}

// Dial устанавливает CONNECT-IP сессию через QUIC с отпечатком браузера.
// Возвращённый Conn владеет соединением: Close закрывает и его, и UDP-сокет.
func Dial(ctx context.Context, cfg Config) (*masque.Conn, error) {
	spec, err := resolveSpec(cfg)
	if err != nil {
		return nil, err
	}
	proto := cfg.Protocol
	if proto == "" {
		proto = masque.ProtocolConnectIP
	}
	if proto != masque.ProtocolConnectIP && proto != masque.ProtocolWebTransport {
		return nil, fmt.Errorf("utlsquic: unknown protocol %q", proto)
	}

	host, _, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("utlsquic: bad server address: %w", err)
	}
	serverName := cfg.ServerName
	if serverName == "" {
		serverName = host
	}
	authority := cfg.Authority
	if authority == "" {
		authority = cfg.Addr
	}
	path := cfg.Path
	if path == "" {
		path = masque.DefaultPath
	}
	keepAlive := cfg.KeepAlivePeriod
	if keepAlive == 0 {
		keepAlive = masque.RandomKeepAlive()
	}

	raddr, err := net.ResolveUDPAddr("udp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("utlsquic: resolve: %w", err)
	}
	listen := cfg.ListenUDP
	if listen == nil {
		listen = func() (*net.UDPConn, error) { return net.ListenUDP("udp", &net.UDPAddr{}) }
	}
	udpConn, err := listen()
	if err != nil {
		return nil, fmt.Errorf("utlsquic: listen udp: %w", err)
	}
	cleanup := func() { _ = udpConn.Close() }

	qconf := &uquic.Config{EnableDatagrams: true, KeepAlivePeriod: keepAlive}
	spec.UpdateConfig(qconf)
	mtu := newMTUTracker(raddr)
	mtu.configure(qconf)

	ut := &uquic.UTransport{Transport: &uquic.Transport{Conn: udpConn}, QUICSpec: &spec}
	qc, err := ut.Dial(ctx, raddr, &utls.Config{
		ServerName:         serverName,
		RootCAs:            cfg.RootCAs,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		NextProtos:         []string{"h3"},
	}, qconf)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("utlsquic: QUIC dial: %w", err)
	}
	closeAll := func() error {
		_ = qc.CloseWithError(0, "")
		cleanup()
		return nil
	}

	var extra map[uint64]uint64
	if proto == masque.ProtocolWebTransport {
		extra = masque.WebTransportSettings()
	}
	h3, err := newH3Conn(ctx, qc, extra)
	if err != nil {
		closeAll()
		return nil, err
	}
	h3.mtu = mtu
	if !h3.extendedConnect {
		closeAll()
		return nil, fmt.Errorf("utlsquic: server does not support Extended CONNECT")
	}
	if !h3.datagrams {
		closeAll()
		return nil, fmt.Errorf("utlsquic: server does not support HTTP Datagrams")
	}

	hdr := http.Header{}
	for k, v := range cfg.Header {
		hdr[k] = append([]string(nil), v...)
	}
	hdr.Set("capsule-protocol", "?1")

	str, status, date, err := h3.connectIP(ctx, proto, authority, path, hdr)
	if err != nil {
		closeAll()
		return nil, err
	}
	if status < 200 || status > 299 {
		closeAll()
		return nil, &masque.ResponseError{
			StatusCode: status,
			ClockSkew:  masque.ClockSkewFromDate(date),
		}
	}
	conn := masque.NewClientConn(str, masque.ClientConnOptions{
		Shaping: cfg.Shaping,
		Packing: cfg.Packing,
		Closer:  closeAll,
	})
	// Проверка связи — тем же GET к сайту-прикрытию, что и прикрытие
	// потоками: снаружи не отличить (см. masque.Conn.Probe).
	conn.SetProber(func(ctx context.Context) error {
		return h3.get(ctx, authority, "/", masque.ProbeBodyBytes)
	})
	if cfg.CoverBrowsing != nil {
		h3.startCoverBrowsing(conn, authority, cfg.CoverBrowsing)
	}
	return conn, nil
}

// ErrNotBuilt — для единообразия API с заглушкой; в этой сборке не возвращается.
var ErrNotBuilt = errors.New("utlsquic: собрано без тега utls (пересоберите: go build -tags utls)")

// GREASE в ClientHello (RFC 8701).
//
// Найдено аудитом 2026-09-18. Встроенный профиль Chrome 115 из uquic GREASE НЕ
// содержит: в шифронаборах, supported_groups, key_share и supported_versions
// GREASE-значений нет, отдельных GREASE-расширений тоже нет — они есть только
// в транспортных параметрах QUIC. Настоящий Chrome шлёт GREASE во всех этих
// местах, начиная с 2016 года; так работает BoringSSL у всех, кто на нём
// собран, — Chrome, Edge, Opera, Яндекс.Браузер.
//
// Почему это важно: «клиент TLS 1.3 без GREASE» — признак, который считается
// одним взглядом на ClientHello и не зависит ни от порядка расширений, ни от
// версии браузера. Профиль без GREASE не похож НИ НА ОДИН браузер, то есть
// вся работа над отпечатком до сих пор упиралась в эту одну строку.
//
// Здесь GREASE добавляется ровно так, как это делает BoringSSL: GREASE-набор
// первым в списке шифронаборов, GREASE-группа первой в supported_groups и в
// key_share (с однобайтным телом), GREASE-версия первой в supported_versions,
// и два GREASE-расширения — по краям списка расширений. Значения подставляет
// uTLS: он же следит, чтобы два расширения получили РАЗНЫЕ значения и чтобы
// второе несло нулевой байт, — как BoringSSL.
//
// Перемешивание расширений это не ломает: ShuffleChromeTLSExtensions не трогает
// GREASE и padding, они остаются на своих местах.
func withChromeGREASE(spec uquic.QUICSpec) uquic.QUICSpec {
	ch := spec.ClientHelloSpec
	if ch == nil {
		return spec
	}
	out := *ch
	out.CipherSuites = append([]uint16{utls.GREASE_PLACEHOLDER}, ch.CipherSuites...)

	exts := make([]utls.TLSExtension, 0, len(ch.Extensions)+2)
	exts = append(exts, &utls.UtlsGREASEExtension{})
	for _, e := range ch.Extensions {
		switch x := e.(type) {
		case *utls.SupportedCurvesExtension:
			x.Curves = append([]utls.CurveID{utls.CurveID(utls.GREASE_PLACEHOLDER)}, x.Curves...)
		case *utls.KeyShareExtension:
			x.KeyShares = append([]utls.KeyShare{
				{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
			}, x.KeyShares...)
		case *utls.SupportedVersionsExtension:
			x.Versions = append([]uint16{utls.GREASE_PLACEHOLDER}, x.Versions...)
		}
		exts = append(exts, e)
	}
	exts = append(exts, &utls.UtlsGREASEExtension{})
	out.Extensions = exts

	spec.ClientHelloSpec = &out
	return spec
}

// hasGREASE сообщает, есть ли в ClientHello хоть одно GREASE-значение
// (для тестов и проверки снятых профилей).
func hasGREASE(ch *utls.ClientHelloSpec) bool {
	for _, c := range ch.CipherSuites {
		if isGREASE(c) {
			return true
		}
	}
	for _, e := range ch.Extensions {
		if _, ok := e.(*utls.UtlsGREASEExtension); ok {
			return true
		}
	}
	return false
}

// isGREASE — значение из решётки GREASE (0x?a?a, обе половины равны).
func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v&0xff == v>>8
}
