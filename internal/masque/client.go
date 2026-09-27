package masque

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// DefaultPath — путь URI-шаблона по умолчанию
// ("/.well-known/masque/ip/{target}/{ipproto}/") для полного туннеля:
// target = "*", ipproto = "*".
const DefaultPath = "/.well-known/masque/ip/*/*/"

// DefaultInitialPacketSize — размер QUIC-пакетов с первого пакета.
//
// Почему не меньше: полезная нагрузка датаграммы = пакет минус заголовок QUIC,
// AEAD-тег и заголовки кадра — около 50 байт. При 1280 (умолчание quic-go) в
// датаграмму помещается ~1230 байт IP-пакета, а IPv6 требует от канала не
// меньше 1280 и сообщения Packet Too Big ниже этого игнорирует — IPv6 внутри
// туннеля просто не работал бы. 1350 — классический безопасный размер QUIC
// (его долго использовал Chrome), он проходит через PPPoE и большинство
// мобильных сетей.
const DefaultInitialPacketSize = 1350

// ClientConfig — параметры подключения клиента.
type ClientConfig struct {
	// Addr — адрес сервера host:port (UDP).
	Addr string
	// TLSConfig — TLS-настройки. ALPN h3 проставляется автоматически.
	TLSConfig *tls.Config
	// QUICConfig — настройки QUIC. Датаграммы включаются принудительно.
	QUICConfig *quic.Config
	// Authority — значение :authority; по умолчанию Addr.
	Authority string
	// Path — путь запроса; по умолчанию DefaultPath.
	Path string
	// Header — дополнительные заголовки запроса (например, для аутентификации).
	Header http.Header
	// Shaping — параметры маскировки исходящего трафика (паддинг, джиттер, cover).
	Shaping *Shaping
	// Packing — упаковка датаграмм (агрегация, фрагментация, профиль потока).
	// Работает только если сервер подтвердил поддержку кадров.
	Packing *Packing
	// Protocol — значение :protocol. По умолчанию ProtocolConnectIP.
	// ProtocolWebTransport маскирует сессию под WebTransport (см. disguise.go).
	Protocol string
	// CoverBrowsing, если задан, включает фоновые HTTP/3 GET-запросы к сайту-
	// прикрытию по тому же соединению: несколько потоков вместо одного.
	CoverBrowsing *CoverBrowsing
	// Dialer, если задан, используется вместо quic.DialAddr для установления
	// QUIC-соединения. Это шов для подстановки uTLS-совместимого транспорта
	// (байт-в-байт отпечаток ClientHello, пункт 2.7), не затрагивая ядро.
	// Реализация обязана согласовать датаграммы (EnableDatagrams).
	Dialer func(ctx context.Context, addr string, tlsConf *tls.Config, quicConf *quic.Config) (*quic.Conn, error)
	// ListenUDP, если задан, создаёт UDP-сокет соединения (вместо сокета
	// quic-go по умолчанию). Нужен, чтобы пометить сокет: на Linux — SO_MARK
	// (пакеты туннеля идут мимо самого туннеля), на Android — VpnService.protect.
	// Сокет принадлежит соединению и закрывается вместе с ним.
	// Игнорируется, если задан Dialer.
	ListenUDP func() (*net.UDPConn, error)
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

// ResponseError — сервер ответил не-2xx на CONNECT-IP запрос.
//
// Для постороннего это выглядит как обычный ответ веб-сервера, и это
// сознательно: сервер не выдаёт, что он VPN. Но у своего же клиента самая
// частая причина такого ответа — разъехавшиеся часы: токен привязан ко
// времени, и при расхождении больше допустимого сервер отвечает ровно так
// же, как постороннему. Поэтому сверяем свои часы с заголовком Date и
// говорим об этом прямо, иначе такую поломку ищут часами.
type ResponseError struct {
	StatusCode int
	// ClockSkew — расхождение наших часов с серверными (положительное —
	// наши впереди). 0, если измерить не удалось.
	ClockSkew time.Duration
}

// ClockSkewTolerance — расхождение, о котором уже стоит предупреждать.
const ClockSkewTolerance = 20 * time.Second

func (e *ResponseError) Error() string {
	msg := fmt.Sprintf("masque: server responded with status %d", e.StatusCode)
	if e.ClockSkew > ClockSkewTolerance || e.ClockSkew < -ClockSkewTolerance {
		msg += fmt.Sprintf(" (часы разошлись с сервером на %v — токен привязан ко времени, проверьте NTP)",
			e.ClockSkew.Round(time.Second))
	}
	return msg
}

// ClockSkewFromDate вычисляет расхождение часов по заголовку Date ответа.
// Пустой или неразобранный заголовок даёт 0.
func ClockSkewFromDate(date string) time.Duration {
	if date == "" {
		return 0
	}
	t, err := http.ParseTime(date)
	if err != nil {
		return 0
	}
	return time.Since(t)
}

// Dial устанавливает QUIC-соединение и открывает CONNECT-IP сессию.
// Возвращённый Conn владеет QUIC-соединением: Close закрывает и его.
func Dial(ctx context.Context, cfg ClientConfig) (*Conn, error) {
	var tlsConf *tls.Config
	if cfg.TLSConfig != nil {
		tlsConf = cfg.TLSConfig.Clone()
	} else {
		tlsConf = &tls.Config{}
	}
	tlsConf.NextProtos = []string{http3.NextProtoH3}
	if tlsConf.ServerName == "" {
		host, _, err := net.SplitHostPort(cfg.Addr)
		if err != nil {
			return nil, fmt.Errorf("masque: bad server address: %w", err)
		}
		tlsConf.ServerName = host
	}

	var qconf *quic.Config
	if cfg.QUICConfig != nil {
		qconf = cfg.QUICConfig.Clone()
	} else {
		qconf = &quic.Config{}
	}
	qconf.EnableDatagrams = true
	// Path MTU Discovery выключен принудительно из-за ошибки quic-go v0.59:
	// после успешной пробы оценка «сколько влезает в датаграмму» заменяется
	// СЫРЫМ размером пакета (без вычета заголовка и AEAD-тега, connection.go,
	// handleAckFrame). SendDatagram тогда принимает датаграммы, которые на
	// упаковке молча выбрасываются, — чёрная дыра в полосе ~40 байт под
	// потолком. Без PMTUD оценка честная и консервативная.
	qconf.DisablePathMTUDiscovery = true
	if qconf.InitialPacketSize == 0 {
		qconf.InitialPacketSize = DefaultInitialPacketSize
	}
	if qconf.KeepAlivePeriod == 0 {
		// Разброс, а не константа: одинаковый у всех клиентов период keep-alive
		// сам по себе метроном и признак сборки.
		qconf.KeepAlivePeriod = randomKeepAlive()
	}

	dial := cfg.Dialer
	var ownSocket io.Closer
	if dial == nil && cfg.ListenUDP != nil {
		dial = func(ctx context.Context, addr string, tlsConf *tls.Config, quicConf *quic.Config) (*quic.Conn, error) {
			raddr, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				return nil, err
			}
			udp, err := cfg.ListenUDP()
			if err != nil {
				return nil, fmt.Errorf("listen udp: %w", err)
			}
			tr := &quic.Transport{Conn: udp}
			qc, err := tr.Dial(ctx, raddr, tlsConf, quicConf)
			if err != nil {
				_ = tr.Close()
				_ = udp.Close()
				return nil, err
			}
			ownSocket = closerFunc(func() error { _ = tr.Close(); return udp.Close() })
			return qc, nil
		}
	}
	if dial == nil {
		dial = quic.DialAddr
	}
	qc, err := dial(ctx, cfg.Addr, tlsConf, qconf)
	if err != nil {
		return nil, fmt.Errorf("masque: QUIC dial: %w", err)
	}
	closeQUIC := func(msg string) {
		_ = qc.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), msg)
		if ownSocket != nil {
			_ = ownSocket.Close()
		}
	}

	// closer передаём внутрь: он должен быть установлен ДО запуска фоновых
	// горутин сессии, иначе они прочитают его наперегонки с записью здесь.
	conn, err := openSession(ctx, qc, cfg, func() error { closeQUIC(""); return nil })
	if err != nil {
		closeQUIC("")
		return nil, err
	}
	return conn, nil
}

func openSession(ctx context.Context, qc *quic.Conn, cfg ClientConfig, closer func() error) (*Conn, error) {
	proto, ok := normalizeProtocol(cfg.Protocol)
	if !ok {
		return nil, fmt.Errorf("masque: unknown protocol %q", cfg.Protocol)
	}
	tr := &http3.Transport{EnableDatagrams: true}
	if proto == ProtocolWebTransport {
		// Объявляем себя WebTransport-клиентом: иначе метка :protocol
		// не согласуется с нашими же SETTINGS.
		tr.AdditionalSettings = WebTransportSettings()
	}
	cc := tr.NewClientConn(qc)

	select {
	case <-cc.ReceivedSettings():
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-qc.Context().Done():
		return nil, fmt.Errorf("masque: connection closed before SETTINGS: %w", context.Cause(qc.Context()))
	}
	s := cc.Settings()
	if !s.EnableExtendedConnect {
		return nil, errors.New("masque: server does not support Extended CONNECT")
	}
	if !s.EnableDatagrams {
		return nil, errors.New("masque: server does not support HTTP Datagrams")
	}

	rstr, err := cc.OpenRequestStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("masque: open request stream: %w", err)
	}

	authority := cfg.Authority
	if authority == "" {
		authority = cfg.Addr
	}
	path := cfg.Path
	if path == "" {
		path = DefaultPath
	}
	u, err := url.Parse("https://" + authority + path)
	if err != nil {
		return nil, fmt.Errorf("masque: bad request URI: %w", err)
	}
	hdr := http.Header{}
	for k, v := range cfg.Header {
		hdr[k] = append([]string(nil), v...)
	}
	hdr.Set(http3.CapsuleProtocolHeader, "?1")

	req := (&http.Request{
		Method: http.MethodConnect,
		Proto:  proto,
		Host:   authority,
		URL:    u,
		Header: hdr,
	}).WithContext(ctx)

	if err := rstr.SendRequestHeader(req); err != nil {
		return nil, fmt.Errorf("masque: send request: %w", err)
	}
	rsp, err := rstr.ReadResponse()
	if err != nil {
		return nil, fmt.Errorf("masque: read response: %w", err)
	}
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		rstr.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		rstr.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		return nil, &ResponseError{
			StatusCode: rsp.StatusCode,
			ClockSkew:  ClockSkewFromDate(rsp.Header.Get("Date")),
		}
	}

	c := newConn(requestStream{rstr}, roleClient, closer)
	c.shaping = cfg.Shaping
	c.packing = cfg.Packing
	st := qc.ConnectionState()
	c.resumed = st.TLS.DidResume
	c.used0RTT = st.Used0RTT
	c.start()
	if cfg.CoverBrowsing != nil {
		startCoverBrowsing(c, cc, authority, cfg.CoverBrowsing)
	}
	return c, nil
}
