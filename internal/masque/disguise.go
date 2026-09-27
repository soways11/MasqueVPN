package masque

import (
	"math/rand/v2"
	"time"
)

const (
	defaultKeepAliveBase   = 15 * time.Second
	defaultKeepAliveSpread = 5 * time.Second
)

// RandomKeepAlive — период keep-alive со случайным разбросом, для транспортов
// вне этого пакета (uTLS).
func RandomKeepAlive() time.Duration { return randomKeepAlive() }

// randomKeepAlive — период keep-alive со случайным разбросом ±spread.
func randomKeepAlive() time.Duration {
	delta := time.Duration(rand.Int64N(int64(2*defaultKeepAliveSpread))) - defaultKeepAliveSpread
	return defaultKeepAliveBase + delta
}

// Маскировка сессии под WebTransport (пункт 5 плана обхода DPI).
//
// Проблема, которую это решает: рукопожатие можно сделать неотличимым от Chrome
// (см. internal/utlsquic), но дальше поведение выдаёт нас с головой. Обычный сайт
// по HTTP/3 не гоняет QUIC-датаграммы вообще, а у нас ими идёт весь объём.
// Для классификатора, который смотрит не только на первый пакет, этого достаточно.
//
// WebTransport (draft-ietf-webtrans-http3) — настоящий, поддержанный браузерами
// протокол поверх ровно того же механизма: Extended CONNECT по HTTP/3 плюс
// HTTP-датаграммы (RFC 9297). Им пользуются низколатентные приложения — облачный
// гейминг, live-видео, игры. Если предъявить сессию как WebTransport, то
// датаграммный трафик перестаёт быть аномалией и становится ожидаемым.
//
// Внутри при этом остаётся тот же CONNECT-IP: те же капсулы ADDRESS_ASSIGN /
// ROUTE_ADVERTISEMENT и те же IP-пакеты в датаграммах. Меняется только внешняя
// метка и объявляемые SETTINGS.
//
// Цена: с меткой webtransport мы перестаём быть совместимы со сторонним
// CONNECT-IP прокси по RFC 9484 — но оба конца туннеля наши, так что это не
// ограничение на практике.

// Значения псевдозаголовка :protocol.
const (
	// ProtocolConnectIP — штатный режим RFC 9484.
	ProtocolConnectIP = "connect-ip"
	// ProtocolWebTransport — маскировочный режим: сессия выглядит как WebTransport.
	ProtocolWebTransport = "webtransport"
)

// Идентификаторы SETTINGS WebTransport. Значения сверены с эталонной
// реализацией quic-go/webtransport-go и черновиком draft-ietf-webtrans-http3.
const (
	// settingEnableWebTransport — ранний вариант, его же шлёт webtransport-go.
	settingEnableWebTransport = 0x2b603742
	// settingWebTransportMaxSessions — актуальный вариант черновика.
	settingWebTransportMaxSessions = 0xc671706a
)

// WebTransportSettings возвращает SETTINGS, которые объявляет настоящий
// WebTransport-сервер. Реальные развёртывания в период перехода объявляют оба
// идентификатора, поэтому объявляем оба и мы.
func WebTransportSettings() map[uint64]uint64 {
	return map[uint64]uint64{
		settingEnableWebTransport:      1,
		settingWebTransportMaxSessions: 1,
	}
}

// IsWebTransportCapable сообщает, объявил ли пир поддержку WebTransport.
func IsWebTransportCapable(other map[uint64]uint64) bool {
	if other == nil {
		return false
	}
	if v, ok := other[settingEnableWebTransport]; ok && v > 0 {
		return true
	}
	v, ok := other[settingWebTransportMaxSessions]
	return ok && v > 0
}

// normalizeProtocol подставляет значение по умолчанию и проверяет допустимость.
func normalizeProtocol(p string) (string, bool) {
	switch p {
	case "":
		return ProtocolConnectIP, true
	case ProtocolConnectIP, ProtocolWebTransport:
		return p, true
	default:
		return "", false
	}
}
