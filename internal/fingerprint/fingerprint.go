// Package fingerprint приближает отпечаток нашего QUIC/HTTP-3 клиента к Chrome
// (пункт 2.7 плана) в той части, которую позволяет контролировать quic-go v0.59.
//
// # Что здесь делается
//
// Через публичный quic.Config задаются транспортные параметры, которые видны в
// расшифрованном ClientHello (Initial-пакеты QUIC шифруются выводимым из
// открытого заголовка ключом, поэтому DPI может их прочитать):
//   - только QUIC v1 (RFC 9000), без предложения v2 и без Version Negotiation;
//   - фиксированный размер Initial-пакета 1200 байт и отключённый Path MTU
//     Discovery — размер стабилен, как у типового веб-клиента;
//   - размеры окон приёма и таймауты, близкие к профилю браузера;
//   - keep-alive, чтобы соединение не простаивало «по-VPN-ному».
//
// # Граница возможного (важно)
//
// Байт-в-байт отпечаток TLS ClientHello — набор и ПОРЯДОК расширений, GREASE,
// значения cipher suites, нарезка ClientHello на несколько CRYPTO-фреймов —
// формирует crypto/tls внутри quic-go, и v0.59 не даёт это переопределить.
// Полная мимикрия требует QUIC-стека поверх uTLS (например, форк uquic) и здесь
// НЕ реализована. Поэтому Apply — это сближение по транспортным параметрам, а не
// неотличимость на уровне TLS. Оставлен шов Dialer, чтобы позже подставить
// uTLS-совместимый транспорт, не трогая ядро.
package fingerprint

import (
	"crypto/tls"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// Profile — набор значений транспортных параметров QUIC.
type Profile struct {
	Versions                       []quic.Version
	InitialPacketSize              uint16
	DisablePathMTUDiscovery        bool
	InitialStreamReceiveWindow     uint64
	MaxStreamReceiveWindow         uint64
	InitialConnectionReceiveWindow uint64
	MaxConnectionReceiveWindow     uint64
	MaxIdleTimeout                 time.Duration
	KeepAlivePeriod                time.Duration
	MaxIncomingStreams             int64
	MaxIncomingUniStreams          int64
}

// Chrome возвращает профиль, приближенный к десктопному Chrome.
// Значения окон соответствуют порядкам величин, используемым браузером
// (15 МБ на соединение, 6 МБ на поток), размер Initial-пакета — 1200 байт.
func Chrome() Profile {
	return Profile{
		Versions:                       []quic.Version{quic.Version1},
		InitialPacketSize:              1200,
		DisablePathMTUDiscovery:        true,
		InitialStreamReceiveWindow:     6 * 1024 * 1024,
		MaxStreamReceiveWindow:         6 * 1024 * 1024,
		InitialConnectionReceiveWindow: 15 * 1024 * 1024,
		MaxConnectionReceiveWindow:     15 * 1024 * 1024,
		MaxIdleTimeout:                 30 * time.Second,
		KeepAlivePeriod:                15 * time.Second,
		MaxIncomingStreams:             100,
		MaxIncomingUniStreams:          103,
	}
}

// QUICConfig собирает *quic.Config из профиля. EnableDatagrams всегда включён —
// он обязателен для CONNECT-IP.
func (p Profile) QUICConfig() *quic.Config {
	return &quic.Config{
		Versions:                       p.Versions,
		InitialPacketSize:              p.InitialPacketSize,
		DisablePathMTUDiscovery:        p.DisablePathMTUDiscovery,
		InitialStreamReceiveWindow:     p.InitialStreamReceiveWindow,
		MaxStreamReceiveWindow:         p.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: p.InitialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     p.MaxConnectionReceiveWindow,
		MaxIdleTimeout:                 p.MaxIdleTimeout,
		KeepAlivePeriod:                p.KeepAlivePeriod,
		MaxIncomingStreams:             p.MaxIncomingStreams,
		MaxIncomingUniStreams:          p.MaxIncomingUniStreams,
		EnableDatagrams:                true,
	}
}

// TLSConfig готовит tls.Config: ALPN h3 и TLS 1.3 (как у QUIC-браузера).
// base может быть nil. Возвращается копия, исходный конфиг не меняется.
func (p Profile) TLSConfig(base *tls.Config) *tls.Config {
	var c *tls.Config
	if base != nil {
		c = base.Clone()
	} else {
		c = &tls.Config{}
	}
	c.NextProtos = []string{http3.NextProtoH3}
	c.MinVersion = tls.VersionTLS13
	c.MaxVersion = tls.VersionTLS13
	return c
}
