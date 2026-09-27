//go:build !utls

// Package utlsquic — заглушка для сборки без тега `utls`.
//
// Транспорт с отпечатком браузера тянет тяжёлую зависимость (uquic + uTLS),
// поэтому он опционален. Набор экспортируемых имён здесь тот же, что и в
// utls-сборке, поэтому вызывающий код компилируется в обоих вариантах:
//
//	go build ./...              — без uTLS, Dial возвращает ErrNotBuilt
//	go build -tags utls ./...   — с uTLS
package utlsquic

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/soways11/masquevpn/internal/masque"
)

// ErrNotBuilt возвращается, если бинарник собран без тега `utls`.
var ErrNotBuilt = errors.New("utlsquic: собрано без тега utls (пересоберите: go build -tags utls)")

// Профили отпечатка (значения Config.Parrot) — те же имена, что и в utls-сборке.
const (
	ParrotChrome153     = "chrome-153"
	ParrotChrome115     = "chrome-115"
	ParrotChrome115IPv6 = "chrome-115-ipv6"
	ParrotFirefox116    = "firefox-116"
)

// DefaultParrot — профиль по умолчанию.
const DefaultParrot = ParrotChrome153

// Available сообщает, собран ли бинарник с поддержкой uTLS.
func Available() bool { return false }

// Parrots возвращает список поддерживаемых профилей отпечатка.
func Parrots() []string { return nil }

// Config — те же поля, что и в utls-сборке.
type Config struct {
	Addr               string
	ServerName         string
	RootCAs            *x509.CertPool
	InsecureSkipVerify bool
	Authority          string
	Path               string
	Header             http.Header
	Shaping            *masque.Shaping
	Packing            *masque.Packing
	CoverBrowsing      *masque.CoverBrowsing
	Parrot             string
	CustomSpec         any
	Protocol           string
	KeepAlivePeriod    time.Duration
	ListenUDP          func() (*net.UDPConn, error)
}

// Dial всегда возвращает ErrNotBuilt в сборке без тега `utls`.
func Dial(ctx context.Context, cfg Config) (*masque.Conn, error) { return nil, ErrNotBuilt }

// LoadSpec в сборке без тега `utls` всегда возвращает ErrNotBuilt.
func LoadSpec(path string) (any, error) { return nil, ErrNotBuilt }
