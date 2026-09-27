// Package acme — автоматический сертификат (пункт 2.6 плана).
//
// Зачем он в проекте про обход DPI. Сертификат из файла означает ручное
// продление раз в три месяца, а забытое продление — это домен с просроченным
// сертификатом, то есть ровно та аномалия, которой у живого сайта не бывает.
// Плюс на чистой машине сервер должен подниматься сам, без предварительного
// хождения за certbot.
//
// # Почему tls-alpn-01, а не http-01
//
// У нас UDP/443 и HTTP/3, а проверка ACME идёт по TCP. Слушатель TCP/443 уже
// есть и нужен независимо (домен, у которого есть HTTP/3, но по TCP
// соединение отбивается, — аномалия, видимая одним curl). Проверка
// tls-alpn-01 проходит по тому же порту 443 и не требует ни отдельного
// HTTP-порта, ни доступа к DNS-зоне: удостоверяющий центр подключается к
// нашему же TCP/443 с ALPN «acme-tls/1», а autocert отдаёт ему специальный
// самоподписанный сертификат с меткой проверки. Поэтому ACME требует
// включённого TCP-слушателя.
//
// # Что здесь добавлено поверх autocert
//
//   - Запасной сертификат. Если ACME недоступен (сеть, лимиты, отзыв
//     аккаунта), сервер обязан продолжать работать: отдаём последний
//     успешно полученный, а если такого нет — сертификат из файлов, если он
//     задан. Молча падать в момент, когда у удостоверяющего центра учёт
//     запросов, — худшее, что можно сделать с туннелем.
//   - Продление без перезапуска и без клиентов. autocert обновляет
//     сертификат при обращении к GetCertificate, но у VPN обращения могут не
//     случаться неделями: клиенты сидят на долгих соединениях. Поэтому
//     Maintain сам ходит за сертификатом по расписанию.
package acme

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"

	xacme "golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// ALPNChallenge — значение ALPN, по которому удостоверяющий центр приходит
// на проверку tls-alpn-01.
const ALPNChallenge = xacme.ALPNProto

// DefaultRenewCheck — как часто сами проверяем, не пора ли продлевать.
const DefaultRenewCheck = 12 * time.Hour

// Config — параметры автоматического сертификата.
type Config struct {
	// Domains — имена, на которые выпускается сертификат. Пусто — ACME выключен.
	Domains []string
	// Email — контакт для удостоверяющего центра (не обязателен, но он шлёт
	// на него предупреждения об истечении — это полезно).
	Email string
	// CacheDir — каталог кэша: там лежат ключ аккаунта и сами сертификаты.
	// Его нужно сохранять между перезапусками, иначе каждый запуск — это
	// новый заказ, а у удостоверяющего центра есть лимиты.
	CacheDir string
	// DirectoryURL — каталог ACME. Пусто — боевой Let's Encrypt.
	// Для отладки полезен staging: у него лимиты мягче, но сертификат
	// браузеры не примут.
	DirectoryURL string
	// HTTPClient — клиент для запросов к удостоверяющему центру (для тестов).
	HTTPClient *http.Client
	// Fallback — сертификат из файлов: им отвечаем, если ACME недоступен и
	// своего сертификата ещё нет.
	Fallback *tls.Certificate
	// RenewCheck — период самостоятельной проверки; 0 — DefaultRenewCheck.
	RenewCheck time.Duration
	// HandshakeWait — сколько рукопожатие ждёт ACME, прежде чем уйти с
	// запасным сертификатом; 0 — DefaultHandshakeWait.
	HandshakeWait time.Duration
	// AttemptTimeout — после этого попытка считается зависшей и можно
	// начинать новую; 0 — DefaultAttemptTimeout.
	AttemptTimeout time.Duration
	// RetryCooldown — минимум между попытками по своей инициативе;
	// 0 — DefaultRetryCooldown.
	RetryCooldown time.Duration
	Logger        *slog.Logger
}

// Manager выдаёт сертификаты серверу.
type Manager struct {
	auto   *autocert.Manager
	cfg    Config
	log    *slog.Logger
	domain string

	mu      sync.Mutex
	last    *tls.Certificate // последний успешно полученный
	cur     *attempt         // идущая попытка
	nextTry time.Time        // когда можно начать следующую
	// shortWarned — предупреждение о коротком сертификате уже выдано.
	shortWarned bool
	// failed — было ли уже сообщено об отказе; чтобы не сыпать в журнал
	// одинаковыми предупреждениями на каждое рукопожатие.
	failed bool
}

// New создаёт менеджер. Пустой Domains — ошибка: вызывающий сам решает,
// включать ли ACME.
func New(cfg Config) (*Manager, error) {
	if len(cfg.Domains) == 0 {
		return nil, errors.New("acme: не заданы домены")
	}
	if cfg.CacheDir == "" {
		return nil, errors.New("acme: не задан каталог кэша (в нём ключ аккаунта и сертификаты)")
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(cfg.CacheDir),
		HostPolicy: autocert.HostWhitelist(cfg.Domains...),
		Email:      cfg.Email,
	}
	if cfg.DirectoryURL != "" || cfg.HTTPClient != nil {
		m.Client = &xacme.Client{DirectoryURL: cfg.DirectoryURL, HTTPClient: cfg.HTTPClient}
	}
	return &Manager{auto: m, cfg: cfg, log: log, domain: cfg.Domains[0]}, nil
}

// Domain — первое имя из списка (оно же идёт в SNI и на сайт-прикрытие).
func (m *Manager) Domain() string { return m.domain }

// Выдача сертификата вынесена из рукопожатия.
//
// autocert делает всю работу прямо в GetCertificate и держит её до пяти
// минут. Если удостоверяющий центр недоступен или тянет, каждое рукопожатие
// висит на нём целиком — то есть отказ ACME превращается в отказ сервера.
// Поэтому попытка живёт отдельно: рукопожатие либо забирает готовый
// сертификат сразу, либо ждёт чуть-чуть и уходит с запасным, а попытка
// доводится в фоне.
const (
	// DefaultHandshakeWait — сколько рукопожатие готово ждать ACME.
	DefaultHandshakeWait = 5 * time.Second
	// DefaultAttemptTimeout — после этого попытку считаем зависшей и
	// разрешаем начать новую (прежняя доработает сама и, если успеет,
	// сохранит результат).
	DefaultAttemptTimeout = 2 * time.Minute
	// DefaultRetryCooldown — не чаще этого начинаем новую попытку по своей
	// инициативе: у удостоверяющего центра лимиты на заказы, и упереться в
	// них хуже, чем неделю походить со старым сертификатом.
	DefaultRetryCooldown = 10 * time.Minute
	// renewBefore — за сколько до истечения пора продлевать (как у autocert).
	renewBefore = 30 * 24 * time.Hour
)

// attempt — одна попытка получить сертификат.
type attempt struct {
	done     chan struct{}
	deadline time.Time
	cert     *tls.Certificate
	err      error
}

// GetCertificate — для tls.Config. Не возвращает ошибку, если есть чем
// ответить: туннель важнее свежести сертификата.
func (m *Manager) GetCertificate(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if isChallenge(hi) {
		// Проверочное соединение удостоверяющего центра: autocert отдаёт
		// заранее подготовленный сертификат из памяти, ждать нечего. И
		// подменять его запасным нельзя — проверка не пройдёт.
		return m.auto.GetCertificate(hi)
	}
	name := hi.ServerName
	if name == "" {
		name = m.domain
	}
	if cert := m.cached(); cert != nil {
		if expiringSoon(cert) {
			m.start(name, false) // продление в фоне, клиента не задерживаем
		}
		return cert, nil
	}
	if a := m.start(name, false); a != nil {
		select {
		case <-a.done:
			if a.err == nil {
				return a.cert, nil
			}
			m.note(a.err)
		case <-time.After(m.dur(m.cfg.HandshakeWait, DefaultHandshakeWait)):
			m.note(errors.New("ACME не ответил вовремя"))
		}
	}
	if cert := m.cached(); cert != nil {
		return cert, nil
	}
	if m.cfg.Fallback != nil {
		return m.cfg.Fallback, nil
	}
	return nil, errors.New("acme: сертификата нет — ни своего, ни запасного")
}

// start возвращает текущую попытку или начинает новую. nil — сейчас пробовать
// рано (force это обходит; так ходят Obtain и плановая проверка).
func (m *Manager) start(name string, force bool) *attempt {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	if a := m.cur; a != nil && now.Before(a.deadline) {
		return a // уже идёт
	}
	if !force && now.Before(m.nextTry) {
		return nil
	}
	a := &attempt{done: make(chan struct{}), deadline: now.Add(m.dur(m.cfg.AttemptTimeout, DefaultAttemptTimeout))}
	m.cur = a
	m.nextTry = now.Add(m.dur(m.cfg.RetryCooldown, DefaultRetryCooldown))
	go m.run(name, a)
	return a
}

func (m *Manager) run(name string, a *attempt) {
	cert, err := m.auto.GetCertificate(hello(name))
	m.mu.Lock()
	if m.cur == a {
		m.cur = nil
	}
	if err == nil {
		m.last = cert
		if m.failed {
			m.log.Info("сертификат ACME снова получен", "домен", name)
			m.failed = false
		}
		// Autocert обновляет сертификат за 30 дней до истечения. Если
		// удостоверяющий центр выдаёт более короткий, обновление становится
		// непрерывным — а это прямой путь в лимиты. Предупреждаем один раз.
		if l := cert.Leaf; l != nil && !m.shortWarned && l.NotAfter.Sub(l.NotBefore) < 2*renewBefore {
			m.shortWarned = true
			m.log.Warn("удостоверяющий центр выдаёт короткий сертификат — продление будет частым",
				"срок", l.NotAfter.Sub(l.NotBefore).Round(time.Hour))
		}
	}
	m.mu.Unlock()
	a.cert, a.err = cert, err
	close(a.done)
}

func (m *Manager) cached() *tls.Certificate {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.last == nil {
		return nil
	}
	if m.last.Leaf != nil && time.Now().After(m.last.Leaf.NotAfter) {
		return nil // просроченный хуже отсутствующего
	}
	return m.last
}

func expiringSoon(c *tls.Certificate) bool {
	return c.Leaf != nil && time.Until(c.Leaf.NotAfter) < renewBefore
}

func (m *Manager) dur(v, def time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return def
}

// note пишет об отказе один раз, а не на каждое рукопожатие.
func (m *Manager) note(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.failed {
		m.log.Warn("ACME не отдал сертификат — работаем на прежнем", "err", err)
		m.failed = true
	}
}

func isChallenge(hi *tls.ClientHelloInfo) bool {
	for _, p := range hi.SupportedProtos {
		if p == ALPNChallenge {
			return true
		}
	}
	return false
}

// hello — искусственный ClientHello для фоновой выдачи: по нему autocert
// выбирает тип ключа, а к соединению он не привязан.
func hello(name string) *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{
		ServerName:        name,
		SupportedProtos:   []string{"h2"},
		SignatureSchemes:  defaultSigSchemes,
		SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
		CipherSuites:      defaultCiphers,
	}
}

// TCPConfig — настройки TLS для слушателя TCP: к обычным протоколам
// добавляется acme-tls/1, иначе проверка не сможет к нам подключиться.
func (m *Manager) TCPConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: m.GetCertificate,
		NextProtos:     []string{"h2", "http/1.1", ALPNChallenge},
		MinVersion:     tls.VersionTLS12,
	}
}

// QUICConfig — настройки TLS для HTTP/3. ALPN проставит http3.
func (m *Manager) QUICConfig() *tls.Config {
	return &tls.Config{GetCertificate: m.GetCertificate, MinVersion: tls.VersionTLS13}
}

// Obtain получает сертификат прямо сейчас, не дожидаясь первого клиента, и
// сообщает, чем всё кончилось. Ошибка не фатальна: сервер продолжит работать
// на запасном, а следующая попытка случится по расписанию или при
// рукопожатии.
func (m *Manager) Obtain(ctx context.Context) error {
	a := m.start(m.domain, true)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-a.done:
		if a.err != nil {
			m.note(a.err)
			return a.err
		}
		if a.cert != nil && a.cert.Leaf != nil {
			m.log.Info("сертификат получен", "домен", m.domain,
				"издатель", a.cert.Leaf.Issuer.CommonName,
				"до", a.cert.Leaf.NotAfter.UTC().Format(time.RFC3339))
		}
		return nil
	}
}

// Maintain периодически сам ходит за сертификатом, чтобы продление
// случалось и без новых рукопожатий: клиенты VPN сидят на долгих
// соединениях, и autocert иначе может не получить повода обновиться.
func (m *Manager) Maintain(ctx context.Context) {
	period := m.cfg.RenewCheck
	if period <= 0 {
		period = DefaultRenewCheck
	}
	for {
		// Разброс, чтобы все серверы сборки не ходили к удостоверяющему
		// центру в одну и ту же минуту.
		d := period + time.Duration(rand.Int64N(int64(period/4)))
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		octx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		if err := m.Obtain(octx); err != nil {
			m.log.Warn("плановая проверка сертификата не удалась", "err", err)
		}
		cancel()
	}
}

// Значения ниже нужны только затем, чтобы ClientHelloInfo в Obtain выглядел
// как настоящий: autocert по нему выбирает тип ключа.
var (
	defaultSigSchemes = []tls.SignatureScheme{
		tls.ECDSAWithP256AndSHA256, tls.PSSWithSHA256, tls.PKCS1WithSHA256,
	}
	defaultCiphers = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}
)
