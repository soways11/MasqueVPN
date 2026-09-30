// Package auth реализует аутентификацию клиента на уровне CONNECT-IP запроса
// (пункт 2.1 плана) и её защиту от активного зондирования (пункт 2.2).
//
// Клиент кладёт в обычный HTTP-заголовок токен
//
//	base64url( version(1) | ts(8, big-endian сек) | client(8) | device(8) | nonce(16) | HMAC-SHA256(key, ...)[:16] )
//
// Сервер проверяет HMAC (в постоянном времени), окно свежести по времени и
// отсутствие повтора nonce. Токен без валидной подписи неотличим для стороннего
// наблюдателя от отсутствия токена — сервер в обоих случаях отдаёт запрос в
// Fallback (обычный веб-ответ), не выдавая факт существования VPN.
//
// Поле client — псевдоним клиента: 8 случайных байт, постоянных для установки.
// Он подписан тем же HMAC, поэтому подделать его нельзя, и НЕ является
// секретом сам по себе — он нужен серверу, чтобы узнать вернувшегося клиента
// и вернуть ему прежний адрес при ротации и переподключении (см. аренду
// адресов в masque). Раньше адрес был привязан к сессии, и при ротации новая
// сессия не могла получить его, пока его держала старая: передача вставала на
// каждой ротации, а после смены сети рвались все соединения внутри туннеля.
//
// Поле device (версия 3) — псевдоним УСТРОЙСТВА внутри одного доступа. Один
// ключ живёт на ноутбуке и на телефоне: client у них общий (это запись в
// реестре ключей, по ней находится ключ), и без второго поля сервер считал
// оба устройства одним. Тогда оба получали один туннельный адрес, а таблица
// «адрес → сессия» хранит одну запись — входящий трафик уходил только в
// последнюю подключившуюся сессию, и на остальных устройствах туннель
// замолкал. Ротация же требует обратного: две сессии ОДНОГО устройства
// должны делить адрес. Отсюда и разделение: ключ ищется по client, адрес
// закрепляется за парой client+device.
//
// Токены версии 1 (без полей client и device) и 2 (без device) по-прежнему
// принимаются: клиент старой сборки работает, просто все его устройства
// сервер видит как одно.
//
// Заголовок по умолчанию — Authorization: Bearer <token>, но имя настраивается,
// чтобы совпадать с легитимным сервисом-прикрытием.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// clientIDDomain — префикс свёртки псевдонима клиента (см. New). Неизменен
// со времён, когда проект назывался govpn: это протокольная константа.
const clientIDDomain = "govpn client id\x00"

const (
	tokenV1 = 1
	// tokenV2 добавляет псевдоним клиента.
	tokenV2 = 2
	// tokenV3 добавляет псевдоним устройства.
	tokenV3 = 3
	// tokenVersion — версия, которую мы выпускаем.
	tokenVersion = tokenV3

	nonceLen    = 16
	clientIDLen = 8
	deviceIDLen = 8
	macLen      = 16 // усечённый HMAC-SHA256

	tokenLenV1 = 1 + 8 + nonceLen + macLen
	tokenLenV2 = 1 + 8 + clientIDLen + nonceLen + macLen
	tokenLenV3 = 1 + 8 + clientIDLen + deviceIDLen + nonceLen + macLen
)

// ClientIDLen — длина псевдонима клиента в байтах (поле client в токене).
const ClientIDLen = clientIDLen

// DeviceIDLen — длина псевдонима устройства в байтах (поле device в токене).
const DeviceIDLen = deviceIDLen

// DefaultHeader — имя заголовка и схема по умолчанию.
const (
	DefaultHeader = "Authorization"
	bearerScheme  = "Bearer "
)

var enc = base64.RawURLEncoding

// Authenticator подписывает и проверяет токены на общем секрете.
// Одна структура используется и клиентом (Header), и сервером (Authorize).
type Authenticator struct {
	key      []byte
	keys     KeyLookup
	dummyKey []byte
	header   string
	skew     time.Duration
	bearer   bool
	clientID [clientIDLen]byte
	deviceID [deviceIDLen]byte

	now   func() time.Time
	nonce func([]byte) (int, error)

	replay *replayCache
}

// Options — необязательные параметры.
type Options struct {
	// Header — имя HTTP-заголовка с токеном. По умолчанию Authorization (схема Bearer).
	// При другом имени заголовок содержит только сам токен (без "Bearer ").
	Header string
	// Skew — допустимое отклонение времени в обе стороны. По умолчанию 30 с.
	Skew time.Duration
	// MaxReplayEntries — потолок числа записей в кэше защиты от повтора.
	// 0 — defaultMaxReplayEntries. Кэш ограничен сознательно: иначе при большом
	// потоке подключений он растёт неограниченно.
	MaxReplayEntries int
	// ClientID — псевдоним этой установки клиента. Пусто — случайный на
	// время работы процесса (этого хватает для ротации и переподключения;
	// постоянное значение вдобавок сохраняет адрес и через перезапуск).
	// Длина любая: значение сворачивается в 8 байт.
	ClientID []byte
	// ClientIDExact — точный псевдоним длиной clientIDLen байт, выданный
	// сервером вместе с личным ключом. В отличие от ClientID не сворачивается
	// хэшем: сервер ищет по нему запись клиента, и значение должно совпасть
	// байт в байт. Имеет приоритет над ClientID.
	ClientIDExact []byte
	// DeviceID — псевдоним УСТРОЙСТВА внутри доступа. Ключ один, а устройств
	// у человека несколько, и каждому нужен свой туннельный адрес: без этого
	// работает только то, что подключилось последним (см. описание пакета).
	//
	// Длина любая: значение сворачивается в 8 байт хэшем. Пусто — случайный
	// на время работы процесса: одновременная работа устройств от этого уже
	// в порядке, но адрес меняется при каждом перезапуске, поэтому клиенту
	// стоит передавать сюда постоянное значение (см. config.DeviceID).
	//
	// Секретом не является и в реестре не ищется: сервер только отличает по
	// нему одно устройство от другого.
	DeviceID []byte
	// Keys — поиск ключа по псевдониму клиента (режим «ключ на клиента»).
	// Задан — сервер проверяет подпись ключом НАЙДЕННОГО клиента, а не общим;
	// тогда key в New не нужен и служит только запасным для токенов версии 1.
	//
	// В этом режиме токены версии 1 не принимаются вовсе: в них нет поля
	// client, а значит нечем выбрать ключ.
	Keys KeyLookup
}

// KeyLookup находит ключ клиента по его псевдониму (16 шестнадцатеричных
// цифр). Второе значение — false, если такого клиента нет или доступ ему
// закрыт.
type KeyLookup func(clientID string) ([]byte, bool)

const defaultMaxReplayEntries = 100_000

// New создаёт Authenticator. key должен быть общим секретом достаточной длины
// (рекомендуется >= 32 байт).
func New(key []byte, opts Options) (*Authenticator, error) {
	if opts.Keys == nil && len(key) < 16 {
		return nil, errors.New("auth: key too short (need >= 16 bytes)")
	}
	if opts.Keys != nil && len(key) > 0 {
		// Общий ключ рядом с личными — это чёрный ход: отозванный клиент
		// продолжал бы заходить по нему, и весь отзыв терял бы смысл.
		return nil, errors.New("auth: общий ключ и ключи по клиентам одновременно не работают")
	}
	header := opts.Header
	bearer := false
	if header == "" {
		header = DefaultHeader
		bearer = true
	}
	skew := opts.Skew
	if skew == 0 {
		skew = 30 * time.Second
	}
	a := &Authenticator{
		key:    append([]byte(nil), key...),
		keys:   opts.Keys,
		header: header,
		skew:   skew,
		bearer: bearer,
		now:    time.Now,
		nonce:  rand.Read,
	}
	if a.keys != nil {
		// Ключ-пустышка для неизвестных клиентов: HMAC считается всё равно,
		// чтобы по времени ответа нельзя было перебрать, какие псевдонимы
		// существуют. Отказ по «нет такого клиента» должен стоить столько же,
		// сколько отказ по неверной подписи.
		a.dummyKey = make([]byte, 32)
		if _, err := rand.Read(a.dummyKey); err != nil {
			return nil, err
		}
	}
	switch {
	case len(opts.ClientIDExact) > 0:
		if len(opts.ClientIDExact) != clientIDLen {
			return nil, errors.New("auth: ClientIDExact должен быть длиной " +
				strconv.Itoa(clientIDLen) + " байт")
		}
		copy(a.clientID[:], opts.ClientIDExact)
	case len(opts.ClientID) == 0:
		if _, err := rand.Read(a.clientID[:]); err != nil {
			return nil, err
		}
	default:
		// Сворачиваем через хэш: значение может быть любой длины и любого
		// происхождения, а в токене поле фиксированное.
		//
		// Префикс — часть протокола, а не название: по нему сервер и все
		// выданные доступы вычисляют один и тот же псевдоним. Проект
		// переименован, а префикс — нет и не будет: смена отрезала бы всех
		// уже выданных клиентов.
		sum := sha256.Sum256(append([]byte(clientIDDomain), opts.ClientID...))
		copy(a.clientID[:], sum[:clientIDLen])
	}
	if len(opts.DeviceID) == 0 {
		if _, err := rand.Read(a.deviceID[:]); err != nil {
			return nil, err
		}
	} else {
		sum := sha256.Sum256(append([]byte("masquevpn device id\x00"), opts.DeviceID...))
		copy(a.deviceID[:], sum[:deviceIDLen])
	}
	maxEntries := opts.MaxReplayEntries
	if maxEntries == 0 {
		maxEntries = defaultMaxReplayEntries
	}
	a.replay = newReplayCache(2*skew, maxEntries)
	return a, nil
}

// HeaderName возвращает имя заголовка, куда кладётся токен.
func (a *Authenticator) HeaderName() string { return a.header }

// ClientID — псевдоним клиента в шестнадцатеричном виде (для журнала и
// конфигурации).
func (a *Authenticator) ClientID() string { return hex.EncodeToString(a.clientID[:]) }

// DeviceID — псевдоним устройства в шестнадцатеричном виде (для журнала).
func (a *Authenticator) DeviceID() string { return hex.EncodeToString(a.deviceID[:]) }

func (a *Authenticator) mac(version byte, ts int64, client, device, nonce []byte) []byte {
	return a.macWith(a.key, version, ts, client, device, nonce)
}

func (a *Authenticator) macWith(key []byte, version byte, ts int64, client, device, nonce []byte) []byte {
	h := hmac.New(sha256.New, key)
	var buf [1 + 8]byte
	buf[0] = version
	binary.BigEndian.PutUint64(buf[1:], uint64(ts))
	h.Write(buf[:])
	h.Write(client)
	h.Write(device)
	h.Write(nonce)
	return h.Sum(nil)[:macLen]
}

// Token генерирует свежий токен.
func (a *Authenticator) Token() (string, error) { return a.token(tokenVersion) }

func (a *Authenticator) token(version byte) (string, error) {
	nonce := make([]byte, nonceLen)
	if _, err := a.nonce(nonce); err != nil {
		return "", err
	}
	device := a.deviceID[:]
	if version < tokenV3 {
		device = nil
	}
	ts := a.now().Unix()
	tok := make([]byte, 0, tokenLenV3)
	tok = append(tok, version)
	tok = binary.BigEndian.AppendUint64(tok, uint64(ts))
	tok = append(tok, a.clientID[:]...)
	tok = append(tok, device...)
	tok = append(tok, nonce...)
	tok = append(tok, a.mac(version, ts, a.clientID[:], device, nonce)...)
	return enc.EncodeToString(tok), nil
}

// SetHeader кладёт свежий токен в заголовки h (создаёт map при необходимости).
func (a *Authenticator) SetHeader(h http.Header) error {
	return a.setHeader(h, tokenVersion)
}

// SetHeaderLegacy кладёт токен версии 2 — без псевдонима устройства.
//
// Нужен для одного случая: сервер прошлой сборки не знает версии 3 и
// отвечает на неё так же, как постороннему (обычной страницей). Клиент,
// получив такой отказ, повторяет попытку старым токеном — иначе обновление
// клиента раньше сервера означало бы «ничего не работает, и непонятно
// почему». Все устройства такого клиента сервер видит как одно.
func (a *Authenticator) SetHeaderLegacy(h http.Header) error {
	return a.setHeader(h, tokenV2)
}

func (a *Authenticator) setHeader(h http.Header, version byte) error {
	tok, err := a.token(version)
	if err != nil {
		return err
	}
	if a.bearer {
		tok = bearerScheme + tok
	}
	h.Set(a.header, tok)
	return nil
}

// Header возвращает новый http.Header с валидным токеном — удобно для
// masque.ClientConfig.Header.
func (a *Authenticator) Header() (http.Header, error) {
	h := http.Header{}
	return h, a.SetHeader(h)
}

// HeaderLegacy — то же с токеном версии 2 (см. SetHeaderLegacy).
func (a *Authenticator) HeaderLegacy() (http.Header, error) {
	h := http.Header{}
	return h, a.SetHeaderLegacy(h)
}

// Authorize проверяет запрос. Годится как masque.ServerConfig.Authorize.
// Любая ошибка (нет заголовка, битый токен, чужая подпись, протухшее время,
// повтор) возвращает false — сервер отдаёт запрос в Fallback.
func (a *Authenticator) Authorize(r *http.Request) bool {
	_, _, ok := a.Identify(r)
	return ok
}

// Identify проверяет запрос и возвращает псевдонимы клиента и его устройства.
// Годится как masque.ServerConfig.Identify. У токена версии 1 нет псевдонима
// клиента, у версии 2 — псевдонима устройства: соответствующее значение тогда
// пустое при ok = true.
func (a *Authenticator) Identify(r *http.Request) (clientID, deviceID string, ok bool) {
	v := r.Header.Get(a.header)
	if v == "" {
		return "", "", false
	}
	if a.bearer {
		if !strings.HasPrefix(v, bearerScheme) {
			return "", "", false
		}
		v = strings.TrimPrefix(v, bearerScheme)
	}
	return a.verify(v)
}

func (a *Authenticator) verify(token string) (string, string, bool) {
	raw, err := enc.DecodeString(token)
	if err != nil || len(raw) == 0 {
		return "", "", false
	}
	var client, device, nonce, mac []byte
	switch {
	case raw[0] == tokenV3 && len(raw) == tokenLenV3:
		client = raw[9 : 9+clientIDLen]
		device = raw[9+clientIDLen : 9+clientIDLen+deviceIDLen]
		nonce = raw[9+clientIDLen+deviceIDLen : 9+clientIDLen+deviceIDLen+nonceLen]
		mac = raw[9+clientIDLen+deviceIDLen+nonceLen:]
	case raw[0] == tokenV2 && len(raw) == tokenLenV2:
		client = raw[9 : 9+clientIDLen]
		nonce = raw[9+clientIDLen : 9+clientIDLen+nonceLen]
		mac = raw[9+clientIDLen+nonceLen:]
	case raw[0] == tokenV1 && len(raw) == tokenLenV1:
		nonce = raw[9 : 9+nonceLen]
		mac = raw[9+nonceLen:]
	default:
		return "", "", false
	}
	ts := int64(binary.BigEndian.Uint64(raw[1:9]))

	// Каким ключом проверять. В режиме «ключ на клиента» — ключом того, чей
	// псевдоним в токене; неизвестный псевдоним получает ключ-пустышку, чтобы
	// работа была той же и по времени ответа нельзя было перебирать
	// существующие псевдонимы.
	key, known := a.key, true
	if a.keys != nil {
		if len(client) == 0 {
			return "", "", false // версия 1 не несёт псевдонима — выбрать ключ нечем
		}
		// Ключ берём тот, что вернул реестр, даже когда он отвечает отказом:
		// решает ниже именно отказ, а не то, сойдётся ли подпись. Иначе эта
		// проверка была бы украшением — подпись не сошлась бы и так, — и
		// правка ветки выбора ключа сломала бы доступ незаметно.
		k, ok := a.keys(hex.EncodeToString(client))
		if len(k) == 0 {
			// Считать HMAC всё равно надо: иначе по времени ответа
			// перебирается, какие псевдонимы существуют.
			k = a.dummyKey
		}
		key, known = k, ok
	}

	// Подпись — в постоянном времени, до всех остальных проверок.
	if subtle.ConstantTimeCompare(mac, a.macWith(key, raw[0], ts, client, device, nonce)) != 1 {
		return "", "", false
	}
	if !known {
		return "", "", false
	}
	// Окно свежести.
	delta := a.now().Unix() - ts
	if delta < 0 {
		delta = -delta
	}
	if time.Duration(delta)*time.Second > a.skew {
		return "", "", false
	}
	// Защита от повтора.
	if !a.replay.checkAndStore(string(nonce), a.now()) {
		return "", "", false
	}
	return hex.EncodeToString(client), hex.EncodeToString(device), true
}

// ---------- replay cache ----------

type replayCache struct {
	mu   sync.Mutex
	ttl  time.Duration
	max  int
	seen map[string]time.Time
	last time.Time // время последней уборки
}

func newReplayCache(ttl time.Duration, max int) *replayCache {
	return &replayCache{ttl: ttl, max: max, seen: make(map[string]time.Time)}
}

// checkAndStore возвращает true, если nonce ранее не встречался (в пределах ttl).
func (c *replayCache) checkAndStore(nonce string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now.Sub(c.last) > c.ttl {
		for k, t := range c.seen {
			if now.Sub(t) > c.ttl {
				delete(c.seen, k)
			}
		}
		c.last = now
	}
	if _, ok := c.seen[nonce]; ok {
		return false
	}
	if c.max > 0 && len(c.seen) >= c.max {
		// Чистим просроченное прямо сейчас; если места всё равно нет — отказываем.
		// Отказ безопаснее, чем пустить токен без проверки на повтор: потерять
		// подключение хуже, чем потерять защиту от переигрывания, но не намного,
		// а вот выесть память сервера — это отказ в обслуживании для всех.
		for k, t := range c.seen {
			if now.Sub(t) > c.ttl {
				delete(c.seen, k)
			}
		}
		if len(c.seen) >= c.max {
			return false
		}
	}
	c.seen[nonce] = now
	return true
}
