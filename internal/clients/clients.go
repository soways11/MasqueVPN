// Package clients — реестр клиентов сервера: у каждого свой ключ, свой
// псевдоним, свои лимиты и своя квота.
//
// Зачем он. До него у сервера был ОДИН общий ключ на всех. Из этого следовало
// три неприятности сразу: получивший ключ неотличим от законного владельца;
// отозвать доступ одному нельзя — только сменить ключ и разослать новый всем
// остальным; и посчитать, кто сколько израсходовал, не на чем — сервер не
// знает, чей это трафик.
//
// Псевдоним клиента (8 байт) уже ездил в токене и был подписан — за ним
// закреплялась аренда адреса. Здесь он получает вторую роль: по нему сервер
// находит, КАКИМ ключом проверять подпись. Псевдоним не секрет, секрет — ключ.
//
// Хранилище — JSON-файл, который перечитывается на лету. Базы данных тут нет
// сознательно: у проекта нет внешних зависимостей, а файл со списком на
// десяток-другой записей правится руками и переживает перезапуск. Всё, что
// снаружи знает о хранилище, спрятано за интерфейсом Store — заменить файл на
// что-то другое можно, не трогая ни сервер, ни auth.
//
// Обратная сторона, о которой стоит сказать прямо: реестр делает трафик
// АТРИБУТИРУЕМЫМ. С общим ключом сервер не знал, чей поток он обслуживает;
// теперь знает. Для своего сервера на несколько человек это выигрыш в
// управляемости, для раздачи широкому кругу — свойство, о котором надо
// предупреждать.
package clients

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// IDLen — длина псевдонима клиента в байтах. Совпадает с полем client в
// токене (см. internal/auth): это одно и то же значение.
const IDLen = 8

// KeyLen — длина выдаваемого ключа. 32 байта — как требует конфигурация.
const KeyLen = 32

// Client — запись о клиенте.
type Client struct {
	// ID — псевдоним, 16 шестнадцатеричных цифр (8 байт). Выдаётся сервером
	// при создании и едет в каждом токене открытым текстом.
	ID string `json:"id"`
	// Name — человеческое имя, только для журнала и списка.
	Name string `json:"name,omitempty"`
	// Key — ключ клиента (base64). Секрет; файл поэтому 0600.
	Key Secret `json:"key"`
	// Disabled — доступ приостановлен. Отличается от удаления тем, что
	// запись и накопленный расход остаются.
	Disabled bool `json:"disabled,omitempty"`
	// MaxSessions — сколько сессий этому клиенту разрешено одновременно.
	// 0 — без персонального лимита.
	MaxSessions int `json:"max_sessions,omitempty"`
	// MaxBytesPerSecond — персональный потолок полосы. 0 — общий из
	// конфигурации сервера. Считается на клиента, а не на сессию: иначе
	// пять сессий дают пятикратную полосу.
	MaxBytesPerSecond int `json:"max_bytes_per_second,omitempty"`
	// Quota — сколько байт клиенту разрешено за период. 0 — без квоты.
	Quota int64 `json:"quota,omitempty"`
	// Period — период сброса квоты: "month", "day" или пусто (не сбрасывать).
	Period string `json:"period,omitempty"`
	// Created — когда запись создана.
	Created time.Time `json:"created,omitempty"`
	// Note — произвольная пометка.
	Note string `json:"note,omitempty"`
}

// Secret — ключ в base64. Отдельный тип, чтобы не печатать его случайно в
// журнале: String() показывает длину, а не содержимое.
type Secret string

// String намеренно не показывает ключ.
func (s Secret) String() string {
	if s == "" {
		return "<нет>"
	}
	return fmt.Sprintf("<ключ, %d симв.>", len(s))
}

// Bytes декодирует ключ.
func (s Secret) Bytes() ([]byte, error) { return decodeKey(string(s)) }

func (c *Client) validate() error {
	if len(c.ID) != IDLen*2 {
		return fmt.Errorf("id %q: нужно %d шестнадцатеричных цифр", c.ID, IDLen*2)
	}
	if _, err := hex.DecodeString(c.ID); err != nil {
		return fmt.Errorf("id %q: %w", c.ID, err)
	}
	key, err := c.Key.Bytes()
	if err != nil {
		return fmt.Errorf("клиент %s: ключ: %w", c.ID, err)
	}
	if len(key) < 32 {
		return fmt.Errorf("клиент %s: ключ %d байт, нужно не меньше 32", c.ID, len(key))
	}
	switch c.Period {
	case "", "month", "day":
	default:
		return fmt.Errorf("клиент %s: period %q, допустимо month, day или пусто", c.ID, c.Period)
	}
	if c.Quota < 0 {
		return fmt.Errorf("клиент %s: отрицательная квота", c.ID)
	}
	return nil
}

// file — формат файла реестра.
type file struct {
	Version int      `json:"version"`
	Clients []Client `json:"clients"`
}

const fileVersion = 1

// Store — то, что нужно серверу от реестра. Сервер видит только этот
// интерфейс, поэтому файл можно заменить чем угодно.
type Store interface {
	// Lookup находит клиента по псевдониму. Второе значение — false, если
	// такого нет.
	Lookup(id string) (Client, bool)
	// Snapshot — копия всех записей, для списка и журнала.
	Snapshot() []Client
}

// Registry — реестр в JSON-файле.
type Registry struct {
	path string

	mu      sync.RWMutex
	byID    map[string]Client
	modTime time.Time
	size    int64
}

var _ Store = (*Registry)(nil)

// Open читает файл реестра. Несуществующий файл — не ошибка: реестр просто
// пуст, и сервер об этом предупредит.
func Open(path string) (*Registry, error) {
	r := &Registry{path: path, byID: map[string]Client{}}
	if err := r.reload(true); err != nil {
		return nil, err
	}
	return r, nil
}

// Path — путь к файлу реестра.
func (r *Registry) Path() string { return r.path }

func (r *Registry) reload(initial bool) error {
	st, err := os.Stat(r.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if initial {
			return nil // пустой реестр
		}
		// Файл исчез на ходу. Считаем это ошибкой чтения, а НЕ «всех отозвали»:
		// стереть реестр случайно куда проще, чем намеренно, и молча отключить
		// всех клиентов из-за опечатки в пути было бы хуже всего.
		return fmt.Errorf("clients: файл реестра исчез: %s", r.path)
	case err != nil:
		return err
	}
	r.mu.RLock()
	same := st.ModTime().Equal(r.modTime) && st.Size() == r.size
	r.mu.RUnlock()
	if same && !initial {
		return nil
	}

	raw, err := os.ReadFile(r.path)
	if err != nil {
		return err
	}
	var f file
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return fmt.Errorf("clients: %s: %w", r.path, err)
	}
	if f.Version != 0 && f.Version != fileVersion {
		return fmt.Errorf("clients: %s: версия файла %d, поддерживается %d", r.path, f.Version, fileVersion)
	}
	byID := make(map[string]Client, len(f.Clients))
	for _, c := range f.Clients {
		c.ID = strings.ToLower(c.ID)
		if err := c.validate(); err != nil {
			return fmt.Errorf("clients: %s: %w", r.path, err)
		}
		if _, dup := byID[c.ID]; dup {
			return fmt.Errorf("clients: %s: повтор id %s", r.path, c.ID)
		}
		byID[c.ID] = c
	}
	r.mu.Lock()
	r.byID = byID
	r.modTime = st.ModTime()
	r.size = st.Size()
	r.mu.Unlock()
	return nil
}

// Reload перечитывает файл, если он изменился. Возвращает псевдонимы тех, кто
// потерял доступ с прошлого чтения (удалён или выключен) — их живые сессии
// нужно закрыть, иначе отзыв не отзыв: токен проверяется один раз, при
// подключении, и уже открытая сессия живёт сколько угодно долго.
func (r *Registry) Reload() (revoked []string, err error) {
	before := r.allowedSet()
	if err := r.reload(false); err != nil {
		return nil, err
	}
	after := r.allowedSet()
	for id := range before {
		if !after[id] {
			revoked = append(revoked, id)
		}
	}
	sort.Strings(revoked)
	return revoked, nil
}

func (r *Registry) allowedSet() map[string]bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m := make(map[string]bool, len(r.byID))
	for id, c := range r.byID {
		if !c.Disabled {
			m[id] = true
		}
	}
	return m
}

// Lookup находит клиента по псевдониму.
func (r *Registry) Lookup(id string) (Client, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.byID[strings.ToLower(id)]
	return c, ok
}

// Snapshot — копия всех записей, отсортированная по имени и псевдониму.
func (r *Registry) Snapshot() []Client {
	r.mu.RLock()
	out := make([]Client, 0, len(r.byID))
	for _, c := range r.byID {
		out = append(out, c)
	}
	r.mu.RUnlock()
	slices.SortFunc(out, func(a, b Client) int {
		if a.Name != b.Name {
			return strings.Compare(a.Name, b.Name)
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out
}

// Len — сколько записей в реестре.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byID)
}

// Watch перечитывает файл раз в interval и зовёт onRevoked с псевдонимами
// потерявших доступ. Возвращается, когда закрыт stop.
//
// Опрос, а не подписка на события файловой системы: реестр правится руками
// или соседней командой раз в месяц, а inotify — это ещё одна зависимость и
// ещё один источник особых случаев (переименование, NFS, докер-монтирование).
func (r *Registry) Watch(stop <-chan struct{}, interval time.Duration,
	onRevoked func([]string), onError func(error)) {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			revoked, err := r.Reload()
			if err != nil {
				if onError != nil {
					onError(err)
				}
				continue
			}
			if len(revoked) > 0 && onRevoked != nil {
				onRevoked(revoked)
			}
		}
	}
}

// ---------- изменение реестра ----------

// NewID выдаёт случайный псевдоним клиента.
func NewID() (string, error) {
	var b [IDLen]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// NewKey выдаёт случайный ключ клиента.
func NewKey() (Secret, error) {
	b := make([]byte, KeyLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return Secret(encodeKey(b)), nil
}

// Add создаёт клиента и записывает файл. Псевдоним и ключ выдаются здесь:
// клиент не должен выбирать их сам — иначе два клиента могут взять один
// псевдоним и начать отбирать друг у друга адрес.
func (r *Registry) Add(c Client) (Client, error) {
	if c.ID == "" {
		id, err := NewID()
		if err != nil {
			return Client{}, err
		}
		c.ID = id
	}
	if c.Key == "" {
		k, err := NewKey()
		if err != nil {
			return Client{}, err
		}
		c.Key = k
	}
	if c.Created.IsZero() {
		c.Created = time.Now().UTC().Truncate(time.Second)
	}
	c.ID = strings.ToLower(c.ID)
	if err := c.validate(); err != nil {
		return Client{}, err
	}
	err := r.mutate(func(m map[string]Client) error {
		if _, dup := m[c.ID]; dup {
			return fmt.Errorf("clients: клиент %s уже есть", c.ID)
		}
		m[c.ID] = c
		return nil
	})
	return c, err
}

// Update меняет запись существующего клиента.
func (r *Registry) Update(id string, fn func(*Client) error) (Client, error) {
	id = strings.ToLower(id)
	var out Client
	err := r.mutate(func(m map[string]Client) error {
		c, ok := m[id]
		if !ok {
			return fmt.Errorf("clients: нет клиента %s", id)
		}
		if err := fn(&c); err != nil {
			return err
		}
		if err := c.validate(); err != nil {
			return err
		}
		m[id] = c
		out = c
		return nil
	})
	return out, err
}

// Remove удаляет клиента.
func (r *Registry) Remove(id string) error {
	id = strings.ToLower(id)
	return r.mutate(func(m map[string]Client) error {
		if _, ok := m[id]; !ok {
			return fmt.Errorf("clients: нет клиента %s", id)
		}
		delete(m, id)
		return nil
	})
}

// mutate применяет изменение и записывает файл целиком. Запись атомарная:
// временный файл рядом и переименование — иначе падение посреди записи
// оставило бы обрезанный реестр, то есть отключило бы всех.
func (r *Registry) mutate(fn func(map[string]Client) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	m := make(map[string]Client, len(r.byID))
	for k, v := range r.byID {
		m[k] = v
	}
	if err := fn(m); err != nil {
		return err
	}
	list := make([]Client, 0, len(m))
	for _, c := range m {
		list = append(list, c)
	}
	slices.SortFunc(list, func(a, b Client) int {
		if a.Name != b.Name {
			return strings.Compare(a.Name, b.Name)
		}
		return strings.Compare(a.ID, b.ID)
	})
	raw, err := json.MarshalIndent(file{Version: fileVersion, Clients: list}, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if err := writeFileAtomic(r.path, raw, 0o600); err != nil {
		return err
	}
	r.byID = m
	if st, err := os.Stat(r.path); err == nil {
		r.modTime, r.size = st.ModTime(), st.Size()
	}
	return nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // если переименование не дошло
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
