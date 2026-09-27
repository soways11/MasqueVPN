package clients

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"
)

// Учёт расхода и квоты.
//
// Расход хранится отдельным файлом от реестра. Так реестр остаётся тем, что
// правят руками, и его не переписывает на ходу сервер: смешать эти две вещи в
// одном файле — значит рано или поздно затереть чужую правку своим
// периодическим сохранением.
//
// Гранулярность учёта — секунды, а не байты: сервер снимает счётчики сессии по
// таймеру и на закрытии. Байт в байт считать здесь нечего, а лезть в горячий
// путь ради точности до килобайта — плохой размен.

// Usage — расход одного клиента.
type Usage struct {
	ID string `json:"id"`
	// Bytes — израсходовано за текущий период.
	Bytes int64 `json:"bytes"`
	// Total — за всё время. Период сбрасывает Bytes, но не Total.
	Total int64 `json:"total"`
	// PeriodStart — начало текущего периода (UTC).
	PeriodStart time.Time `json:"period_start,omitempty"`
	// LastSeen — когда клиент последний раз что-то передавал.
	LastSeen time.Time `json:"last_seen,omitempty"`
	// Sessions — сколько сессий клиент открыл за всё время.
	Sessions int64 `json:"sessions,omitempty"`
}

type usageFile struct {
	Version int     `json:"version"`
	Usage   []Usage `json:"usage"`
}

// Accountant считает расход и отвечает на вопрос «клиенту ещё можно?».
type Accountant struct {
	path  string
	store Store

	mu    sync.Mutex
	byID  map[string]*Usage
	dirty bool

	now func() time.Time
}

// NewAccountant создаёт учёт. path — файл расхода; пустой путь означает, что
// расход считается только в памяти и теряется при перезапуске (годится для
// тестов, но не для квот: квота без сохранения обнуляется перезапуском).
func NewAccountant(path string, store Store) (*Accountant, error) {
	a := &Accountant{path: path, store: store, byID: map[string]*Usage{}, now: time.Now}
	if path == "" {
		return a, nil
	}
	raw, err := os.ReadFile(path)
	switch {
	case os.IsNotExist(err):
		return a, nil
	case err != nil:
		return nil, err
	}
	var f usageFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("clients: %s: %w", path, err)
	}
	for i := range f.Usage {
		u := f.Usage[i]
		a.byID[u.ID] = &u
	}
	return a, nil
}

// periodStart — начало периода, в который попадает t.
func periodStart(t time.Time, period string) time.Time {
	t = t.UTC()
	switch period {
	case "month":
		return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
	case "day":
		return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	default:
		return time.Time{}
	}
}

// entry возвращает запись расхода, перекатывая период при необходимости.
// Вызывается под mu.
func (a *Accountant) entry(id, period string) *Usage {
	u, ok := a.byID[id]
	if !ok {
		u = &Usage{ID: id}
		a.byID[id] = u
	}
	start := periodStart(a.now(), period)
	if !start.IsZero() && !start.Equal(u.PeriodStart) {
		u.Bytes = 0
		u.PeriodStart = start
		a.dirty = true
	}
	return u
}

// Account учитывает n байт трафика клиента.
func (a *Accountant) Account(id string, n int64) {
	if n <= 0 {
		return
	}
	period := ""
	if c, ok := a.lookup(id); ok {
		period = c.Period
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	u := a.entry(id, period)
	u.Bytes += n
	u.Total += n
	u.LastSeen = a.now().UTC().Truncate(time.Second)
	a.dirty = true
}

// StartedSession отмечает открытие сессии (для статистики).
func (a *Accountant) StartedSession(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	u := a.entry(id, "")
	u.Sessions++
	a.dirty = true
}

func (a *Accountant) lookup(id string) (Client, bool) {
	if a.store == nil {
		return Client{}, false
	}
	return a.store.Lookup(id)
}

// Usage возвращает расход клиента.
func (a *Accountant) Usage(id string) Usage {
	period := ""
	if c, ok := a.lookup(id); ok {
		period = c.Period
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return *a.entry(id, period)
}

// All возвращает расход всех известных клиентов.
func (a *Accountant) All() []Usage {
	a.mu.Lock()
	out := make([]Usage, 0, len(a.byID))
	for _, u := range a.byID {
		out = append(out, *u)
	}
	a.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Reset обнуляет расход клиента за текущий период.
func (a *Accountant) Reset(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if u, ok := a.byID[id]; ok {
		u.Bytes = 0
		u.PeriodStart = periodStart(a.now(), "")
		a.dirty = true
	}
}

// ErrQuota — квота клиента исчерпана.
type ErrQuota struct {
	ID    string
	Used  int64
	Quota int64
}

func (e *ErrQuota) Error() string {
	return fmt.Sprintf("клиент %s: квота исчерпана (%d из %d байт)", e.ID, e.Used, e.Quota)
}

// ErrDisabled — клиент есть, но выключен.
type ErrDisabled struct{ ID string }

func (e *ErrDisabled) Error() string {
	return "клиент " + e.ID + ": доступ приостановлен"
}

// ErrUnknown — клиента нет в реестре.
type ErrUnknown struct{ ID string }

func (e *ErrUnknown) Error() string { return "клиент " + e.ID + ": нет в реестре" }

// ErrTooManySessions — у клиента уже столько сессий, сколько ему разрешено.
type ErrTooManySessions struct {
	ID    string
	Live  int
	Limit int
}

func (e *ErrTooManySessions) Error() string {
	return fmt.Sprintf("клиент %s: уже %d сессий при лимите %d", e.ID, e.Live, e.Limit)
}

// Admit решает, пускать ли клиента ещё в одну сессию. live — сколько сессий у
// него сейчас. Годится как masque.Policy.
//
// Проверка квоты здесь ОТКАЗЫВАЕТ в новой сессии, но не рвёт текущие: рвать
// соединение на середине скачивания из-за перебора на сотню байт — злее, чем
// нужно. Живые сессии закрывает отдельный обход (см. OverQuota).
func (a *Accountant) Admit(id string, live int) error {
	c, ok := a.lookup(id)
	if !ok {
		return &ErrUnknown{ID: id}
	}
	if c.Disabled {
		return &ErrDisabled{ID: id}
	}
	if c.MaxSessions > 0 && live >= c.MaxSessions {
		return &ErrTooManySessions{ID: id, Live: live, Limit: c.MaxSessions}
	}
	if c.Quota > 0 {
		u := a.Usage(id)
		if u.Bytes >= c.Quota {
			return &ErrQuota{ID: id, Used: u.Bytes, Quota: c.Quota}
		}
	}
	return nil
}

// RateLimit — персональный потолок полосы клиента. Нули означают «общий
// лимит сервера».
func (a *Accountant) RateLimit(id string) (int, int) {
	c, ok := a.lookup(id)
	if !ok || c.MaxBytesPerSecond <= 0 {
		return 0, 0
	}
	return c.MaxBytesPerSecond, 0
}

// OverQuota возвращает псевдонимы клиентов, вышедших за квоту. Сервер
// закрывает их сессии — иначе квота не потолок, а пожелание: сессию открыли
// до исчерпания, и она качает дальше сколько угодно.
func (a *Accountant) OverQuota() []string {
	if a.store == nil {
		return nil
	}
	var out []string
	for _, c := range a.store.Snapshot() {
		if c.Quota <= 0 {
			continue
		}
		if u := a.Usage(c.ID); u.Bytes >= c.Quota {
			out = append(out, c.ID)
		}
	}
	sort.Strings(out)
	return out
}

// Save записывает расход на диск, если он менялся.
func (a *Accountant) Save() error {
	if a.path == "" {
		return nil
	}
	a.mu.Lock()
	if !a.dirty {
		a.mu.Unlock()
		return nil
	}
	list := make([]Usage, 0, len(a.byID))
	for _, u := range a.byID {
		list = append(list, *u)
	}
	a.dirty = false
	a.mu.Unlock()

	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	raw, err := json.MarshalIndent(usageFile{Version: fileVersion, Usage: list}, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(a.path, append(raw, '\n'), 0o600); err != nil {
		a.mu.Lock()
		a.dirty = true // не сохранилось — пусть попробует в следующий раз
		a.mu.Unlock()
		return err
	}
	return nil
}

// Run периодически сохраняет расход, пока не закрыт stop; на выходе сохраняет
// в последний раз.
func (a *Accountant) Run(stop <-chan struct{}, every time.Duration, onError func(error)) {
	if every <= 0 {
		every = 30 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			if err := a.Save(); err != nil && onError != nil {
				onError(err)
			}
			return
		case <-t.C:
			if err := a.Save(); err != nil && onError != nil {
				onError(err)
			}
		}
	}
}
