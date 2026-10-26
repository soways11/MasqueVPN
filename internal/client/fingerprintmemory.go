package client

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FingerprintMemory помнит здоровье профилей отпечатка: какой подключился
// удачно в прошлый раз и какие временно выпали из пула.
//
// Зачем это, а не случайная ротация: смена отпечатка на КАЖДОМ подключении
// сама стала бы приметой — обычная машина ходит одним-двумя браузерами, а не
// меняет их при каждом дозвоне. Поэтому выбор устойчив: удачный профиль
// помнится и идёт первым, а меняется он лишь когда с ним перестаёт
// получаться подключиться (молчат все порты — признак блокировки на
// проводе, см. PortsError). Такой профиль уходит на кулдаун и возвращается
// в пул сам, когда кулдаун истечёт: блокировки по отпечатку бывают
// временными, и навсегда вычёркивать профиль нельзя.
//
// Память — по хосту: у клиента может быть несколько серверов, и блокировка
// на пути к одному не повод менять профиль для другого.
type FingerprintMemory interface {
	// Good — профиль, подключившийся к host в прошлый раз; пусто — не
	// запоминали.
	Good(host string) string
	// Enabled сообщает, доступен ли профиль name для host сейчас (не на
	// кулдауне).
	Enabled(host, name string, now time.Time) bool
	// RememberGood: профиль name подключился к host — запомнить удачным и
	// снять с него кулдаун.
	RememberGood(host, name string)
	// Penalize: с профилем name не удалось подключиться к host — отправить на
	// кулдаун, растущий при повторных неудачах.
	Penalize(host, name string, now time.Time)
}

// Политика кулдауна: с первой неудачи профиль выпадает на fpCooldownBase,
// при каждой следующей подряд срок удваивается до потолка fpCooldownMax.
// Успешное подключение сбрасывает счётчик.
const (
	fpCooldownBase = 15 * time.Minute
	fpCooldownMax  = 6 * time.Hour
)

func cooldownFor(fails int) time.Duration {
	if fails < 1 {
		fails = 1
	}
	d := fpCooldownBase
	for i := 1; i < fails; i++ {
		d *= 2
		if d >= fpCooldownMax {
			return fpCooldownMax
		}
	}
	return d
}

// fpHealth — здоровье профилей одного хоста в файле.
type fpHealth struct {
	Good     string                `json:"good,omitempty"`
	Cooldown map[string]fpCooldown `json:"cooldown,omitempty"`
}

type fpCooldown struct {
	Until time.Time `json:"until"`
	Fails int       `json:"fails"`
}

// applyGood и applyPenalty — общая логика поверх карты host→здоровье, чтобы
// файловая и внутрипамятная реализации не расходились.
func applyGood(m map[string]fpHealth, host, name string) bool {
	h := m[host]
	changed := false
	if h.Good != name {
		h.Good = name
		changed = true
	}
	if _, ok := h.Cooldown[name]; ok {
		delete(h.Cooldown, name)
		changed = true
	}
	if len(h.Cooldown) == 0 {
		h.Cooldown = nil
	}
	m[host] = h
	return changed
}

func applyPenalty(m map[string]fpHealth, host, name string, now time.Time) {
	h := m[host]
	if h.Cooldown == nil {
		h.Cooldown = map[string]fpCooldown{}
	}
	c := h.Cooldown[name]
	c.Fails++
	c.Until = now.Add(cooldownFor(c.Fails))
	h.Cooldown[name] = c
	// Профиль, который только что не смог подключиться, перестаёт быть
	// «удачным» — иначе следующий запуск снова начал бы с него.
	if h.Good == name {
		h.Good = ""
	}
	m[host] = h
}

func enabledIn(m map[string]fpHealth, host, name string, now time.Time) bool {
	c, ok := m[host].Cooldown[name]
	if !ok {
		return true
	}
	return !now.Before(c.Until)
}

// FingerprintsFile — имя файла с памятью профилей (рядом с ports.json).
const FingerprintsFile = "fingerprints.json"

// FileFingerprintMemory — FingerprintMemory в JSON-файле. Ошибки чтения и
// записи молча проглатываются: без памяти клиент просто начинает с первого
// профиля пула — ради этого файла подключение ломаться не должно.
func FileFingerprintMemory(path string) FingerprintMemory {
	return &fileFingerprints{path: path}
}

type fileFingerprints struct {
	mu   sync.Mutex
	path string
}

func (f *fileFingerprints) load() map[string]fpHealth {
	m := map[string]fpHealth{}
	if raw, err := os.ReadFile(f.path); err == nil {
		_ = json.Unmarshal(raw, &m)
	}
	return m
}

func (f *fileFingerprints) save(m map[string]fpHealth) {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(f.path), 0o700); err != nil {
		return
	}
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, f.path)
}

func (f *fileFingerprints) Good(host string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.load()[host].Good
}

func (f *fileFingerprints) Enabled(host, name string, now time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return enabledIn(f.load(), host, name, now)
}

func (f *fileFingerprints) RememberGood(host, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.load()
	if applyGood(m, host, name) {
		f.save(m)
	}
}

func (f *fileFingerprints) Penalize(host, name string, now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.load()
	applyPenalty(m, host, name, now)
	f.save(m)
}

// MemFingerprintMemory — FingerprintMemory в памяти процесса: переживает
// переподключения и новые сессии, но не перезапуск. Для платформ, где файлу
// негде лежать.
func MemFingerprintMemory() FingerprintMemory {
	return &memFingerprints{m: map[string]fpHealth{}}
}

type memFingerprints struct {
	mu sync.Mutex
	m  map[string]fpHealth
}

func (p *memFingerprints) Good(host string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.m[host].Good
}

func (p *memFingerprints) Enabled(host, name string, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return enabledIn(p.m, host, name, now)
}

func (p *memFingerprints) RememberGood(host, name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	applyGood(p.m, host, name)
}

func (p *memFingerprints) Penalize(host, name string, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	applyPenalty(p.m, host, name, now)
}
