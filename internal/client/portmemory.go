package client

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// PortMemory помнит, какой порт сервера ответил в прошлый раз.
//
// Без неё удачный порт жил только до перезапуска: каждый запуск снова
// начинался с первого порта в адресе, и если его режет провайдер, человек
// ждал ~5 секунд таймаута на каждом включении. Теперь клиент начинает с того,
// что сработало в прошлый раз.
type PortMemory interface {
	// Port — запомненный порт сервера host; пусто — не запоминали.
	Port(host string) string
	// Remember запоминает, что сервер host ответил на порту port.
	Remember(host, port string)
}

// PortsFile — имя файла с запомненными портами (рядом с профилями).
const PortsFile = "ports.json"

// FilePortMemory — PortMemory в JSON-файле: хост → порт. Ошибки чтения и
// записи молча проглатываются: не запомнили — начнём с первого порта, как
// раньше; ради этого файла подключение ломаться не должно.
func FilePortMemory(path string) PortMemory {
	return &filePorts{path: path}
}

type filePorts struct {
	mu   sync.Mutex
	path string
}

func (f *filePorts) load() map[string]string {
	m := map[string]string{}
	if raw, err := os.ReadFile(f.path); err == nil {
		_ = json.Unmarshal(raw, &m)
	}
	return m
}

func (f *filePorts) Port(host string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.load()[host]
}

func (f *filePorts) Remember(host, port string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.load()
	if m[host] == port {
		return
	}
	m[host] = port
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

// MemPortMemory — PortMemory в памяти процесса: переживает переподключения и
// новые сессии, но не перезапуск. Для платформ, где файлу негде лежать.
func MemPortMemory() PortMemory { return &memPorts{m: map[string]string{}} }

type memPorts struct {
	mu sync.Mutex
	m  map[string]string
}

func (p *memPorts) Port(host string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.m[host]
}

func (p *memPorts) Remember(host, port string) {
	p.mu.Lock()
	p.m[host] = port
	p.mu.Unlock()
}
