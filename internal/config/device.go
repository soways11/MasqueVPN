package config

// Псевдоним устройства: чем одна установка отличается от другой.
//
// # Зачем
//
// Ключ у человека один, а устройств несколько: ноутбук, домашний компьютер,
// телефон. Ссылку доступа он переносит как есть, поэтому client_id у всех
// установок одинаковый — это запись в реестре ключей на сервере, а не
// железка. Пока сервер не различал устройства, он выдавал им ОДИН туннельный
// адрес, и работало только то, что подключилось последним (см. internal/auth
// и аренду адресов в internal/masque).
//
// Отличать устройства должно что-то местное — то, что не едет в ссылке. Этим
// занимается DeviceID.
//
// # Как получается значение
//
// Соль из файла `device.id` рядом с программой плюс приметы машины (имя
// хоста, machine-id там, где он есть). Соль — случайная, создаётся при первом
// запуске; приметы добавлены на случай, который иначе возвращал бы поломку:
// папку с программой копируют на другой компьютер целиком, вместе с
// профилями и солью. Тогда соль совпала бы, а имя хоста — почти наверняка
// нет.
//
// Если файл создать не удалось (папка только для чтения, нет прав), значение
// выходит случайным на время работы процесса. Одновременная работа устройств
// от этого не страдает — страдает только постоянство адреса между
// перезапусками.
//
// Секретом значение не является: сервер не ищет по нему ничего и ничего на
// него не пускает.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// DeviceIDFile — имя файла с солью псевдонима устройства.
const DeviceIDFile = "device.id"

// DefaultDeviceIDPath — файл соли там же, где профили (см. DataDir).
func DefaultDeviceIDPath() string { return filepath.Join(DataDir(), DeviceIDFile) }

var (
	deviceOnce sync.Once
	deviceID   string
)

// DeviceID — псевдоним этого устройства (шестнадцатеричная строка). Считается
// один раз за время работы процесса: он должен быть одинаковым у всех
// подключений программы, иначе при ротации сессия получит другой адрес.
func DeviceID() string {
	deviceOnce.Do(func() { deviceID = DeviceIDAt(DefaultDeviceIDPath()) })
	return deviceID
}

// DeviceIDAt — то же с указанным файлом соли (для тестов и нестандартной
// установки).
func DeviceIDAt(path string) string {
	h := sha256.New()
	h.Write([]byte("masquevpn device\x00"))
	h.Write([]byte(deviceSalt(path)))
	h.Write([]byte{0})
	h.Write([]byte(machineMarks()))
	return hex.EncodeToString(h.Sum(nil)[:8])
}

// deviceSalt читает соль из файла, создавая её при первом запуске. При любой
// беде возвращает случайную: лучше непостоянный псевдоним, чем отказ
// подключаться.
func deviceSalt(path string) string {
	raw, err := os.ReadFile(path)
	if err == nil {
		if s := strings.TrimSpace(string(raw)); s != "" {
			return s
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return randomSalt()
	}
	salt := randomSalt()
	// Каталога может ещё не быть: у установленной программы это
	// /var/lib/masquevpn, и первым в него пишет именно этот файл. 0700 —
	// рядом лягут профили с ключами.
	if dir := filepath.Dir(path); dir != "" {
		_ = os.MkdirAll(dir, 0o700)
	}
	// 0600: файл хоть и не секрет, но лежит рядом с профилями, где ключи, и
	// разнобой в правах только путает.
	if err := os.WriteFile(path, []byte(salt+"\n"), 0o600); err != nil {
		return salt // не записалось — живём одним запуском
	}
	return salt
}

func randomSalt() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// rand.Read не возвращает ошибку на поддерживаемых системах; но если
		// вернул, лучше пустая соль (останутся приметы машины), чем паника.
		return ""
	}
	return hex.EncodeToString(b)
}

// machineMarks — приметы машины: то, что отличает два компьютера с одной
// скопированной папкой. Ничего из этого не обязано существовать.
func machineMarks() string {
	var parts []string
	if host, err := os.Hostname(); err == nil {
		parts = append(parts, host)
	}
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if raw, err := os.ReadFile(p); err == nil {
			parts = append(parts, strings.TrimSpace(string(raw)))
			break
		}
	}
	return strings.Join(parts, "\x00")
}
