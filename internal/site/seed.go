package site

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// LoadSeed читает секрет установки из файла, а если файла нет — создаёт его.
//
// Seed хранится отдельно от конфигурации сознательно: установщик не
// переписывает существующий server.json, и если бы seed жил только там, на
// серверах, поставленных раньше, его не было бы вовсе. Файл же появляется
// сам при первом запуске новой версии. Потерять его не страшно (клиенты от
// него не зависят), но сайт после этого будет другим — как после смены
// дизайна.
//
// created сообщает, что файл создан только что.
func LoadSeed(path string) (seed string, created bool, err error) {
	if b, err := os.ReadFile(path); err == nil {
		s := strings.TrimSpace(string(b))
		if len(s) < 16 {
			return "", false, fmt.Errorf("%s: seed короче 16 символов", path)
		}
		return s, false, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", false, err
	}

	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", false, err
	}
	seed = hex.EncodeToString(raw)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", false, err
	}
	// O_EXCL: если два процесса стартовали разом, файл пишет один, второй
	// читает уже записанное — иначе у них оказались бы разные сайты.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return LoadSeed(path)
	}
	if err != nil {
		return "", false, err
	}
	if _, err := f.WriteString(seed + "\n"); err != nil {
		f.Close()
		os.Remove(path)
		return "", false, err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return "", false, err
	}
	return seed, true, nil
}

// RandomSeed — seed на один запуск, когда сохранить его некуда.
func RandomSeed() string {
	raw := make([]byte, 16)
	_, _ = rand.Read(raw)
	return hex.EncodeToString(raw)
}
