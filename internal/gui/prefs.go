package gui

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// WindowPrefsFile — имя файла, где окно помнит свою высоту. Лежит рядом с
// профилями (config.DataDir).
const WindowPrefsFile = "window.json"

// WindowPrefs — что окно помнит между запусками.
//
// Только высота: ширина не меняется, а положение на экране окно всякий раз
// выбирает само — запомненное положение на другом мониторе или после смены
// разрешения оставило бы окно за краем экрана.
type WindowPrefs struct {
	Height int32 `json:"height,omitempty"`
}

// LoadWindowPrefs читает настройки окна. Нет файла или он испорчен —
// умолчания: из-за этого файла окно не должно отказываться открываться.
func LoadWindowPrefs(path string) WindowPrefs {
	var p WindowPrefs
	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, &p)
	}
	p.Height = ClampHeight(p.Height)
	return p
}

// SaveWindowPrefs записывает настройки окна.
func SaveWindowPrefs(path string, p WindowPrefs) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
