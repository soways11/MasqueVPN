package config

import (
	"os"
	"path/filepath"
	"testing"
)

// Сервер, поставленный до переименования, держит конфигурацию в
// /etc/govpn. Обновлённая программа находит её сама — пока новой нет; как
// только новая появилась (установщик перенёс каталог), берётся новая.
func TestPreferExisting(t *testing.T) {
	dir := t.TempDir()
	cur := filepath.Join(dir, "masquevpn", "server.json")
	legacy := filepath.Join(dir, "govpn", "server.json")

	if got := preferExisting(cur, legacy); got != cur {
		t.Fatalf("ничего нет — ожидался новый путь, получен %s", got)
	}
	os.MkdirAll(filepath.Dir(legacy), 0o700)
	os.WriteFile(legacy, []byte("{}"), 0o600)
	if got := preferExisting(cur, legacy); got != legacy {
		t.Fatalf("есть только прежний — ожидался он, получен %s", got)
	}
	os.MkdirAll(filepath.Dir(cur), 0o700)
	os.WriteFile(cur, []byte("{}"), 0o600)
	if got := preferExisting(cur, legacy); got != cur {
		t.Fatalf("есть оба — ожидался новый, получен %s", got)
	}
}
