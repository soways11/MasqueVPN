package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Реестр — единственное место, где живут ключи клиентов: восстановить их
// неоткуда, и потеря файла отключает всех разом. Тесты ниже проверяют, что
// копия действительно спасает, а восстановление не делает хуже.

func writeRegistry(t *testing.T, dir string) (regPath, usagePath string) {
	t.Helper()
	regPath = filepath.Join(dir, "clients.json")
	usagePath = regPath + ".usage"
	reg := `[{"id":"66bbb6180401ba34","name":"телефон","key":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="},
{"id":"29ed77c27fa9ac0a","name":"Ноутбук","key":"IB8eHRwbGhkYFxYVFBMSERAPDg0MCwoJCAcGBQQDAgE="}]`
	if err := os.WriteFile(regPath, []byte(reg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(usagePath, []byte(`{"66bbb6180401ba34":{"bytes":123}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return regPath, usagePath
}

// TestBackupRestoreKeepsKeys — главный сценарий: сняли копию, потеряли
// реестр, восстановили. Ключи обязаны совпасть побайтно: «столько же
// клиентов» тут ничего не значит, доступ определяется именно ключом.
func TestBackupRestoreKeepsKeys(t *testing.T) {
	dir := t.TempDir()
	regPath, usagePath := writeRegistry(t, dir)
	before, err := os.ReadFile(regPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeUsage, err := os.ReadFile(usagePath)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	copyPath := filepath.Join(dir, "copy.json")
	if code := makeBackup(&buf, regPath, usagePath, copyPath); code != 0 {
		t.Fatalf("снятие копии вернуло %d: %s", code, buf.String())
	}
	checkMode(t, copyPath)

	// Теряем и реестр, и учёт — ровно то, от чего защищаемся.
	os.Remove(regPath)
	os.Remove(usagePath)

	buf.Reset()
	if code := restoreBackup(&buf, regPath, usagePath, copyPath); code != 0 {
		t.Fatalf("восстановление вернуло %d: %s", code, buf.String())
	}
	t.Log(buf.String())

	after, err := os.ReadFile(regPath)
	if err != nil {
		t.Fatal(err)
	}
	// Сравниваем содержимое, а не байты: копия — читаемый JSON с отступами,
	// и вложенный реестр при этом переформатируется. Для доступа важны
	// записи, а не расстановка пробелов; побайтное равенство здесь
	// потребовало бы хранить реестр строкой и сделало бы копию нечитаемой.
	if !sameJSON(t, before, after) {
		t.Errorf("восстановленный реестр отличается от исходного — ключи не те:\n%s\n%s", before, after)
	}
	afterUsage, err := os.ReadFile(usagePath)
	if err != nil {
		t.Fatalf("учёт расхода не восстановлен: %v", err)
	}
	if !sameJSON(t, beforeUsage, afterUsage) {
		t.Error("учёт расхода отличается: квоты начнут считаться заново")
	}
	checkMode(t, regPath)
}

// TestRestoreKeepsPreviousAside — восстановление «не из той» копии само по
// себе потеря доступа, поэтому прежние файлы должны остаться рядом.
func TestRestoreKeepsPreviousAside(t *testing.T) {
	dir := t.TempDir()
	regPath, usagePath := writeRegistry(t, dir)
	current, _ := os.ReadFile(regPath)

	// Копия с одним клиентом — как будто снята давно.
	old := `[{"id":"aaaaaaaaaaaaaaaa","name":"старый","key":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="}]`
	copyPath := filepath.Join(dir, "old.json")
	raw, _ := json.Marshal(backupFile{
		Kind: backupKind, Version: 1, Created: "2026-09-01T00:00:00Z",
		Clients: json.RawMessage(old),
	})
	if err := os.WriteFile(copyPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if code := restoreBackup(&buf, regPath, usagePath, copyPath); code != 0 {
		t.Fatalf("восстановление вернуло %d", code)
	}
	aside, err := os.ReadFile(regPath + ".before-restore")
	if err != nil {
		t.Fatalf("прежний реестр не сохранён: %v", err)
	}
	// Здесь как раз побайтно: отложенный файл — копия того, что было, и
	// переформатировать его незачем.
	if !bytes.Equal(aside, current) {
		t.Error("сохранён не тот файл")
	}
}

// TestRestoreRefusesGarbage — понятный отказ вместо молчаливой перезаписи
// реестра чем попало.
func TestRestoreRefusesGarbage(t *testing.T) {
	dir := t.TempDir()
	regPath, usagePath := writeRegistry(t, dir)
	original, _ := os.ReadFile(regPath)

	cases := map[string]string{
		"чужой JSON":       `{"foo":1}`,
		"пустая копия":     `{"kind":"masquevpn-clients-backup","version":1,"clients":[]}`,
		"не JSON":          `не файл вовсе`,
		"копия без вида":   `{"version":1,"clients":[{"id":"x"}]}`,
		"копия без ключей": `{"kind":"masquevpn-clients-backup","version":1,"clients":{}}`,
	}
	for name, body := range cases {
		path := filepath.Join(dir, "bad.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		if code := restoreBackup(&buf, regPath, usagePath, path); code == 0 {
			t.Errorf("%s: восстановление прошло, хотя не должно", name)
		}
		now, _ := os.ReadFile(regPath)
		if !bytes.Equal(now, original) {
			t.Fatalf("%s: реестр перезаписан при неудачном восстановлении", name)
		}
	}
}

// TestBackupRefusesBrokenRegistry — копировать испорченный реестр незачем:
// это сохранит поломку и обнаружится только при восстановлении.
func TestBackupRefusesBrokenRegistry(t *testing.T) {
	dir := t.TempDir()
	regPath := filepath.Join(dir, "clients.json")
	if err := os.WriteFile(regPath, []byte("{обрезано"), 0o600); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if code := makeBackup(&buf, regPath, regPath+".usage", filepath.Join(dir, "copy.json")); code == 0 {
		t.Error("копия испорченного реестра снята")
	}
}

// TestBackupWarnsAboutKeys — в копии лежат ключи, и человек должен это
// понимать: она такой же секрет, как сам реестр.
func TestBackupWarnsAboutKeys(t *testing.T) {
	dir := t.TempDir()
	regPath, usagePath := writeRegistry(t, dir)
	var buf bytes.Buffer
	if code := makeBackup(&buf, regPath, usagePath, filepath.Join(dir, "copy.json")); code != 0 {
		t.Fatal(buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "ключи") {
		t.Error("в выводе нет предупреждения, что копия содержит ключи")
	}
	if !strings.Contains(out, "restore") {
		t.Error("не сказано, как восстанавливать")
	}
}

// sameJSON сравнивает два документа по содержимому.
func sameJSON(t *testing.T, a, b []byte) bool {
	t.Helper()
	var x, y any
	if err := json.Unmarshal(a, &x); err != nil {
		t.Fatalf("исходный документ не разбирается: %v", err)
	}
	if err := json.Unmarshal(b, &y); err != nil {
		t.Fatalf("восстановленный документ не разбирается: %v", err)
	}
	return reflect.DeepEqual(x, y)
}

// Копия, снятая до переименования проекта (вид "govpn-clients-backup"),
// обязана восстанавливаться: такие файлы лежат у людей на флешках, и
// отказ означал бы потерю всех выданных доступов.
func TestRestoreAcceptsLegacyKind(t *testing.T) {
	dir := t.TempDir()
	regPath, usagePath := writeRegistry(t, dir)
	old := `[{"id":"aaaaaaaaaaaaaaaa","name":"старый","key":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="}]`
	copyPath := filepath.Join(dir, "legacy.json")
	raw, _ := json.Marshal(backupFile{
		Kind: legacyBackupKind, Version: 1, Created: "2026-09-01T00:00:00Z",
		Clients: json.RawMessage(old),
	})
	if err := os.WriteFile(copyPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if code := restoreBackup(&buf, regPath, usagePath, copyPath); code != 0 {
		t.Fatalf("копия прежней версии не восстановилась (%d): %s", code, buf.String())
	}
}
