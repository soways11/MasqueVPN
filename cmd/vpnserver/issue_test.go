package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/soways11/masquevpn/internal/clients"
	"github.com/soways11/masquevpn/internal/config"
)

func testClient() clients.Client {
	return clients.Client{
		ID:   "66bbb6180401ba34",
		Name: "телефон",
		Key:  clients.Secret("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="),
	}
}

// TestIssueToFileKeepsSecretOut — при -out наружу не выходит ни ключ, ни
// ссылка.
//
// Ссылка несёт тот же ключ, и печатать её рядом со словами «ключ в терминале
// не показан» — обман. Первая версия так и делала; замечено при живой
// проверке, теперь стережётся тестом.
func TestIssueToFileKeepsSecretOut(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "phone.json")
	c := testClient()

	var buf bytes.Buffer
	if code := clientsIssue(&buf, c, "vpn.example.com:443", out); code != 0 {
		t.Fatalf("выдача вернула %d", code)
	}
	printed := buf.String()
	t.Log("напечатано:\n" + printed)

	if strings.Contains(printed, string(c.Key)) {
		t.Error("ключ напечатан в терминал")
	}
	if strings.Contains(printed, config.LinkScheme+"://") {
		t.Error("ссылка напечатана в терминал — она несёт тот же ключ")
	}

	// Файл конфигурации: три поля и права 0600.
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if len(m) != 3 {
		t.Errorf("в файле %d полей, ожидалось три: %v", len(m), m)
	}
	checkMode(t, out)

	// Ссылка легла во второй файл и разбирается обратно.
	linkPath := filepath.Join(dir, "phone.link")
	linkRaw, err := os.ReadFile(linkPath)
	if err != nil {
		t.Fatalf("файла ссылки нет: %v", err)
	}
	checkMode(t, linkPath)
	cfg, name, err := config.DecodeLink(string(linkRaw))
	if err != nil {
		t.Fatalf("ссылка из файла не разбирается: %v", err)
	}
	if name != c.Name {
		t.Errorf("имя профиля в ссылке %q, ожидалось %q", name, c.Name)
	}
	if cfg.ClientID != c.ID || string(cfg.AuthKey) != string(c.Key) {
		t.Error("ссылка ведёт не к тому клиенту")
	}
	if cfg.KillSwitch == nil || !*cfg.KillSwitch {
		t.Error("выданная конфигурация приходит с выключенным аварийным отключением")
	}
}

// TestIssueToTerminalWarns — без -out ключ и ссылка печатаются, но с
// предупреждением: иначе человек не узнает, что они осели в истории.
func TestIssueToTerminalWarns(t *testing.T) {
	var buf bytes.Buffer
	c := testClient()
	if code := clientsIssue(&buf, c, "vpn.example.com:443", ""); code != 0 {
		t.Fatalf("выдача вернула %d", code)
	}
	printed := buf.String()
	if !strings.Contains(printed, string(c.Key)) {
		t.Error("без -out ключ должен быть показан — иначе его негде взять")
	}
	if !strings.Contains(printed, config.LinkScheme+"://") {
		t.Error("ссылка не напечатана")
	}
	if !strings.Contains(printed, "-out") {
		t.Error("нет подсказки про -out: человек не узнает, что ключ осел в истории терминала")
	}
}

// TestIssuedConfigIsMinimal — выдаётся ровно то, что нужно.
//
// Прежняя версия печатала шесть полей, из которых три повторяли умолчания.
// Лишние строки в конфигурации не бесплатны: человек перестаёт замечать те,
// которые стоит менять.
func TestIssuedConfigIsMinimal(t *testing.T) {
	cfg := clientConfig(testClient(), "vpn.example.com:443")
	m := minimalClientJSON(cfg)
	if len(m) != 3 {
		t.Fatalf("в конфигурации %d полей: %v", len(m), m)
	}
	for _, k := range []string{"server", "auth_key", "client_id"} {
		if _, ok := m[k]; !ok {
			t.Errorf("нет поля %q", k)
		}
	}
	// И этого достаточно, чтобы конфигурация была работоспособной.
	cfg.Defaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("выданная конфигурация негодна: %v", err)
	}
	if cfg.FullTunnel == nil || !*cfg.FullTunnel {
		t.Error("полный туннель не включился по умолчанию")
	}
	if len(cfg.DNS) == 0 {
		t.Error("резолвер не подставился — имена уйдут мимо туннеля")
	}
}

func checkMode(t *testing.T, path string) {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// В Windows права Unix не действуют: Go показывает у любого файла
	// 0666, а доступ решают ACL папки. Проверка — только там, где права есть.
	if runtime.GOOS == "windows" {
		return
	}
	if mode := st.Mode().Perm(); mode != 0o600 {
		t.Errorf("%s: права %o, ожидались 600", filepath.Base(path), mode)
	}
}
