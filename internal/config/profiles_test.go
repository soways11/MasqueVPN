package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func newProfiles(t *testing.T) *Profiles {
	t.Helper()
	return &Profiles{path: filepath.Join(t.TempDir(), ProfilesFile)}
}

// TestProfilesAddAndSelect — основное: несколько доступов, выбранный один.
func TestProfilesAddAndSelect(t *testing.T) {
	p := newProfiles(t)
	home := sampleClient()
	work := sampleClient()
	work.Server = "work.example.com:443"

	if _, err := p.Add("домашний", home); err != nil {
		t.Fatal(err)
	}
	// Первый добавленный выбирается сам: иначе после импорта пришлось бы
	// отдельно выбирать единственный профиль.
	if p.Current != "домашний" {
		t.Errorf("первый профиль не выбран: %q", p.Current)
	}
	if _, err := p.Add("работа", work); err != nil {
		t.Fatal(err)
	}
	if p.Current != "домашний" {
		t.Errorf("добавление второго переключило выбор: %q", p.Current)
	}

	if err := p.Select("работа"); err != nil {
		t.Fatal(err)
	}
	active, ok := p.Active()
	if !ok || active.Name != "работа" || active.Config.Server != work.Server {
		t.Fatalf("выбран не тот профиль: %+v", active)
	}
	if err := p.Select("которого нет"); err == nil {
		t.Error("выбран несуществующий профиль")
	}
}

// TestProfilesReimportReplaces — повторный импорт того же имени чинит
// доступ, а не плодит «домашний (2)».
func TestProfilesReimportReplaces(t *testing.T) {
	p := newProfiles(t)
	first := sampleClient()
	if _, err := p.Add("домашний", first); err != nil {
		t.Fatal(err)
	}
	second := sampleClient()
	second.Server = "new.example.com:443"
	if _, err := p.Add("ДОМАШНИЙ", second); err != nil { // регистр не важен
		t.Fatal(err)
	}
	if len(p.List) != 1 {
		t.Fatalf("профилей %d, ожидался один: %+v", len(p.List), p.List)
	}
	if p.List[0].Config.Server != "new.example.com:443" {
		t.Error("повторный импорт не заменил конфигурацию")
	}
}

// TestProfilesRemoveKeepsSelection — после удаления выбранного клиент не
// должен остаться «без профиля» при непустом списке.
func TestProfilesRemoveKeepsSelection(t *testing.T) {
	p := newProfiles(t)
	a, b := sampleClient(), sampleClient()
	b.Server = "b.example.com:443"
	_, _ = p.Add("первый", a)
	_, _ = p.Add("второй", b)
	_ = p.Select("первый")

	if err := p.Remove("первый"); err != nil {
		t.Fatal(err)
	}
	if p.Current != "второй" {
		t.Errorf("после удаления выбранного текущий стал %q", p.Current)
	}
	active, ok := p.Active()
	if !ok || active.Name != "второй" {
		t.Errorf("активный профиль: %+v", active)
	}

	if err := p.Remove("второй"); err != nil {
		t.Fatal(err)
	}
	if _, ok := p.Active(); ok {
		t.Error("при пустом списке нашёлся активный профиль")
	}
	if err := p.Remove("второй"); err == nil {
		t.Error("удаление несуществующего прошло")
	}
}

// TestProfilesSurviveSaveLoad — профили переживают перезапуск, и ключи
// остаются рабочими.
func TestProfilesSurviveSaveLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ProfilesFile)
	p := &Profiles{path: path}
	c := sampleClient()
	if _, err := p.Add("домашний", c); err != nil {
		t.Fatal(err)
	}
	if err := p.Save(); err != nil {
		t.Fatal(err)
	}

	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := st.Mode().Perm(); mode != 0o600 && runtime.GOOS != "windows" {
		t.Errorf("права %o, ожидались 600: внутри ключи", mode)
	}

	again, err := LoadProfiles(path)
	if err != nil {
		t.Fatal(err)
	}
	active, ok := again.Active()
	if !ok {
		t.Fatal("после чтения нет активного профиля")
	}
	if active.Name != "домашний" || active.Config.Server != c.Server {
		t.Errorf("профиль изменился: %+v", active)
	}
	if err := active.Config.Validate(); err != nil {
		t.Errorf("прочитанная конфигурация негодна: %v", err)
	}
	if active.Config.KillSwitch == nil {
		t.Error("умолчания не применились при чтении профилей")
	}
}

// TestProfilesFirstRun — отсутствие файла не ошибка: это первый запуск.
func TestProfilesFirstRun(t *testing.T) {
	p, err := LoadProfiles(filepath.Join(t.TempDir(), "нет.json"))
	if err != nil {
		t.Fatalf("первый запуск считается ошибкой: %v", err)
	}
	if _, ok := p.Active(); ok {
		t.Error("на пустом месте нашёлся профиль")
	}
}

// TestProfilesImportLink — импорт ссылки, включая имя из неё.
func TestProfilesImportLink(t *testing.T) {
	p := newProfiles(t)
	link, err := EncodeLink(sampleClient(), "телефон")
	if err != nil {
		t.Fatal(err)
	}
	pr, err := p.ImportLink(link)
	if err != nil {
		t.Fatal(err)
	}
	if pr.Name != "телефон" {
		t.Errorf("имя профиля %q, ожидалось «телефон»", pr.Name)
	}
	if _, err := p.ImportLink("совсем не ссылка"); err == nil {
		t.Error("мусор импортирован как профиль")
	}
}

// TestProfilesNameFromServer — без имени профиль называется по домену: это
// говорит больше, чем «профиль 1».
func TestProfilesNameFromServer(t *testing.T) {
	p := newProfiles(t)
	if _, err := p.Add("", sampleClient()); err != nil {
		t.Fatal(err)
	}
	if p.List[0].Name != "vpn.example.com" {
		t.Errorf("имя по умолчанию %q", p.List[0].Name)
	}
}

// TestProfilesImportFile — импорт из файла и имя из имени файла.
func TestProfilesImportFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "работа.json")
	if err := os.WriteFile(path, []byte(`{
		"server": "work.example.com:443",
		"auth_key": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
		"client_id": "66bbb6180401ba34"
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	p := newProfiles(t)
	pr, err := p.ImportFile(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if pr.Name != "работа" {
		t.Errorf("имя профиля %q, ожидалось «работа»", pr.Name)
	}

	// А «client.json» — имя по умолчанию, оно ничего не говорит: тогда
	// берётся домен.
	plain := filepath.Join(dir, "client.json")
	if err := os.WriteFile(plain, []byte(`{
		"server": "vpn.example.com:443",
		"auth_key": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
		"client_id": "66bbb6180401ba34"
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	pr, err = p.ImportFile(plain, "")
	if err != nil {
		t.Fatal(err)
	}
	if pr.Name != "vpn.example.com" {
		t.Errorf("имя профиля из client.json — %q", pr.Name)
	}
}
