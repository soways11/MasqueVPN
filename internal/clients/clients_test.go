package clients

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func tempRegistry(t *testing.T) *Registry {
	t.Helper()
	r, err := Open(filepath.Join(t.TempDir(), "clients.json"))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestAddAndLookup(t *testing.T) {
	r := tempRegistry(t)
	if r.Len() != 0 {
		t.Fatalf("новый реестр не пуст: %d", r.Len())
	}
	c, err := r.Add(Client{Name: "Ноутбук", Quota: 1000, Period: "month"})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.ID) != IDLen*2 {
		t.Fatalf("псевдоним %q неверной длины", c.ID)
	}
	key, err := c.Key.Bytes()
	if err != nil || len(key) != KeyLen {
		t.Fatalf("ключ: %v, %d байт", err, len(key))
	}

	got, ok := r.Lookup(c.ID)
	if !ok || got.Name != "Ноутбук" {
		t.Fatalf("Lookup дал %+v, %v", got, ok)
	}
	if _, ok := r.Lookup("00112233aabbccdd"); ok {
		t.Fatal("нашёлся несуществующий клиент")
	}

	// Файл читается заново — то есть запись переживает перезапуск сервера.
	r2, err := Open(r.Path())
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := r2.Lookup(c.ID); !ok || got.Key != c.Key {
		t.Fatal("после перечитывания клиент потерялся или ключ не тот")
	}
}

func TestAddGivesDifferentKeys(t *testing.T) {
	r := tempRegistry(t)
	a, err := r.Add(Client{Name: "a"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.Add(Client{Name: "b"})
	if err != nil {
		t.Fatal(err)
	}
	if a.ID == b.ID {
		t.Fatal("двум клиентам выдан один псевдоним")
	}
	if a.Key == b.Key {
		t.Fatal("двум клиентам выдан один ключ — весь смысл реестра в том, что ключи разные")
	}
}

func TestSecretDoesNotPrint(t *testing.T) {
	c := Client{Key: Secret("СЕКРЕТНЫЙ-КЛЮЧ")}
	// Ключ не должен попасть в журнал через обычное форматирование записи.
	if s := c.Key.String(); strings.Contains(s, "СЕКРЕТНЫЙ") {
		t.Fatalf("ключ виден в String(): %q", s)
	}
}

func TestReloadReportsRevoked(t *testing.T) {
	r := tempRegistry(t)
	keep, _ := r.Add(Client{Name: "остаётся"})
	gone, _ := r.Add(Client{Name: "удаляют"})
	off, _ := r.Add(Client{Name: "выключают"})

	// Правим файл «снаружи», как это сделал бы администратор или соседняя
	// команда: реестр обязан заметить это сам.
	raw, err := os.ReadFile(r.Path())
	if err != nil {
		t.Fatal(err)
	}
	var f file
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	var out []Client
	for _, c := range f.Clients {
		switch c.ID {
		case gone.ID:
			continue // удалён
		case off.ID:
			c.Disabled = true
		}
		out = append(out, c)
	}
	writeRegistry(t, r.Path(), out)

	revoked, err := r.Reload()
	if err != nil {
		t.Fatal(err)
	}
	if len(revoked) != 2 {
		t.Fatalf("отозвано %v, ожидалось двое (удалённый и выключенный)", revoked)
	}
	has := map[string]bool{}
	for _, id := range revoked {
		has[id] = true
	}
	if !has[gone.ID] || !has[off.ID] {
		t.Fatalf("не те отозваны: %v", revoked)
	}
	if has[keep.ID] {
		t.Fatal("отозван тот, кого не трогали")
	}
	// Выключенный остаётся в реестре — запись и расход не теряются.
	if c, ok := r.Lookup(off.ID); !ok || !c.Disabled {
		t.Fatal("выключенный клиент должен остаться в реестре с пометкой")
	}
}

// Битый или исчезнувший файл не должен отключать всех разом: это куда чаще
// опечатка в пути или оборванная запись, чем намерение закрыть доступ всем.
func TestReloadKeepsClientsOnBadFile(t *testing.T) {
	r := tempRegistry(t)
	c, _ := r.Add(Client{Name: "живой"})

	if err := os.WriteFile(r.Path(), []byte("{ это не json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reload(); err == nil {
		t.Fatal("битый файл принят молча")
	}
	if _, ok := r.Lookup(c.ID); !ok {
		t.Fatal("клиент пропал из-за битого файла")
	}

	if err := os.Remove(r.Path()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reload(); err == nil {
		t.Fatal("исчезнувший файл принят молча")
	}
	if _, ok := r.Lookup(c.ID); !ok {
		t.Fatal("клиент пропал из-за исчезнувшего файла")
	}
}

func TestRejectsBrokenRecords(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"короткий ключ": `{"version":1,"clients":[{"id":"00112233aabbccdd","key":"c2hvcnQ="}]}`,
		"плохой id":     `{"version":1,"clients":[{"id":"нехекс","key":"` + longKey() + `"}]}`,
		"короткий id":   `{"version":1,"clients":[{"id":"00112233","key":"` + longKey() + `"}]}`,
		"повтор id": `{"version":1,"clients":[{"id":"00112233aabbccdd","key":"` + longKey() + `"},` +
			`{"id":"00112233aabbccdd","key":"` + longKey() + `"}]}`,
		"чужой период":  `{"version":1,"clients":[{"id":"00112233aabbccdd","key":"` + longKey() + `","period":"век"}]}`,
		"чужое поле":    `{"version":1,"clients":[{"id":"00112233aabbccdd","key":"` + longKey() + `","колхоз":1}]}`,
		"чужая версия":  `{"version":99,"clients":[]}`,
		"не тот формат": `[]`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(dir, "c.json")
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(p); err == nil {
				t.Fatal("принято то, что должно быть отвергнуто")
			}
		})
	}
}

func TestUpdateAndRemove(t *testing.T) {
	r := tempRegistry(t)
	c, _ := r.Add(Client{Name: "кто-то"})

	if _, err := r.Update(c.ID, func(c *Client) error { c.Disabled = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.Lookup(c.ID); !got.Disabled {
		t.Fatal("Update не сохранил изменение")
	}
	if _, err := r.Update("00000000deadbeef", func(*Client) error { return nil }); err == nil {
		t.Fatal("Update несуществующего клиента прошёл")
	}
	if err := r.Remove(c.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Lookup(c.ID); ok {
		t.Fatal("удалённый клиент остался")
	}
	if err := r.Remove(c.ID); err == nil {
		t.Fatal("повторное удаление прошло")
	}
}

// Файл реестра — секрет: в нём лежат ключи всех клиентов.
func TestFileIsNotWorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("в Windows права Unix не действуют, доступ решают ACL папки")
	}
	r := tempRegistry(t)
	if _, err := r.Add(Client{Name: "кто-то"}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(r.Path())
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("права на файл реестра %v — ключи видны посторонним", st.Mode().Perm())
	}
}

func TestWatchNoticesRevocation(t *testing.T) {
	r := tempRegistry(t)
	c, _ := r.Add(Client{Name: "уходит"})

	got := make(chan []string, 1)
	stop := make(chan struct{})
	defer close(stop)
	go r.Watch(stop, 10*time.Millisecond, func(ids []string) { got <- ids }, nil)

	// mtime файловых систем бывает грубым — меняем и размер тоже, а заодно
	// именно так это и выглядит при настоящей правке.
	writeRegistry(t, r.Path(), nil)

	select {
	case ids := <-got:
		if len(ids) != 1 || ids[0] != c.ID {
			t.Fatalf("Watch сообщил %v, ожидался %s", ids, c.ID)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Watch не заметил правку файла")
	}
}

func writeRegistry(t *testing.T, path string, list []Client) {
	t.Helper()
	raw, err := json.MarshalIndent(file{Version: fileVersion, Clients: list}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	// Гарантируем отличие mtime на файловых системах с секундной точностью.
	old := time.Now().Add(-2 * time.Second)
	_ = os.Chtimes(path, old, time.Now().Add(time.Second))
}

func longKey() string {
	k, err := NewKey()
	if err != nil {
		panic(err)
	}
	return string(k)
}
