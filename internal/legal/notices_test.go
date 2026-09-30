package legal

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const root = "../.."

// TestNoticesUpToDate — THIRD_PARTY_NOTICES.txt совпадает с тем, что
// собирает скрипт из текущих зависимостей. Добавили зависимость и не
// пересобрали файл — в установщики уехал бы код без текста его лицензии.
func TestNoticesUpToDate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("скрипт на sh; концы строк на Windows другие — проверяет Linux-CI")
	}
	if testing.Short() {
		t.Skip("перебирает зависимости всех сборок")
	}
	fresh := filepath.Join(t.TempDir(), "notices.txt")
	cmd := exec.Command("sh", "deploy/third-party-notices.sh", fresh)
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	want, err := os.ReadFile(fresh)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(root, "THIRD_PARTY_NOTICES.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("THIRD_PARTY_NOTICES.txt устарел — пересоберите: sh deploy/third-party-notices.sh")
	}
}

// TestLicensesShipped — LICENSE и THIRD_PARTY_NOTICES.txt кладутся во все
// пакеты, где есть бинарники.
func TestLicensesShipped(t *testing.T) {
	for f, want := range map[string][]string{
		"deploy/linux/build-deb.sh":    {"LICENSE", "THIRD_PARTY_NOTICES.txt"},
		"deploy/vps/build.sh":          {"LICENSE", "THIRD_PARTY_NOTICES.txt"},
		"deploy/windows/masquevpn.nsi": {"LICENSE", "THIRD_PARTY_NOTICES.txt"},
	} {
		b, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range want {
			if !strings.Contains(string(b), w) {
				t.Errorf("%s не кладёт %s в пакет", f, w)
			}
		}
	}
	lic, err := os.ReadFile(filepath.Join(root, "LICENSE"))
	if err != nil || !strings.HasPrefix(string(lic), "MIT License") {
		t.Fatalf("LICENSE: %v", err)
	}
}
