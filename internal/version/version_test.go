package version

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Скрипты сборки задают версию именно этим флагом. Разойдись путь пакета с
// флагом — компоновщик промолчит, и в релиз уйдёт «dev».
func TestScriptsSetVersion(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, f := range []string{
		"deploy/linux/build-deb.sh",
		"deploy/windows/build-installer.sh",
		"deploy/vps/build.sh",
	} {
		b, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			t.Fatal(err)
		}
		if n := strings.Count(string(b), LDFlag); n == 0 {
			t.Errorf("%s не задаёт версию (%s…)", f, LDFlag)
		}
		// Каждый go build в скрипте — с версией.
		if builds := strings.Count(string(b), "go build"); builds != strings.Count(string(b), LDFlag) {
			t.Errorf("%s: go build %d раз, версия задаётся %d", f, builds, strings.Count(string(b), LDFlag))
		}
	}
}

// Флаг действительно доходит до программы: собираем настоящий клиент с
// версией и спрашиваем её.
func TestLDFlagWorks(t *testing.T) {
	if testing.Short() {
		t.Skip("собирает программу")
	}
	bin := filepath.Join(t.TempDir(), "vpnclient")
	cmd := exec.Command("go", "build", "-ldflags", LDFlag+"9.8.7", "-o", bin, "./cmd/vpnclient")
	cmd.Dir = filepath.Join("..", "..")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	out, err := exec.Command(bin, "-version").Output()
	if err != nil || strings.TrimSpace(string(out)) != "masquevpn-cli 9.8.7" {
		t.Fatalf("вывод %q, %v", out, err)
	}
}
