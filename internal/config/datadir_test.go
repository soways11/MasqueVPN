package config

import (
	"runtime"
	"testing"
)

// Где лежат ключи — вопрос не удобства: не туда положенные, они либо
// теряются (переносная папка без профилей), либо становятся видны чужим
// (домашний каталог root посреди пользовательского), либо не пишутся вовсе
// (/usr/bin).
func TestDataDirFor(t *testing.T) {
	none := func(string) bool { return false }
	cases := []struct {
		exe, goos string
		exists    func(string) bool
		want      string
	}{
		{"/home/user/Downloads/masquevpn/linux/masquevpn-gui", "linux", none, "/home/user/Downloads/masquevpn/linux"},
		{"/usr/lib/masquevpn/masquevpn-gui", "linux", none, LinuxDataDir},
		{"/opt/masquevpn/masquevpn-gui", "linux", none, LinuxDataDir},
		// Файлы разложены руками рядом с установленной — явное главнее.
		{"/usr/lib/masquevpn/masquevpn-gui", "linux",
			func(p string) bool { return p == "/usr/lib/masquevpn/profiles.json" }, "/usr/lib/masquevpn"},
		// Windows: и переносная, и установленная — рядом с программой.
		{`C:\Program Files\masquevpn\masquevpn.exe`, "windows", none, `C:\Program Files\masquevpn`},
	}
	for _, c := range cases {
		if c.goos == "linux" && runtime.GOOS == "windows" {
			// filepath в Windows переписывает / в \ — пути Linux здесь не проверить.
			continue
		}
		got := dataDirFor(c.exe, c.goos, c.exists)
		if c.goos == "windows" && runtime.GOOS == "windows" {
			if got != c.want {
				t.Errorf("%s: каталог данных %q, ожидался %q", c.exe, got, c.want)
			}
			continue
		}
		if c.goos == "windows" {
			// filepath на Linux не понимает обратных слэшей — сравниваем
			// только то, что каталог не подменён на /var/lib.
			if got == LinuxDataDir {
				t.Errorf("%s: Windows получил каталог Linux", c.exe)
			}
			continue
		}
		if got != c.want {
			t.Errorf("%s (%s): каталог данных %q, ожидался %q", c.exe, c.goos, got, c.want)
		}
	}
}

// Первый запуск установленной программы: каталога данных ещё нет, и
// псевдоним устройства обязан его создать, а не молча стать случайным на
// каждый запуск (тогда адрес менялся бы при каждом перезапуске).
func TestDeviceIDCreatesDataDir(t *testing.T) {
	path := t.TempDir() + "/ещё/нет/" + DeviceIDFile
	first := DeviceIDAt(path)
	if !fileExists(path) {
		t.Fatal("каталог данных не создан — псевдоним будет новым при каждом запуске")
	}
	if DeviceIDAt(path) != first {
		t.Fatal("псевдоним сменился между запусками")
	}
}
