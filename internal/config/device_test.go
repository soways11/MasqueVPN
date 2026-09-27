package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Псевдоним устройства решает, смогут ли два устройства с одним ключом
// работать одновременно и сохранится ли адрес после перезапуска. Отсюда три
// требования: постоянство при том же файле, различие при разных файлах и
// работоспособность без файла вовсе.

func TestDeviceIDStableAcrossRuns(t *testing.T) {
	path := filepath.Join(t.TempDir(), DeviceIDFile)
	first := DeviceIDAt(path)
	if first == "" {
		t.Fatal("псевдоним пуст")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("файл соли не создан: %v — псевдоним будет новым при каждом запуске", err)
	}
	if second := DeviceIDAt(path); second != first {
		t.Fatalf("псевдоним сменился между запусками: %q → %q — после перезапуска сервер выдаст другой адрес", first, second)
	}
}

func TestDeviceIDDiffersPerInstallation(t *testing.T) {
	a := DeviceIDAt(filepath.Join(t.TempDir(), DeviceIDFile))
	b := DeviceIDAt(filepath.Join(t.TempDir(), DeviceIDFile))
	if a == b {
		t.Fatalf("две установки получили один псевдоним %q — работать будет только та, что подключилась последней", a)
	}
}

// Соль не записалась (папка только для чтения, флешка, каталог программы под
// правами администратора) — это не повод не подключаться: псевдоним остаётся
// случайным на запуск.
func TestDeviceIDWorksWhenSaltUnwritable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("права на каталог проверяются иначе")
	}
	if os.Geteuid() == 0 {
		t.Skip("под root каталог только для чтения всё равно доступен на запись")
	}
	dir := t.TempDir()
	ro := filepath.Join(dir, "ro")
	if err := os.Mkdir(ro, 0o500); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(ro, DeviceIDFile)
	id := DeviceIDAt(path)
	if id == "" {
		t.Fatal("без записываемого файла псевдоним не выдан — клиент не подключится")
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("файл всё-таки создан — проверка ничего не проверяет")
	}
	if other := DeviceIDAt(path); other == id {
		t.Fatal("псевдоним повторился, хотя соли нет: он не случаен")
	}
}

// Битый или пустой файл соли не должен ронять клиент: заводим новую соль.
func TestDeviceIDRecoversFromEmptySalt(t *testing.T) {
	path := filepath.Join(t.TempDir(), DeviceIDFile)
	if err := os.WriteFile(path, []byte("   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	id := DeviceIDAt(path)
	if id == "" {
		t.Fatal("псевдоним пуст")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 10 {
		t.Fatalf("пустая соль не заменена: %q", raw)
	}
	if again := DeviceIDAt(path); again != id {
		t.Fatalf("новая соль не сохранилась: %q → %q", id, again)
	}
}
