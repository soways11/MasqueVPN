package config

// Где программа держит свои файлы: профили (в них ключи) и псевдоним
// устройства.
//
// # Три случая
//
//   - Переносная копия — папка, скачанная и запущенная как есть. Файлы
//     рядом с программой: так папку можно унести на флешке вместе с
//     доступами. Так было всегда, и так остаётся.
//   - Windows, установленная в Program Files, — тоже рядом с программой.
//     Окно всегда работает с правами администратора (UAC), каталог ему
//     доступен на запись, а удаление программы файлы профилей не трогает.
//   - Linux, установленная пакетом (/usr/…), — /var/lib/masquevpn. В /usr
//     писать нельзя и незачем, а домашний каталог не годится: окно работает
//     от root (через pkexec — туннелю и DNS нужны права), и ключи в
//     ~/.config оказались бы в файлах root посреди чужого каталога. В
//     /var/lib они доступны только root — другим пользователям машины их не
//     прочитать.
//
// Если рядом с установленной программой всё же лежит profiles.json (кто-то
// разложил файлы руками), побеждает он: явное главнее умолчания.

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// LinuxDataDir — каталог данных программы, установленной пакетом в Linux.
const LinuxDataDir = "/var/lib/masquevpn"

// DataDir — каталог файлов программы (см. описание файла).
func DataDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	return dataDirFor(exe, runtime.GOOS, fileExists)
}

// dataDirFor — то же для заданного пути к программе (для тестов).
func dataDirFor(exe, goos string, exists func(string) bool) string {
	dir := filepath.Dir(exe)
	if exists(filepath.Join(dir, ProfilesFile)) {
		return dir
	}
	if goos == "linux" && installedLinux(dir) {
		return LinuxDataDir
	}
	return dir
}

// installedLinux — программа стоит там, куда её кладёт пакет, а не лежит в
// папке пользователя.
func installedLinux(dir string) bool {
	dir = filepath.ToSlash(filepath.Clean(dir))
	return strings.HasPrefix(dir, "/usr/") || strings.HasPrefix(dir, "/opt/")
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}
