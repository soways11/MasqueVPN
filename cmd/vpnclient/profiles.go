package main

// Профили в консольном клиенте: импорт, список, выбор.
//
// Окно получит то же самое, когда за него возьмёмся; здесь это нужно и само
// по себе — чтобы завести доступ на сервере без графики, и чтобы механизм
// профилей проверялся не только тестами.
//
// Флаг -config при этом остаётся главным: если он задан явно, профили не
// трогаются вовсе. Человек, у которого всё работает с файлом, не должен
// узнать о профилях из того, что его конфигурация перестала применяться.

import (
	"fmt"
	"os"
	"strings"

	"github.com/soways11/masquevpn/internal/config"
)

// profileCommands — что можно сделать с профилями из командной строки.
type profileCommands struct {
	path   string // файл профилей
	list   bool
	add    string // ссылка masquevpn:// или путь к файлу
	name   string // имя для добавляемого профиля
	use    string // выбрать профиль
	remove string // удалить профиль
}

// any сообщает, попросили ли что-нибудь сделать с профилями.
func (p profileCommands) any() bool {
	return p.list || p.add != "" || p.use != "" || p.remove != ""
}

// run выполняет запрошенное действие. Возвращает код выхода.
func (p profileCommands) run() int {
	path := p.path
	if path == "" {
		path = config.DefaultProfilesPath()
	}
	profiles, err := config.LoadProfiles(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "vpnclient:", err)
		return 1
	}

	switch {
	case p.add != "":
		pr, err := importProfile(profiles, p.add, p.name)
		if err != nil {
			fmt.Fprintln(os.Stderr, "vpnclient:", err)
			return 1
		}
		if err := profiles.Save(); err != nil {
			fmt.Fprintln(os.Stderr, "vpnclient:", err)
			return 1
		}
		fmt.Printf("профиль добавлен: %s → %s\n", pr.Name, pr.Config.Server)
		if active, ok := profiles.Active(); ok && !strings.EqualFold(active.Name, pr.Name) {
			// Импорт не переключает выбранный профиль: туннель может быть
			// поднят, и переключение окажется неожиданностью. Но человек
			// должен знать, что подключаться будет не туда.
			fmt.Printf("выбран по-прежнему: %s (переключить: -profile-use %q)\n", active.Name, pr.Name)
		}
		return 0

	case p.use != "":
		if err := profiles.Select(p.use); err != nil {
			fmt.Fprintln(os.Stderr, "vpnclient:", err)
			return 1
		}
		if err := profiles.Save(); err != nil {
			fmt.Fprintln(os.Stderr, "vpnclient:", err)
			return 1
		}
		fmt.Printf("выбран профиль: %s\n", profiles.Current)
		return 0

	case p.remove != "":
		if err := profiles.Remove(p.remove); err != nil {
			fmt.Fprintln(os.Stderr, "vpnclient:", err)
			return 1
		}
		if err := profiles.Save(); err != nil {
			fmt.Fprintln(os.Stderr, "vpnclient:", err)
			return 1
		}
		fmt.Printf("профиль удалён: %s\n", p.remove)
		if profiles.Current != "" {
			fmt.Printf("выбран: %s\n", profiles.Current)
		}
		return 0

	default: // list
		return listProfiles(profiles, path)
	}
}

func importProfile(profiles *config.Profiles, src, name string) (config.Profile, error) {
	// Ссылку от пути отличаем по схеме: пути к файлам в Windows содержат
	// двоеточие после буквы диска, поэтому смотреть просто на «://» надёжнее.
	if config.IsLink(src) {
		return profiles.ImportLink(src)
	}
	return profiles.ImportFile(src, name)
}

func listProfiles(profiles *config.Profiles, path string) int {
	if len(profiles.List) == 0 {
		fmt.Println("профилей нет:", path)
		fmt.Println("добавить: vpnclient -profile-add masquevpn://… или -profile-add client.json")
		return 0
	}
	fmt.Println("профили:", path)
	for _, pr := range profiles.List {
		mark := "  "
		if strings.EqualFold(pr.Name, profiles.Current) {
			mark = "→ "
		}
		server := "—"
		if pr.Config != nil {
			server = pr.Config.Server
		}
		fmt.Printf("%s%-24s %s\n", mark, pr.Name, server)
	}
	return 0
}

// activeProfileConfig возвращает конфигурацию выбранного профиля.
//
// Используется, когда -config не задан явно: тогда клиент работает
// профилями. Если профилей нет, вызывающий откатывается на файл по
// умолчанию — так у тех, кто уже пользуется client.json, ничего не меняется.
func activeProfileConfig(path string) (*config.Client, string, bool) {
	if path == "" {
		path = config.DefaultProfilesPath()
	}
	profiles, err := config.LoadProfiles(path)
	if err != nil {
		return nil, "", false
	}
	pr, ok := profiles.Active()
	if !ok || pr.Config == nil {
		return nil, "", false
	}
	return pr.Config, pr.Name, true
}
