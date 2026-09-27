package config

// Профили: несколько доступов в одном клиенте.
//
// # Зачем
//
// До сих пор клиент знал ровно одну конфигурацию — файл рядом с программой.
// Стоит завести второй доступ (рабочий, запасной, чужой сервер), и человек
// начинает переименовывать файлы руками, а окно показывает путь к файлу
// вместо ответа на вопрос «куда я сейчас подключён».
//
// Профиль — это именованная конфигурация плюс отметка, какой из них выбран.
// Ничего больше: ни синхронизации, ни истории, ни групп. Всё это легко
// придумать и тяжело поддерживать, а нужно оно куда реже, чем кажется.
//
// # Где лежит
//
// Рядом с программой, в её каталоге: `profiles.json`. Не в профиле
// пользователя, потому что клиент работает от администратора, и файл в
// AppData администратора невидим для того, кто запустил программу обычным
// двойным щелчком. Не в ProgramData — чтобы папку с программой можно было
// перенести на флешке вместе со всеми доступами.
//
// Права 0600: внутри ключи.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ProfilesFile — имя файла профилей рядом с программой.
const ProfilesFile = "profiles.json"

// Profile — именованный доступ.
type Profile struct {
	// Name — как его называет человек: «домашний», «работа».
	Name string `json:"name"`
	// Config — сама конфигурация, в минимальном виде.
	Config *Client `json:"config"`
}

// Profiles — все доступы и выбранный.
type Profiles struct {
	// Current — имя выбранного профиля.
	Current string    `json:"current,omitempty"`
	List    []Profile `json:"profiles"`

	path string
}

// LoadProfiles читает файл профилей. Отсутствие файла — не ошибка: это
// первый запуск.
func LoadProfiles(path string) (*Profiles, error) {
	p := &Profiles{path: path}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return nil, err
	}
	// Разбор общий с телефоном, где профили лежат не в файле, а в
	// хранилище приложения: правила чтения одни.
	parsed, err := ParseProfiles(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	parsed.path = path
	return parsed, nil
}

// Save записывает профили. Права 0600: внутри ключи.
func (p *Profiles) Save() error {
	if p.path == "" {
		return errors.New("config: не задан путь к файлу профилей")
	}
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(p.path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	return os.WriteFile(p.path, append(raw, '\n'), 0o600)
}

// Add добавляет профиль и возвращает добавленный. Имя, совпадающее с уже
// существующим, заменяет его: человек, импортирующий ссылку второй раз,
// чинит доступ, а не заводит «домашний (2)».
//
// Выбранный профиль при этом НЕ меняется — кроме случая, когда его ещё нет.
// Импорт второго доступа не должен переключать туда, где человек сейчас
// работает: туннель может быть поднят, и переключение окажется полной
// неожиданностью.
func (p *Profiles) Add(name string, c *Client) (Profile, error) {
	if c == nil {
		return Profile{}, errors.New("config: пустая конфигурация")
	}
	if err := c.Validate(); err != nil {
		return Profile{}, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = defaultName(c)
	}
	for i, pr := range p.List {
		if strings.EqualFold(pr.Name, name) {
			p.List[i].Config = c
			return p.List[i], nil
		}
	}
	added := Profile{Name: name, Config: c}
	p.List = append(p.List, added)
	if p.Current == "" {
		p.Current = name
	}
	return added, nil
}

// Remove удаляет профиль по имени.
func (p *Profiles) Remove(name string) error {
	for i, pr := range p.List {
		if !strings.EqualFold(pr.Name, name) {
			continue
		}
		p.List = append(p.List[:i], p.List[i+1:]...)
		if strings.EqualFold(p.Current, name) {
			// Выбранный удалён — выбираем первый оставшийся, чтобы клиент
			// не оказался «без профиля» при непустом списке.
			p.Current = ""
			if len(p.List) > 0 {
				p.Current = p.List[0].Name
			}
		}
		return nil
	}
	return fmt.Errorf("config: нет профиля %q", name)
}

// Select выбирает профиль.
func (p *Profiles) Select(name string) error {
	for _, pr := range p.List {
		if strings.EqualFold(pr.Name, name) {
			p.Current = pr.Name
			return nil
		}
	}
	return fmt.Errorf("config: нет профиля %q", name)
}

// Active возвращает выбранный профиль.
func (p *Profiles) Active() (Profile, bool) {
	if len(p.List) == 0 {
		return Profile{}, false
	}
	for _, pr := range p.List {
		if strings.EqualFold(pr.Name, p.Current) {
			return pr, true
		}
	}
	// Выбранного нет (файл правили руками) — берём первый, но не молчим:
	// вызывающий увидит имя, отличное от запрошенного.
	return p.List[0], true
}

// ImportLink добавляет профиль из ссылки masquevpn:// (или прежней govpn://).
func (p *Profiles) ImportLink(link string) (Profile, error) {
	c, name, err := DecodeLink(link)
	if err != nil {
		return Profile{}, err
	}
	return p.Add(name, c)
}

// ImportFile добавляет профиль из файла конфигурации. Имя берётся из
// аргумента, а при пустом — из имени файла: `работа.json` даёт «работа».
func (p *Profiles) ImportFile(path, name string) (Profile, error) {
	c, err := LoadClient(path)
	if err != nil {
		return Profile{}, err
	}
	if name == "" {
		base := filepath.Base(path)
		name = strings.TrimSuffix(base, filepath.Ext(base))
		if strings.EqualFold(name, "client") {
			// «client.json» — имя по умолчанию, оно ничего не говорит.
			name = ""
		}
	}
	return p.Add(name, c)
}

// defaultName — имя профиля, когда его не дали: домен сервера без порта.
// Лучше, чем «профиль 1»: по нему видно, куда он ведёт.
func defaultName(c *Client) string {
	host := c.Server
	if i := strings.LastIndexByte(host, ':'); i > 0 {
		host = host[:i]
	}
	if host == "" {
		return "профиль"
	}
	return host
}

// DefaultProfilesPath — файл профилей: рядом с программой или, у
// установленной пакетом в Linux, в /var/lib/masquevpn (см. DataDir).
func DefaultProfilesPath() string { return filepath.Join(DataDir(), ProfilesFile) }
