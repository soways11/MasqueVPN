package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/soways11/masquevpn/internal/clients"
	"github.com/soways11/masquevpn/internal/config"
)

// Команды управления клиентами.
//
//	vpnserver clients list
//	vpnserver clients add -name "Ноутбук" -quota 200GB -period month
//	vpnserver clients show    -id 1a2b...
//	vpnserver clients disable -id 1a2b...
//	vpnserver clients enable  -id 1a2b...
//	vpnserver clients remove  -id 1a2b...
//
// Работают без root и без запущенного сервера: это правка файла. Сервер
// перечитывает реестр сам, отзыв доходит до него за несколько секунд.

const clientsUsage = `vpnserver clients — управление клиентами

  list                    список клиентов и расход
  add                     создать клиента (выдаёт псевдоним и ключ)
  show    -id ID          подробности по клиенту
  disable -id ID          приостановить доступ (запись и расход остаются)
  enable  -id ID          вернуть доступ
  remove  -id ID          удалить клиента
  backup                  снять резервную копию реестра и учёта
  restore -from ФАЙЛ      вернуть реестр и учёт из копии

Общие флаги:
  -config ФАЙЛ   конфигурация сервера, из неё берётся clients_file
  -file ФАЙЛ     файл реестра напрямую (без конфигурации)

Флаги add:
  -name ИМЯ           человеческое имя
  -quota РАЗМЕР       квота за период, например 200GB (0 — без квоты)
  -period month|day   когда сбрасывать квоту (по умолчанию month при quota)
  -max-sessions N     сколько сессий разрешено одновременно
  -rate РАЗМЕР        потолок полосы, например 20MB (в секунду)
  -server АДРЕС       адрес сервера для готовой конфигурации клиента;
                      запасные порты из конфигурации сервера (alt_ports)
                      дописываются сами: host:8443 → host:8443,2053,…
  -single-port        не дописывать запасные порты (клиенты до 0.4.0 не
                      понимают адрес с несколькими портами)
  -note ТЕКСТ         пометка
  -out ФАЙЛ           записать конфигурацию в файл; ключ и ссылка
                      не попадут в терминал (рядом ляжет ФАЙЛ.link)

Флаги backup/restore:
  -out ФАЙЛ      куда снять копию (по умолчанию рядом с реестром, с датой)
  -from ФАЙЛ     из какой копии восстанавливать

В реестре лежат ключи всех клиентов, и восстановить их неоткуда: потеря
файла отключает всех разом. Снимайте копию после каждой выдачи.
`

func clientsCommand(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, clientsUsage)
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("clients "+sub, flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, clientsUsage) }
	cfgPath := fs.String("config", "", "конфигурация сервера (из неё берётся clients_file)")
	file := fs.String("file", "", "файл реестра клиентов")
	id := fs.String("id", "", "псевдоним клиента")
	name := fs.String("name", "", "имя клиента")
	quota := fs.String("quota", "", "квота за период (например 200GB)")
	period := fs.String("period", "", "период сброса квоты: month или day")
	maxSessions := fs.Int("max-sessions", 0, "сколько сессий разрешено одновременно")
	rate := fs.String("rate", "", "потолок полосы в секунду (например 20MB)")
	server := fs.String("server", "", "адрес сервера для конфигурации клиента")
	singlePort := fs.Bool("single-port", false, "не дописывать запасные порты")
	note := fs.String("note", "", "пометка")
	out := fs.String("out", "", "куда записать конфигурацию клиента или резервную копию")
	from := fs.String("from", "", "из какой копии восстанавливать (restore)")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	path, srvFromCfg, cfgPorts, err := clientsPath(*cfgPath, *file)
	if err != nil {
		fmt.Fprintln(os.Stderr, "vpnserver clients:", err)
		return 2
	}
	if *server == "" {
		*server = srvFromCfg
	}
	if *server != "" && sub == "add" {
		if *server, err = withServerPorts(*server, cfgPorts, *singlePort); err != nil {
			fmt.Fprintln(os.Stderr, "vpnserver clients: -server:", err)
			return 2
		}
	}
	reg, err := clients.Open(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "vpnserver clients:", err)
		return 1
	}
	acc, err := clients.NewAccountant(usagePathFor(path, *cfgPath), reg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "vpnserver clients:", err)
		return 1
	}

	switch sub {
	case "list":
		return clientsList(reg, acc)
	case "add":
		q, err := parseSize(*quota)
		if err != nil {
			fmt.Fprintln(os.Stderr, "vpnserver clients: -quota:", err)
			return 2
		}
		r, err := parseSize(*rate)
		if err != nil {
			fmt.Fprintln(os.Stderr, "vpnserver clients: -rate:", err)
			return 2
		}
		p := *period
		if q > 0 && p == "" {
			p = "month"
		}
		c, err := reg.Add(clients.Client{
			Name: *name, Quota: q, Period: p,
			MaxSessions: *maxSessions, MaxBytesPerSecond: int(r), Note: *note,
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "vpnserver clients:", err)
			return 1
		}
		return clientsIssue(os.Stdout, c, *server, *out)
	case "show":
		c, ok := reg.Lookup(*id)
		if !ok {
			fmt.Fprintf(os.Stderr, "vpnserver clients: нет клиента %s\n", *id)
			return 1
		}
		u := acc.Usage(c.ID)
		fmt.Printf("%s  %s\n", c.ID, c.Name)
		fmt.Printf("  доступ:        %s\n", accessWord(c))
		fmt.Printf("  создан:        %s\n", c.Created.Format(time.DateOnly))
		fmt.Printf("  квота:         %s\n", quotaWord(c, u))
		fmt.Printf("  полоса:        %s\n", rateWord(c))
		fmt.Printf("  сессий разом:  %s\n", limitWord(c.MaxSessions))
		fmt.Printf("  израсходовано: %s за период, %s всего\n", size(u.Bytes), size(u.Total))
		fmt.Printf("  сессий всего:  %d\n", u.Sessions)
		if !u.LastSeen.IsZero() {
			fmt.Printf("  последний раз: %s\n", u.LastSeen.Format(time.DateTime))
		}
		if c.Note != "" {
			fmt.Printf("  пометка:       %s\n", c.Note)
		}
		return 0
	case "disable", "enable":
		want := sub == "disable"
		c, err := reg.Update(*id, func(c *clients.Client) error { c.Disabled = want; return nil })
		if err != nil {
			fmt.Fprintln(os.Stderr, "vpnserver clients:", err)
			return 1
		}
		fmt.Printf("клиент %s (%s): %s\n", c.ID, c.Name, accessWord(c))
		if want {
			fmt.Println("сервер закроет его живые сессии при ближайшем перечитывании реестра")
		}
		return 0
	case "backup":
		return makeBackup(os.Stdout, path, usagePathFor(path, *cfgPath), *out)
	case "restore":
		if *from == "" {
			fmt.Fprintln(os.Stderr, "vpnserver clients restore: нужен -from ФАЙЛ")
			return 2
		}
		return restoreBackup(os.Stdout, path, usagePathFor(path, *cfgPath), *from)
	case "remove":
		if err := reg.Remove(*id); err != nil {
			fmt.Fprintln(os.Stderr, "vpnserver clients:", err)
			return 1
		}
		fmt.Printf("клиент %s удалён; сервер закроет его сессии при ближайшем перечитывании\n", *id)
		return 0
	default:
		fmt.Fprint(os.Stderr, clientsUsage)
		return 2
	}
}

func clientsList(reg *clients.Registry, acc *clients.Accountant) int {
	list := reg.Snapshot()
	if len(list) == 0 {
		fmt.Println("реестр пуст:", reg.Path())
		fmt.Println("добавьте клиента: vpnserver clients add -name ИМЯ")
		return 0
	}
	fmt.Printf("%-16s  %-20s  %-9s  %-18s  %s\n", "ПСЕВДОНИМ", "ИМЯ", "ДОСТУП", "РАСХОД", "ПОСЛЕДНИЙ РАЗ")
	for _, c := range list {
		u := acc.Usage(c.ID)
		last := "—"
		if !u.LastSeen.IsZero() {
			last = u.LastSeen.Format(time.DateTime)
		}
		used := size(u.Bytes)
		if c.Quota > 0 {
			used = fmt.Sprintf("%s / %s", size(u.Bytes), size(c.Quota))
		}
		fmt.Printf("%-16s  %-20s  %-9s  %-18s  %s\n", c.ID, trim(c.Name, 20), accessWord(c), used, last)
	}
	return 0
}

// clientsPath выясняет, где лежит реестр: из -file либо из конфигурации.
func clientsPath(cfgPath, file string) (path, server string, ports []int, err error) {
	if file != "" {
		return file, "", nil, nil
	}
	if cfgPath == "" {
		cfgPath = config.DefaultServerConfig()
	}
	cfg, err := config.LoadServer(cfgPath)
	if err != nil {
		return "", "", nil, fmt.Errorf("%s: %w (укажите -file, если конфигурации нет)", cfgPath, err)
	}
	if cfg.ClientsFile == "" {
		return "", "", nil, errors.New("в конфигурации не задан clients_file")
	}
	ports, err = cfg.UDPPorts()
	if err != nil {
		return "", "", nil, err
	}
	if len(cfg.ACME.Domains) > 0 {
		server = config.JoinServer(cfg.ACME.Domains[0], ports)
	}
	return cfg.ClientsFile, server, ports, nil
}

// withServerPorts дописывает к адресу из -server запасные порты сервера.
//
// Человек пишет адрес так, как привык, — «домен:8443», — а клиент должен
// знать все порты: иначе при блокировке основного ему некуда уйти. Порт из
// адреса идёт первым (с него клиент начнёт), остальные — в порядке
// конфигурации. Адрес, где порты уже перечислены, не трогаем: значит, их
// выбрали сознательно.
func withServerPorts(server string, cfgPorts []int, single bool) (string, error) {
	host, ports, err := config.SplitServer(config.WithDefaultPort(server))
	if err != nil {
		return "", err
	}
	if single {
		return net.JoinHostPort(host, ports[0]), nil
	}
	if len(ports) > 1 || len(cfgPorts) < 2 {
		return config.WithDefaultPort(server), nil
	}
	first, _ := strconv.Atoi(ports[0])
	out := []int{first}
	for _, p := range cfgPorts {
		if p != first {
			out = append(out, p)
		}
	}
	return config.JoinServer(host, out), nil
}

func usagePathFor(clientsFile, cfgPath string) string {
	if cfgPath != "" {
		if cfg, err := config.LoadServer(cfgPath); err == nil {
			if p := cfg.UsagePath(); p != "" {
				return p
			}
		}
	}
	return clientsFile + ".usage"
}

// clientConfigJSON печатает готовую конфигурацию клиента.
// clientsIssue выдаёт доступ: конфигурация, ссылка для импорта и понятное
// напутствие.
//
// # Почему по умолчанию в файл, а не в терминал
//
// Ключ, напечатанный в терминал, остаётся в его истории, в буфере обмена и
// в журнале сессии SSH, а оттуда — в резервных копиях. Владелец сервера
// обычно об этом не думает: команду он выполняет один раз.
//
// Поэтому при -out наружу не выходит НИ ключ, НИ ссылка: ссылка несёт тот же
// ключ, и печатать её рядом со словами «ключ в терминале не показан» значило
// бы обманывать. Она уезжает во второй файл, рядом с конфигурацией.
// Замечено при первой же живой проверке.
func clientsIssue(w io.Writer, c clients.Client, server, out string) int {
	cfg := clientConfig(c, server)
	link, err := config.EncodeLink(cfg, c.Name)
	if err != nil {
		fmt.Fprintln(os.Stderr, "vpnserver clients:", err)
		return 1
	}
	raw, err := json.MarshalIndent(minimalClientJSON(cfg), "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "vpnserver clients:", err)
		return 1
	}

	fmt.Fprintf(w, "клиент создан: %s  %s\n", c.ID, c.Name)
	if _, ports, err := config.SplitServer(cfg.Server); err == nil && len(ports) > 1 {
		fmt.Fprintf(w, "порты сервера:  %s — клиент перебирает их сам, если основной закрыт\n", strings.Join(ports, ", "))
		fmt.Fprintln(w, "                (такой адрес понимают клиенты 0.4.0 и новее; для старых — -single-port)")
	}
	fmt.Fprintln(w)

	if out != "" {
		linkPath := strings.TrimSuffix(out, filepath.Ext(out)) + ".link"
		if err := os.WriteFile(out, append(raw, '\n'), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "vpnserver clients:", err)
			return 1
		}
		if err := os.WriteFile(linkPath, []byte(link+"\n"), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "vpnserver clients:", err)
			return 1
		}
		fmt.Fprintf(w, "конфигурация:    %s\n", out)
		fmt.Fprintf(w, "ссылка импорта:  %s\n", linkPath)
		fmt.Fprintln(w, "оба файла с правами 0600")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Ни ключ, ни ссылка в терминале не показаны: ссылка несёт тот же")
		fmt.Fprintln(w, "ключ. Передавайте файлы так же осторожно, как сам ключ.")
		return 0
	}

	fmt.Fprintln(w, "Конфигурация клиента (client.json):")
	fmt.Fprintln(w, string(raw))
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Ссылка для импорта (вставить в клиент на компьютере или телефоне):")
	fmt.Fprintln(w, link)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Ключ больше нигде не показывается в открытом виде — сохраните его сейчас.")
	fmt.Fprintln(w, "И ключ, и ссылка сейчас остались в истории терминала: -out ФАЙЛ")
	fmt.Fprintln(w, "запишет их в файлы и ничего не напечатает.")
	return 0
}

// clientConfig собирает конфигурацию клиента.
//
// Заполняются только обязательные поля: всё остальное клиент подставит сам
// (полный туннель, IPv6, транспорт с отпечатком браузера, метка
// WebTransport, резолвер, ротация, прикрытие). Писать их явно значит
// показывать человеку десяток строк, из которых ни одну не нужно трогать, —
// и он перестаёт замечать те, которые трогать как раз стоит.
func clientConfig(c clients.Client, server string) *config.Client {
	if server == "" {
		server = "ВАШ.ДОМЕН:443"
	}
	return &config.Client{
		Server:   server,
		AuthKey:  config.Key(c.Key),
		ClientID: c.ID,
	}
}

// minimalClientJSON — та же конфигурация в виде, пригодном для файла.
func minimalClientJSON(c *config.Client) map[string]any {
	return map[string]any{
		"server":    c.Server,
		"auth_key":  string(c.AuthKey),
		"client_id": c.ClientID,
	}
}

func accessWord(c clients.Client) string {
	if c.Disabled {
		return "закрыт"
	}
	return "открыт"
}

func quotaWord(c clients.Client, u clients.Usage) string {
	if c.Quota <= 0 {
		return "без квоты"
	}
	word := map[string]string{"month": "в месяц", "day": "в сутки"}[c.Period]
	if word == "" {
		word = "без сброса"
	}
	return fmt.Sprintf("%s %s (осталось %s)", size(c.Quota), word, size(max64(c.Quota-u.Bytes, 0)))
}

func rateWord(c clients.Client) string {
	if c.MaxBytesPerSecond <= 0 {
		return "общая для сервера"
	}
	return size(int64(c.MaxBytesPerSecond)) + "/с"
}

func limitWord(n int) string {
	if n <= 0 {
		return "без лимита"
	}
	return strconv.Itoa(n)
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func trim(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

// size печатает размер по-человечески.
func size(n int64) string {
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < 4; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "kMGTP"[exp])
}

// parseSize читает размер вида 200GB, 512MB, 1000000. Десятичные приставки,
// а не двоичные: у провайдеров и в тарифах гигабайт — это 10^9, и считать
// квоту не так, как считает счёт за трафик, — способ удивить пользователя.
func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" || s == "0" {
		return 0, nil
	}
	mult := int64(1)
	for _, suf := range []struct {
		s string
		m int64
	}{
		{"KB", 1_000}, {"MB", 1_000_000}, {"GB", 1_000_000_000}, {"TB", 1_000_000_000_000},
		{"K", 1_000}, {"M", 1_000_000}, {"G", 1_000_000_000}, {"T", 1_000_000_000_000},
	} {
		if strings.HasSuffix(s, suf.s) {
			mult = suf.m
			s = strings.TrimSpace(strings.TrimSuffix(s, suf.s))
			break
		}
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("не похоже на размер: %q", s)
	}
	if v < 0 {
		return 0, errors.New("размер отрицательный")
	}
	return int64(v * float64(mult)), nil
}
