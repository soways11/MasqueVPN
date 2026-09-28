package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/soways11/masquevpn/internal/config"
)

// Команда портов:
//
//	vpnserver ports [-config ФАЙЛ]                     порты через пробел
//	vpnserver ports [-config ФАЙЛ] -set 8443,2053,2083 записать порты
//	vpnserver ports [-config ФАЙЛ] -set default        стандартный набор
//
// Нужна установщику: править JSON из shell построчно — значит однажды
// сломать чужую конфигурацию. Здесь правка идёт разбором: меняются только
// listen (его порт; адрес остаётся) и alt_ports, порядок остальных полей
// сохраняется, результат проверяется целиком до записи, прежний файл
// остаётся копией рядом.

const portsUsage = `vpnserver ports — UDP-порты сервера

  vpnserver ports [-config ФАЙЛ]              показать (через пробел, первый — основной)
  vpnserver ports [-config ФАЙЛ] -set СПИСОК  записать: первый порт — в listen,
                                              остальные — в alt_ports
  vpnserver ports [-config ФАЙЛ] -set default стандартный набор: ` + "443 8443 2053 2083 2087 2096" + `

Сервер подхватывает порты при перезапуске: systemctl restart masquevpn.
Клиентам, выданным раньше, новые порты не известны — их адрес содержит
только прежний порт; перевыдайте доступ (clients add), чтобы клиент знал все.
`

func portsCommand(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ports", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, portsUsage) }
	cfgPath := fs.String("config", config.DefaultServerConfig(), "конфигурация сервера")
	set := fs.String("set", "", "порты через запятую или default")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *set == "" {
		cfg, err := config.LoadServer(*cfgPath)
		if err != nil {
			fmt.Fprintln(stderr, "vpnserver ports:", err)
			return 1
		}
		ports, err := cfg.UDPPorts()
		if err != nil {
			fmt.Fprintln(stderr, "vpnserver ports:", err)
			return 1
		}
		fmt.Fprintln(stdout, joinInts(ports, " "))
		return 0
	}
	ports, err := config.ParsePorts(*set)
	if err != nil {
		fmt.Fprintln(stderr, "vpnserver ports:", err)
		return 2
	}
	cur, err := config.LoadServer(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "vpnserver ports:", err)
		return 1
	}
	if have, err := cur.UDPPorts(); err == nil && joinInts(have, " ") == joinInts(ports, " ") {
		fmt.Fprintln(stdout, "порты уже такие:", joinInts(ports, " "))
		return 0
	}
	raw, err := os.ReadFile(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "vpnserver ports:", err)
		return 1
	}
	out, err := setPortsJSON(raw, ports)
	if err != nil {
		fmt.Fprintf(stderr, "vpnserver ports: %s: %v\n", *cfgPath, err)
		return 1
	}
	// Проверяем результат целиком, как его прочтёт сервер, — до записи.
	tmp := *cfgPath + ".new"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		fmt.Fprintln(stderr, "vpnserver ports:", err)
		return 1
	}
	if _, err := config.LoadServer(tmp); err != nil {
		os.Remove(tmp)
		fmt.Fprintln(stderr, "vpnserver ports: конфигурация после правки не проходит проверку, файл не тронут:", err)
		return 1
	}
	backup := fmt.Sprintf("%s.bak.%d", *cfgPath, time.Now().Unix())
	if err := os.WriteFile(backup, raw, 0o600); err != nil {
		os.Remove(tmp)
		fmt.Fprintln(stderr, "vpnserver ports:", err)
		return 1
	}
	if err := os.Rename(tmp, *cfgPath); err != nil {
		os.Remove(tmp)
		fmt.Fprintln(stderr, "vpnserver ports:", err)
		return 1
	}
	fmt.Fprintln(stdout, "порты записаны:", joinInts(ports, " "), "(основной —", strconv.Itoa(ports[0])+")")
	fmt.Fprintln(stdout, "прежняя конфигурация:", backup)
	return 0
}

// setPortsJSON меняет в конфигурации порт listen и alt_ports, сохраняя
// порядок полей. Адрес из listen (например 0.0.0.0) остаётся.
func setPortsJSON(raw []byte, ports []int) ([]byte, error) {
	if len(ports) == 0 {
		return nil, errors.New("список портов пуст")
	}
	type kv struct {
		k string
		v json.RawMessage
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, errors.New("это не JSON-объект")
	}
	var kvs []kv
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		kvs = append(kvs, kv{t.(string), v})
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}

	host := ""
	li := -1
	for i, e := range kvs {
		if e.k == "listen" {
			var l string
			if err := json.Unmarshal(e.v, &l); err != nil {
				return nil, fmt.Errorf("listen: %w", err)
			}
			if h, _, err := net.SplitHostPort(l); err == nil {
				host = h
			}
			li = i
		}
	}
	listen, _ := json.Marshal(net.JoinHostPort(host, strconv.Itoa(ports[0])))
	if li < 0 {
		kvs = append([]kv{{"listen", listen}}, kvs...)
		li = 0
	} else {
		kvs[li].v = listen
	}
	// alt_ports — сразу за listen: так их видно вместе.
	kept := kvs[:0]
	for _, e := range kvs {
		if e.k != "alt_ports" {
			kept = append(kept, e)
		}
	}
	kvs = kept
	for i, e := range kvs {
		if e.k == "listen" {
			li = i
		}
	}
	if len(ports) > 1 {
		alt := []byte("[" + joinInts(ports[1:], ", ") + "]")
		kvs = append(kvs[:li+1], append([]kv{{"alt_ports", alt}}, kvs[li+1:]...)...)
	}

	var b bytes.Buffer
	b.WriteString("{\n")
	for i, e := range kvs {
		key, _ := json.Marshal(e.k)
		b.WriteString("  ")
		b.Write(key)
		b.WriteString(": ")
		// Значение пишется байт в байт, как было в файле: вложенные блоки
		// уже с отступами под этот уровень, а json.Indent развернул бы
		// короткие «{ "name": …, "mtu": … }» в столбик.
		b.Write(e.v)
		if i < len(kvs)-1 {
			b.WriteByte(',')
		}
		b.WriteByte('\n')
	}
	b.WriteString("}\n")
	return b.Bytes(), nil
}

func joinInts(p []int, sep string) string {
	s := make([]string, len(p))
	for i, v := range p {
		s[i] = strconv.Itoa(v)
	}
	return strings.Join(s, sep)
}
