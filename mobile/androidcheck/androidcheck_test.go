// Package androidcheck проверяет Android-клиент без Android SDK.
//
// Собрать APK в среде разработки нечем (SDK и Maven закрыты сетью), и
// первая сборка случается на чужой машине. Самые частые причины, по которым
// она падает, видны и без компилятора: ссылка на ресурс, которого нет;
// идентификатор из Kotlin, которого нет в разметке; метод ядра, которого
// gomobile не создал; класс в манифесте, которого нет в исходниках. Здесь
// всё это ловится обычным `go test`.
//
// Kotlin этим не компилируется — типы, импорты и сигнатуры Android API
// проверит только настоящая сборка. Но то, что проверено здесь, на ней уже
// не всплывёт.
package androidcheck

import (
	"bytes"
	"encoding/xml"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var (
	appDir  = filepath.Join("..", "android", "app", "src", "main")
	resDir  = filepath.Join(appDir, "res")
	javaDir = filepath.Join(appDir, "java")
)

// resources — что объявлено в res/: тип → имена.
type resources map[string]map[string]bool

func (r resources) add(typ, name string) {
	if r[typ] == nil {
		r[typ] = map[string]bool{}
	}
	r[typ][name] = true
}

func (r resources) has(typ, name string) bool { return r[typ][name] }

// collect читает res/: файлы дают drawable, layout, mipmap; values — цвета,
// размеры, строки, стили; разметка — идентификаторы @+id.
func collect(t *testing.T) (resources, map[string]string) {
	t.Helper()
	res := resources{}
	files := map[string]string{} // путь → содержимое
	err := filepath.Walk(resDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		dir := filepath.Base(filepath.Dir(path))
		typ := strings.SplitN(dir, "-", 2)[0] // mipmap-anydpi-v26 → mipmap
		name := strings.TrimSuffix(info.Name(), filepath.Ext(info.Name()))
		if typ != "values" {
			res.add(typ, name)
		}
		if filepath.Ext(path) != ".xml" {
			return nil
		}
		raw, err := readText(path)
		if err != nil {
			return err
		}
		files[path] = string(raw)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	for path, text := range files {
		dec := xml.NewDecoder(strings.NewReader(text))
		for {
			tok, err := dec.Token()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("%s: негодный XML: %v", path, err)
			}
			se, ok := tok.(xml.StartElement)
			if !ok {
				continue
			}
			for _, a := range se.Attr {
				if strings.HasPrefix(a.Value, "@+id/") {
					res.add("id", strings.TrimPrefix(a.Value, "@+id/"))
				}
			}
			if filepath.Base(filepath.Dir(path)) != "values" {
				continue
			}
			name := attr(se, "name")
			switch se.Name.Local {
			case "color", "dimen", "string", "plurals", "style":
				res.add(se.Name.Local, name)
				if se.Name.Local == "style" && !hasAttr(se, "parent") {
					res.add("style-implicit", name)
				}
			case "item":
				if typ := attr(se, "type"); typ != "" {
					res.add(typ, name)
				}
			}
		}
	}
	// Стиль с точкой в имени и без parent неявно наследует то, что до
	// последней точки: Masque.Row → Masque. Если такого родителя нет,
	// поведение зависит от версии сборщика ресурсов — полагаться на это
	// незачем. Явный parent="" (или настоящий родитель) снимает вопрос.
	for name := range res["style-implicit"] {
		if i := strings.LastIndexByte(name, '.'); i > 0 && !res.has("style", name[:i]) {
			t.Errorf("стиль %s без parent: неявный родитель %s не существует — задайте parent явно", name, name[:i])
		}
	}
	delete(res, "style-implicit")
	return res, files
}

func hasAttr(se xml.StartElement, local string) bool {
	for _, a := range se.Attr {
		if a.Name.Local == local {
			return true
		}
	}
	return false
}

func attr(se xml.StartElement, local string) string {
	for _, a := range se.Attr {
		if a.Name.Local == local {
			return a.Value
		}
	}
	return ""
}

var xmlRef = regexp.MustCompile(`@(color|dimen|string|drawable|style|mipmap|id|plurals)/([A-Za-z0-9_.]+)`)

// Каждая ссылка @тип/имя в XML ведёт на объявленный ресурс.
func TestXMLReferencesResolve(t *testing.T) {
	res, files := collect(t)
	for path, text := range files {
		for _, m := range xmlRef.FindAllStringSubmatch(text, -1) {
			typ, name := m[1], m[2]
			if !res.has(typ, name) {
				t.Errorf("%s: ссылка @%s/%s — такого ресурса нет", rel(path), typ, name)
			}
		}
	}
	// Ссылки на ресурсы системы (@android:…) не проверяем — они есть в SDK.
}

var ktRef = regexp.MustCompile(`\bR\.(id|layout|drawable|string|color|dimen|style|plurals|mipmap)\.([A-Za-z0-9_]+)`)

// Каждое R.тип.имя из Kotlin существует. Стиль Foo.Bar в R — Foo_Bar.
func TestKotlinReferencesResolve(t *testing.T) {
	res, _ := collect(t)
	styles := map[string]bool{}
	for s := range res["style"] {
		styles[strings.ReplaceAll(s, ".", "_")] = true
	}
	for path, text := range kotlinFiles(t) {
		for _, m := range ktRef.FindAllStringSubmatch(text, -1) {
			typ, name := m[1], m[2]
			ok := res.has(typ, name)
			if typ == "style" {
				ok = styles[name]
			}
			if !ok {
				t.Errorf("%s: R.%s.%s — такого ресурса нет", rel(path), typ, name)
			}
		}
	}
}

// findViewById<…>(R.id.x) ищет в той разметке, которую показывает экран.
// Идентификатор из чужой разметки собрался бы, но на экране вернул бы null
// и уронил приложение при первом касании.
func TestViewIDsBelongToTheirLayout(t *testing.T) {
	_, files := collect(t)
	layoutIDs := func(layout string) map[string]bool {
		ids := map[string]bool{}
		text := files[filepath.Join(resDir, "layout", layout+".xml")]
		for _, m := range regexp.MustCompile(`@\+id/([A-Za-z0-9_]+)`).FindAllStringSubmatch(text, -1) {
			ids[m[1]] = true
		}
		return ids
	}
	contentView := regexp.MustCompile(`setContentView\(R\.layout\.([a-z_]+)\)`)
	byID := regexp.MustCompile(`findViewById(?:<[^>]+>)?\(R\.id\.([a-z_]+)\)`)
	rowFind := regexp.MustCompile(`row\.findViewById(?:<[^>]+>)?\(R\.id\.([a-z_]+)\)`)
	checked := 0
	for path, text := range kotlinFiles(t) {
		m := contentView.FindStringSubmatch(text)
		if m == nil {
			continue
		}
		own := layoutIDs(m[1])
		row := layoutIDs("item_profile")
		rowIDs := map[string]bool{}
		for _, r := range rowFind.FindAllStringSubmatch(text, -1) {
			rowIDs[r[1]] = true
			if !row[r[1]] {
				t.Errorf("%s: R.id.%s ищется в строке профиля, а в item_profile его нет", rel(path), r[1])
			}
		}
		for _, f := range byID.FindAllStringSubmatch(text, -1) {
			checked++
			if rowIDs[f[1]] {
				continue
			}
			if !own[f[1]] {
				t.Errorf("%s: R.id.%s ищется на экране %s, а в его разметке его нет", rel(path), f[1], m[1])
			}
		}
	}
	if checked < 20 {
		t.Fatalf("проверено всего %d поисков по id — разбор сломан, проверка пустая", checked)
	}
}

// bindings — методы ядра, которые создал gobind (по BINDINGS.md).
func bindings(t *testing.T) (static, profiles, tunnel map[string]bool) {
	t.Helper()
	raw, err := readText(filepath.Join("..", "core", "BINDINGS.md"))
	if err != nil {
		t.Fatal(err)
	}
	static, profiles, tunnel = map[string]bool{}, map[string]bool{}, map[string]bool{}
	var cur map[string]bool
	method := regexp.MustCompile(`public (?:static )?(?:final )?(?:native )?[A-Za-z]+ +([a-zA-Z]+)\(`)
	constant := regexp.MustCompile(`public static final \w+ +([A-Za-z]+) *=`)
	for _, line := range strings.Split(string(raw), "\n") {
		switch {
		case strings.Contains(line, "class Core"):
			cur = static
		case strings.Contains(line, "class Profiles"):
			cur = profiles
		case strings.Contains(line, "class Tunnel"):
			cur = tunnel
		case strings.HasPrefix(line, "public interface"):
			cur = nil
		}
		if cur == nil {
			continue
		}
		if m := method.FindStringSubmatch(line); m != nil {
			cur[m[1]] = true
		}
		if m := constant.FindStringSubmatch(line); m != nil {
			cur[m[1]] = true
		}
	}
	if len(profiles) < 10 || len(tunnel) < 6 || len(static) < 8 {
		t.Fatalf("из BINDINGS.md прочитано мало методов (%d/%d/%d) — разбор сломан",
			len(static), len(profiles), len(tunnel))
	}
	return
}

// Каждый вызов ядра из Kotlin существует в привязке. Опечатка в имени или
// метод, который gomobile переименовал, иначе всплыли бы только при сборке.
func TestCoreCallsExistInBindings(t *testing.T) {
	static, profiles, tunnel := bindings(t)
	staticCall := regexp.MustCompile(`\bCore\.([a-zA-Z]+)`)
	// Получатели, про которые известно, что это Profiles или Tunnel.
	profilesCall := regexp.MustCompile(`(?:Store\.profiles\([^)]*\)|\b(?:p|fresh|profiles))\.([a-zA-Z]+)\(`)
	tunnelCall := regexp.MustCompile(`\b(?:tunnel|running\?)\.([a-zA-Z]+)\(`)
	calls := 0
	for path, text := range kotlinFiles(t) {
		text = stripComments(text)
		for _, m := range staticCall.FindAllStringSubmatch(text, -1) {
			calls++
			if !static[m[1]] {
				t.Errorf("%s: Core.%s — в привязке ядра такого нет", rel(path), m[1])
			}
		}
		for _, m := range profilesCall.FindAllStringSubmatch(text, -1) {
			calls++
			if !profiles[m[1]] {
				t.Errorf("%s: Profiles.%s — в привязке ядра такого нет", rel(path), m[1])
			}
		}
		for _, m := range tunnelCall.FindAllStringSubmatch(text, -1) {
			calls++
			if !tunnel[m[1]] {
				t.Errorf("%s: Tunnel.%s — в привязке ядра такого нет", rel(path), m[1])
			}
		}
	}
	if calls < 25 {
		t.Fatalf("найдено всего %d вызовов ядра — разбор сломан, проверка пустая", calls)
	}
}

// Классы из манифеста есть в исходниках, и ни одна активность не забыта.
func TestManifestMatchesSources(t *testing.T) {
	raw, err := readText(filepath.Join(appDir, "AndroidManifest.xml"))
	if err != nil {
		t.Fatal(err)
	}
	manifest := string(raw)
	declared := map[string]bool{}
	for _, m := range regexp.MustCompile(`android:name="\.([A-Za-z]+)"`).FindAllStringSubmatch(manifest, -1) {
		declared[m[1]] = true
	}
	classes := map[string]string{}
	classRe := regexp.MustCompile(`(?m)^class ([A-Za-z]+) *: *([A-Za-z]+)`)
	for path, text := range kotlinFiles(t) {
		for _, m := range classRe.FindAllStringSubmatch(text, -1) {
			classes[m[1]] = m[2]
			_ = path
		}
	}
	for name := range declared {
		if _, ok := classes[name]; !ok {
			t.Errorf("в манифесте .%s, а в исходниках такого класса нет", name)
		}
	}
	for name, base := range classes {
		if (base == "Activity" || base == "VpnService") && !declared[name] {
			t.Errorf("класс %s (%s) не объявлен в манифесте — система его не запустит", name, base)
		}
	}
	res, _ := collect(t)
	for _, m := range xmlRef.FindAllStringSubmatch(manifest, -1) {
		if !res.has(m[1], m[2]) {
			t.Errorf("манифест: @%s/%s — такого ресурса нет", m[1], m[2])
		}
	}
	// Пакет в исходниках совпадает с namespace сборки: иначе R не найдётся.
	gradle, err := readText(filepath.Join("..", "android", "app", "build.gradle.kts"))
	if err != nil {
		t.Fatal(err)
	}
	ns := regexp.MustCompile(`namespace = "([^"]+)"`).FindStringSubmatch(string(gradle))
	if ns == nil {
		t.Fatal("в build.gradle.kts нет namespace")
	}
	for path, text := range kotlinFiles(t) {
		if !strings.Contains(text, "package "+ns[1]+"\n") {
			t.Errorf("%s: пакет не %s — R и BuildConfig окажутся в другом пакете", rel(path), ns[1])
		}
	}
}

// Строки, которые Kotlin форматирует через getString(id, аргументы), должны
// содержать подстановки — и наоборот.
func TestFormatStringsHaveArguments(t *testing.T) {
	_, files := collect(t)
	strs := map[string]string{}
	re := regexp.MustCompile(`<string name="([a-z_]+)">([^<]*)</string>`)
	for path, text := range files {
		if filepath.Base(path) != "strings.xml" {
			continue
		}
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			strs[m[1]] = m[2]
		}
	}
	withArgs := regexp.MustCompile(`getString\(R\.string\.([a-z_]+),`)
	for path, text := range kotlinFiles(t) {
		for _, m := range withArgs.FindAllStringSubmatch(text, -1) {
			if !strings.Contains(strs[m[1]], "%1$s") && !strings.Contains(strs[m[1]], "%d") {
				t.Errorf("%s: getString(R.string.%s, …) — в строке нет подстановки: %q", rel(path), m[1], strs[m[1]])
			}
		}
	}
}

// stripComments убирает комментарии Kotlin: «Core.State*» в пояснении —
// не вызов, и проверять его по привязке незачем.
func stripComments(src string) string {
	src = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(src, "")
	return regexp.MustCompile(`//[^\n]*`).ReplaceAllString(src, "")
}

func kotlinFiles(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(javaDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || filepath.Ext(path) != ".kt" {
			return err
		}
		raw, err := readText(path)
		if err != nil {
			return err
		}
		out[path] = string(raw)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) < 4 {
		t.Fatalf("найдено %d файлов Kotlin — не тот каталог?", len(out))
	}
	return out
}

func rel(path string) string {
	r, err := filepath.Rel(filepath.Join("..", "android"), path)
	if err != nil {
		return path
	}
	return r
}

// Для отладки самого теста: какие ресурсы он видит.
func TestResourceInventory(t *testing.T) {
	res, _ := collect(t)
	var types []string
	for typ := range res {
		types = append(types, typ)
	}
	sort.Strings(types)
	for _, typ := range types {
		t.Logf("%s: %d", typ, len(res[typ]))
	}
	for _, need := range []string{"color", "dimen", "string", "style", "drawable", "layout", "mipmap", "id"} {
		if len(res[need]) == 0 {
			t.Errorf("ресурсов типа %s не найдено — разбор res/ сломан", need)
		}
	}
}

// Вызовы системных API, которым нужно разрешение, — и разрешение в
// манифесте. Без разрешения такой вызов не ошибка компиляции, а
// SecurityException на телефоне: так первая сборка и упала на
// ConnectivityManager.activeNetwork. Список — только то, что приложение
// действительно зовёт; новый вызов такого рода — новая строка здесь.
func TestPermissionsForAPIs(t *testing.T) {
	raw, err := readText(filepath.Join(appDir, "AndroidManifest.xml"))
	if err != nil {
		t.Fatal(err)
	}
	manifest := stripXMLComments(string(raw))
	needs := []struct {
		api        *regexp.Regexp
		permission string
	}{
		{regexp.MustCompile(`\bactiveNetwork\b|getLinkProperties\(|getNetworkCapabilities\(|registerNetworkCallback\(|allNetworks\b`), "android.permission.ACCESS_NETWORK_STATE"},
		{regexp.MustCompile(`\bstartForeground\(`), "android.permission.FOREGROUND_SERVICE"},
		{regexp.MustCompile(`\bnotify\(`), "android.permission.POST_NOTIFICATIONS"},
		{regexp.MustCompile(`\bVpnService\b`), "android.permission.INTERNET"},
	}
	used := 0
	for path, text := range kotlinFiles(t) {
		code := stripComments(text)
		for _, n := range needs {
			if !n.api.MatchString(code) {
				continue
			}
			used++
			if !strings.Contains(manifest, `<uses-permission android:name="`+n.permission+`"`) {
				t.Errorf("%s зовёт %q, а в манифесте нет %s — на телефоне это SecurityException",
					rel(path), n.api.FindString(code), n.permission)
			}
		}
	}
	if used < 3 {
		t.Fatalf("найдено всего %d вызовов из списка — разбор сломан, проверка пустая", used)
	}
}

func stripXMLComments(s string) string {
	return regexp.MustCompile(`(?s)<!--.*?-->`).ReplaceAllString(s, "")
}

// readText читает исходник с концами строк как в репозитории. Git для
// Windows (и раннер GitHub) по умолчанию выдаёт файлы с CRLF, а проверки
// ищут "\n" — без этого они видят чужие ошибки.
func readText(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	return bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n")), err
}
