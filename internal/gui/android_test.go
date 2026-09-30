package gui

import (
	"encoding/xml"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var updateAndroid = flag.Bool("update", false, "переписать ресурсы Android из палитры")

// androidValues — каталог ресурсов Android-клиента относительно этого пакета.
var androidValues = filepath.Join("..", "..", "mobile", "android", "app", "src", "main", "res", "values")

// Ресурсы в репозитории должны совпадать с палитрой и метриками окна. Если
// поменяли цвет здесь и не пересобрали ресурсы, телефон молча остался бы со
// старым — ровно та рассинхронизация, ради которой ресурсы генерируются.
func TestAndroidResources(t *testing.T) {
	files := map[string]string{
		"colors.xml":      AndroidColorsXML(),
		"dimens.xml":      AndroidDimensXML(),
		"text_styles.xml": AndroidTextStylesXML(),
	}
	for name, want := range files {
		// Сперва — что это вообще разбирается как XML: ошибка в генераторе
		// иначе всплыла бы только при сборке APK, на чужой машине.
		if err := xml.Unmarshal([]byte(want), new(struct{})); err != nil {
			t.Fatalf("%s: сгенерирован негодный XML: %v", name, err)
		}
		path := filepath.Join(androidValues, name)
		if *updateAndroid {
			if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v — пересоберите: go test ./internal/gui -run TestAndroidResources -update", name, err)
		}
		// Git для Windows выдаёт файлы с CRLF — сравниваем содержимое, а не концы строк.
		if strings.ReplaceAll(string(got), "\r\n", "\n") != want {
			t.Errorf("%s разошёлся с палитрой окна — пересоберите: go test ./internal/gui -run TestAndroidResources -update", name)
		}
	}
}

// Каждый цвет палитры доехал до телефона. Новый цвет, добавленный в
// theme.go и забытый здесь, иначе всплыл бы на телефоне «похожим» оттенком,
// подобранным руками.
func TestAndroidPaletteIsComplete(t *testing.T) {
	src, err := os.ReadFile("theme.go")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?m)^\s*(Color[A-Za-z0-9]+)\s+Color\s*=\s*0x([0-9A-Fa-f]{6})`)
	have := map[Color]bool{}
	for _, s := range AndroidPalette {
		have[s.Color] = true
	}
	found := 0
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		found++
		var c Color
		for _, ch := range strings.ToUpper(m[2]) {
			c <<= 4
			if ch >= 'A' {
				c |= Color(ch-'A') + 10
			} else {
				c |= Color(ch - '0')
			}
		}
		if !have[c] {
			t.Errorf("%s (#%06X) нет в AndroidPalette — на телефоне его не будет", m[1], uint32(c))
		}
	}
	if found < 15 {
		t.Fatalf("в theme.go найдено всего %d цветов — разбор палитры сломан, проверка пустая", found)
	}

	names := map[string]bool{}
	for _, s := range AndroidPalette {
		if names[s.Name] {
			t.Errorf("имя %q в палитре дважды", s.Name)
		}
		names[s.Name] = true
		if !regexp.MustCompile(`^[a-z][a-z0-9_]*$`).MatchString(s.Name) {
			t.Errorf("имя %q не годится для ресурса Android", s.Name)
		}
	}
}

// Кегли на телефоне не мельче того, что Android считает читаемым, и
// сохраняют порядок окна: подпись мельче строки, строка мельче заголовка.
func TestAndroidTextSizes(t *testing.T) {
	sizes := map[string]float64{}
	for _, d := range AndroidDimens() {
		if d.Unit == "sp" {
			sizes[d.Name] = d.Value
			if d.Value < 11 {
				t.Errorf("%s = %v sp — мельче 11 sp на телефоне не читается", d.Name, d.Value)
			}
		}
	}
	if !(sizes["text_label"] < sizes["text_row"] && sizes["text_row"] < sizes["text_title"]) {
		t.Errorf("порядок кеглей нарушен: метка %v, строка %v, заголовок %v",
			sizes["text_label"], sizes["text_row"], sizes["text_title"])
	}
}

// TestAndroidPingPill — кнопка пинга на телефоне та же, что в окне: видимая
// высота PingPillH (44dp нажатия минус отступы фона), рамки тех же цветов,
// что рисует paintPingPill.
func TestAndroidPingPill(t *testing.T) {
	dir := filepath.Join("..", "..", "mobile", "android", "app", "src", "main", "res", "drawable")
	for name, stroke := range map[string]string{
		"bg_ping.xml":      "@color/border_dim",
		"bg_ping_ok.xml":   "@color/accent_dim",
		"bg_ping_fail.xml": "@color/danger_line",
	} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		s := string(raw)
		inset := fmt.Sprintf(`android:insetTop="%ddp" android:insetBottom="%ddp"`, (44-PingPillH)/2, (44-PingPillH)/2)
		if strings.Count(s, inset) != 2 {
			t.Errorf("%s: видимая высота не PingPillH (%d): нужны отступы %q", name, PingPillH, inset)
		}
		if strings.Count(s, `android:color="`+stroke+`"`) != 2 {
			t.Errorf("%s: рамка не %s", name, stroke)
		}
	}
	// Цвета рамок совпадают с окном.
	colors := map[string]Color{}
	for _, c := range AndroidPalette {
		colors[c.Name] = c.Color
	}
	if colors["danger_line"] != ColorDanger.Darken(0.45) || colors["accent_dim"] != ColorAccentDim || colors["border_dim"] != ColorBorderDim {
		t.Error("цвета рамок кнопки пинга разошлись с paintPingPill")
	}
}
