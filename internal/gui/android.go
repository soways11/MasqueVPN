package gui

// Дизайн-система для Android: цвета и размеры в виде ресурсов.
//
// # Почему генерируются, а не пишутся руками
//
// Android-клиент рисуется своими средствами (View и XML), а не этим пакетом:
// так на телефоне работают клавиатура, TalkBack, системные отступы и жест
// «назад». Но цвета и размеры обязаны быть теми же, что в окнах Windows и
// Linux, — иначе «стилистически похоже» превратится в «примерно похоже», и
// разойдётся при первой правке палитры.
//
// Поэтому colors.xml и dimens.xml — производные: их пишет этот код, а тест
// сверяет лежащие в репозитории файлы с тем, что получилось бы сейчас.
// Поменяли цвет здесь и забыли пересобрать ресурсы — тест красный.
//
//	go test ./internal/gui -run TestAndroidResources -update

import (
	"fmt"
	"math"
	"strings"
)

// Swatch — цвет палитры под именем ресурса.
type Swatch struct {
	Name  string // имя ресурса: @color/<Name>
	Color Color
	Note  string
}

// AndroidPalette — все цвета, которые нужны Android-клиенту.
//
// Первая часть — палитра как есть. Вторая — производные состояния
// (нажатие, фон журнала): в окнах они считаются на лету через Lighten и
// Darken, а в XML считать нечем, поэтому они вычисляются здесь теми же
// формулами, что в paint.go.
var AndroidPalette = []Swatch{
	{"bg", ColorBG, "фон окна"},
	{"caption", ColorCaption, "полоса заголовка"},
	{"caption_line", ColorCaptionLn, "черта под заголовком"},
	{"surface", ColorSurface, "карточки и строки"},
	{"surface2", ColorSurface2, "блок цифр"},
	{"tile", ColorTile, "плитки и поля ввода"},
	{"card_top", ColorCardTop, "градиент карточки: верх"},
	{"card_bot", ColorCardBot, "градиент карточки: низ"},
	{"border", ColorBorder, "рамка карточки"},
	{"border_dim", ColorBorderDim, "рамка строк"},
	{"accent", ColorAccent, "зелёный акцент"},
	{"accent_ink", ColorAccentInk, "текст на акценте"},
	{"accent_dim", ColorAccentDim, "обводка второстепенных кнопок"},
	{"text", ColorText, "основной текст"},
	{"dim", ColorDim, "подписи"},
	{"muted", ColorMuted, "служебное"},
	{"bar", ColorBar, "столбики графика"},
	{"bar_dim", ColorBarDim, "столбики вне истории"},
	{"idle_dot", ColorIdleDot, "индикатор без подключения"},
	{"danger", ColorDanger, "ошибка"},

	// Производные — те же формулы, что в paint.go.
	{"accent_pressed", ColorAccent.Darken(0.14), "акцентная кнопка нажата"},
	{"surface_pressed", ColorSurface.Lighten(0.06), "обведённая кнопка нажата"},
	{"row_pressed", ColorSurface.Lighten(hoverShade), "строка нажата"},
	{"log_bg", ColorBG.Lighten(0.02), "фон журнала"},
	{"toggle_off", ColorSurface2.Lighten(0.06), "дорожка выключенного переключателя"},
	{"danger_line", ColorDanger.Darken(0.45), "обводка кнопки удаления"},
	{"tile_border", ColorBorder.Darken(0.35), "рамка плитки скорости"},
	{"dot_busy", ColorAccent.Mix(ColorIdleDot, 0.45), "индикатор при подключении и отключении (State.DotColor)"},
	{"ripple", ColorText.Mix(ColorBG, 0.88), "волна нажатия: текст, почти растворённый в фоне"},
}

// Dimen — размер под именем ресурса.
type Dimen struct {
	Name  string
	Value float64
	Unit  string // dp или sp
	Note  string
}

// PhoneTextScale — во сколько раз текст на телефоне крупнее кегля окна.
//
// Кегли окна заданы в точках при 96 dpi. На телефоне в sp те же числа
// давали бы примерно тот же угловой размер (телефон держат вдвое ближе), но
// мелкие подписи в 10 sp мельче самого мелкого, что допускает Android
// (11 sp у Material). Отсюда небольшой общий множитель — тот же приём, что
// uiZoom в окнах: растёт всё разом, пропорции не меняются.
const PhoneTextScale = 1.15

func sp(f Font) float64 {
	return math.Round(f.Size*PhoneTextScale*2) / 2 // до половины sp
}

// em — разрядка в долях кегля: так её понимает android:letterSpacing.
func em(f Font) float64 {
	if f.Size == 0 {
		return 0
	}
	return math.Round(f.Track/f.Size*1000) / 1000
}

// AndroidDimens — размеры и кегли. Размеры раскладки переносятся в dp как
// есть: 48 dp кнопки и 52 dp строки — как раз те высоты, которые Android
// считает удобными для пальца.
func AndroidDimens() []Dimen {
	return []Dimen{
		{"pad_x", PadX, "dp", "поля слева и справа"},
		{"radius", Radius, "dp", "скругление карточек"},
		{"radius_sm", RadiusSm, "dp", "скругление строк и полей"},
		{"row_h", RowH, "dp", "высота строки списка"},
		{"row_gap", RowGap, "dp", "между строками"},
		{"row_pad", 15, "dp", "внутренний отступ строки (Inset(15) в paint.go)"},
		{"button_h", 48, "dp", "главная кнопка"},
		{"tile_h", 54, "dp", "плитка скорости"},
		{"tile_gap", 10, "dp", "между плитками"},
		{"icon_button", 36, "dp", "кнопки «+» и настроек: в окне 30, пальцу мало"},
		{"icon_radius", 8, "dp", "скругление кнопок-значков"},
		{"field_h", 48, "dp", "поле ввода"},
		{"dot", 6, "dp", "индикатор состояния"},
		{"section_line", 22, "dp", "тире перед меткой раздела"},
		{"logo_mark", LogoMark, "dp", "знак-черепаха в шапке"},

		{"text_title", sp(FaceTitle), "sp", "заголовок экрана"},
		{"text_button", sp(FaceButton), "sp", "надпись на кнопке"},
		{"text_row", sp(FaceRow), "sp", "строки списков"},
		{"text_value", sp(FaceValue), "sp", "числа в плитках"},
		{"text_number", sp(FaceNumber), "sp", "крупные цифры"},
		{"text_small", sp(FaceSmall), "sp", "пояснения"},
		{"text_label", sp(FaceLabel), "sp", "мелкие заглавные метки"},
		{"text_mono", sp(FaceMono) - 1.5, "sp", "журнал: строки длинные, чуть мельче"},
		{"text_logo", sp(FaceLogo), "sp", "логотип"},
		{"text_footer", sp(FaceFooter), "sp", "подпись внизу"},
	}
}

const androidHeader = `<?xml version="1.0" encoding="utf-8"?>
<!--
    СГЕНЕРИРОВАНО из internal/gui (android.go) — руками не править.
    Поменять цвет или размер: правка в internal/gui, затем
        go test ./internal/gui -run TestAndroidResources -update
-->
`

// AndroidColorsXML — содержимое res/values/colors.xml.
func AndroidColorsXML() string {
	var b strings.Builder
	b.WriteString(androidHeader)
	b.WriteString("<resources>\n")
	for _, s := range AndroidPalette {
		fmt.Fprintf(&b, "    <color name=\"%s\">#%06X</color> <!-- %s -->\n", s.Name, uint32(s.Color), s.Note)
	}
	b.WriteString("</resources>\n")
	return b.String()
}

// AndroidDimensXML — содержимое res/values/dimens.xml.
func AndroidDimensXML() string {
	var b strings.Builder
	b.WriteString(androidHeader)
	b.WriteString("<resources>\n")
	for _, d := range AndroidDimens() {
		fmt.Fprintf(&b, "    <dimen name=\"%s\">%s%s</dimen> <!-- %s -->\n", d.Name, num(d.Value), d.Unit, d.Note)
	}
	b.WriteString("</resources>\n")
	return b.String()
}

// TextStyle — начертание окна в виде стиля текста Android.
type TextStyle struct {
	Name  string // TextAppearance.Masque.<Name>
	Face  Font
	Size  string // ссылка на размер: @dimen/text_*
	Color string // @color/…
}

// AndroidTextStyles — начертания окна как стили текста.
func AndroidTextStyles() []TextStyle {
	return []TextStyle{
		{"Title", FaceTitle, "@dimen/text_title", "@color/text"},
		{"Button", FaceButton, "@dimen/text_button", "@color/accent_ink"},
		{"Row", FaceRow, "@dimen/text_row", "@color/text"},
		{"Value", FaceValue, "@dimen/text_value", "@color/text"},
		{"Number", FaceNumber, "@dimen/text_number", "@color/text"},
		{"Small", FaceSmall, "@dimen/text_small", "@color/dim"},
		{"Label", FaceLabel, "@dimen/text_label", "@color/dim"},
		{"Mono", FaceMono, "@dimen/text_mono", "@color/dim"},
		{"Logo", FaceLogo, "@dimen/text_logo", "@color/text"},
		{"Footer", FaceFooter, "@dimen/text_footer", "@color/muted"},
	}
}

// family — гарнитура Android для толщины окна. Semibold (600) в Roboto
// ближе всего к Medium (500); жирный — обычная гарнитура с textStyle=bold.
func family(f Font) (family string, bold bool) {
	switch {
	case f.Mono:
		return "monospace", false
	case f.Weight >= WeightBold:
		return "sans-serif", true
	case f.Weight >= WeightSemibold:
		return "sans-serif-medium", false
	}
	return "sans-serif", false
}

// AndroidTextStylesXML — содержимое res/values/text_styles.xml.
func AndroidTextStylesXML() string {
	var b strings.Builder
	b.WriteString(androidHeader)
	b.WriteString("<resources>\n")
	for _, st := range AndroidTextStyles() {
		fam, bold := family(st.Face)
		// Родитель — системный TextAppearance: с ним подсветка выделения и
		// прочие мелочи — системные, а неявного родителя
		// «TextAppearance.Masque», которого нет, не возникает.
		fmt.Fprintf(&b, "    <style name=\"TextAppearance.Masque.%s\" parent=\"@android:style/TextAppearance\">\n", st.Name)
		fmt.Fprintf(&b, "        <item name=\"android:textSize\">%s</item>\n", st.Size)
		fmt.Fprintf(&b, "        <item name=\"android:textColor\">%s</item>\n", st.Color)
		fmt.Fprintf(&b, "        <item name=\"android:fontFamily\">%s</item>\n", fam)
		if bold {
			b.WriteString("        <item name=\"android:textStyle\">bold</item>\n")
		}
		if sp := em(st.Face); sp > 0 {
			fmt.Fprintf(&b, "        <item name=\"android:letterSpacing\">%s</item>\n", num(sp))
		}
		if st.Face.Upper {
			b.WriteString("        <item name=\"android:textAllCaps\">true</item>\n")
		}
		b.WriteString("    </style>\n")
	}
	b.WriteString("</resources>\n")
	return b.String()
}

func num(v float64) string {
	s := fmt.Sprintf("%.3f", v)
	s = strings.TrimRight(s, "0")
	return strings.TrimSuffix(s, ".")
}
