package gui

// Отрисовка окна: каким цветом и в каком порядке закрасить то, что посчитала
// раскладка.
//
// Здесь нет ни одного числа, задающего положение: все прямоугольники
// приходят из layout.go, где их проверяют тесты. И нет ни одного обращения
// к Windows: рисование идёт через Canvas, поэтому тот же код выводится и в
// окно, и в SVG для проверки.

import (
	"fmt"
	"strings"
	"time"
)

// hoverShade — насколько светлеет поверхность под курсором. Одно число на
// весь интерфейс: разнобой в подсветке читается как разная «нажимаемость».
const hoverShade = 0.05

// Предельные длины надписей, которые приходят извне: домен сервера, имя
// профиля, строка журнала. Они вынесены в константы, потому что за ними
// следит тест: обрезка должна происходить раньше, чем текст упрётся в край
// своего прямоугольника, иначе он налезет на соседний.
const (
	maxServerChars        = 24
	maxProfileChars       = 14
	maxProfileNameChars   = 22
	maxProfileServerChars = 30
	maxLogLineChars       = 51
	// MaxClipboardChars — предел показа чужого текста из буфера обмена в
	// сообщении об ошибке. Наружу вынесен потому, что подставляет его окно.
	maxErrorChars  = 50
	maxNoticeChars = 52

	// MaxClipboardChars — предел показа чужого текста из буфера обмена в
	// сообщении об ошибке. Наружу вынесен потому, что подставляет его окно.
	MaxClipboardChars = 80
)

// paint рисует весь экран целиком. Частичной перерисовки нет: окно
// маленькое, а «обновили только счётчик» — источник расхождений между тем,
// что на экране, и тем, что в состоянии.
func Paint(cv Canvas, v View, hot, pressed ItemID, now time.Time) {
	cv.Clear(ColorBG)
	switch v.Screen {
	case ScreenSettings:
		paintSettings(cv, v, hot, pressed)
	case ScreenAdd:
		paintAdd(cv, v, hot, pressed)
	case ScreenLog:
		paintLog(cv, v, hot, pressed)
	default:
		paintMain(cv, v, hot, pressed, now)
	}
}

func paintMain(cv Canvas, v View, hot, pressed ItemID, now time.Time) {
	m := MainLayout(len(v.Profiles), v.H())
	paintCaption(cv, m.Caption, hot)

	cv.DrawImage(m.Mark, LogoPixels(int(cv.Px(m.Mark.W))))
	cv.Text(AppWordmark, FaceLogo, m.Logo, ColorText, AlignLeft)
	paintIconButton(cv, m.Plus, hot == ItemAddProfile, func(r Rect) { drawPlus(cv, r, ColorAccent) })
	paintIconButton(cv, m.Gear, hot == ItemSettings, func(r Rect) { drawSliders(cv, r) })

	// Состояние — строкой, а не карточкой: карточка вокруг двух слов
	// занимала место, которое нужнее кнопке.
	cv.Dot(m.StatusDot, v.State.DotColor())
	cv.Text(v.StatusText(), FaceLabel, m.StatusText, v.StatusColor(), AlignLeft)
	if d := v.Session(now); d > 0 {
		cv.Text(Duration(d), FaceLabel, m.Session, ColorDim, AlignRight)
	}

	paintButton(cv, v, m.Button, hot == ItemConnect, pressed == ItemConnect)

	paintTile(cv, m.TileDown, "↓ Загрузка", Rate(v.RateIn))
	paintTile(cv, m.TileUp, "↑ Отдача", Rate(v.RateOut))

	// Причина неудачи — под кнопкой, там же, где обычно скорости: место
	// свободно, а отправлять за объяснением в журнал — лишний шаг.
	if v.State == Off && v.Error != "" {
		// Две строки: причина неудачи в одну помещается редко, а
		// обрезанная причина не объясняет ничего.
		first, second := wrapTwo(v.Error, maxErrorChars)
		y := m.TileDown.Bottom() + 12
		cv.Text(first, FaceSmall, Rect{X: PadX, Y: y, W: ContentW, H: 16}, ColorDanger, AlignLeft)
		cv.Text(second, FaceSmall, Rect{X: PadX, Y: y + 16, W: ContentW, H: 16}, ColorDanger, AlignLeft)
	} else {
		paintStats(cv, v, m, now)
	}

	paintProfileList(cv, v, m, hot)
	paintLogRow(cv, v, m, hot == ItemLog)

	cv.Text(AppName+" · MASQUE CONNECT-IP", FaceFooter, m.Footer, ColorMuted, AlignCenter)
}

// paintProfileList рисует список профилей на главном экране.
//
// Нажатие на строку выбирает профиль — за этим список сюда и вынесен:
// переключение сервера было единственным частым действием, ради которого
// приходилось уходить в настройки.
func paintProfileList(cv Canvas, v View, m Main, hot ItemID) {
	sectionLabel(cv, m.SectProfiles, "Профили")

	for i, r := range m.Profiles {
		pr := v.Profiles[i]
		fill := ColorSurface
		if hot == ItemProfileBase+ItemID(i) {
			fill = fill.Lighten(hoverShade)
		}
		border := ColorBorderDim
		if pr.Selected {
			// Выбранный обведён акцентом: по рамке видно сразу, а имя
			// приходится читать.
			border = ColorAccentDim
		}
		card(cv, r, RadiusSm, fill, border)

		in := r.Inset(15)
		menu := m.ProfileMenus[i]
		name, nameColor := Ellipsis(pr.Name, maxProfileNameChars), ColorText
		if pr.Selected {
			nameColor = ColorAccent
			cv.Dot(Rect{X: menu.X - 16, Y: r.Y + r.H/2 - 3, W: 6, H: 6}, ColorAccent)
		}
		cv.Text(name, FaceRow, Rect{X: in.X, Y: in.Y, W: in.W - 60, H: 16}, nameColor, AlignLeft)
		cv.Text(Ellipsis(Host(pr.Server), maxProfileServerChars), FaceSmall,
			Rect{X: in.X, Y: in.Y + 18, W: in.W - 60, H: 14}, ColorDim, AlignLeft)

		if hot == ItemProfileMenuBase+ItemID(i) {
			cv.Round(menu, 8, ColorSurface2)
		}
		drawDots(cv, menu, ColorDim)
	}

	if !m.MoreProfiles.Empty() {
		n := len(v.Profiles) - len(m.Profiles)
		cv.Text(fmt.Sprintf("ещё %d %s — в настройках", n, plural(n, "профиль", "профиля", "профилей")),
			FaceSmall, m.MoreProfiles, ColorDim, AlignLeft)
	}
}

func paintCaption(cv Canvas, c Caption, hot ItemID) {
	cv.Fill(c.Bar, ColorCaption)
	// Черта по нижнему краю: полоса заголовка отделена от содержимого не
	// только оттенком. Оттенок в тёмной теме различается плохо, особенно на
	// матовых экранах, и заголовок выглядел продолжением окна.
	cv.Fill(c.Line, ColorCaptionLn)

	minColor, closeColor := ColorDim, ColorDim
	if hot == ItemMinimize {
		cv.Round(c.Minimize, 6, ColorSurface2)
		minColor = ColorText
	}
	if hot == ItemClose {
		// Красным светится только «закрыть»: это единственная кнопка в
		// заголовке, которая обрывает соединение.
		cv.Round(c.Close, 6, ColorDanger.Darken(0.55))
		closeColor = ColorText
	}
	// Знак «свернуть» — полоска; «закрыть» — крест из двух диагоналей.
	// Оба нарисованы, а не набраны символами: шрифтовые глифы стрелок и
	// крестов в разных версиях Windows выглядят по-разному.
	bar := Rect{X: c.Minimize.X + (c.Minimize.W-10)/2, Y: c.Minimize.Y + c.Minimize.H/2, W: 10, H: 1}
	cv.Fill(bar, minColor)
	drawCross(cv, Rect{X: c.Close.X + (c.Close.W-9)/2, Y: c.Close.Y + (c.Close.H-9)/2, W: 9, H: 9}, closeColor)
}

func paintTile(cv Canvas, r Rect, label, value string) {
	card(cv, r, 10, ColorTile, ColorBorder.Darken(0.35))
	in := r.Inset(11)
	cv.Text(label, FaceLabel, Rect{X: in.X, Y: in.Y, W: in.W, H: 12}, ColorDim, AlignLeft)
	cv.Text(value, FaceValue, Rect{X: in.X, Y: in.Y + 15, W: in.W, H: 18}, ColorText, AlignLeft)
}

func paintButton(cv Canvas, v View, r Rect, hot, down bool) {
	rad := r.H / 2
	label := v.State.Button()
	if v.State.Accent() {
		c := ColorAccent
		switch {
		case down:
			c = c.Darken(0.14)
		case hot:
			c = c.Lighten(0.10)
		}
		cv.Round(r, rad, c)
		cv.Text(label, FaceButton, r, ColorAccentInk, AlignCenter)
		// Стрелка стоит у правого края, а не вплотную за надписью: считать
		// её положение от ширины текста значит зависеть от метрик шрифта, и
		// на системе без Segoe UI стрелка наехала бы на букву.
		drawArrow(cv, Rect{X: r.Right() - 26, Y: r.Y + r.H/2 - 4, W: 9, H: 8}, ColorAccentInk)
		return
	}
	// Отключение и отмена — обведённой кнопкой: их не нажимают походя.
	fill := ColorSurface
	if down {
		fill = ColorSurface.Lighten(0.06)
	} else if hot {
		fill = ColorSurface.Lighten(hoverShade)
	}
	cv.Round(r, rad, fill)
	cv.Border(r, rad, ColorAccentDim, 1)
	color := ColorText
	if v.State == Stopping {
		color = ColorDim
	}
	cv.Text(label, FaceButton, r, color, AlignCenter)
}

func paintStats(cv Canvas, v View, m Main, now time.Time) {
	card(cv, m.Stats, RadiusSm, ColorSurface2, ColorBorderDim)
	cells := [3]struct{ value, label string }{
		{Bytes(v.BytesIn), "Принято"},
		{Bytes(v.BytesOut), "Отправлено"},
		{Duration(v.Session(now)), "Сессия"},
	}
	for i, c := range cells {
		r := m.StatCells[i]
		if i > 0 { // разделители между ячейками, как в образце
			cv.Fill(Rect{X: r.X, Y: r.Y + 10, W: 1, H: r.H - 20}, ColorBorderDim)
		}
		in := Rect{X: r.X + 14, Y: r.Y + 12, W: r.W - 20, H: 18}
		cv.Text(c.value, FaceNumber, in, ColorText, AlignLeft)
		cv.Text(c.label, FaceLabel,
			Rect{X: in.X, Y: in.Y + 22, W: in.W, H: 12}, ColorDim, AlignLeft)
	}
}

func paintLogRow(cv Canvas, v View, m Main, hot bool) {
	fill := ColorSurface
	if hot {
		fill = fill.Lighten(hoverShade)
	}
	card(cv, m.LogRow, RadiusSm, fill, ColorBorderDim)
	in := m.LogRow.Inset(15)
	cv.Text("Журнал", FaceRow, Rect{X: in.X, Y: in.Y, W: in.W - 30, H: 16}, ColorText, AlignLeft)

	sub := "пусто"
	if n := len(v.LogLines); n > 0 {
		sub = fmt.Sprintf("%d %s", n, plural(n, "запись", "записи", "записей"))
		if last := v.LogLines[n-1]; len(last) >= 8 {
			sub += ", последняя " + last[:5]
		}
	}
	cv.Text(sub, FaceSmall, Rect{X: in.X, Y: in.Y + 18, W: in.W - 30, H: 14}, ColorDim, AlignLeft)

	// Стрелка вправо, а не уголок: строка теперь ведёт на свой экран, а не
	// раскрывает блок под собой.
	drawArrow(cv, Rect{X: m.LogRow.Right() - 30, Y: m.LogRow.Y + m.LogRow.H/2 - 4, W: 9, H: 8}, ColorDim)
}

// paintLog рисует экран журнала: заголовок, «Копировать», строки с
// прокруткой.
func paintLog(cv Canvas, v View, hot, pressed ItemID) {
	l := LogLayout(v.H())
	paintCaption(cv, l.Caption, hot)
	paintIconButton(cv, l.Back, hot == ItemBack, func(r Rect) {
		drawArrowLeft(cv, Rect{X: r.X + 10, Y: r.Y + r.H/2 - 4, W: 9, H: 8}, ColorText)
	})
	cv.Text("Журнал", FaceTitle, l.Title, ColorText, AlignLeft)
	copyLabel := "Копировать"
	if v.LogCopied {
		copyLabel = "Скопировано"
	}
	paintSecondaryButton(cv, l.Copy, copyLabel, hot == ItemLogCopy, pressed == ItemLogCopy)

	card(cv, l.Box, RadiusSm, ColorBG.Lighten(0.02), ColorBorderDim)
	if len(v.LogLines) == 0 {
		cv.Text("Записей пока нет", FaceSmall, l.Box, ColorDim, AlignCenter)
	} else {
		paintLogLines(cv, v.LogLines, l, v.LogScroll)
	}
	cv.Text(AppName+" · MASQUE CONNECT-IP", FaceFooter, l.Footer, ColorMuted, AlignCenter)
}

// paintLogLines печатает видимую часть журнала и полосу прокрутки.
//
// Длинные записи переносятся, а не обрезаются. Обрезание стоило разбора
// вживую: сообщение «ошибка: подключение: utlsquic: QUIC dial …» кончалось
// ровно там, где начиналась причина.
func paintLogLines(cv Canvas, lines []string, l Log, scroll int32) {
	rows := l.Rows()
	if rows <= 0 {
		return
	}
	in := l.Box.Inset(12)
	shown, first, total, _ := LogWindow(lines, rows, LogChars(cv), scroll)
	cv.Clip(in)
	for i, s := range shown {
		cv.Text(s, FaceMono,
			Rect{X: in.X, Y: in.Y + int32(i)*LogLineH, W: in.W, H: LogLineH},
			ColorDim, AlignLeft)
	}
	cv.Unclip()
	// Полоса прокрутки — только когда есть что прокручивать: по ней видно,
	// что строк больше, чем на экране, и где мы в журнале.
	if total > rows {
		track := Rect{X: l.Box.Right() - 7, Y: in.Y, W: 3, H: in.H}
		thumbH := max(track.H*int32(rows)/int32(total), 16)
		thumbY := track.Y + (track.H-thumbH)*int32(first)/int32(max(total-rows, 1))
		cv.Round(track, 1, ColorSurface2)
		cv.Round(Rect{X: track.X, Y: thumbY, W: track.W, H: thumbH}, 1, ColorDim)
	}
}

// LogChars — сколько знаков моноширинного шрифта помещается в строку
// журнала на этом холсте.
//
// Считается измерением, а не заданным числом: моноширинный шрифт в Windows
// (Consolas) и в Linux (DejaVu Sans Mono) разной ширины, и строка, выверенная
// под один, у другого уезжала за рамку — обрезанными оказывались ровно
// концы сообщений об ошибках. Окно запоминает это число при отрисовке, чтобы
// прокрутка колесом знала, сколько строк получится после переноса.
func LogChars(cv Canvas) int {
	w := LogLayout(DefaultWinH).Box.Inset(12).W
	per := cv.Width(strings.Repeat("ш", 20), FaceMono) / 20
	if per <= 0 {
		return maxLogLineChars
	}
	return max(int(float64(w)/per), 20)
}

// WrapLog разбивает записи журнала на строки не длиннее width знаков.
//
// Продолжение записи сдвинуто вправо на ширину отметки времени: так видно,
// где кончается одна запись и начинается следующая, — без отступа перенос
// читался бы как новое событие.
func WrapLog(lines []string, width int) []string {
	const indent = "         " // под «15:04:05  »
	var out []string
	for _, line := range lines {
		r := []rune(line)
		if len(r) <= width {
			out = append(out, line)
			continue
		}
		out = append(out, string(r[:width]))
		rest := r[width:]
		for len(rest) > 0 {
			n := width - len([]rune(indent))
			if n < 1 {
				n = 1
			}
			if len(rest) < n {
				n = len(rest)
			}
			out = append(out, indent+string(rest[:n]))
			rest = rest[n:]
		}
	}
	return out
}

// ---------- настройки ----------

func paintSettings(cv Canvas, v View, hot, pressed ItemID) {
	s := SettingsLayout(len(v.Profiles), v.H())
	paintCaption(cv, s.Caption, hot)

	paintIconButton(cv, s.Back, hot == ItemBack, func(r Rect) {
		drawArrowLeft(cv, Rect{X: r.X + 10, Y: r.Y + r.H/2 - 4, W: 9, H: 8}, ColorText)
	})
	cv.Text("Настройки", FaceTitle, s.Title, ColorText, AlignLeft)

	cv.Clip(s.Viewport)
	defer cv.Unclip()
	dy := s.Viewport.Y - v.ScrollY
	move := func(r Rect) Rect { r.Y += dy; return r }

	section := func(r Rect, text string) { sectionLabel(cv, move(r), text) }

	section(s.SectGuard, "Защита")
	paintToggleRow(cv, move(s.KillSwitch), "Аварийное отключение",
		killSwitchHint(v), v.KillSwitch, hot == ItemKillSwitch)
	paintLinkRow(cv, move(s.Allow), "Исключения",
		allowHint(v.AllowCount), "Изменить", hot == ItemAllowEdit)

	section(s.SectProfiles, "Профили")
	for i, pr := range v.Profiles {
		paintProfileRow(cv, move(s.Profiles[i]), move(s.ProfileMenus[i]), pr,
			hot == ItemProfileBase+ItemID(i),
			hot == ItemProfileMenuBase+ItemID(i))
	}
	paintAddRow(cv, move(s.AddProfile), hot == ItemAddProfile)

	section(s.SectSystem, "Система")
	paintToggleRow(cv, move(s.Autostart), "Запускать при входе в систему",
		"И сразу подключаться к выбранному профилю", v.Autostart,
		hot == ItemAutostart)

	cv.Unclip()
	cv.Text(AppName+" · MASQUE CONNECT-IP", FaceFooter, s.Footer, ColorMuted, AlignCenter)
}

func killSwitchHint(v View) string {
	if !v.KillSwitch {
		return "Без туннеля трафик пойдёт открыто"
	}
	return "Без туннеля сеть закрыта, кроме исключений"
}

func allowHint(n int) string {
	if n == 0 {
		return "Ничего не пропускается мимо туннеля"
	}
	return fmt.Sprintf("%d %s мимо туннеля", n, plural(n, "адрес", "адреса", "адресов"))
}

func paintRowBase(cv Canvas, r Rect, hot bool) Rect {
	fill := ColorSurface
	if hot {
		fill = fill.Lighten(hoverShade)
	}
	card(cv, r, RadiusSm, fill, ColorBorderDim)
	return r.Inset(15)
}

func paintRowText(cv Canvas, in Rect, title, hint string, titleColor Color) {
	cv.Text(title, FaceRow, Rect{X: in.X, Y: in.Y, W: in.W - 60, H: 16}, titleColor, AlignLeft)
	cv.Text(hint, FaceSmall,
		Rect{X: in.X, Y: in.Y + 18, W: in.W - 60, H: 14}, ColorDim, AlignLeft)
}

func paintToggleRow(cv Canvas, r Rect, title, hint string, on, hot bool) {
	in := paintRowBase(cv, r, hot)
	paintRowText(cv, in, title, hint, ColorText)
	paintToggle(cv, Toggle(r), on)
}

func paintToggle(cv Canvas, r Rect, on bool) {
	track, knob := ColorSurface2.Lighten(0.06), ColorDim
	if on {
		track, knob = ColorAccent, ColorAccentInk
	}
	cv.Round(r, r.H/2, track)
	const pad = 3
	d := r.H - 2*pad
	x := r.X + pad
	if on {
		x = r.Right() - pad - d
	}
	cv.Dot(Rect{X: x, Y: r.Y + pad, W: d, H: d}, knob)
}

func paintLinkRow(cv Canvas, r Rect, title, hint, link string, hot bool) {
	in := paintRowBase(cv, r, hot)
	paintRowText(cv, in, title, hint, ColorText)
	color := ColorAccent
	if hot {
		color = color.Lighten(0.15)
	}
	cv.Text(link, FaceSmall,
		Rect{X: in.Right() - 90, Y: in.Y + 9, W: 90, H: 16}, color, AlignRight)
}

func paintProfileRow(cv Canvas, r, menu Rect, pr ProfileItem, hot, menuHot bool) {
	in := paintRowBase(cv, r, hot)
	title := Ellipsis(pr.Name, maxProfileNameChars)
	color := ColorText
	if pr.Selected {
		color = ColorAccent
	}
	cv.Text(title, FaceRow, Rect{X: in.X, Y: in.Y, W: in.W - 60, H: 16}, color, AlignLeft)
	cv.Text(Ellipsis(pr.Server, maxProfileServerChars), FaceSmall,
		Rect{X: in.X, Y: in.Y + 18, W: in.W - 60, H: 14}, ColorDim, AlignLeft)

	// Выбранный профиль помечен рамкой-галочкой слева от меню, а не словом:
	// слово «выбран» на каждой строке пришлось бы читать, чтобы найти нужную.
	if pr.Selected {
		cv.Dot(Rect{X: menu.X - 16, Y: r.Y + r.H/2 - 3, W: 6, H: 6}, ColorAccent)
	}
	if menuHot {
		cv.Round(menu, 8, ColorSurface2)
	}
	drawDots(cv, menu, ColorDim)
}

func paintAddRow(cv Canvas, r Rect, hot bool) {
	fill := ColorBG
	if hot {
		fill = ColorSurface
	}
	cv.Round(r, RadiusSm, fill)
	cv.Border(r, RadiusSm, ColorAccentDim, 1)
	in := r.Inset(15)
	cv.Text("+  Добавить сервер", FaceRow,
		Rect{X: in.X, Y: in.Y, W: in.W, H: 16}, ColorAccent, AlignLeft)
	cv.Text("Вставить ссылку "+LinkScheme+":// или конфигурацию", FaceSmall,
		Rect{X: in.X, Y: in.Y + 18, W: in.W, H: 14}, ColorDim, AlignLeft)
}

// ---------- добавление сервера ----------

// paintAdd рисует экран добавления. Само поле ввода не рисуется: там стоит
// настоящий системный элемент, и здесь под него оставляется рамка.
func paintAdd(cv Canvas, v View, hot, pressed ItemID) {
	a := AddLayout(v.Editing, v.H())
	paintCaption(cv, a.Caption, hot)

	paintIconButton(cv, a.Back, hot == ItemBack, func(r Rect) {
		drawArrowLeft(cv, Rect{X: r.X + 10, Y: r.Y + r.H/2 - 4, W: 9, H: 8}, ColorText)
	})
	title, confirm := "Добавить сервер", "Добавить"
	if v.Editing {
		title, confirm = "Изменить сервер", "Сохранить"
	}
	cv.Text(title, FaceTitle, a.Title, ColorText, AlignLeft)

	// Три поля — ровно то, что выдаёт сервер. Рамка проблемного поля
	// краснеет: подсвечивать нужно именно то место, где ошибка, а не
	// форму целиком.
	for i, f := range a.Fields {
		sectionLabel(cv, f.Label, AddFieldTitles[i])
		border := ColorBorderDim
		if v.AddBadField == i+1 {
			border = ColorDanger
		}
		card(cv, f.Box, RadiusSm, ColorTile, border)
	}

	paintSecondaryButton(cv, a.Paste, "Вставить из буфера",
		hot == ItemPasteLink, pressed == ItemPasteLink)

	paintPrimaryButton(cv, a.Confirm, confirm,
		hot == ItemAddConfirm, pressed == ItemAddConfirm)

	if !a.Delete.Empty() {
		fill := ColorSurface
		if pressed == ItemDeleteProfile {
			fill = fill.Lighten(0.06)
		} else if hot == ItemDeleteProfile {
			fill = fill.Lighten(hoverShade)
		}
		cv.Round(a.Delete, a.Delete.H/2, fill)
		cv.Border(a.Delete, a.Delete.H/2, ColorDanger.Darken(0.45), 1)
		cv.Text("Удалить", FaceRow, a.Delete, ColorDanger, AlignCenter)
	}

	notice, color := v.AddNotice, ColorDim
	if notice == "" {
		notice = "Эти три значения выдаёт сервер командой clients add. Можно вставить ссылку — она разложится по полям."
		if v.Editing {
			notice = "Изменения применятся при следующем подключении."
		}
	}
	if v.AddFailed {
		color = ColorDanger
	}
	// Две строки: объяснение ошибки в одну строку не всегда помещается, а
	// обрезанное объяснение хуже, чем никакого.
	first, second := wrapTwo(notice, maxNoticeChars)
	cv.Text(first, FaceSmall, Rect{X: a.Notice.X, Y: a.Notice.Y, W: a.Notice.W, H: 16}, color, AlignLeft)
	cv.Text(second, FaceSmall, Rect{X: a.Notice.X, Y: a.Notice.Y + 16, W: a.Notice.W, H: 16}, color, AlignLeft)

	cv.Text(AppName+" · MASQUE CONNECT-IP", FaceFooter, a.Footer, ColorMuted, AlignCenter)
}

// sectionLabel — зелёная метка раздела с тире, как в образце.
func sectionLabel(cv Canvas, r Rect, text string) {
	cv.Fill(Rect{X: r.X, Y: r.Y + 7, W: 22, H: 1}, ColorAccent)
	cv.Text(text, FaceLabel, Rect{X: r.X + 32, Y: r.Y, W: r.W - 32, H: r.H}, ColorAccent, AlignLeft)
}

// paintPrimaryButton — залитая акцентом кнопка со стрелкой.
func paintPrimaryButton(cv Canvas, r Rect, label string, hot, down bool) {
	c := ColorAccent
	switch {
	case down:
		c = c.Darken(0.14)
	case hot:
		c = c.Lighten(0.10)
	}
	cv.Round(r, r.H/2, c)
	cv.Text(label, FaceButton, r, ColorAccentInk, AlignCenter)
	drawArrow(cv, Rect{X: r.Right() - 26, Y: r.Y + r.H/2 - 4, W: 9, H: 8}, ColorAccentInk)
}

// paintSecondaryButton — обведённая кнопка для действия попроще.
func paintSecondaryButton(cv Canvas, r Rect, label string, hot, down bool) {
	fill := ColorSurface
	switch {
	case down:
		fill = fill.Lighten(0.06)
	case hot:
		fill = fill.Lighten(hoverShade)
	}
	cv.Round(r, r.H/2, fill)
	cv.Border(r, r.H/2, ColorAccentDim, 1)
	cv.Text(label, FaceRow, r, ColorText, AlignCenter)
}

// wrapTwo делит строку на две по ширине, не разрывая слов. Переноса текста
// в отрисовке нет вовсе: всё остальное в окне — короткие подписи, и ради
// них заводить разметку абзаца незачем.
func wrapTwo(s string, width int) (string, string) {
	r := []rune(s)
	if len(r) <= width {
		return s, ""
	}
	cut := width
	for i := width; i > width/2; i-- {
		if r[i] == ' ' {
			cut = i
			break
		}
	}
	second := string(r[cut:])
	if len([]rune(second)) > width {
		second = Ellipsis(second, width)
	}
	return string(r[:cut]), trimLeadingSpace(second)
}

func trimLeadingSpace(s string) string {
	for i, c := range s {
		if c != ' ' {
			return s[i:]
		}
	}
	return ""
}

// ---------- примитивы значков ----------

// paintIconButton рисует круглую кнопку со значком.
func paintIconButton(cv Canvas, r Rect, hot bool, icon func(Rect)) {
	fill := ColorBG
	if hot {
		fill = ColorSurface
	}
	cv.Round(r, 8, fill)
	cv.Border(r, 8, ColorBorderDim, 1)
	icon(r)
}

// drawSliders — значок настроек: две полоски с бегунками. Рисуется
// примитивами, потому что глиф шестерёнки есть не во всех системных шрифтах,
// а подставленный взамен квадратик выглядит поломкой.
func drawSliders(cv Canvas, r Rect) {
	cx, cy := r.X+r.W/2, r.Y+r.H/2
	cv.Fill(Rect{X: cx - 6, Y: cy - 3, W: 12, H: 1}, ColorDim)
	cv.Fill(Rect{X: cx - 6, Y: cy + 3, W: 12, H: 1}, ColorDim)
	cv.Dot(Rect{X: cx + 1, Y: cy - 5, W: 4, H: 4}, ColorAccent)
	cv.Dot(Rect{X: cx - 5, Y: cy + 1, W: 4, H: 4}, ColorAccent)
}

// drawPlus — знак «плюс» из двух полосок.
func drawPlus(cv Canvas, r Rect, col Color) {
	cx, cy := r.X+r.W/2, r.Y+r.H/2
	cv.Fill(Rect{X: cx - 5, Y: cy, W: 11, H: 1}, col)
	cv.Fill(Rect{X: cx, Y: cy - 5, W: 1, H: 11}, col)
}

// drawCross — крест из двух диагоналей, построенных путём.
func drawCross(cv Canvas, r Rect, col Color) {
	t := cv.Px(1)
	if t < 1 {
		t = 1
	}
	x, y, w, h := cv.Px(r.X), cv.Px(r.Y), cv.Px(r.W), cv.Px(r.H)
	cv.Quad([4][2]int32{{x, y}, {x + t, y}, {x + w, y + h - t}, {x + w - t, y + h}}, col)
	cv.Quad([4][2]int32{{x + w - t, y}, {x + w, y}, {x + t, y + h}, {x, y + h - t}}, col)
}

// drawArrow — стрелка вправо: черта и два пера. Как в образце на кнопке.
func drawArrow(cv Canvas, r Rect, col Color) {
	t := cv.Px(1)
	if t < 1 {
		t = 1
	}
	x, y, w, h := cv.Px(r.X), cv.Px(r.Y), cv.Px(r.W), cv.Px(r.H)
	mid := y + h/2
	cv.FillPixels(x, mid, w, t, col)
	cv.Quad([4][2]int32{{x + w - h/2, y}, {x + w - h/2 + t, y}, {x + w, mid}, {x + w - t, mid}}, col)
	cv.Quad([4][2]int32{{x + w, mid}, {x + w - t, mid}, {x + w - h/2 + t, y + h}, {x + w - h/2, y + h}}, col)
}

// drawArrowLeft — та же стрелка, развёрнутая: кнопка «назад».
func drawArrowLeft(cv Canvas, r Rect, col Color) {
	t := cv.Px(1)
	if t < 1 {
		t = 1
	}
	x, y, w, h := cv.Px(r.X), cv.Px(r.Y), cv.Px(r.W), cv.Px(r.H)
	mid := y + h/2
	cv.FillPixels(x, mid, w, t, col)
	cv.Quad([4][2]int32{{x + h/2, y}, {x + h/2 - t, y}, {x, mid}, {x + t, mid}}, col)
	cv.Quad([4][2]int32{{x, mid}, {x + t, mid}, {x + h/2 - t, y + h}, {x + h/2, y + h}}, col)
}

// drawDots — три точки: меню строки.
func drawDots(cv Canvas, r Rect, col Color) {
	cy := r.Y + r.H/2 - 1
	for i := int32(0); i < 3; i++ {
		cv.Dot(Rect{X: r.X + 9 + i*7, Y: cy, W: 3, H: 3}, col)
	}
}

// Upper переводит строку в заглавные для кириллицы и латиницы.
//
// Экспортирована, потому что нужна и вне пакета: растровый холст делает ту
// же работу, что оконный, и повторять таблицу в двух местах — верный способ
// однажды их разъединить.
func Upper(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			r -= 'a' - 'A'
		case r >= 'а' && r <= 'я':
			r -= 'а' - 'А'
		case r == 'ё':
			r = 'Ё'
		}
		out = append(out, r)
	}
	return string(out)
}

// plural склоняет существительное при числе: «1 запись», «2 записи»,
// «5 записей». Без этого интерфейс сразу выдаёт машинный перевод.
func plural(n int, one, few, many string) string {
	n = abs(n) % 100
	if n >= 11 && n <= 14 {
		return many
	}
	switch n % 10 {
	case 1:
		return one
	case 2, 3, 4:
		return few
	default:
		return many
	}
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// card — то, чем рисуется почти всё в окне: заливка плюс рамка.
func card(cv Canvas, r Rect, radius int32, fill, stroke Color) {
	cv.Round(r, radius, fill)
	if stroke != fill {
		cv.Border(r, radius, stroke, 1)
	}
}

// PaintMenu рисует всплывающее меню: фон, рамка, пункты.
//
// Вынесено сюда, а не в окно, по той же причине, что и остальная
// отрисовка: так его видно на проверочных картинках и оно не может
// разойтись с палитрой окна.
func PaintMenu(cv Canvas, items []MenuItem, m Menu, hot int) {
	all := Rect{0, 0, m.W, m.H}
	cv.Round(all, MenuRadius, ColorSurface)
	cv.Border(all, MenuRadius, ColorBorder, 1)

	for i, it := range items {
		r := m.Items[i]
		if r.H == 0 { // разделитель
			cv.Fill(Rect{X: MenuSepInset, Y: r.Y + MenuSepH/2, W: m.W - 2*MenuSepInset, H: 1},
				ColorBorderDim)
			continue
		}
		color := ColorText
		if it.Danger {
			color = ColorDanger
		}
		if i == hot {
			// Подсветка не во всю ширину, а с полями: так видно, что это
			// пункт списка, а не выделенная полоса.
			cv.Round(Rect{X: 4, Y: r.Y + 1, W: m.W - 8, H: r.H - 2}, 7, ColorSurface2.Lighten(0.04))
		}
		cv.Text(it.Text, FaceRow,
			Rect{X: MenuPadX, Y: r.Y, W: m.W - 2*MenuPadX, H: r.H}, color, AlignLeft)
	}
}
