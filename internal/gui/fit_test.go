package gui

import (
	"strings"
	"testing"
)

// Проверка, что надписи помещаются в отведённые им прямоугольники.
//
// Точных метрик шрифта тут нет и быть не может — они у каждой системы свои.
// Поэтому ширина оценивается сверху: берётся заведомо широкий символ.
// Оценка грубая, но ловит именно то, ради чего написана: «поменял кегль —
// подпись налезла на цифру» и «домен длиннее, чем место под него».
//
// Занижать оценку нельзя, завышать — можно: ложная тревога стоит минуту,
// а пропущенная обрезка живёт до чьей-нибудь жалобы.

// widthOf — оценка ширины строки в логических точках.
//
// 0.62 кегля на знак — потолок для Segoe UI на кириллице: средняя около
// 0.5, заглавные с разрядкой шире. Моноширинный Consolas — ровно 0.55.
func widthOf(s string, f Font) float64 {
	n := float64(len([]rune(s)))
	k := 0.62
	if f.Mono {
		k = 0.55
	}
	return n*f.Size*k + n*f.Track
}

// fits проверяет, что строка помещается в ширину.
func fits(t *testing.T, name, s string, f Font, w int32) {
	t.Helper()
	if got := widthOf(s, f); got > float64(w) {
		t.Errorf("%s: %q не помещается — нужно ≈%.0f точек, отведено %d", name, s, got, w)
	}
}

// TestMainTextFits — надписи главного экрана.
func TestMainTextFits(t *testing.T) {
	m := MainLayout(false, 2)

	for _, s := range []string{"Нет подключения", "Соединение защищено", "Подключение", "Отключение", "Не подключилось"} {
		fits(t, "статус", s, FaceLabel, m.StatusText.W)
	}
	fits(t, "время сессии", "25:00:00", FaceLabel, m.Session.W)
	fits(t, "логотип", AppWordmark, FaceLogo, m.Plus.X-m.Logo.X-12)

	// Плитки: подпись и значение лежат внутри, с отступом 11 с каждой стороны.
	tileText := m.TileDown.W - 22
	for _, s := range []string{"↓ Загрузка", "↑ Отдача"} {
		fits(t, "подпись плитки", s, FaceLabel, tileText)
	}
	for _, s := range []string{"999 бит/с", "9,9 Кбит/с", "938 Мбит/с", "9,9 Гбит/с"} {
		fits(t, "скорость", s, FaceValue, tileText)
	}

	// Список профилей: имя и адрес обрезаются, место под отметку выбранного.
	rowText := m.Profiles[0].W - 2*15 - 30
	fits(t, "имя профиля", strings.Repeat("ш", maxProfileNameChars), FaceRow, rowText)
	fits(t, "адрес профиля", strings.Repeat("ш", maxProfileServerChars), FaceSmall, rowText)
	fits(t, "метка профилей", "Профили", FaceLabel, m.SectProfiles.W-32)
	many := MainLayout(false, 9)
	fits(t, "ещё профили", "ещё 5 профилей — в настройках", FaceSmall, many.MoreProfiles.W)
}

// TestErrorTextFits — причина неудачи рисуется на месте графика и должна
// поместиться в его ширину: обрезанное объяснение хуже, чем никакого.
func TestErrorTextFits(t *testing.T) {
	fits(t, "ошибка", strings.Repeat("ш", maxErrorChars), FaceSmall, ContentW)
}

// TestStatsTextFits — блок из трёх цифр самый тесный: ячейка вчетверо уже
// окна, а подписи в ней полноразмерные.
func TestStatsTextFits(t *testing.T) {
	m := MainLayout(false, 2)
	for i, c := range []struct{ value, label string }{
		{"1023 Б", "Принято"},
		{"938 МБ", "Отправлено"},
		{"25:00:00", "Сессия"},
	} {
		w := m.StatCells[i].W - 20 // отступы внутри ячейки
		fits(t, "число", c.value, FaceNumber, w)
		fits(t, "подпись", c.label, FaceLabel, w)
	}
}

// TestRowTextFits — строки настроек: заголовок и пояснение под ним.
// Справа у каждой строки переключатель или ссылка, поэтому текст живёт не
// во всей ширине — именно это соотношение тест и стережёт.
func TestRowTextFits(t *testing.T) {
	s := SettingsLayout(2)
	textW := s.KillSwitch.W - 2*15 - 60 // поля строки и место под переключатель

	rows := []struct{ title, hint string }{
		{"Аварийное отключение", "Без туннеля сеть закрыта, кроме исключений"},
		{"Аварийное отключение", "Без туннеля трафик пойдёт открыто"},
		{"Исключения", "3 адреса мимо туннеля"},
		{"Исключения", "Ничего не пропускается мимо туннеля"},
		{"Весь трафик через VPN", "Иначе — только маршруты из профиля"},
		{"Запускать при входе в систему", "И сразу подключаться к выбранному профилю"},
	}
	for _, r := range rows {
		fits(t, "заголовок строки", r.title, FaceRow, textW)
		fits(t, "пояснение", r.hint, FaceSmall, textW)
	}

	// Профили: имя и адрес обрезаются, проверяем предельную длину.
	fits(t, "имя профиля", strings.Repeat("ш", maxProfileNameChars), FaceRow, textW)
	fits(t, "адрес профиля", strings.Repeat("ш", maxProfileServerChars), FaceSmall, textW)

	// Строка добавления — во всю ширину, без переключателя.
	addW := s.AddProfile.W - 2*15
	fits(t, "добавить", "+  Добавить по ссылке masquevpn://", FaceRow, addW)
	fits(t, "подсказка", "Ссылку выдаёт сервер командой clients add", FaceSmall, addW)
}

// TestButtonTextFits — надписи кнопки не должны доезжать до стрелки справа.
func TestButtonTextFits(t *testing.T) {
	m := MainLayout(false, 2)
	// Текст выровнен по центру, стрелка стоит у правого края: значит с
	// каждой стороны от текста должно остаться место под неё.
	const arrowZone = 26 * 2
	for _, s := range []State{Off, Connecting, On, Stopping} {
		fits(t, "кнопка", s.Button(), FaceButton, m.Button.W-arrowZone)
	}
}

// TestLogLineFits — строка журнала обрезается раньше, чем упрётся в край
// поля: иначе она молча уезжала бы под рамку.
func TestLogLineFits(t *testing.T) {
	m := MainLayout(true, 2)
	fits(t, "журнал", strings.Repeat("ш", maxLogLineChars), FaceMono, m.LogBox.W-24)

	// А в свёрнутом виде — подпись под словом «Журнал».
	fits(t, "подпись журнала", "12 записей, последняя 14:02", FaceSmall, m.LogRow.W-30-30)
}

// TestFooterFits — подпись внизу окна.
func TestFooterFits(t *testing.T) {
	m := MainLayout(false, 2)
	fits(t, "подпись окна", "masquevpn · MASQUE CONNECT-IP", FaceFooter, m.Footer.W)
	fits(t, "заголовок настроек", "Настройки", FaceTitle, SettingsLayout(0).Title.W)
}

// TestPluralRu — склонение при числе. Без него интерфейс сразу выдаёт
// машинный перевод: «5 запись».
func TestPluralRu(t *testing.T) {
	cases := map[int]string{
		1: "запись", 2: "записи", 4: "записи", 5: "записей",
		11: "записей", 12: "записей", 14: "записей", // особый случай второго десятка
		21: "запись", 22: "записи", 25: "записей",
		101: "запись", 111: "записей", 0: "записей",
	}
	for n, want := range cases {
		if got := plural(n, "запись", "записи", "записей"); got != want {
			t.Errorf("%d %s, ожидалось %s", n, got, want)
		}
	}
}

// TestAddLayoutFits — экран добавления: три поля не выходят за окно и
// каждое лежит внутри своей рамки. Поля ввода — настоящие системные
// элементы, и уехав за рамку, они выглядели бы белыми заплатами поверх окна.
func TestAddLayoutFits(t *testing.T) {
	a := AddLayout(false)
	named := map[string]Rect{
		"назад": a.Back, "заголовок": a.Title, "вставить": a.Paste,
		"добавить": a.Confirm, "сообщение": a.Notice, "подпись": a.Footer,
	}
	for i, f := range a.Fields {
		named["метка "+AddFieldTitles[i]] = f.Label
		named["рамка "+AddFieldTitles[i]] = f.Box
	}
	for name, r := range named {
		if r.X < 0 || r.Right() > WinW {
			t.Errorf("%s выходит за ширину окна: %+v", name, r)
		}
		if r.Y < CaptionH || r.Bottom() > AddLayout(false).Height {
			t.Errorf("%s выходит за высоту окна: %+v (окно %d)", name, r, AddLayout(false).Height)
		}
	}
	for i, f := range a.Fields {
		e := a.Edit(f.Box)
		if !contains(f.Box, e) {
			t.Errorf("поле %d вышло за рамку: %+v вне %+v", i, e, f.Box)
		}
		if e.H <= 0 || e.W <= 0 {
			t.Errorf("поле %d схлопнулось: %+v", i, e)
		}
	}

	// Блоки идут сверху вниз и не налезают — подпись внизу окна тоже в
	// этом ряду: сообщение об ошибке занимает две строки и легко доезжает
	// до неё.
	order := []Rect{}
	for _, f := range a.Fields {
		order = append(order, f.Label, f.Box)
	}
	order = append(order, a.Paste, a.Confirm, a.Notice, a.Footer)
	for i := 1; i < len(order); i++ {
		if order[i].Y < order[i-1].Bottom() {
			t.Errorf("блок %d налезает на предыдущий: %+v после %+v", i, order[i], order[i-1])
		}
	}
}

// TestAddTextFits — надписи экрана добавления.
func TestAddTextFits(t *testing.T) {
	a := AddLayout(false)
	fits(t, "заголовок", "Добавить сервер", FaceTitle, a.Title.W)
	for i, f := range a.Fields {
		fits(t, "метка поля", AddFieldTitles[i], FaceLabel, f.Label.W-32)
	}
	fits(t, "кнопка вставки", "Вставить из буфера", FaceRow, a.Paste.W-20)
	fits(t, "кнопка добавления", "Добавить", FaceButton, a.Confirm.W-52)

	// Сообщения переносятся на две строки, каждая — в свою ширину.
	messages := []string{
		"Эти три значения выдаёт сервер командой clients add. Можно вставить ссылку — она разложится по полям.",
		"Значения из буфера — проверьте адрес сервера и нажмите «Добавить».",
		"Укажите адрес сервера — например, vpn.example.com",
		"Без ключа доступа сервер не пустит: его выдаёт clients add",
		"в буфере не ссылка " + LinkScheme + ":// и не содержимое client.json",
	}
	for _, m := range messages {
		first, second := wrapTwo(m, maxNoticeChars)
		fits(t, "сообщение, строка 1", first, FaceSmall, a.Notice.W)
		fits(t, "сообщение, строка 2", second, FaceSmall, a.Notice.W)
	}
}

// TestWrapTwo — перенос не рвёт слова и не теряет текста.
func TestWrapTwo(t *testing.T) {
	first, second := wrapTwo("короткая строка", 40)
	if first != "короткая строка" || second != "" {
		t.Errorf("короткая строка перенесена: %q / %q", first, second)
	}

	long := "нужна ссылка masquevpn://… или содержимое файла client.json"
	first, second = wrapTwo(long, 30)
	if second == "" {
		t.Fatal("длинная строка не перенесена")
	}
	if strings.HasSuffix(first, " ") || strings.HasPrefix(second, " ") {
		t.Errorf("пробел на стыке строк: %q / %q", first, second)
	}
	// Слово не разорвано: стык пришёлся на пробел исходной строки.
	if !strings.Contains(long, strings.TrimSpace(first)) {
		t.Errorf("первая строка изменила текст: %q", first)
	}
	joined := strings.TrimSpace(first) + " " + second
	if joined != long {
		t.Errorf("перенос потерял или добавил текст:\n%q\n%q", joined, long)
	}
	if n := len([]rune(first)); n > 30 {
		t.Errorf("первая строка длиннее предела: %d", n)
	}
}

// TestAddHitsMatchLayout — кнопки экрана добавления нажимаются там, где
// нарисованы, и рамки полей ввода не перехватывают нажатия: внутри них
// стоит системный элемент со своим поведением.
func TestAddHitsMatchLayout(t *testing.T) {
	a := AddLayout(false)
	got := map[ItemID]Rect{}
	for _, h := range a.Hits() {
		got[h.ID] = h.Rect
	}
	for id, want := range map[ItemID]Rect{
		ItemBack: a.Back, ItemPasteLink: a.Paste, ItemAddConfirm: a.Confirm,
		ItemClose: a.Caption.Close, ItemMinimize: a.Caption.Minimize,
	} {
		if got[id] != want {
			t.Errorf("область %d: %+v, ожидалось %+v", id, got[id], want)
		}
	}
	for _, h := range a.Hits() {
		for i, f := range a.Fields {
			if overlap(h.Rect, f.Box) {
				t.Errorf("область %d накрывает поле %d: %+v", h.ID, i, h.Rect)
			}
		}
	}
}

// TestAddAndEditFields — на обоих экранах одни и те же четыре поля, и
// индексы у них совпадают: окно кладёт текст по FieldServer и не должно
// гадать, какой это номер на этом экране.
func TestAddAndEditFields(t *testing.T) {
	add, edit := AddLayout(false), AddLayout(true)
	for name, a := range map[string]Add{"добавление": add, "правка": edit} {
		if len(a.Fields) != MaxAddFields {
			t.Errorf("%s: полей %d, ожидалось %d", name, len(a.Fields), MaxAddFields)
		}
	}
	for i := range add.Fields {
		if add.Fields[i] != edit.Fields[i] {
			t.Errorf("поле %d стоит по-разному на двух экранах", i)
		}
	}
	if !edit.Editing || add.Editing {
		t.Error("режим не отражён в раскладке")
	}
	// Экран правки выше на кнопку удаления — больше ничем не отличается.
	if edit.Height <= add.Height {
		t.Errorf("окно правки не выросло под кнопку удаления: %d → %d", add.Height, edit.Height)
	}

	// Всё помещается и не налезает.
	for name, a := range map[string]Add{"добавление": add, "правка": edit} {
		order := []Rect{}
		for _, f := range a.Fields {
			order = append(order, f.Label, f.Box)
		}
		order = append(order, a.Paste, a.Confirm)
		if !a.Delete.Empty() {
			order = append(order, a.Delete)
		}
		order = append(order, a.Notice, a.Footer)
		for i := 1; i < len(order); i++ {
			if order[i].Y < order[i-1].Bottom() {
				t.Errorf("%s: блок %d налезает на предыдущий: %+v после %+v",
					name, i, order[i], order[i-1])
			}
		}
		if a.Footer.Bottom() > a.Height {
			t.Errorf("%s: подпись вышла за окно: %d > %d", name, a.Footer.Bottom(), a.Height)
		}
	}

	fits(t, "метка имени", AddFieldTitles[FieldName], FaceLabel, add.Fields[FieldName].Label.W-32)
	fits(t, "заголовок правки", "Изменить сервер", FaceTitle, edit.Title.W)
	fits(t, "кнопка сохранения", "Сохранить", FaceButton, edit.Confirm.W-52)
	first, second := wrapTwo("Изменения применятся при следующем подключении.", maxNoticeChars)
	fits(t, "сообщение правки, строка 1", first, FaceSmall, edit.Notice.W)
	fits(t, "сообщение правки, строка 2", second, FaceSmall, edit.Notice.W)
}

// TestDeleteOnEditOnly — кнопка удаления есть только при правке: при
// добавлении удалять нечего, и пустая кнопка там смотрелась бы ошибкой.
func TestDeleteOnEditOnly(t *testing.T) {
	if add := AddLayout(false); !add.Delete.Empty() {
		t.Error("на экране добавления есть кнопка удаления")
	}
	edit := AddLayout(true)
	if edit.Delete.Empty() {
		t.Fatal("на экране правки нет кнопки удаления")
	}
	if edit.Delete.Y < edit.Confirm.Bottom() {
		t.Error("удаление выше сохранения — его нажмут по ошибке")
	}
	if overlap(edit.Delete, edit.Notice) || overlap(edit.Delete, edit.Footer) {
		t.Error("кнопка удаления налезает на текст под ней")
	}
	fits(t, "кнопка удаления", "Удалить профиль", FaceRow, edit.Delete.W-20)

	// И она нажимается — ровно там, где нарисована.
	var found bool
	for _, h := range edit.Hits() {
		if h.ID == ItemDeleteProfile {
			found = true
			if h.Rect != edit.Delete {
				t.Errorf("область удаления %+v, нарисована %+v", h.Rect, edit.Delete)
			}
		}
	}
	if !found {
		t.Error("кнопка удаления не нажимается")
	}
	for _, h := range AddLayout(false).Hits() {
		if h.ID == ItemDeleteProfile {
			t.Error("на экране добавления удаление нажимается")
		}
	}
}

// TestMenuLayout — пункты идут сверху вниз, не налезают, помещаются в
// меню, и попадание указывает на тот пункт, который под курсором.
func TestMenuLayout(t *testing.T) {
	items := []MenuItem{
		{Text: "Сделать выбранным"},
		{Separator: true},
		{Text: "Переименовать"},
		{Text: "Изменить"},
		{Text: "Скопировать ссылку " + LinkScheme + "://"},
		{Separator: true},
		{Text: "Удалить профиль", Danger: true},
	}
	longest := 0
	for _, it := range items {
		if n := len([]rune(it.Text)); n > longest {
			longest = n
		}
	}
	m := MenuLayout(items, int32(widthOf(strings.Repeat("ш", longest), FaceRow)))

	if m.W < MenuMinW || m.W > MenuMaxW {
		t.Errorf("ширина меню %d вне разумных границ", m.W)
	}
	prev := int32(0)
	for i, r := range m.Items {
		if r.Y < prev {
			t.Errorf("пункт %d выше предыдущего: %+v", i, r)
		}
		prev = r.Y
		if r.Bottom() > m.H {
			t.Errorf("пункт %d выходит за меню: %d > %d", i, r.Bottom(), m.H)
		}
		if items[i].Separator != (r.H == 0) {
			t.Errorf("пункт %d: разделитель и высота не согласованы (%+v)", i, r)
		}
	}
	// Текст помещается: иначе длинные пункты обрежутся посередине слова.
	for _, it := range items {
		if it.Text == "" {
			continue
		}
		fits(t, "пункт меню", it.Text, FaceRow, m.W-2*MenuPadX)
	}

	// Попадание: центр каждого пункта указывает на него самого.
	for i, r := range m.Items {
		if r.H == 0 {
			if got := m.Hit(m.W/2, r.Y+MenuSepH/2); got == i {
				t.Errorf("разделитель %d считается пунктом", i)
			}
			continue
		}
		if got := m.Hit(m.W/2, r.Y+r.H/2); got != i {
			t.Errorf("центр пункта %d попал в %d", i, got)
		}
	}
	if got := m.Hit(m.W/2, -5); got != -1 {
		t.Errorf("точка выше меню попала в пункт %d", got)
	}
	if got := m.Hit(m.W+5, m.Items[0].Y+2); got != -1 {
		t.Errorf("точка правее меню попала в пункт %d", got)
	}
}

// TestWrapLog — длинные записи журнала переносятся, а не теряются: в
// обрезанном сообщении об ошибке причина как раз и оказывается за краем.
func TestWrapLog(t *testing.T) {
	long := "21:47:38  ошибка: подключение: utlsquic: QUIC dial: timeout: no recent network activity"
	out := WrapLog([]string{long}, maxLogLineChars)
	if len(out) < 2 {
		t.Fatalf("длинная запись не перенесена: %q", out)
	}
	// Склеиваем обратно, снимая ровно отступ продолжения: TrimLeft съел бы
	// и пробел исходной строки, попавший на границу переноса.
	const indent = "         "
	joined := out[0]
	for _, s := range out[1:] {
		joined += strings.TrimPrefix(s, indent)
	}
	if joined != long {
		t.Errorf("перенос изменил текст:\n%q\n%q", joined, long)
	}
	for i, s := range out {
		if n := len([]rune(s)); n > maxLogLineChars {
			t.Errorf("строка %d длиннее предела: %d знаков", i, n)
		}
		fits(t, "строка журнала", s, FaceMono, MainLayout(true, 2).LogBox.W-24)
	}
	// Продолжение отличается отступом — иначе читается как новая запись.
	if strings.HasPrefix(out[1], " ") == false {
		t.Error("продолжение записи не сдвинуто вправо")
	}
	// Короткие записи остаются как есть.
	short := []string{"21:47:10  готов к подключению"}
	if got := WrapLog(short, maxLogLineChars); len(got) != 1 || got[0] != short[0] {
		t.Errorf("короткая запись изменилась: %q", got)
	}
}
