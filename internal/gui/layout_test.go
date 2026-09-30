package gui

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

// overlap сообщает, пересекаются ли два прямоугольника.
func overlap(a, b Rect) bool {
	return a.X < b.Right() && b.X < a.Right() && a.Y < b.Bottom() && b.Y < a.Bottom()
}

// TestMainLayoutFits — ничего не вылезает за окно.
//
// Это та ошибка, которую на своей машине не видно: при 100% масштаба всё
// помещается, а у человека со 150% нижняя строка уезжает под край.
func TestMainLayoutFits(t *testing.T) {
	for _, h := range []int32{MinWinH, DefaultWinH, 900} {
		for _, n := range []int{0, 1, 3, 9, 30} {
			m := MainLayout(n, h)
			if m.Height != h {
				t.Fatalf("h=%d: раскладка посчитана для высоты %d", h, m.Height)
			}
			named := map[string]Rect{
				"логотип": m.Logo, "плюс": m.Plus, "шестерёнка": m.Gear,
				"статус": m.StatusText, "сессия": m.Session, "кнопка": m.Button,
				"плитка вниз": m.TileDown, "плитка вверх": m.TileUp,
				"цифры": m.Stats, "профили": m.SectProfiles, "ещё профили": m.MoreProfiles,
				"журнал": m.LogRow, "подпись": m.Footer,
				"закрыть": m.Caption.Close,
			}
			for i, r := range m.Profiles {
				named[fmt.Sprintf("профиль %d", i)] = r
			}
			for name, r := range named {
				if r.Empty() {
					continue
				}
				if r.X < 0 || r.Y < 0 {
					t.Errorf("h=%d n=%d: %s начинается за пределами окна: %+v", h, n, name, r)
				}
				if r.Right() > WinW {
					t.Errorf("h=%d n=%d: %s выходит вправо: %d > %d", h, n, name, r.Right(), WinW)
				}
				if r.Bottom() > h {
					t.Errorf("h=%d n=%d: %s выходит вниз: %d > %d", h, n, name, r.Bottom(), h)
				}
			}
		}
	}
}

// TestHeightIsFixed — высоту окна задаёт окно, а не содержимое: ни число
// профилей, ни экран её не меняют. Раньше окно прыгало при каждом переходе.
func TestHeightIsFixed(t *testing.T) {
	for _, h := range []int32{MinWinH, DefaultWinH, 777} {
		for _, n := range []int{0, 1, 4, 12} {
			if got := MainLayout(n, h).Height; got != h {
				t.Errorf("главный экран, %d профилей: высота %d вместо %d", n, got, h)
			}
			if got := SettingsLayout(n, h).Footer.Bottom(); got != FooterRect(h).Bottom() {
				t.Errorf("настройки, %d профилей: подпись на %d", n, got)
			}
		}
		for _, e := range []bool{false, true} {
			if got := AddLayout(e, h).Height; got != h {
				t.Errorf("добавление (правка=%v): высота %d вместо %d", e, got, h)
			}
		}
	}
	// Подпись стоит на одном месте на всех экранах: при переходе ничего не
	// дёргается.
	h := int32(DefaultWinH)
	foot := FooterRect(h)
	for name, r := range map[string]Rect{
		"главный": MainLayout(2, h).Footer, "настройки": SettingsLayout(2, h).Footer,
		"добавление": AddLayout(false, h).Footer, "журнал": LogLayout(h).Footer,
	} {
		if r != foot {
			t.Errorf("%s: подпись %+v, на остальных %+v", name, r, foot)
		}
	}
}

// TestClampHeight — мусор из файла настроек и крайности не ломают окно.
func TestClampHeight(t *testing.T) {
	for in, want := range map[int32]int32{
		0: DefaultWinH, -5: DefaultWinH, 10: MinWinH, MinWinH: MinWinH,
		700: 700, MaxWinH + 1: MaxWinH,
	} {
		if got := ClampHeight(in); got != want {
			t.Errorf("ClampHeight(%d) = %d, ожидалось %d", in, got, want)
		}
	}
	if !OnResizeEdge(DefaultWinH-1, DefaultWinH) || OnResizeEdge(DefaultWinH-ResizeEdge-1, DefaultWinH) {
		t.Error("полоса растяжения не у нижнего края")
	}
	// Полоса растяжения не накрывает ничего нажимаемого: подпись — не кнопка,
	// а строка журнала кончается выше.
	if m := MainLayout(2, DefaultWinH); m.LogRow.Bottom() > DefaultWinH-ResizeEdge {
		t.Error("строка журнала заходит в полосу растяжения")
	}
}

// TestMinHeightFitsEverything — MinWinH не выдуман: на этой высоте целиком
// помещается правка профиля, главный экран показывает хотя бы один профиль,
// а журнал — разумное число строк.
func TestMinHeightFitsEverything(t *testing.T) {
	for _, e := range []bool{false, true} {
		a := AddLayout(e, MinWinH)
		if a.ContentBottom > a.Footer.Y-8 {
			t.Errorf("правка=%v: форма (до %d) налезает на подпись (%d) при высоте %d",
				e, a.ContentBottom, a.Footer.Y, MinWinH)
		}
	}
	if m := MainLayout(3, MinWinH); len(m.Profiles) < 1 {
		t.Error("при наименьшей высоте на главном экране не видно ни одного профиля")
	}
	if rows := LogLayout(MinWinH).Rows(); rows < 20 {
		t.Errorf("журнал при наименьшей высоте показывает %d строк", rows)
	}
}

// TestMainLayoutNoOverlap — соседние блоки не налезают друг на друга.
func TestMainLayoutNoOverlap(t *testing.T) {
	m := MainLayout(3, 900)
	blocks := []struct {
		name string
		r    Rect
	}{
		{"статус", m.StatusText}, {"кнопка", m.Button},
		{"плитка вниз", m.TileDown}, {"плитка вверх", m.TileUp},
		{"цифры", m.Stats}, {"метка профилей", m.SectProfiles},
		{"строка журнала", m.LogRow}, {"ещё профили", m.MoreProfiles}, {"подпись", m.Footer},
	}
	for i, r := range m.Profiles {
		blocks = append(blocks, struct {
			name string
			r    Rect
		}{fmt.Sprintf("профиль %d", i), r})
	}
	for i := 0; i < len(blocks); i++ {
		for j := i + 1; j < len(blocks); j++ {
			if overlap(blocks[i].r, blocks[j].r) {
				t.Errorf("%s и %s пересекаются: %+v / %+v",
					blocks[i].name, blocks[j].name, blocks[i].r, blocks[j].r)
			}
		}
	}
	// Состояние и время сессии смотрят в разные стороны и обязаны разойтись.
	if overlap(m.StatusText, m.Session) {
		t.Errorf("статус налезает на время сессии: %+v / %+v", m.StatusText, m.Session)
	}
	// Кнопка — главный элемент и стоит выше сводки: искать её под цифрами
	// было бы странно.
	if m.Button.Y > m.Stats.Y {
		t.Error("кнопка оказалась ниже блока цифр")
	}
	if m.Button.Y < m.StatusText.Y {
		t.Error("кнопка оказалась выше строки состояния")
	}
}

// TestMainProfileList — профили занимают место между цифрами и журналом:
// сколько влезло — столько показано, остальные — строкой «ещё N — в
// настройках». Окно ради них не растёт.
func TestMainProfileList(t *testing.T) {
	one, two := MainLayout(1, DefaultWinH), MainLayout(2, DefaultWinH)
	if len(one.Profiles) != 1 || len(two.Profiles) != 2 {
		t.Fatalf("строк в списке: %d и %d", len(one.Profiles), len(two.Profiles))
	}
	if !one.MoreProfiles.Empty() || !two.MoreProfiles.Empty() {
		t.Error("строка «ещё» появилась, хотя все профили влезли")
	}

	many := MainLayout(9, DefaultWinH)
	if len(many.Profiles) == 0 || len(many.Profiles) >= 9 {
		t.Errorf("показано %d профилей из 9 при высоте %d", len(many.Profiles), DefaultWinH)
	}
	if many.MoreProfiles.Empty() {
		t.Error("при девяти профилях нет строки «ещё N — в настройках»")
	}
	last := many.MoreProfiles
	if last.Bottom() > many.LogRow.Y {
		t.Errorf("строка «ещё» (%+v) налезает на журнал (%+v)", last, many.LogRow)
	}
	// Выше окно — больше профилей на главном экране.
	if tall := MainLayout(9, 900); len(tall.Profiles) <= len(many.Profiles) {
		t.Errorf("высокое окно показывает %d профилей, обычное %d", len(tall.Profiles), len(many.Profiles))
	}

	// Без профилей список пуст, а окно всё равно собирается.
	none := MainLayout(0, DefaultWinH)
	if len(none.Profiles) != 0 || !none.MoreProfiles.Empty() {
		t.Errorf("пустой список сломал раскладку: %+v", none)
	}
	// Строка журнала прижата к низу при любом числе профилей.
	if none.LogRow != many.LogRow {
		t.Error("строка журнала сдвигается от числа профилей")
	}
}

// TestMainProfileHits — по строке профиля можно нажать, и нажатие ведёт
// именно к тому профилю, который под курсором.
func TestMainProfileHits(t *testing.T) {
	m := MainLayout(3, 900)
	got := map[int]Rect{}
	for _, h := range m.Hits() {
		if i, ok := ProfileIndex(h.ID); ok {
			got[i] = h.Rect
		}
	}
	if len(got) != 3 {
		t.Fatalf("нажимаемых профилей %d, ожидалось 3", len(got))
	}
	for i, r := range m.Profiles {
		if got[i] != r {
			t.Errorf("профиль %d: область %+v, нарисован %+v", i, got[i], r)
		}
	}
	// Кнопка «…» в строке профиля: своё действие, и она обязана стоять в
	// списке раньше самой строки — иначе нажатие на неё выбирало бы
	// профиль вместо открытия меню.
	menuAt, rowAt := -1, -1
	for i, h := range m.Hits() {
		if h.ID == ItemProfileMenuBase && menuAt < 0 {
			menuAt = i
		}
		if h.ID == ItemProfileBase && rowAt < 0 {
			rowAt = i
		}
	}
	if menuAt < 0 {
		t.Fatal("у строки профиля нет кнопки меню")
	}
	if menuAt > rowAt {
		t.Error("строка профиля перехватывает нажатие на кнопку меню")
	}
	for i, menu := range m.ProfileMenus {
		if !contains(m.Profiles[i], menu) {
			t.Errorf("кнопка меню %d лежит вне своей строки: %+v / %+v", i, menu, m.Profiles[i])
		}
	}

	// Строка «ещё N» ведёт в настройки — иначе она выглядела бы кнопкой,
	// которая ничего не делает.
	many := MainLayout(9, DefaultWinH)
	found := false
	for _, h := range many.Hits() {
		if h.ID == ItemSettings && h.Rect == many.MoreProfiles {
			found = true
		}
	}
	if !found {
		t.Error("строка «ещё N — в настройках» не нажимается")
	}
}

// TestLogScreen — журнал занимает весь экран, у него есть «назад» и
// «копировать», и нажатия попадают туда, где нарисовано.
func TestLogScreen(t *testing.T) {
	for _, h := range []int32{MinWinH, DefaultWinH, 1000} {
		l := LogLayout(h)
		for name, r := range map[string]Rect{"назад": l.Back, "копировать": l.Copy, "строки": l.Box, "подпись": l.Footer} {
			if r.Empty() || r.X < 0 || r.Right() > WinW || r.Bottom() > h {
				t.Errorf("h=%d: %s вне окна: %+v", h, name, r)
			}
		}
		if overlap(l.Box, l.Footer) || overlap(l.Copy, l.Title) || overlap(l.Box, l.Copy) {
			t.Errorf("h=%d: элементы журнала наложились", h)
		}
		want := map[ItemID]Rect{ItemClose: l.Caption.Close, ItemMinimize: l.Caption.Minimize,
			ItemBack: l.Back, ItemLogCopy: l.Copy}
		got := map[ItemID]Rect{}
		for _, hit := range l.Hits() {
			got[hit.ID] = hit.Rect
		}
		if !reflect.DeepEqual(want, got) {
			t.Errorf("области нажатия журнала: %+v", got)
		}
	}
	// Выше окно — больше строк.
	if LogLayout(900).Rows() <= LogLayout(DefaultWinH).Rows() {
		t.Error("высокое окно не показывает больше строк журнала")
	}
}

// TestLogWindow — прокрутка журнала считается от конца: без прокрутки видно
// последние строки, прокрутка вверх сдвигает окно, и за края она не уходит.
func TestLogWindow(t *testing.T) {
	var lines []string
	for i := 0; i < 50; i++ {
		lines = append(lines, fmt.Sprintf("12:00:%02d  запись %d", i, i))
	}
	shown, first, total, sc := LogWindow(lines, 10, 0, 0)
	if total != 50 || first != 40 || len(shown) != 10 || sc != 0 || shown[9] != lines[49] {
		t.Fatalf("хвост: first=%d total=%d n=%d scroll=%d last=%q", first, total, len(shown), sc, shown[len(shown)-1])
	}
	shown, first, _, sc = LogWindow(lines, 10, 0, 5)
	if first != 35 || shown[0] != lines[35] || sc != 5 {
		t.Fatalf("прокрутка на 5: first=%d scroll=%d", first, sc)
	}
	_, first, _, sc = LogWindow(lines, 10, 0, 1000)
	if first != 0 || sc != 40 {
		t.Fatalf("прокрутка за начало: first=%d scroll=%d", first, sc)
	}
	_, _, _, sc = LogWindow(lines, 10, 0, -3)
	if sc != 0 {
		t.Fatalf("отрицательная прокрутка: %d", sc)
	}
	// Строк меньше, чем места, — прокручивать нечего.
	shown, first, _, sc = LogWindow(lines[:3], 10, 0, 7)
	if len(shown) != 3 || first != 0 || sc != 0 {
		t.Fatalf("короткий журнал: n=%d first=%d scroll=%d", len(shown), first, sc)
	}
	// Длинная запись переносится, и перенос учитывается в прокрутке.
	long := []string{"12:00:00  " + strings.Repeat("а", 3*maxLogLineChars)}
	if _, _, total, _ := LogWindow(long, 10, 0, 0); total < 3 {
		t.Fatalf("длинная запись не перенесена: %d строк", total)
	}
	// Уже строка — больше строк после переноса: прокрутка это учитывает.
	if _, _, narrow, _ := LogWindow(long, 10, 30, 0); narrow <= 3 {
		t.Fatalf("при 30 знаках в строке запись заняла %d строк", narrow)
	}
}

// TestStatCellsCoverStats — три ячейки делят блок цифр без щелей и нахлёстов.
// 392 на три нацело не делится, и остаток обязан достаться последней.
func TestStatCellsCoverStats(t *testing.T) {
	m := MainLayout(2, DefaultWinH)
	if m.StatCells[0].X != m.Stats.X {
		t.Error("первая ячейка не начинается с левого края блока")
	}
	for i := 1; i < len(m.StatCells); i++ {
		if m.StatCells[i].X != m.StatCells[i-1].Right() {
			t.Errorf("между ячейками %d и %d щель или нахлёст: %d ≠ %d",
				i-1, i, m.StatCells[i].X, m.StatCells[i-1].Right())
		}
	}
	if last := m.StatCells[len(m.StatCells)-1]; last.Right() != m.Stats.Right() {
		t.Errorf("ячейки не покрывают блок: %d ≠ %d", last.Right(), m.Stats.Right())
	}
}

// TestCaptionDragExcludesButtons — за кнопки окно не таскается, иначе
// «закрыть» превращается в перетаскивание при малейшем дрожании руки.
func TestCaptionDragExcludesButtons(t *testing.T) {
	c := captionLayout()
	if overlap(c.Drag, c.Close) || overlap(c.Drag, c.Minimize) {
		t.Errorf("область перетаскивания накрывает кнопки: %+v", c)
	}
	if c.Close.Right() > WinW {
		t.Error("кнопка закрытия вышла за окно")
	}
	if overlap(c.Close, c.Minimize) {
		t.Error("кнопки заголовка наложились")
	}
}

// TestMainHitsMatchLayout — области нажатия совпадают с нарисованным.
// Расхождение здесь — это «нажимаю на кнопку, ничего не происходит».
func TestMainHitsMatchLayout(t *testing.T) {
	m := MainLayout(2, DefaultWinH)
	want := map[ItemID]Rect{
		ItemClose: m.Caption.Close, ItemMinimize: m.Caption.Minimize,
		ItemSettings: m.Gear, ItemAddProfile: m.Plus,
		ItemConnect: m.Button, ItemLog: m.LogRow,
		ItemPingAll: m.PingAll,
	}
	got := map[ItemID]Rect{}
	for _, h := range m.Hits() {
		if _, ok := ProfileIndex(h.ID); ok {
			continue // профили проверяются отдельно
		}
		if _, ok := ProfileMenuIndex(h.ID); ok {
			continue
		}
		if _, ok := ProfilePingIndex(h.ID); ok {
			continue
		}
		got[h.ID] = h.Rect
	}
	if !reflect.DeepEqual(want, got) {
		t.Errorf("области нажатия разошлись с раскладкой:\nнужно %+v\nесть  %+v", want, got)
	}
	// Центр кнопки обязан попадать в саму кнопку — проверка самой Contains.
	if !m.Button.Contains(m.Button.X+m.Button.W/2, m.Button.Y+m.Button.H/2) {
		t.Error("центр кнопки не считается попаданием")
	}
	if m.Button.Contains(m.Button.Right(), m.Button.Y) {
		t.Error("правая граница включена в прямоугольник: соседний элемент перехватит нажатие")
	}
}

// TestHeaderButtonsSeparate — кнопки в шапке не наложились друг на друга и
// не наехали на логотип: между ними нажатие должно попадать в ту, что
// нарисована.
func TestHeaderButtonsSeparate(t *testing.T) {
	m := MainLayout(2, DefaultWinH)
	if overlap(m.Plus, m.Gear) {
		t.Errorf("плюс и шестерёнка пересекаются: %+v / %+v", m.Plus, m.Gear)
	}
	if m.Plus.Right() > m.Gear.X {
		t.Error("плюс заходит на шестерёнку")
	}
	if overlap(m.Plus, m.Logo) && m.Logo.Right() > m.Plus.X {
		t.Error("логотип дотягивается до кнопок шапки")
	}
	if m.Plus.Y != m.Gear.Y || m.Plus.H != m.Gear.H {
		t.Error("кнопки шапки стоят на разной высоте")
	}
}

// TestSettingsLayoutGrows — список профилей удлиняет ленту, а окно остаётся
// прежним: растёт прокрутка, а не окно. Выше окно — больше окно просмотра.
func TestSettingsLayoutGrows(t *testing.T) {
	one, many := SettingsLayout(1, DefaultWinH), SettingsLayout(6, DefaultWinH)
	if many.ContentH <= one.ContentH {
		t.Errorf("шесть профилей не удлинили ленту: %d → %d", one.ContentH, many.ContentH)
	}
	if many.Viewport != one.Viewport {
		t.Error("окно просмотра изменилось от числа профилей")
	}
	if one.MaxScroll() != 0 {
		t.Errorf("с одним профилем лента прокручивается на %d, а должна помещаться", one.MaxScroll())
	}
	if many.MaxScroll() == 0 {
		t.Error("с шестью профилями прокрутка не появилась")
	}
	if tall := SettingsLayout(6, 1100); tall.Viewport.H <= many.Viewport.H || tall.MaxScroll() >= many.MaxScroll() {
		t.Error("высокое окно не увеличило окно просмотра настроек")
	}
	if len(many.Profiles) != 6 || len(many.ProfileMenus) != 6 {
		t.Fatalf("профилей в раскладке %d/%d, ожидалось 6", len(many.Profiles), len(many.ProfileMenus))
	}
	for i, r := range many.Profiles {
		if i > 0 && r.Y <= many.Profiles[i-1].Y {
			t.Errorf("профиль %d не ниже предыдущего", i)
		}
		if !contains(r, many.ProfileMenus[i]) {
			t.Errorf("кнопка меню профиля %d лежит вне его строки: %+v / %+v",
				i, many.ProfileMenus[i], r)
		}
	}
}

// TestNoFullTunnelSwitch — переключателя «весь трафик через VPN» больше нет:
// выключенный, он без списка сетей давал нерабочий профиль, а списка сетей в
// окне нет. Раздельный туннель остался для тех, кто правит файл.
func TestNoFullTunnelSwitch(t *testing.T) {
	s := SettingsLayout(2, DefaultWinH)
	if s.Allow.Bottom()+RowGap+12 != s.SectProfiles.Y {
		t.Errorf("после «Исключений» лишняя строка: %+v → %+v", s.Allow, s.SectProfiles)
	}
	for _, h := range s.ScrollHits(0) {
		if h.Rect.Y > s.Allow.Bottom()+s.Viewport.Y && h.Rect.Y < s.SectProfiles.Y+s.Viewport.Y {
			t.Errorf("между защитой и профилями нажимается что-то ещё: %+v", h)
		}
	}
}

func contains(outer, inner Rect) bool {
	return inner.X >= outer.X && inner.Right() <= outer.Right() &&
		inner.Y >= outer.Y && inner.Bottom() <= outer.Bottom()
}

// TestSettingsScrollHitsClip — уехавшее за край окна просмотра не нажимается.
// Иначе щелчок по заголовку экрана попадал бы в прокрученную под него строку.
func TestSettingsScrollHitsClip(t *testing.T) {
	s := SettingsLayout(8, DefaultWinH)
	top := s.ScrollHits(0)
	if len(top) == 0 {
		t.Fatal("без прокрутки не нашлось ни одной области")
	}
	for _, h := range top {
		if h.Rect.Bottom() <= s.Viewport.Y || h.Rect.Y >= s.Viewport.Bottom() {
			t.Errorf("область %d нарисована вне окна просмотра: %+v", h.ID, h.Rect)
		}
	}
	// Прокрутив до конца, первую строку («аварийное отключение») нажать
	// нельзя — она уехала вверх.
	bottom := s.ScrollHits(s.MaxScroll())
	for _, h := range bottom {
		if h.ID == ItemKillSwitch {
			t.Error("прокрученная за верх строка осталась нажимаемой")
		}
	}
	// Зато нажимается последняя.
	found := false
	for _, h := range bottom {
		if h.ID == ItemAutostart {
			found = true
		}
	}
	if !found {
		t.Error("после прокрутки до конца последняя строка недоступна")
	}
}

// TestSettingsMenuBeforeRow — кнопка меню профиля обязана стоять в списке
// раньше самой строки: первое совпадение выигрывает, и иначе нажатие на
// «…» выбирало бы профиль вместо открытия меню.
func TestSettingsMenuBeforeRow(t *testing.T) {
	s := SettingsLayout(3, DefaultWinH)
	hits := s.ScrollHits(0)
	menuAt, rowAt := -1, -1
	for i, h := range hits {
		if h.ID == ItemProfileMenuBase && menuAt < 0 {
			menuAt = i
		}
		if h.ID == ItemProfileBase && rowAt < 0 {
			rowAt = i
		}
	}
	if menuAt < 0 || rowAt < 0 {
		t.Fatalf("не нашлись области профиля: меню %d, строка %d", menuAt, rowAt)
	}
	if menuAt > rowAt {
		t.Error("строка профиля перехватывает нажатие на кнопку меню")
	}
}

// TestProfileIndexRoundTrip — номер профиля восстанавливается из
// идентификатора, и диапазоны не пересекаются.
func TestProfileIndexRoundTrip(t *testing.T) {
	for _, i := range []int{0, 1, 17, 999} {
		if got, ok := ProfileIndex(ItemProfileBase + ItemID(i)); !ok || got != i {
			t.Errorf("профиль %d вернулся как %d (ok=%v)", i, got, ok)
		}
		if got, ok := ProfileMenuIndex(ItemProfileMenuBase + ItemID(i)); !ok || got != i {
			t.Errorf("меню профиля %d вернулось как %d (ok=%v)", i, got, ok)
		}
	}
	if _, ok := ProfileIndex(ItemConnect); ok {
		t.Error("кнопка подключения опознана как профиль")
	}
	if _, ok := ProfileIndex(ItemProfileMenuBase); ok {
		t.Error("диапазоны профилей и их меню пересекаются")
	}
	for _, i := range []int{0, 5, 999} {
		if got, ok := ProfilePingIndex(ItemProfilePingBase + ItemID(i)); !ok || got != i {
			t.Errorf("пинг профиля %d вернулся как %d (ok=%v)", i, got, ok)
		}
	}
	if _, ok := ProfileMenuIndex(ItemProfilePingBase); ok {
		t.Error("диапазоны меню и пинга пересекаются")
	}
	if _, ok := ProfilePingIndex(ItemProfileMenuBase + 999); ok {
		t.Error("меню опознано как пинг")
	}
}

// TestPingButtons — кнопка пинга стоит в каждой строке, внутри неё, слева от
// «…» и не налезая на неё; в списке нажатий она раньше строки (иначе нажатие
// выбирало бы профиль). «Пинг всех» — справа от метки «Профили», на её
// уровне, и не задевает ни строк, ни цифр над меткой.
func TestPingButtons(t *testing.T) {
	m := MainLayout(3, DefaultWinH)
	if len(m.ProfilePings) != len(m.Profiles) {
		t.Fatalf("кнопок пинга %d на %d строк", len(m.ProfilePings), len(m.Profiles))
	}
	order := map[ItemID]int{}
	for i, h := range m.Hits() {
		if _, ok := order[h.ID]; !ok {
			order[h.ID] = i
		}
	}
	for i, p := range m.ProfilePings {
		row, menu := m.Profiles[i], m.ProfileMenus[i]
		if !contains(row, p) {
			t.Errorf("пинг %d вне строки: %+v / %+v", i, p, row)
		}
		if overlap(p, menu) || p.Right() > menu.X {
			t.Errorf("пинг %d налез на «…» или стоит правее: %+v / %+v", i, p, menu)
		}
		if p.W != PingPillW || p.H != PingPillH {
			t.Errorf("пинг %d размером %dx%d", i, p.W, p.H)
		}
		// По вертикали — посередине строки, как и «…».
		if p.Y+p.H/2 != row.Y+row.H/2 {
			t.Errorf("пинг %d не по центру строки", i)
		}
		pi, ok1 := order[ItemProfilePingBase+ItemID(i)]
		ri, ok2 := order[ItemProfileBase+ItemID(i)]
		if !ok1 || !ok2 || pi > ri {
			t.Errorf("строка %d перехватывает нажатие на пинг", i)
		}
	}

	pa := m.PingAll
	if pa.Empty() {
		t.Fatal("нет «Пинг всех»")
	}
	if pa.Right() != m.SectProfiles.Right() {
		t.Errorf("«Пинг всех» не прижат вправо: %d ≠ %d", pa.Right(), m.SectProfiles.Right())
	}
	mid := m.SectProfiles.Y + m.SectProfiles.H/2
	if pa.Y > mid || pa.Bottom() < mid {
		t.Error("«Пинг всех» не на уровне метки «Профили»")
	}
	if overlap(pa, m.Stats) || overlap(pa, m.Profiles[0]) {
		t.Errorf("«Пинг всех» задевает соседей: %+v", pa)
	}
	// Метка слева и кнопка справа не сходятся.
	if float64(m.SectProfiles.X+32)+widthOf("Профили", FaceLabel) > float64(pa.X) {
		t.Error("«Пинг всех» налезает на метку «Профили»")
	}
	if _, ok := order[ItemPingAll]; !ok {
		t.Error("«Пинг всех» не нажимается")
	}

	// В настройках — такие же кнопки, и в ленте нажатий они раньше строк.
	st := SettingsLayout(3, DefaultWinH)
	for i, p := range st.ProfilePings {
		if !contains(st.Profiles[i], p) || overlap(p, st.ProfileMenus[i]) {
			t.Errorf("настройки, пинг %d: %+v", i, p)
		}
	}
	sorder := map[ItemID]int{}
	for i, h := range st.ScrollHits(0) {
		if _, ok := sorder[h.ID]; !ok {
			sorder[h.ID] = i
		}
	}
	if p, ok := sorder[ItemProfilePingBase]; !ok || p > sorder[ItemProfileBase] {
		t.Error("в настройках строка перехватывает нажатие на пинг")
	}

	// Без профилей пинговать некого: кнопки нет.
	if e := MainLayout(0, DefaultWinH); !e.PingAll.Empty() {
		t.Error("«Пинг всех» при пустом списке")
	}
	for _, h := range MainLayout(0, DefaultWinH).Hits() {
		if h.ID == ItemPingAll {
			t.Error("пустой «Пинг всех» в списке нажатий")
		}
	}
}

// TestToggleInsideRow — переключатель не вылезает из своей строки.
func TestToggleInsideRow(t *testing.T) {
	s := SettingsLayout(2, DefaultWinH)
	for _, row := range []Rect{s.KillSwitch, s.Autostart} {
		tg := Toggle(row)
		if !contains(row, tg) {
			t.Errorf("переключатель вне строки: %+v / %+v", tg, row)
		}
		if tg.Right() >= row.Right() {
			t.Error("переключатель прижат к самому краю строки")
		}
	}
}

// Полоса заголовка должна читаться как отдельная полоса, а не как верх окна.
//
// Раньше она отличалась от фона на один-два уровня яркости (0x0A100D против
// 0x090F0C) — на тёмном экране это не различается вовсе, и кнопки «свернуть»
// и «закрыть» висели прямо в содержимом. Поэтому здесь две проверки: оттенок
// и черта по нижнему краю.
func TestCaptionReadsAsSeparateBar(t *testing.T) {
	c := captionLayout()

	if c.Line.W != WinW || c.Line.H < 1 {
		t.Fatalf("черта под заголовком %+v — она должна идти во всю ширину окна", c.Line)
	}
	if c.Line.Bottom() != c.Bar.Bottom() {
		t.Fatalf("черта кончается на %d, а полоса на %d — черта не на границе",
			c.Line.Bottom(), c.Bar.Bottom())
	}
	// Черта не должна наезжать на кнопки полосы.
	if c.Line.Y < c.Close.Bottom() {
		t.Fatalf("черта на %d проходит по кнопкам (низ кнопки %d)", c.Line.Y, c.Close.Bottom())
	}
	// И содержимое всех экранов начинается ниже полосы.
	m := MainLayout(1, DefaultWinH)
	if m.Logo.Y < c.Bar.Bottom() {
		t.Fatalf("логотип на %d заходит в полосу заголовка (низ %d)", m.Logo.Y, c.Bar.Bottom())
	}

	diff := func(a, b Color) int {
		ar, ag, ab := a.Parts()
		br, bg, bb := b.Parts()
		d := int(ar) - int(br)
		if v := int(ag) - int(bg); v < d {
			d = v
		}
		if v := int(ab) - int(bb); v < d {
			d = v
		}
		return d
	}
	if d := diff(ColorCaption, ColorBG); d < 3 {
		t.Fatalf("полоса заголовка светлее фона всего на %d — на экране это одно и то же", d)
	}
	if d := diff(ColorCaptionLn, ColorCaption); d < 5 {
		t.Fatalf("черта светлее полосы на %d — её не будет видно", d)
	}
}

func TestWindowPrefs(t *testing.T) {
	path := t.TempDir() + "/sub/" + WindowPrefsFile
	if p := LoadWindowPrefs(path); p.Height != DefaultWinH {
		t.Fatalf("без файла высота %d", p.Height)
	}
	if err := SaveWindowPrefs(path, WindowPrefs{Height: 777}); err != nil {
		t.Fatal(err)
	}
	if p := LoadWindowPrefs(path); p.Height != 777 {
		t.Fatalf("высота не сохранилась: %d", p.Height)
	}
	if err := os.WriteFile(path, []byte("мусор"), 0o600); err != nil {
		t.Fatal(err)
	}
	if p := LoadWindowPrefs(path); p.Height != DefaultWinH {
		t.Fatalf("испорченный файл дал высоту %d", p.Height)
	}
	if err := os.WriteFile(path, []byte(`{"height":5}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if p := LoadWindowPrefs(path); p.Height != MinWinH {
		t.Fatalf("слишком низкое окно не поднято до MinWinH: %d", p.Height)
	}
}
