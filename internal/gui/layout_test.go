package gui

import (
	"fmt"
	"reflect"
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
	for _, logOpen := range []bool{false, true} {
		for _, n := range []int{0, 1, 3, 9} {
			m := MainLayout(logOpen, n)
			named := map[string]Rect{
				"логотип": m.Logo, "плюс": m.Plus, "шестерёнка": m.Gear,
				"статус": m.StatusText, "сессия": m.Session, "кнопка": m.Button,
				"плитка вниз": m.TileDown, "плитка вверх": m.TileUp,
				"цифры": m.Stats, "профили": m.SectProfiles, "ещё профили": m.MoreProfiles,
				"журнал": m.LogRow, "поле журнала": m.LogBox, "подпись": m.Footer,
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
					t.Errorf("n=%d logOpen=%v: %s начинается за пределами окна: %+v", n, logOpen, name, r)
				}
				if r.Right() > WinW {
					t.Errorf("n=%d logOpen=%v: %s выходит вправо: %d > %d", n, logOpen, name, r.Right(), WinW)
				}
				if r.Bottom() > m.Height {
					t.Errorf("n=%d logOpen=%v: %s выходит вниз: %d > %d", n, logOpen, name, r.Bottom(), m.Height)
				}
			}
		}
	}
}

// TestMainLayoutNoOverlap — соседние блоки не налезают друг на друга.
func TestMainLayoutNoOverlap(t *testing.T) {
	m := MainLayout(true, 3)
	blocks := []struct {
		name string
		r    Rect
	}{
		{"статус", m.StatusText}, {"кнопка", m.Button},
		{"плитка вниз", m.TileDown}, {"плитка вверх", m.TileUp},
		{"цифры", m.Stats}, {"метка профилей", m.SectProfiles},
		{"строка журнала", m.LogRow}, {"поле журнала", m.LogBox}, {"подпись", m.Footer},
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

// TestMainProfileList — список профилей растит окно, но не бесконечно:
// после потолка появляется строка «ещё N — в настройках».
func TestMainProfileList(t *testing.T) {
	one, three := MainLayout(false, 1), MainLayout(false, 3)
	if len(one.Profiles) != 1 || len(three.Profiles) != 3 {
		t.Fatalf("строк в списке: %d и %d", len(one.Profiles), len(three.Profiles))
	}
	if three.Height <= one.Height {
		t.Errorf("три профиля не подняли высоту окна: %d → %d", one.Height, three.Height)
	}
	if !one.MoreProfiles.Empty() || !three.MoreProfiles.Empty() {
		t.Error("строка «ещё» появилась, хотя все профили влезли")
	}

	many := MainLayout(false, 9)
	if len(many.Profiles) != MaxMainProfiles {
		t.Errorf("показано %d профилей, потолок %d", len(many.Profiles), MaxMainProfiles)
	}
	if many.MoreProfiles.Empty() {
		t.Error("при девяти профилях нет строки «ещё N — в настройках»")
	}
	if many.Height > MaxMainProfiles*(RowH+RowGap)+600 {
		t.Errorf("окно выросло сверх ожидаемого: %d", many.Height)
	}

	// Без профилей список пуст, а окно всё равно собирается.
	none := MainLayout(false, 0)
	if len(none.Profiles) != 0 || none.Height <= 0 {
		t.Errorf("пустой список сломал раскладку: %+v", none)
	}
}

// TestMainProfileHits — по строке профиля можно нажать, и нажатие ведёт
// именно к тому профилю, который под курсором.
func TestMainProfileHits(t *testing.T) {
	m := MainLayout(false, 3)
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
	many := MainLayout(false, 9)
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

// TestMainLogTogglesHeight — раскрытый журнал добавляет окну высоты, и
// ровно один раз.
func TestMainLogTogglesHeight(t *testing.T) {
	closed, open := MainLayout(false, 2), MainLayout(true, 2)
	if !closed.LogBox.Empty() {
		t.Error("свёрнутый журнал занимает место")
	}
	if open.Height <= closed.Height {
		t.Errorf("раскрытие журнала не увеличило окно: %d → %d", closed.Height, open.Height)
	}
	if open.LogBox.H != LogBoxH {
		t.Errorf("высота поля журнала %d, ожидалась %d", open.LogBox.H, LogBoxH)
	}
	// Верхняя часть окна от раскрытия не сдвигается.
	if open.Button != closed.Button || open.Stats != closed.Stats {
		t.Error("раскрытие журнала сдвинуло кнопку или цифры")
	}
	if again := MainLayout(true, 2); !reflect.DeepEqual(again, open) {
		t.Error("раскладка зависит не только от аргументов")
	}
}

// TestStatCellsCoverStats — три ячейки делят блок цифр без щелей и нахлёстов.
// 392 на три нацело не делится, и остаток обязан достаться последней.
func TestStatCellsCoverStats(t *testing.T) {
	m := MainLayout(false, 2)
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
	m := MainLayout(false, 2)
	want := map[ItemID]Rect{
		ItemClose: m.Caption.Close, ItemMinimize: m.Caption.Minimize,
		ItemSettings: m.Gear, ItemAddProfile: m.Plus,
		ItemConnect: m.Button, ItemLogToggle: m.LogRow,
	}
	got := map[ItemID]Rect{}
	for _, h := range m.Hits() {
		if _, ok := ProfileIndex(h.ID); ok {
			continue // профили проверяются отдельно
		}
		if _, ok := ProfileMenuIndex(h.ID); ok {
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
	m := MainLayout(false, 2)
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
// прежним: растёт прокрутка, а не окно.
func TestSettingsLayoutGrows(t *testing.T) {
	one, many := SettingsLayout(1), SettingsLayout(6)
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

func contains(outer, inner Rect) bool {
	return inner.X >= outer.X && inner.Right() <= outer.Right() &&
		inner.Y >= outer.Y && inner.Bottom() <= outer.Bottom()
}

// TestSettingsScrollHitsClip — уехавшее за край окна просмотра не нажимается.
// Иначе щелчок по заголовку экрана попадал бы в прокрученную под него строку.
func TestSettingsScrollHitsClip(t *testing.T) {
	s := SettingsLayout(8)
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
	s := SettingsLayout(3)
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
}

// TestToggleInsideRow — переключатель не вылезает из своей строки.
func TestToggleInsideRow(t *testing.T) {
	s := SettingsLayout(2)
	for _, row := range []Rect{s.KillSwitch, s.FullTunnel, s.Autostart} {
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
	m := MainLayout(false, 1)
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
