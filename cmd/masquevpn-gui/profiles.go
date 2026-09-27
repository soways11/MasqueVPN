//go:build linux

package main

// Профили, настройки и меню — те же действия, что в окне Windows.
//
// Меню здесь рисуется слоем поверх окна, а не отдельным окном: в X11
// всплывающее окно требует захвата указателя и своей обработки потери
// фокуса, а выглядит ровно так же — рисует его один и тот же gui.PaintMenu.

import (
	"strings"

	"github.com/soways11/masquevpn/internal/config"
	"github.com/soways11/masquevpn/internal/gui"
	"github.com/soways11/masquevpn/internal/guiraster"
)

// Пункты меню профиля.
const (
	menuUse gui.ItemID = iota + 900
	menuRename
	menuEdit
	menuCopyLink
	menuRemove
)

func (a *app) loadProfiles() {
	path := config.DefaultProfilesPath()
	profiles, err := config.LoadProfiles(path)
	if err != nil {
		a.appendLog("не читается файл профилей: " + err.Error())
		profiles = &config.Profiles{}
	}
	a.profiles = profiles
}

func (a *app) profileCount() int {
	if a.profiles == nil {
		return 0
	}
	return len(a.profiles.List)
}

func (a *app) active() (config.Profile, bool) {
	if a.profiles == nil {
		return config.Profile{}, false
	}
	pr, ok := a.profiles.Active()
	if !ok || pr.Config == nil {
		return config.Profile{}, false
	}
	return pr, true
}

func (a *app) saveProfiles() {
	if err := a.profiles.Save(); err != nil {
		a.appendLog("не удалось сохранить профили: " + err.Error())
	}
}

func (a *app) selectProfile(i int) {
	if i < 0 || i >= len(a.profiles.List) {
		return
	}
	name := a.profiles.List[i].Name
	if strings.EqualFold(name, a.profiles.Current) {
		return
	}
	// На ходу профиль не меняем: переключение означало бы разрыв туннеля в
	// ответ на щелчок, которым человек, возможно, просто смотрел список.
	if a.currentState() != gui.Off {
		a.appendLog("сначала отключитесь — профиль меняется при выключенном туннеле")
		return
	}
	if err := a.profiles.Select(name); err != nil {
		a.appendLog(err.Error())
		return
	}
	a.saveProfiles()
	a.appendLog("выбран профиль: " + name)
}

func (a *app) toggleSetting(name string) {
	pr, ok := a.active()
	if !ok {
		return
	}
	var value bool
	switch name {
	case "kill_switch":
		value = !(pr.Config.KillSwitch != nil && *pr.Config.KillSwitch)
		v := value
		pr.Config.KillSwitch = &v
	case "full_tunnel":
		value = !(pr.Config.FullTunnel != nil && *pr.Config.FullTunnel)
		v := value
		pr.Config.FullTunnel = &v
	default:
		return
	}
	a.saveProfiles()
	a.appendLog(name + ": " + onOff(value))
	if a.currentState() != gui.Off {
		a.appendLog("применится при следующем подключении")
	}
	if name == "kill_switch" && !value {
		// Выключение аварийного отключения — не мелочь: без него при обрыве
		// туннеля трафик пойдёт открыто, и человек об этом не узнает.
		a.appendLog("внимание: при обрыве туннеля трафик пойдёт открыто")
	}
}

func onOff(v bool) string {
	if v {
		return "включено"
	}
	return "выключено"
}

// ---------- экран добавления и правки ----------

func (a *app) openAddScreen() {
	a.addFrom = a.screen
	a.screen, a.editing, a.editIdx = gui.ScreenAdd, false, -1
	a.fields = [gui.MaxAddFields]string{}
	a.focus = gui.FieldServer
	a.clearNotice()
	a.resize()
}

func (a *app) openEditScreen(i, focus int) {
	if i < 0 || i >= len(a.profiles.List) {
		return
	}
	pr := a.profiles.List[i]
	a.addFrom = a.screen
	a.screen, a.editing, a.editIdx = gui.ScreenAdd, true, i
	a.fields[gui.FieldServer] = pr.Config.Server
	a.fields[gui.FieldAuthKey] = string(pr.Config.AuthKey)
	a.fields[gui.FieldClientID] = pr.Config.ClientID
	a.fields[gui.FieldName] = pr.Name
	a.focus = focus
	a.clearNotice()
	a.resize()
}

func (a *app) clearNotice() { a.notice, a.failed, a.badField = "", false, 0 }

func (a *app) fail(field int, text string) {
	a.notice, a.failed, a.badField = text, true, field
	if field > 0 {
		a.focus = field - 1
	}
	a.invalidate()
}

func (a *app) confirmAdd() {
	server := strings.TrimSpace(a.fields[gui.FieldServer])
	key := strings.TrimSpace(a.fields[gui.FieldAuthKey])
	id := strings.TrimSpace(a.fields[gui.FieldClientID])
	name := strings.TrimSpace(a.fields[gui.FieldName])

	// Правила формы общие с Windows и телефоном (config.BuildForm).
	cfg, err := config.BuildForm(server, key, id)
	if err != nil {
		a.fail(config.FormErrorOf(err))
		return
	}
	pr, err := a.storeProfile(cfg, name)
	if err != nil {
		a.fail(0, err.Error())
		return
	}
	a.saveProfiles()
	if a.editing {
		a.appendLog("профиль изменён: " + pr.Name)
	} else {
		a.appendLog("добавлен профиль: " + pr.Name)
	}

	a.screen, a.editing, a.scrollY = gui.ScreenSettings, false, 0
	a.clearNotice()
	a.resize()
}

// storeProfile записывает конфигурацию: при добавлении заводит новый
// профиль, при правке заменяет существующий. Правила правки (выбранный
// остаётся выбранным, чужое имя не затирается) — в config.Profiles.Update.
func (a *app) storeProfile(cfg *config.Client, name string) (config.Profile, error) {
	if !a.editing {
		return a.profiles.Add(name, cfg)
	}
	if a.editIdx < 0 || a.editIdx >= len(a.profiles.List) {
		return config.Profile{}, errText("профиль исчез, пока его правили")
	}
	return a.profiles.Update(a.profiles.List[a.editIdx].Name, name, cfg)
}

func (a *app) deleteEdited() {
	if !a.editing || a.editIdx < 0 || a.editIdx >= len(a.profiles.List) {
		return
	}
	name := a.profiles.List[a.editIdx].Name
	if a.currentState() != gui.Off && strings.EqualFold(name, a.profiles.Current) {
		a.fail(0, "Профиль подключён — сначала отключитесь")
		return
	}
	if err := a.profiles.Remove(name); err != nil {
		a.fail(0, err.Error())
		return
	}
	a.saveProfiles()
	a.appendLog("профиль удалён: " + name)
	a.screen, a.editing, a.scrollY = a.addFrom, false, 0
	a.clearNotice()
	a.resize()
}

type errText string

func (e errText) Error() string { return string(e) }

// ---------- меню ----------

func (a *app) openProfileMenu(i int) {
	if i < 0 || i >= len(a.profiles.List) {
		return
	}
	a.menuOwner = i
	a.menu = []gui.MenuItem{
		{ID: menuUse, Text: "Сделать выбранным"},
		{Separator: true},
		{ID: menuRename, Text: "Переименовать"},
		{ID: menuEdit, Text: "Изменить"},
		{ID: menuCopyLink, Text: "Скопировать ссылку " + config.LinkScheme + "://"},
		{Separator: true},
		{ID: menuRemove, Text: "Удалить профиль", Danger: true},
	}
	a.menuHot = -1

	// Меню встаёт под кнопкой «…» и, если не помещается, поднимается вверх:
	// у нижнего края окна оно иначе уехало бы за его пределы.
	row := a.profileMenuRect(i)
	layout := a.menuLayout()
	x := row.Right() - layout.W
	y := row.Bottom() + 4
	if _, h := a.windowSize(); y+layout.H > int32(float64(h)/a.scale) {
		y = row.Y - layout.H - 4
	}
	if y < gui.CaptionH {
		y = gui.CaptionH
	}
	a.menuAt = gui.Rect{X: x, Y: y, W: layout.W, H: layout.H}
	a.invalidate()
}

// profileMenuRect — где нарисована кнопка «…» у i-го профиля.
func (a *app) profileMenuRect(i int) gui.Rect {
	if a.screen == gui.ScreenSettings {
		s := gui.SettingsLayout(a.profileCount())
		if i < len(s.ProfileMenus) {
			r := s.ProfileMenus[i]
			r.Y = r.Y + s.Viewport.Y - a.scrollY
			return r
		}
		return s.Back
	}
	m := gui.MainLayout(a.logOpen, a.profileCount())
	if i < len(m.ProfileMenus) {
		return m.ProfileMenus[i]
	}
	return m.Gear
}

func (a *app) menuLayout() gui.Menu {
	// Ширину меряем настоящим шрифтом — прикидка обрезала бы длинные пункты.
	cv := guiraster.New(1, 1, a.scale, a.fonts)
	max := 0.0
	for _, it := range a.menu {
		if it.Text == "" {
			continue
		}
		if w := cv.Width(it.Text, gui.FaceRow); w > max {
			max = w
		}
	}
	return gui.MenuLayout(a.menu, int32(max+0.5))
}

func (a *app) closeMenu() {
	a.menu, a.menuHot = nil, -1
}

// menuHitTest ищет пункт под точкой в координатах окна.
func (a *app) menuHitTest(x, y int32) int {
	if a.menu == nil {
		return -1
	}
	return a.menuLayout().Hit(x-a.menuAt.X, y-a.menuAt.Y)
}

func (a *app) paintMenu(cv *guiraster.Canvas) {
	layout := a.menuLayout()
	// Меню рисуется в своих координатах, поэтому холст сдвигается: проще
	// сдвинуть прямоугольники, чем заводить второй холст и склеивать.
	shifted := gui.Menu{W: layout.W, H: layout.H, Items: make([]gui.Rect, len(layout.Items))}
	for i, r := range layout.Items {
		r.X += a.menuAt.X
		r.Y += a.menuAt.Y
		shifted.Items[i] = r
	}
	// Фон и рамку рисуем сами — PaintMenu ждёт начало координат в нуле.
	cv.Round(a.menuAt, gui.MenuRadius, gui.ColorSurface)
	cv.Border(a.menuAt, gui.MenuRadius, gui.ColorBorder, 1)
	for i, it := range a.menu {
		r := shifted.Items[i]
		if r.H == 0 {
			cv.Fill(gui.Rect{X: r.X + gui.MenuSepInset, Y: r.Y + gui.MenuSepH/2,
				W: r.W - 2*gui.MenuSepInset, H: 1}, gui.ColorBorderDim)
			continue
		}
		if i == a.menuHot {
			cv.Round(gui.Rect{X: r.X + 4, Y: r.Y + 1, W: r.W - 8, H: r.H - 2}, 7,
				gui.ColorSurface2.Lighten(0.04))
		}
		color := gui.ColorText
		if it.Danger {
			color = gui.ColorDanger
		}
		cv.Text(it.Text, gui.FaceRow,
			gui.Rect{X: r.X + gui.MenuPadX, Y: r.Y, W: r.W - 2*gui.MenuPadX, H: r.H},
			color, gui.AlignLeft)
	}
}

func (a *app) menuAction(id gui.ItemID) {
	i := a.menuOwner
	switch id {
	case menuUse:
		a.selectProfile(i)
	case menuRename:
		a.openEditScreen(i, gui.FieldName)
	case menuEdit:
		a.openEditScreen(i, gui.FieldServer)
	case menuCopyLink:
		a.copyLink(i)
	case menuRemove:
		a.removeProfile(i)
	}
}

func (a *app) copyLink(i int) {
	if i < 0 || i >= len(a.profiles.List) {
		return
	}
	pr := a.profiles.List[i]
	link, err := config.EncodeLink(pr.Config, pr.Name)
	if err != nil {
		a.appendLog("не удалось собрать ссылку: " + err.Error())
		return
	}
	a.offerClipboard(link)
	// Предупреждение обязательно: в ссылке ключ доступа.
	a.appendLog("ссылка скопирована — в ней ключ доступа, передавайте только адресату")
}

func (a *app) removeProfile(i int) {
	if i < 0 || i >= len(a.profiles.List) {
		return
	}
	name := a.profiles.List[i].Name
	if a.currentState() != gui.Off && strings.EqualFold(name, a.profiles.Current) {
		a.appendLog("профиль подключён — сначала отключитесь")
		return
	}
	if err := a.profiles.Remove(name); err != nil {
		a.appendLog(err.Error())
		return
	}
	a.saveProfiles()
	a.appendLog("профиль удалён: " + name)
	a.resize()
}
