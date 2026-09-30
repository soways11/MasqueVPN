//go:build windows

package main

// Экран добавления сервера: три поля, которые выдаёт сервер.
//
// # Почему именно три
//
// Минимальная конфигурация клиента — адрес, ключ и идентификатор; остальное
// подставляется умолчаниями (см. claude/stage1-clients.md). Поэтому форма
// показывает ровно их: лишние поля не бесплатны, человек перестаёт замечать
// те, которые действительно нужно заполнить.
//
// Ссылку это не отменяет: кнопка «Вставить из буфера» разбирает
// `masquevpn://…` (и прежнюю `govpn://`) или содержимое `client.json` и
// раскладывает значения по этим же полям. Так видно, что именно добавляется,
// — ссылка непрозрачна, а тут перед глазами адрес сервера, к которому
// подключишься.
//
// # Почему здесь появились системные элементы
//
// Всё остальное окно нарисовано вручную, а поля ввода — настоящие EDIT из
// Windows. Текстовый ввод — это курсор, выделение мышью и клавиатурой,
// Ctrl+V, Ctrl+A, прокрутка длинной строки, экранная клавиатура и IME.
// Нарисовать его самому значит написать маленький текстовый редактор, и
// первая же попытка вставить ключ в 44 знака показала бы, чего он не умеет.
//
// В тёмной теме системный EDIT белый, поэтому перекрашивается через
// WM_CTLCOLOREDIT: цвет текста, цвет фона и кисть фона задаются нами.
// Рамку рисует наш же код, и поле садится внутрь неё — снаружи не отличить
// от остального окна.

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/soways11/masquevpn/internal/config"
	"github.com/soways11/masquevpn/internal/gui"
)

// Идентификаторы полей ввода.
const idEditBase = 2001

// Подсказки внутри пустых полей: показывают формат, не занимая места
// отдельной строкой пояснения.
var editCues = [gui.MaxAddFields]string{
	"vpn.example.com:443",
	"ключ из clients add",
	"66bbb6180401ba34",
	"необязательно — иначе домен сервера",
}

// editors — поля ввода экрана добавления. Создаются один раз и прячутся,
// когда экран не показан: пересоздавать их на каждый переход значило бы
// терять уже набранный текст.
type editors struct {
	fields [gui.MaxAddFields]windows.HWND
	font   windows.Handle
	// brush — кисть фона поля. Живёт столько же, сколько окно: Windows
	// спрашивает её при каждой перерисовке элемента.
	brush windows.Handle
}

func (a *app) createEditors(hwnd windows.HWND) {
	inst := moduleHandle()
	a.edit.font = newFont(-int32(float64(gui.FaceRow.Size)*a.scale+0.5), false)
	b, _, _ := procCreateSolidBrush.Call(colorRef(gui.ColorTile))
	a.edit.brush = windows.Handle(b)

	for i := range a.edit.fields {
		h := createWindow("EDIT", "", 0, wsChild|wsTabStop|esAutoHScroll,
			0, 0, 10, 10, hwnd, uintptr(idEditBase+i), inst)
		a.edit.fields[i] = h
		procSendMessage.Call(uintptr(h), wmSetFont, uintptr(a.edit.font), 1)
		procSendMessage.Call(uintptr(h), emSetCueBanner, 1,
			uintptr(unsafe.Pointer(utf16(editCues[i]))))
	}
	a.placeEditors()
}

// placeEditors ставит поля внутрь нарисованных рамок.
func (a *app) placeEditors() {
	if a.edit.fields[0] == 0 {
		return
	}
	l := gui.AddLayout(a.editing, a.winH)
	for i, h := range a.edit.fields {
		r := l.Edit(l.Fields[i].Box)
		procSetWindowPos.Call(uintptr(h), 0,
			uintptr(scaled(r.X, a.scale)), uintptr(scaled(r.Y, a.scale)),
			uintptr(scaled(r.W, a.scale)), uintptr(scaled(r.H, a.scale)),
			swpNoZOrder|swpNoActivate)
	}
}

// showEditors показывает или прячет поля вместе с экраном добавления.
func (a *app) showEditors(show bool) {
	if a.edit.fields[0] == 0 {
		return
	}
	cmd := uintptr(swHide)
	if show {
		cmd = swShow
	}
	for _, h := range a.edit.fields {
		procShowWindow.Call(uintptr(h), cmd)
	}
}

// releaseEditors освобождает то, что создано у Windows.
func (a *app) releaseEditors() {
	if a.edit.font != 0 {
		procDeleteObject.Call(uintptr(a.edit.font))
		a.edit.font = 0
	}
	if a.edit.brush != 0 {
		procDeleteObject.Call(uintptr(a.edit.brush))
		a.edit.brush = 0
	}
}

// colorEdit отвечает на WM_CTLCOLOREDIT: красит поле под тёмную тему.
//
// Возвращает кисть фона; она обязана пережить вызов, поэтому хранится в
// app, а не создаётся здесь. Кисть, созданная на каждый запрос, утекала бы
// по одной на перерисовку — а перерисовок при наборе текста много.
func (a *app) colorEdit(hdc uintptr) uintptr {
	procSetTextColor.Call(hdc, colorRef(gui.ColorText))
	procSetBkColor.Call(hdc, colorRef(gui.ColorTile))
	return uintptr(a.edit.brush)
}

// openAddScreen показывает экран добавления с чистыми полями.
func (a *app) openAddScreen() {
	a.addFrom = a.screen
	a.screen, a.editing, a.editIndex = gui.ScreenAdd, false, -1
	a.clearNotice()
	for _, h := range a.edit.fields {
		setText(h, "")
	}
	a.placeEditors()
	a.invalidate()
	a.showEditors(true)
	procSetFocus.Call(uintptr(a.edit.fields[gui.FieldServer]))
}

// openEditScreen показывает тот же экран, но с полями существующего
// профиля и дополнительным полем имени.
//
// Правка — это не «удалить и завести заново»: у профиля может быть имя,
// под которым его знают, и выбранность, которую нельзя терять от того,
// что человек исправил опечатку в адресе.
func (a *app) openEditScreen(i, focus int) {
	if i < 0 || i >= len(a.profiles.List) {
		return
	}
	pr := a.profiles.List[i]
	a.addFrom = a.screen
	a.screen, a.editing, a.editIndex = gui.ScreenAdd, true, i
	a.clearNotice()

	setText(a.edit.fields[gui.FieldServer], pr.Config.Server)
	setText(a.edit.fields[gui.FieldAuthKey], string(pr.Config.AuthKey))
	setText(a.edit.fields[gui.FieldClientID], pr.Config.ClientID)
	setText(a.edit.fields[gui.FieldName], pr.Name)

	a.placeEditors()
	a.invalidate()
	a.showEditors(true)
	procSetFocus.Call(uintptr(a.edit.fields[focus]))
	// Курсор в конец, иначе всё поле выглядит выделенным и первая же
	// клавиша стирает то, что правили.
	n := uintptr(len([]rune(getText(a.edit.fields[focus]))))
	procSendMessage.Call(uintptr(a.edit.fields[focus]), emSetSel, n, n)
}

func (a *app) clearNotice() {
	a.addNotice, a.addFailed, a.addBadField = "", false, 0
}

// fail показывает ошибку и подсвечивает поле (field — номер с единицы,
// ноль означает, что ошибка не привязана к конкретному полю).
func (a *app) fail(field int, text string) {
	a.addNotice, a.addFailed, a.addBadField = text, true, field
	if field > 0 && a.edit.fields[field-1] != 0 {
		procSetFocus.Call(uintptr(a.edit.fields[field-1]))
	}
}

// pasteIntoForm разбирает буфер обмена и раскладывает его по полям.
//
// Кнопка нужна рядом с Ctrl+V: человек, пришедший из другого клиента, ищет
// глазами именно её. А раскладка по полям вместо молчаливого импорта даёт
// увидеть, к какому серверу он сейчас подключится.
func (a *app) pasteIntoForm() {
	text, ok := clipboardText(a.hwnd)
	if !ok || strings.TrimSpace(text) == "" {
		a.fail(0, "В буфере обмена пусто — скопируйте ссылку и нажмите ещё раз.")
		return
	}
	cfg, name, err := config.ParseShared(text)
	if err != nil {
		a.fail(0, err.Error())
		return
	}
	setText(a.edit.fields[gui.FieldServer], cfg.Server)
	setText(a.edit.fields[gui.FieldAuthKey], string(cfg.AuthKey))
	setText(a.edit.fields[gui.FieldClientID], cfg.ClientID)
	if name != "" {
		// Имя, которое дал выдавший ссылку, — лучше домена: «дача» говорит
		// больше, чем vpn.example.com.
		setText(a.edit.fields[gui.FieldName], name)
	}
	a.clearNotice()
	a.addNotice = "Значения из буфера — проверьте адрес сервера и нажмите «Добавить»."
	procSetFocus.Call(uintptr(a.edit.fields[gui.FieldServer]))
}

// confirmAdd собирает профиль из полей.
func (a *app) confirmAdd() {
	server := strings.TrimSpace(getText(a.edit.fields[gui.FieldServer]))
	key := strings.TrimSpace(getText(a.edit.fields[gui.FieldAuthKey]))
	id := strings.TrimSpace(getText(a.edit.fields[gui.FieldClientID]))

	// Правила формы общие с Linux и телефоном (config.BuildForm): что
	// считать ошибкой и к какому полю её приписать, решается там.
	cfg, err := config.BuildForm(server, key, id)
	if err != nil {
		a.fail(config.FormErrorOf(err))
		return
	}

	name := strings.TrimSpace(getText(a.edit.fields[gui.FieldName]))

	oldName := ""
	if a.editing && a.editIndex >= 0 && a.editIndex < len(a.profiles.List) {
		oldName = a.profiles.List[a.editIndex].Name
	}
	pr, err := a.storeProfile(cfg, name)
	if err != nil {
		a.fail(0, err.Error())
		return
	}
	a.saveProfiles()
	if a.editing {
		// Адрес мог поменяться — старое время пинга уже не про этот профиль.
		a.pings.Forget(oldName)
		a.pings.Forget(pr.Name)
		a.appendLog("профиль изменён: " + pr.Name)
	} else {
		a.appendLog("добавлен профиль: " + pr.Name)
	}

	// После добавления показываем список профилей, даже если пришли с
	// главного экрана: человеку нужно увидеть, что профиль появился, и
	// решить, переключаться ли на него.
	wasEditing := a.editing
	a.showEditors(false)
	a.screen, a.scrollY = a.addFrom, 0
	a.editing = false
	a.clearNotice()
	a.invalidate()

	if wasEditing {
		return
	}
	if active, ok := a.profiles.Active(); ok && !strings.EqualFold(active.Name, pr.Name) {
		// Импорт не переключает выбранный профиль: туннель может быть
		// поднят. Но человек должен знать, куда пойдёт подключение.
		messageBox(a.hwnd, "Профиль «"+pr.Name+"» добавлен.\n\nВыбранным остался «"+active.Name+
			"» — нажмите на новый профиль в списке, чтобы переключиться.",
			gui.AppName, mbOK|mbIconInfo)
	}
}

// deleteEdited удаляет профиль, который сейчас правят.
func (a *app) deleteEdited() {
	if !a.editing || a.editIndex < 0 || a.editIndex >= len(a.profiles.List) {
		return
	}
	name := a.profiles.List[a.editIndex].Name
	before := len(a.profiles.List)
	a.removeProfile(name) // спросит подтверждение и откажет на подключённом
	if len(a.profiles.List) == before {
		return // не удалили: отказались или профиль занят
	}
	a.showEditors(false)
	a.screen, a.editing, a.scrollY = a.addFrom, false, 0
	a.clearNotice()
	a.invalidate()
}

// storeProfile записывает конфигурацию: при добавлении заводит новый
// профиль, при правке заменяет существующий. Правила правки (выбранный
// остаётся выбранным, чужое имя не затирается) — в config.Profiles.Update.
func (a *app) storeProfile(cfg *config.Client, name string) (config.Profile, error) {
	if !a.editing {
		// Пустое имя означает «назвать по домену» — это делает Add.
		return a.profiles.Add(name, cfg)
	}
	if a.editIndex < 0 || a.editIndex >= len(a.profiles.List) {
		return config.Profile{}, errText("профиль исчез, пока его правили")
	}
	return a.profiles.Update(a.profiles.List[a.editIndex].Name, name, cfg)
}

// buildClient собирает конфигурацию из трёх значений.
//

// withPort дописывает порт по умолчанию, если его не указали.
//

// errText — ошибка из готовой строки: заводить ради двух сообщений
// отдельные типы незачем, а fmt.Errorf здесь читался бы хуже.
type errText string

func (e errText) Error() string { return string(e) }
