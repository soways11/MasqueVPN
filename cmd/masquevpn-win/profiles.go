//go:build windows

package main

// Профили и настройки в окне.
//
// Окно работает только профилями — даже когда профиль один. Иначе у
// настроек было бы два источника (client.json рядом с программой и
// profiles.json), и переключатель в окне менял бы один, а подключение шло
// бы по другому. Поэтому при первом запуске лежащий рядом client.json
// молча превращается в первый профиль.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/soways11/masquevpn/internal/config"
	"github.com/soways11/masquevpn/internal/gui"
)

// Пункты меню профиля.
const (
	menuUse uint32 = iota + 1
	menuRename
	menuEdit
	menuCopyLink
	menuRemove
)

func (a *app) loadProfiles() {
	path := config.DefaultProfilesPath()
	profiles, err := config.LoadProfiles(path)
	if err != nil {
		messageBox(0, "Не читается файл профилей:\n"+err.Error()+"\n\n"+path,
			gui.AppName, mbOK|mbIconError)
		profiles = &config.Profiles{}
	}
	a.profiles = profiles

	// Первый запуск после консольного клиента: рядом лежит client.json, а
	// профилей ещё нет. Переносим — человек не должен заводить заново то,
	// что у него уже работает.
	if len(a.profiles.List) == 0 {
		if cfg := defaultConfigPath(); fileExists(cfg) {
			if _, err := a.profiles.ImportFile(cfg, ""); err == nil {
				if err := a.profiles.Save(); err != nil {
					a.appendLog("не удалось сохранить профили: " + err.Error())
				} else {
					a.appendLog("профиль перенесён из client.json")
				}
			}
		}
	}
	a.autostart = autostartEnabled()
}

// defaultConfigPath — client.json рядом с программой: так её проще носить
// одной папкой.
func defaultConfigPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "client.json"
	}
	return filepath.Join(filepath.Dir(exe), "client.json")
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
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
		messageBox(a.hwnd, "Не удалось сохранить профили:\n"+err.Error(), gui.AppName, mbOK|mbIconError)
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
	// ответ на щелчок, которым человек, возможно, просто хотел посмотреть
	// список.
	if a.currentState() != gui.Off {
		messageBox(a.hwnd, "Сначала отключитесь — профиль меняется только при выключенном туннеле.",
			gui.AppName, mbOK|mbIconInfo)
		return
	}
	if err := a.profiles.Select(name); err != nil {
		messageBox(a.hwnd, err.Error(), gui.AppName, mbOK|mbIconError)
		return
	}
	a.saveProfiles()
	a.appendLog("выбран профиль: " + name)
}

func (a *app) profileMenu(i int) {
	if i < 0 || i >= len(a.profiles.List) {
		return
	}
	pr := a.profiles.List[i]
	items := []gui.MenuItem{
		{ID: gui.ItemID(menuUse), Text: "Сделать выбранным"},
		{Separator: true},
		{ID: gui.ItemID(menuRename), Text: "Переименовать"},
		{ID: gui.ItemID(menuEdit), Text: "Изменить"},
		{ID: gui.ItemID(menuCopyLink), Text: "Скопировать ссылку " + config.LinkScheme + "://"},
		{Separator: true},
		{ID: gui.ItemID(menuRemove), Text: "Удалить профиль", Danger: true},
	}
	switch a.showMenu(items) {
	case menuUse:
		a.selectProfile(i)
	case menuRename:
		// Переименование и правка — один экран: имя там такое же поле,
		// как остальные. Разница лишь в том, куда встанет курсор.
		a.openEditScreen(i, gui.FieldName)
	case menuEdit:
		a.openEditScreen(i, gui.FieldServer)
	case menuCopyLink:
		a.copyLink(pr)
	case menuRemove:
		a.removeProfile(pr.Name)
	}
	a.invalidate()
}

func (a *app) copyLink(pr config.Profile) {
	link, err := config.EncodeLink(pr.Config, pr.Name)
	if err != nil {
		messageBox(a.hwnd, "Не удалось собрать ссылку:\n"+err.Error(), gui.AppName, mbOK|mbIconError)
		return
	}
	if !setClipboardText(a.hwnd, link) {
		messageBox(a.hwnd, "Буфер обмена занят другой программой, попробуйте ещё раз.",
			gui.AppName, mbOK|mbIconError)
		return
	}
	// Предупреждение обязательно: в ссылке лежит ключ доступа, и человек
	// должен понимать, что он теперь в буфере обмена.
	messageBox(a.hwnd, "Ссылка скопирована.\n\nВ ней ключ доступа — передавайте её только тому, "+
		"кому этот доступ и предназначен.", gui.AppName, mbOK|mbIconInfo)
}

func (a *app) removeProfile(name string) {
	if a.currentState() != gui.Off && strings.EqualFold(name, a.profiles.Current) {
		messageBox(a.hwnd, "Профиль сейчас подключён. Отключитесь, чтобы его удалить.",
			gui.AppName, mbOK|mbIconInfo)
		return
	}
	if messageBox(a.hwnd, "Удалить профиль «"+name+"»?\n\nКлюч доступа пропадёт вместе с ним: "+
		"восстановить его можно будет только новой ссылкой с сервера.",
		gui.AppName, mbYesNo|mbIconInfo) != idYes {
		return
	}
	if err := a.profiles.Remove(name); err != nil {
		messageBox(a.hwnd, err.Error(), gui.AppName, mbOK|mbIconError)
		return
	}
	a.saveProfiles()
	a.appendLog("профиль удалён: " + name)
}

// toggleSetting переключает настройку выбранного профиля.
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
	a.appendLog(fmt.Sprintf("%s: %s", name, onOff(value)))

	if a.currentState() != gui.Off {
		messageBox(a.hwnd, "Настройка сохранена, но применится при следующем подключении: "+
			"на ходу маршруты и блокировки не перестраиваются.", gui.AppName, mbOK|mbIconInfo)
	}
	if name == "kill_switch" && !value {
		// Выключение аварийного отключения — не мелочь: без него при обрыве
		// туннеля трафик пойдёт открыто, и человек об этом не узнает.
		messageBox(a.hwnd, "Аварийное отключение выключено.\n\nЕсли туннель оборвётся, "+
			"трафик продолжит идти в обход — открыто.", gui.AppName, mbOK|mbIconInfo)
	}
}

func onOff(v bool) string {
	if v {
		return "включено"
	}
	return "выключено"
}

// editAllowList открывает файл профилей в «Блокноте».
//
// Список исключений — это адреса, и вводить их мышью в нарисованном окне
// было бы мучением. Файл честнее: там же видно, к какому профилю они
// относятся, и рядом лежат остальные поля.
func (a *app) editAllowList() {
	pr, ok := a.active()
	if !ok {
		return
	}
	list := "сейчас список пуст"
	if n := len(pr.Config.KillSwitchAllow); n > 0 {
		list = "сейчас в списке: " + strings.Join(pr.Config.KillSwitchAllow, ", ")
	}
	if messageBox(a.hwnd, "Исключения аварийного отключения — адреса, которым разрешено ходить "+
		"мимо туннеля (например, прокси или сервер в локальной сети).\n\n"+list+
		"\n\nОткрыть файл профилей для правки? Изменения подхватятся при следующем подключении.",
		gui.AppName, mbYesNo|mbIconInfo) != idYes {
		return
	}
	path := config.DefaultProfilesPath()
	r, _, err := procShellExecute.Call(uintptr(a.hwnd),
		uintptr(unsafe.Pointer(utf16("open"))),
		uintptr(unsafe.Pointer(utf16("notepad.exe"))),
		uintptr(unsafe.Pointer(utf16(path))),
		0, swNormal)
	if r <= 32 {
		messageBox(a.hwnd, "Не удалось открыть «Блокнот»: "+err.Error()+"\n\nФайл лежит здесь:\n"+path,
			gui.AppName, mbOK|mbIconError)
	}
}

// ---------- автозапуск ----------

// Автозапуск сделан задачей планировщика, а не ключом в реестре: клиенту
// нужны права администратора, и запуск из Run показывал бы запрос UAC при
// каждом входе в систему. Задача с уровнем HIGHEST запускается без него.
const autostartTask = "masquevpn"

// legacyAutostartTask — как задача называлась до переименования проекта.
// Её нужно снимать вместе с новой: иначе у того, кто включил автозапуск
// раньше, при входе в систему запускались бы две копии клиента.
const legacyAutostartTask = "govpn"

func (a *app) toggleAutostart() {
	want := !a.autostart
	var err error
	if want {
		exe, e := os.Executable()
		if e != nil {
			err = e
		} else {
			err = runHidden("schtasks", "/Create", "/TN", autostartTask,
				"/TR", `"`+exe+`"`, "/SC", "ONLOGON", "/RL", "HIGHEST", "/F")
		}
	} else {
		err = runHidden("schtasks", "/Delete", "/TN", autostartTask, "/F")
	}
	// Задача под прежним именем снимается всегда — и при включении тоже:
	// иначе включённый когда-то автозапуск остался бы вторым.
	_ = runHidden("schtasks", "/Delete", "/TN", legacyAutostartTask, "/F")
	if err != nil {
		messageBox(a.hwnd, "Не удалось изменить автозапуск:\n"+err.Error(), gui.AppName, mbOK|mbIconError)
		return
	}
	a.autostart = autostartEnabled()
	a.appendLog("автозапуск: " + onOff(a.autostart))
}

// autostartEnabled спрашивает планировщик, есть ли наша задача. Ответ
// кешируется в app: запускать процесс на каждую перерисовку нельзя.
func autostartEnabled() bool {
	return runHidden("schtasks", "/Query", "/TN", autostartTask) == nil
}

// runHidden запускает служебную программу без консольного окна: иначе при
// каждом запросе поверх интерфейса мигало бы чёрное окно cmd.
func runHidden(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		if s := strings.TrimSpace(string(out)); s != "" {
			return fmt.Errorf("%s: %s", err, gui.Ellipsis(s, 200))
		}
		return err
	}
	return nil
}
