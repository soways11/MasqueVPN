//go:build windows

package main

// Значок в области уведомлений.
//
// # Зачем
//
// До него закрытие окна означало разрыв туннеля: окно и было программой.
// Это неверно для VPN — его включают и забывают, а окно нужно раз в день,
// чтобы посмотреть, всё ли в порядке. Теперь закрытие прячет окно, туннель
// продолжает работать, а выход стал отдельным, осознанным действием.
//
// Значок ещё и показывает состояние цветом: зелёный — трафик идёт через
// туннель, тусклый — нет. Это единственное место, куда можно посмотреть, не
// открывая окна, и ради него значок перерисовывается при каждой смене
// состояния.
//
// # Про иконку
//
// Она рисуется в памяти, а не берётся из ресурсов: ресурсный файл потребовал
// бы отдельного шага сборки (rsrc/windres), а нам нужен простой круг в два
// цвета. Заодно это позволяет менять цвет на ходу — из ресурса пришлось бы
// класть два изображения и следить, чтобы они не разошлись с палитрой.

import (
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/soways11/masquevpn/internal/gui"
)

// Сообщения и пункты меню значка.
const (
	trayUID      = 1
	trayIconSize = 32

	menuTrayShow uint32 = 100 + iota
	menuTrayToggle
	menuTrayExit
)

type tray struct {
	added  bool
	icon   windows.Handle
	color  gui.Color // цвет текущей иконки: чтобы не перерисовывать зря
	told   bool      // уже объясняли, что программа осталась работать
	hidden bool      // окно спрятано в значок
}

// add создаёт значок. Вызывается один раз, после создания окна.
func (a *app) trayAdd() {
	data := a.trayData(nifMessage | nifIcon | nifTip)
	if r, _, _ := procShellNotifyIcon.Call(nimAdd, uintptr(unsafe.Pointer(&data))); r != 0 {
		a.tray.added = true
	}
}

// trayUpdate обновляет иконку и подсказку под текущее состояние.
func (a *app) trayUpdate() {
	if !a.tray.added {
		return
	}
	data := a.trayData(nifMessage | nifIcon | nifTip)
	procShellNotifyIcon.Call(nimModify, uintptr(unsafe.Pointer(&data)))
}

// trayRemove убирает значок. Без этого он остаётся висеть после выхода,
// пока на него не наведут мышь.
func (a *app) trayRemove() {
	if !a.tray.added {
		return
	}
	data := a.trayData(0)
	procShellNotifyIcon.Call(nimDelete, uintptr(unsafe.Pointer(&data)))
	a.tray.added = false
	a.freeTrayIcon()
}

// trayNotify показывает всплывающее уведомление у значка.
func (a *app) trayNotify(title, text string) {
	if !a.tray.added {
		return
	}
	data := a.trayData(nifInfo)
	copy(data.SzInfoTitle[:], windows.StringToUTF16(title))
	copy(data.SzInfo[:], windows.StringToUTF16(text))
	data.DwInfoFlags = niifInfo
	procShellNotifyIcon.Call(nimModify, uintptr(unsafe.Pointer(&data)))
}

// trayData собирает структуру для Shell_NotifyIcon.
func (a *app) trayData(flags uint32) notifyIconData {
	d := notifyIconData{
		CbSize:           uint32(unsafe.Sizeof(notifyIconData{})),
		HWnd:             a.hwnd,
		UID:              trayUID,
		UFlags:           flags,
		UCallbackMessage: wmTray,
	}
	if flags&nifIcon != 0 {
		d.HIcon = a.trayIcon()
	}
	copy(d.SzTip[:], windows.StringToUTF16(a.trayTip()))
	return d
}

// trayTip — подсказка при наведении: состояние и куда подключены.
func (a *app) trayTip() string {
	v := a.view()
	tip := gui.AppName + " — " + v.StatusText()
	if v.State == gui.On && v.Server != "" {
		tip += "\n" + gui.Host(v.Server)
	}
	return tip
}

// trayIcon возвращает иконку под текущее состояние, создавая её при смене
// состояния. Пересоздавать её на каждое обновление подсказки не нужно:
// иконок всего две, а каждая — это три объекта GDI.
func (a *app) trayIcon() windows.Handle {
	want := gui.ColorIdleDot
	if a.currentState() == gui.On {
		want = gui.ColorAccent
	}
	if a.tray.icon != 0 && a.tray.color == want {
		return a.tray.icon
	}
	a.freeTrayIcon()
	a.tray.icon, a.tray.color = makeTrayIcon(want == gui.ColorAccent), want
	return a.tray.icon
}

func (a *app) freeTrayIcon() {
	if a.tray.icon != 0 {
		procDestroyIcon.Call(uintptr(a.tray.icon))
		a.tray.icon = 0
	}
}

// makeTrayIcon — черепаха из логотипа: в цвете и с зелёной точкой, когда
// туннель поднят, серая — когда нет. Картинку собирает gui.TrayPixels (там
// же она проверяется тестом); здесь только перенос в иконку Windows.
//
// Пиксели пишутся прямо в память DIB. Цвета там лежат как BGRA и
// **предумноженные** на альфу — ровно как в image.RGBA, только R и B
// местами: иначе край плитки светился бы белым.
func makeTrayIcon(on bool) windows.Handle {
	const n = trayIconSize
	hdr := bitmapV5Header{
		Size:        uint32(unsafe.Sizeof(bitmapV5Header{})),
		Width:       n,
		Height:      -n, // сверху вниз
		Planes:      1,
		BitCount:    32,
		Compression: biBitfields,
		RedMask:     0x00FF0000,
		GreenMask:   0x0000FF00,
		BlueMask:    0x000000FF,
		AlphaMask:   0xFF000000,
	}
	var bits unsafe.Pointer
	dib, _, _ := procCreateDIBSection.Call(0, uintptr(unsafe.Pointer(&hdr)), dibRGBColors,
		uintptr(unsafe.Pointer(&bits)), 0, 0)
	if dib == 0 || bits == nil {
		return 0
	}
	defer procDeleteObject.Call(dib)

	img := gui.TrayPixels(n, on)
	px := unsafe.Slice((*uint32)(bits), n*n)
	for i := range px {
		p := img.Pix[i*4 : i*4+4 : i*4+4]
		px[i] = uint32(p[3])<<24 | uint32(p[0])<<16 | uint32(p[1])<<8 | uint32(p[2])
	}

	// Маска нужна структуре иконки, но при 32 битах с альфой она не
	// используется: пустая монохромная того же размера.
	mask, _, _ := procCreateBitmap.Call(n, n, 1, 1, 0)
	if mask == 0 {
		return 0
	}
	defer procDeleteObject.Call(mask)

	info := iconInfo{FIcon: 1, HbmMask: windows.Handle(mask), HbmColor: windows.Handle(dib)}
	h, _, _ := procCreateIconIndirect.Call(uintptr(unsafe.Pointer(&info)))
	return windows.Handle(h)
}

// hideToTray прячет окно, оставляя программу работать.
func (a *app) hideToTray() {
	procShowWindow.Call(uintptr(a.hwnd), swHide)
	a.tray.hidden = true
	if !a.tray.told {
		a.tray.told = true
		// Объясняем ровно один раз: человек, закрывший окно и увидевший,
		// что интернет всё ещё идёт через туннель, должен понимать почему.
		a.trayNotify(gui.AppName, "Окно закрыто, туннель продолжает работать.\n"+
			"Значок в области уведомлений — открыть или выйти.")
	}
}

// showFromTray возвращает окно на экран.
func (a *app) showFromTray() {
	// Окно может быть не только спрятано, но и свёрнуто — тогда нужен
	// именно swRestore, иначе оно останется в панели задач.
	cmd := uintptr(swShow)
	if r, _, _ := procIsIconic.Call(uintptr(a.hwnd)); r != 0 {
		cmd = swRestore
	}
	procShowWindow.Call(uintptr(a.hwnd), cmd)
	procSetForegroundWin.Call(uintptr(a.hwnd))
	a.tray.hidden = false
	a.invalidate()
}

// onTrayMessage разбирает нажатия на значок.
func (a *app) onTrayMessage(event uintptr) {
	switch uint32(event) {
	case wmLButtonUp, wmLButtonDblClk:
		if a.tray.hidden {
			a.showFromTray()
		} else {
			a.hideToTray()
		}
	case wmRButtonUp:
		a.trayMenu()
	}
}

// trayMenu — меню по правой кнопке на значке.
func (a *app) trayMenu() {
	toggle := "Подключиться"
	if s := a.currentState(); s == gui.On || s == gui.Connecting {
		toggle = "Отключить"
	}
	items := []gui.MenuItem{
		{ID: gui.ItemID(menuTrayShow), Text: "Открыть " + gui.AppName},
		{ID: gui.ItemID(menuTrayToggle), Text: toggle},
		{Separator: true},
		{ID: gui.ItemID(menuTrayExit), Text: "Выйти", Danger: true},
	}
	switch a.showMenu(items) {
	case menuTrayShow:
		a.showFromTray()
	case menuTrayToggle:
		a.onConnectClicked()
	case menuTrayExit:
		a.exitFromTray()
	}
}

// exitFromTray завершает программу, спросив про поднятый туннель.
func (a *app) exitFromTray() {
	if a.currentState() != gui.Off {
		if messageBox(a.hwnd, "Туннель подключён. Отключить и выйти?",
			gui.AppName, mbYesNo|mbIconInfo) != idYes {
			return
		}
	}
	a.quitting = true
	// Ждём, пока движок вернёт сеть: иначе адаптер и маршруты переживут
	// процесс, и следующий запуск начнётся с уборки.
	a.stopAndWait()
	procDestroyWindow.Call(uintptr(a.hwnd))
}
