//go:build windows

package main

// Всплывающее меню — своим окном.
//
// # Почему не системное
//
// TrackPopupMenu рисует меню средствами Windows, и оно всегда светлое:
// перекрасить его нельзя, а посреди тёмного интерфейса оно выглядит чужой
// заплатой. Owner-drawn пункты помогают наполовину — фон и рамку вокруг них
// всё равно рисует система.
//
// Поэтому меню здесь — обычное окно без рамки, которое рисуется тем же
// кодом и той же палитрой, что и всё остальное. Цена решения: наведение,
// выбор, закрытие по щелчку мимо и по Esc написаны вручную.
//
// # Как оно ведёт себя
//
// Меню модально: showMenu не возвращается, пока человек не выберет пункт
// или не закроет его. Это важно для вызывающего — он пишет обычный switch
// по результату, а не разбирает асинхронное событие где-то в другом месте.
//
// Модальность сделана своим циклом сообщений, а не отдельным потоком:
// окна Windows живут на том потоке, где созданы, и меню обязано быть на том
// же, что и главное окно.

import (
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/soways11/masquevpn/internal/gui"
)

const menuClass = "masquevpnMenu"

// popupState — состояние открытого меню. Одно на процесс: двух открытых
// меню одновременно не бывает, а глобальная переменная избавляет от
// хранения указателя в данных окна.
var popupState struct {
	items  []gui.MenuItem
	layout gui.Menu
	hot    int
	result uint32
	done   bool
	hwnd   windows.HWND
	scale  float64
}

var menuClassRegistered bool

func registerMenuClass() {
	if menuClassRegistered {
		return
	}
	wc := wndClassEx{
		Size:      uint32(unsafe.Sizeof(wndClassEx{})),
		Style:     csDropShadow,
		WndProc:   windows.NewCallback(menuProc),
		Instance:  moduleHandle(),
		ClassName: utf16(menuClass),
	}
	cursor, _, _ := procLoadCursor.Call(0, idcArrow)
	wc.Cursor = windows.Handle(cursor)
	if r, _, _ := procRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc))); r != 0 {
		menuClassRegistered = true
	}
}

// showMenu открывает меню у курсора и возвращает выбранный пункт.
// Ноль означает, что не выбрали ничего.
func (a *app) showMenu(items []gui.MenuItem) uint32 {
	registerMenuClass()
	if !menuClassRegistered {
		return 0
	}

	layout := gui.MenuLayout(items, a.measureMenuText(items))
	popupState.items, popupState.layout = items, layout
	popupState.hot, popupState.result, popupState.done = -1, 0, false
	popupState.scale = a.scale

	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	w, h := scaled(layout.W, a.scale), scaled(layout.H, a.scale)
	x, y := fitOnScreen(pt.X, pt.Y, w, h)

	hwnd := createWindow(menuClass, "", wsExToolWindow|wsExTopmost, wsPopup|wsVisible,
		x, y, w, h, 0, 0, moduleHandle())
	if hwnd == 0 {
		return 0
	}
	popupState.hwnd = hwnd
	procSetForegroundWin.Call(uintptr(hwnd))

	// Свой цикл сообщений: крутим его, пока меню живо. Обычный цикл в
	// main продолжит работать после — сообщения главного окна тоже
	// раздаются отсюда, поэтому оно не «замерзает».
	var m msg
	for !popupState.done {
		r, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
	}
	procDestroyWindow.Call(uintptr(hwnd))
	popupState.hwnd = 0
	return popupState.result
}

// measureMenuText — ширина самой длинной надписи в логических точках.
//
// Меряется настоящим шрифтом на экранном контексте: прикидка «столько-то
// на знак» обрезала бы длинные пункты на одних системах и оставляла бы
// пустое поле на других.
func (a *app) measureMenuText(items []gui.MenuItem) int32 {
	hdc, _, _ := procGetDC.Call(0)
	if hdc == 0 || a.res == nil {
		return 0
	}
	defer procReleaseDC.Call(0, hdc)

	var g uintptr
	procGdipCreateFromHDC.Call(hdc, uintptr(unsafe.Pointer(&g)))
	if g == 0 {
		return 0
	}
	defer procGdipDeleteGraphics.Call(g)

	p := &painter{g: g, hdc: windows.Handle(hdc), res: a.res, scale: a.scale}
	max := 0.0
	for _, it := range items {
		if it.Text == "" {
			continue
		}
		if w := p.Width(it.Text, gui.FaceRow); w > max {
			max = w
		}
	}
	return int32(max/a.scale + 0.5)
}

// fitOnScreen сдвигает меню, если оно не помещается: у нижнего края экрана
// оно должно раскрываться вверх, а не уезжать под панель задач.
func fitOnScreen(x, y, w, h int32) (int32, int32) {
	sw, sh := systemMetric(smCXScreen), systemMetric(smCYScreen)
	if x+w > sw {
		x = sw - w
	}
	if y+h > sh {
		y -= h // вверх от курсора
		if y < 0 {
			y = 0
		}
	}
	if x < 0 {
		x = 0
	}
	return x, y
}

func menuProc(hwnd windows.HWND, message uint32, wParam, lParam uintptr) uintptr {
	defer func() {
		if v := recover(); v != nil {
			reportPanic("меню", v)
			popupState.done = true
		}
	}()

	switch message {
	case wmEraseBkgnd:
		return 1

	case wmPaint:
		paintMenuWindow(hwnd)

	case wmMouseMove:
		x, y := menuPoint(lParam)
		if hot := popupState.layout.Hit(x, y); hot != popupState.hot {
			popupState.hot = hot
			procInvalidateRect.Call(uintptr(hwnd), 0, 0)
		}

	case wmLButtonUp:
		x, y := menuPoint(lParam)
		if i := popupState.layout.Hit(x, y); i >= 0 {
			popupState.result = uint32(popupState.items[i].ID)
		}
		popupState.done = true

	case wmKeyDown:
		if wParam == vkEscape {
			popupState.done = true
		}

	case wmKillFocus, wmActivateApp:
		// Щёлкнули мимо меню — закрываем без выбора. Это то, чего человек
		// ждёт от любого меню, и без этого оно бы висело поверх всего.
		if message == wmKillFocus || wParam == 0 {
			popupState.done = true
		}

	default:
		r, _, _ := procDefWindowProc.Call(uintptr(hwnd), uintptr(message), wParam, lParam)
		return r
	}
	return 0
}

// menuPoint переводит координаты мыши в логические точки меню.
func menuPoint(lParam uintptr) (int32, int32) {
	s := popupState.scale
	if s <= 0 {
		s = 1
	}
	return int32(float64(mouseX(lParam))/s + 0.5), int32(float64(mouseY(lParam))/s + 0.5)
}

func paintMenuWindow(hwnd windows.HWND) {
	var ps paintStruct
	hdc, _, _ := procBeginPaint.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&ps)))
	if hdc == 0 {
		return
	}
	defer procEndPaint.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&ps)))

	var rc rect
	procGetClientRect.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&rc)))
	w, h := rc.Right-rc.Left, rc.Bottom-rc.Top
	if w <= 0 || h <= 0 || a.res == nil {
		return
	}

	// Двойная буферизация, как и в главном окне: иначе меню моргает при
	// каждом движении мыши по пунктам.
	memDC, _, _ := procCreateCompatibleDC.Call(hdc)
	if memDC == 0 {
		return
	}
	defer procDeleteDC.Call(memDC)
	bmp, _, _ := procCreateCompatibleBitmap.Call(hdc, uintptr(w), uintptr(h))
	if bmp == 0 {
		return
	}
	defer procDeleteObject.Call(bmp)
	old, _, _ := procSelectObject.Call(memDC, bmp)
	defer procSelectObject.Call(memDC, old)

	var g uintptr
	procGdipCreateFromHDC.Call(memDC, uintptr(unsafe.Pointer(&g)))
	if g != 0 {
		procGdipSetSmoothingMode.Call(g, smoothingAntiAlias)
		procGdipSetTextRenderingHint.Call(g, textHintAntiAliasGridFit)
		procGdipSetPixelOffsetMode.Call(g, pixelOffsetHalf)
		p := &painter{g: g, hdc: windows.Handle(memDC), res: a.res, scale: popupState.scale}
		// Фон окна за скруглёнными углами: они прозрачными быть не могут,
		// поэтому под меню кладётся цвет фона главного окна.
		p.Clear(gui.ColorBG)
		gui.PaintMenu(p, popupState.items, popupState.layout, popupState.hot)
		procGdipDeleteGraphics.Call(g)
	}
	procBitBlt.Call(hdc, 0, 0, uintptr(w), uintptr(h), memDC, 0, 0, srcCopy)
}
