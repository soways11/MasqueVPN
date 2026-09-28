//go:build windows

package main

import (
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/soways11/masquevpn/internal/gui"
)

// Минимальные привязки Win32.
//
// Окно рисуется прямо на Win32, без библиотек интерфейса: любая из них —
// внешняя зависимость, а проект собирается без доступа к сети. Нужных
// функций тут два десятка, и это дешевле, чем тянуть в сборку целый
// фреймворк ради одного окна с кнопкой.

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	gdi32    = windows.NewLazySystemDLL("gdi32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procRegisterClassEx  = user32.NewProc("RegisterClassExW")
	procCreateWindowEx   = user32.NewProc("CreateWindowExW")
	procDefWindowProc    = user32.NewProc("DefWindowProcW")
	procGetMessage       = user32.NewProc("GetMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procDispatchMessage  = user32.NewProc("DispatchMessageW")
	procPostQuitMessage  = user32.NewProc("PostQuitMessage")
	procPostMessage      = user32.NewProc("PostMessageW")
	procSendMessage      = user32.NewProc("SendMessageW")
	procShowWindow       = user32.NewProc("ShowWindow")
	procUpdateWindow     = user32.NewProc("UpdateWindow")
	procLoadCursor       = user32.NewProc("LoadCursorW")
	procLoadIcon         = user32.NewProc("LoadIconW")
	procLoadImage        = user32.NewProc("LoadImageW")
	procDestroyWindow    = user32.NewProc("DestroyWindow")
	procMessageBox       = user32.NewProc("MessageBoxW")
	procGetSystemMetrics = user32.NewProc("GetSystemMetrics")
	procSetWindowPos     = user32.NewProc("SetWindowPos")
	procGetWindowRect    = user32.NewProc("GetWindowRect")
	procDeleteObject     = gdi32.NewProc("DeleteObject")

	// Скругление окна. Область (region) режет окно по форме — способ старый
	// и работает и в Windows 10, и в 11. DWM-атрибут скругляет красивее (со
	// сглаживанием), но появился только в Windows 11 и на окне без рамки
	// срабатывает не везде, поэтому он — попытка, а область — основа.
	procCreateRoundRectRgn = gdi32.NewProc("CreateRoundRectRgn")
	procSetWindowRgn       = user32.NewProc("SetWindowRgn")

	// Появились в разных версиях Windows 10; вызываем через LazyProc и
	// проверяем Find(), чтобы на старой системе просто обойтись без них.
	procSetDpiAwarenessCtx = user32.NewProc("SetProcessDpiAwarenessContext")
	procSetProcessDPIAware = user32.NewProc("SetProcessDPIAware")
	procGetDpiForSystem    = user32.NewProc("GetDpiForSystem")
	procGetDpiForWindow    = user32.NewProc("GetDpiForWindow")
	procShellExecute       = shell32.NewProc("ShellExecuteW")
	procGetModuleHandle    = kernel32.NewProc("GetModuleHandleW")

	// Мышь, таймер, перетаскивание окна за свою полосу заголовка.
	procSetTimer         = user32.NewProc("SetTimer")
	procKillTimer        = user32.NewProc("KillTimer")
	procTrackMouseEvent  = user32.NewProc("TrackMouseEvent")
	procReleaseCapture   = user32.NewProc("ReleaseCapture")
	procGetCursorPos     = user32.NewProc("GetCursorPos")
	procSetForegroundWin = user32.NewProc("SetForegroundWindow")

	// Буфер обмена: через него в окно попадает ссылка masquevpn://.
	procOpenClipboard    = user32.NewProc("OpenClipboard")
	procCloseClipboard   = user32.NewProc("CloseClipboard")
	procEmptyClipboard   = user32.NewProc("EmptyClipboard")
	procGetClipboardData = user32.NewProc("GetClipboardData")
	procSetClipboardData = user32.NewProc("SetClipboardData")
	procGlobalAlloc      = kernel32.NewProc("GlobalAlloc")
	procGlobalLock       = kernel32.NewProc("GlobalLock")
	procGlobalUnlock     = kernel32.NewProc("GlobalUnlock")
	procGlobalSize       = kernel32.NewProc("GlobalSize")

	// Поле ввода: единственный системный элемент в окне (см. editControl).
	procCreateSolidBrush   = gdi32.NewProc("CreateSolidBrush")
	procSetTextColor       = gdi32.NewProc("SetTextColor")
	procSetBkColor         = gdi32.NewProc("SetBkColor")
	procSetBkMode          = gdi32.NewProc("SetBkMode")
	procSetFocus           = user32.NewProc("SetFocus")
	procSetWindowText      = user32.NewProc("SetWindowTextW")
	procGetWindowText      = user32.NewProc("GetWindowTextW")
	procGetWindowTextLen   = user32.NewProc("GetWindowTextLengthW")
	procCreateFontIndirect = gdi32.NewProc("CreateFontIndirectW")

	// Значок в области уведомлений и иконка для него.
	procShellNotifyIcon    = shell32.NewProc("Shell_NotifyIconW")
	procCreateDIBSection   = gdi32.NewProc("CreateDIBSection")
	procCreateBitmap       = gdi32.NewProc("CreateBitmap")
	procCreateIconIndirect = user32.NewProc("CreateIconIndirect")
	procDestroyIcon        = user32.NewProc("DestroyIcon")

	procGetDC     = user32.NewProc("GetDC")
	procReleaseDC = user32.NewProc("ReleaseDC")

	// Поиск уже работающей копии.
	procFindWindow            = user32.NewProc("FindWindowW")
	procRegisterWindowMessage = user32.NewProc("RegisterWindowMessageW")
	procIsIconic              = user32.NewProc("IsIconic")
)

// Константы Win32, которые здесь нужны.
const (
	wsVisible = 0x10000000

	// WS_EX_APPWINDOW обязателен для окна без системной рамки: без него
	// кнопки на панели задач нет, и свёрнутое окно нечем вернуть.
	wsExAppWindow = 0x00040000

	swShow     = 5
	swHide     = 0
	swNormal   = 1
	swMinimize = 6
	swRestore  = 9

	wmDestroy = 0x0002
	wmClose   = 0x0010
	wmCommand = 0x0111
	wmApp     = 0x8000

	idiApplication = 32512
	idcArrow       = 32512

	mbOK        = 0x0000
	mbIconError = 0x0010
	mbIconInfo  = 0x0040
	mbYesNo     = 0x0004
	idYes       = 6

	cwUseDefault = int32(-0x80000000) // CW_USEDEFAULT

	smCXScreen = 0
	smCYScreen = 1

	wmDpiChanged  = 0x02E0
	swpNoZOrder   = 0x0004
	swpNoActivate = 0x0010
	swpNoMove     = 0x0002

	// Окно без системной рамки: заголовок нарисован свой.
	wsPopup       = 0x80000000
	wsMinimizeBox = 0x00020000
	// WS_THICKFRAME — только ради того, чтобы Windows позволила тянуть окно
	// за край: без него запрос на растяжение (HTBOTTOM) игнорируется. Саму
	// рамку, которую он добавляет, убирает ответ на WM_NCCALCSIZE.
	wsThickFrame = 0x00040000
	csHRedraw    = 0x0002
	csVRedraw    = 0x0001
	csDropShadow = 0x00020000 // тень под окном — вместо потерянной рамки

	wmCreate        = 0x0001
	wmPaint         = 0x000F
	wmEraseBkgnd    = 0x0014
	wmMouseMove     = 0x0200
	wmLButtonDown   = 0x0201
	wmLButtonUp     = 0x0202
	wmMouseWheel    = 0x020A
	wmMouseLeave    = 0x02A3
	wmTimer         = 0x0113
	wmNCLButtonDown = 0x00A1

	htCaption = 2
	htClient  = 1
	htBottom  = 15
	tmeLeave  = 0x00000002

	// Растяжение окна за нижний край.
	wmSize          = 0x0005
	wmGetMinMaxInfo = 0x0024
	wmNCCalcSize    = 0x0083
	wmNCHitTest     = 0x0084
	wmExitSizeMove  = 0x0232
	sizeMinimized   = 1
	smCYMaximized   = 62 // высота развёрнутого окна: экран минус панель задач

	// Область уведомлений.
	nimAdd    = 0x00000000
	nimModify = 0x00000001
	nimDelete = 0x00000002

	nifMessage = 0x00000001
	nifIcon    = 0x00000002
	nifTip     = 0x00000004
	nifInfo    = 0x00000010
	niifInfo   = 0x00000001

	wmRButtonUp     = 0x0205
	wmLButtonDblClk = 0x0203

	// Своё окно меню.
	wsExToolWindow = 0x00000080 // не показывать в панели задач
	wsExTopmost    = 0x00000008
	wmKeyDown      = 0x0100
	wmKillFocus    = 0x0008
	wmActivateApp  = 0x001C
	vkEscape       = 0x1B

	biBitfields  = 3
	dibRGBColors = 0

	cfUnicodeText = 13
	gmemMoveable  = 0x0002

	// Поле ввода.
	wsChild           = 0x40000000
	wsTabStop         = 0x00010000
	esMultiline       = 0x0004
	esAutoVScroll     = 0x0040
	esAutoHScroll     = 0x0080
	wmSetFont         = 0x0030
	wmCtlColorEdit    = 0x0133
	emSetSel          = 0x00B1
	emSetCueBanner    = 0x1501
	bkModeTransparent = 1

	// DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
	dpiPerMonitorV2 = ^uintptr(3) // (HANDLE)-4
)

// setDPIAware объявляет программу знающей про масштабирование экрана.
//
// Без этого Windows рисует окно в 96 точках на дюйм и растягивает картинку:
// на ноутбуке со 125–150% (а это почти любой ноутбук) текст становится
// мыльным. Вызывать нужно ДО создания первого окна.
func setDPIAware() {
	if procSetDpiAwarenessCtx.Find() == nil {
		if r, _, _ := procSetDpiAwarenessCtx.Call(dpiPerMonitorV2); r != 0 {
			return
		}
	}
	if procSetProcessDPIAware.Find() == nil {
		procSetProcessDPIAware.Call()
	}
}

// dpiScale — во сколько раз увеличивать размеры. 96 точек на дюйм — единица.
func dpiScale(hwnd windows.HWND) float64 {
	if hwnd != 0 && procGetDpiForWindow.Find() == nil {
		if d, _, _ := procGetDpiForWindow.Call(uintptr(hwnd)); d > 0 {
			return float64(d) / 96
		}
	}
	if procGetDpiForSystem.Find() == nil {
		if d, _, _ := procGetDpiForSystem.Call(); d > 0 {
			return float64(d) / 96
		}
	}
	return 1
}

// Для LoadImageW и GetSystemMetrics: маленькая иконка окна.
const (
	imageIcon  = 1
	smCxSmIcon = 49
	smCySmIcon = 50
)

func systemMetric(i int32) int32 {
	v, _, _ := procGetSystemMetrics.Call(uintptr(i))
	return int32(v)
}

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   windows.Handle
	Icon       windows.Handle
	Cursor     windows.Handle
	Background windows.Handle
	MenuName   *uint16
	ClassName  *uint16
	IconSm     windows.Handle
}

type point struct{ X, Y int32 }

type rect struct{ Left, Top, Right, Bottom int32 }

// minMaxInfo — MINMAXINFO: пределы размера окна при растяжении.
type minMaxInfo struct {
	Reserved     point
	MaxSize      point
	MaxPosition  point
	MinTrackSize point
	MaxTrackSize point
}

var procMoveMemory = kernel32.NewProc("RtlMoveMemory")

// rectAt читает прямоугольник по адресу, пришедшему в сообщении.
//
// Через RtlMoveMemory, а не приведением к *rect: адрес принадлежит Windows,
// а не памяти Go, и превращать его в unsafe.Pointer — ровно тот случай, от
// которого предостерегает go vet.
func rectAt(addr uintptr) rect {
	var r rect
	if addr == 0 {
		return r
	}
	procMoveMemory.Call(uintptr(unsafe.Pointer(&r)), addr, unsafe.Sizeof(r))
	return r
}

type msg struct {
	Hwnd    windows.HWND
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
	Private uint32
}

type logFont struct {
	Height         int32
	Width          int32
	Escapement     int32
	Orientation    int32
	Weight         int32
	Italic         byte
	Underline      byte
	StrikeOut      byte
	CharSet        byte
	OutPrecision   byte
	ClipPrecision  byte
	Quality        byte
	PitchAndFamily byte
	FaceName       [32]uint16
}

func utf16(s string) *uint16 {
	p, err := windows.UTF16PtrFromString(s)
	if err != nil {
		return nil
	}
	return p
}

func moduleHandle() windows.Handle {
	h, _, _ := procGetModuleHandle.Call(0)
	return windows.Handle(h)
}

func createWindow(class, title string, exStyle, style uint32, x, y, w, h int32,
	parent windows.HWND, id uintptr, inst windows.Handle) windows.HWND {
	hwnd, _, _ := procCreateWindowEx.Call(uintptr(exStyle),
		uintptr(unsafe.Pointer(utf16(class))), uintptr(unsafe.Pointer(utf16(title))),
		uintptr(style), uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		uintptr(parent), id, uintptr(inst), 0)
	return windows.HWND(hwnd)
}

// newFont создаёт шрифт для поля ввода. Segoe UI — системный шрифт Windows;
// остальной текст рисует GDI+, но системному элементу нужен обычный HFONT.
func newFont(height int32, bold bool) windows.Handle {
	lf := logFont{Height: height, CharSet: 204 /*RUSSIAN_CHARSET*/, Quality: 5 /*CLEARTYPE*/}
	if bold {
		lf.Weight = 700
	}
	copy(lf.FaceName[:], windows.StringToUTF16("Segoe UI"))
	h, _, _ := procCreateFontIndirect.Call(uintptr(unsafe.Pointer(&lf)))
	return windows.Handle(h)
}

// colorRef переводит цвет темы в COLORREF: в нём байты идут наоборот —
// 0x00BBGGRR. Перепутать их легко, и тогда зелёный станет синим.
func colorRef(c gui.Color) uintptr {
	r, g, b := c.Parts()
	return uintptr(uint32(b)<<16 | uint32(g)<<8 | uint32(r))
}

func setText(hwnd windows.HWND, s string) {
	procSetWindowText.Call(uintptr(hwnd), uintptr(unsafe.Pointer(utf16(s))))
}

func getText(hwnd windows.HWND) string {
	n, _, _ := procGetWindowTextLen.Call(uintptr(hwnd))
	if n == 0 {
		return ""
	}
	buf := make([]uint16, n+1)
	procGetWindowText.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&buf[0])), n+1)
	return windows.UTF16ToString(buf)
}

// notifyIconData — описание значка в области уведомлений.
//
// Структура полная, версии Vista и новее: cbSize вычисляется от неё же,
// поэтому обрезанные варианты для старых систем не нужны.
type notifyIconData struct {
	CbSize           uint32
	HWnd             windows.HWND
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            windows.Handle
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UVersion         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         windows.GUID
	HBalloonIcon     windows.Handle
}

// bitmapV5Header — заголовок DIB с альфа-каналом: в нём рисуется иконка.
type bitmapV5Header struct {
	Size          uint32
	Width         int32
	Height        int32
	Planes        uint16
	BitCount      uint16
	Compression   uint32
	SizeImage     uint32
	XPelsPerMeter int32
	YPelsPerMeter int32
	ClrUsed       uint32
	ClrImportant  uint32
	RedMask       uint32
	GreenMask     uint32
	BlueMask      uint32
	AlphaMask     uint32
	CSType        uint32
	Endpoints     [36]byte
	GammaRed      uint32
	GammaGreen    uint32
	GammaBlue     uint32
	Intent        uint32
	ProfileData   uint32
	ProfileSize   uint32
	Reserved      uint32
}

type iconInfo struct {
	FIcon    int32
	XHotspot uint32
	YHotspot uint32
	HbmMask  windows.Handle
	HbmColor windows.Handle
}

// trackMouseEvent — подписка на уход курсора из окна.
type trackMouseEvent struct {
	Size      uint32
	Flags     uint32
	Track     windows.HWND
	HoverTime uint32
}

// clipboardText читает текст из буфера обмена.
//
// Через буфер в окно попадает ссылка masquevpn://: поля ввода в окне нет (все
// элементы нарисованы вручную), а заводить его ради одной строки, которую
// человек всё равно копирует из переписки, значило бы написать целый
// текстовый редактор — с выделением, курсором и вставкой.
func clipboardText(owner windows.HWND) (string, bool) {
	if r, _, _ := procOpenClipboard.Call(uintptr(owner)); r == 0 {
		return "", false
	}
	defer procCloseClipboard.Call()

	h, _, _ := procGetClipboardData.Call(cfUnicodeText)
	if h == 0 {
		return "", false
	}
	p, _, _ := procGlobalLock.Call(h)
	if p == 0 {
		return "", false
	}
	defer procGlobalUnlock.Call(h)

	size, _, _ := procGlobalSize.Call(h)
	n := int(size / 2)
	if n <= 0 {
		return "", false
	}
	buf := make([]uint16, n)
	procMoveMemory.Call(uintptr(unsafe.Pointer(&buf[0])), p, size)
	return windows.UTF16ToString(buf), true
}

// setClipboardText кладёт текст в буфер обмена.
func setClipboardText(owner windows.HWND, s string) bool {
	if r, _, _ := procOpenClipboard.Call(uintptr(owner)); r == 0 {
		return false
	}
	defer procCloseClipboard.Call()
	procEmptyClipboard.Call()

	u := windows.StringToUTF16(s)
	size := uintptr(len(u) * 2)
	h, _, _ := procGlobalAlloc.Call(gmemMoveable, size)
	if h == 0 {
		return false
	}
	p, _, _ := procGlobalLock.Call(h)
	if p == 0 {
		return false
	}
	procMoveMemory.Call(p, uintptr(unsafe.Pointer(&u[0])), size)
	procGlobalUnlock.Call(h)
	// После успешной передачи память принадлежит буферу обмена и
	// освобождается системой — освобождать её самим нельзя.
	r, _, _ := procSetClipboardData.Call(cfUnicodeText, h)
	return r != 0
}

func messageBox(parent windows.HWND, text, title string, flags uint32) int {
	r, _, _ := procMessageBox.Call(uintptr(parent),
		uintptr(unsafe.Pointer(utf16(text))), uintptr(unsafe.Pointer(utf16(title))),
		uintptr(flags))
	return int(r)
}
