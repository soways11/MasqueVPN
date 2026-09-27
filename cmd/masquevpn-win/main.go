//go:build windows

// Команда masquevpn-win — оконный клиент masquevpn для Windows.
//
// Внутри тот же движок, что и у консольного клиента (internal/clientrun):
// окно только показывает состояние и нажимает те же кнопки, что и командная
// строка. Собирается без консольного окна:
//
//	go build -ldflags "-H=windowsgui" -o masquevpn.exe ./cmd/masquevpn-win
//
// # Почему окно нарисовано вручную
//
// Здесь нет ни одного системного элемента управления: ни кнопок, ни полей,
// ни рамки окна. Всё рисуется своими руками поверх пустого окна.
//
// Причина не в красоте. Стандартные элементы Windows не умеют быть тёмными:
// кнопка остаётся серой, поле ввода — белым, а заголовок окна — светлой
// полосой поверх тёмного интерфейса. Перекрасить их можно только заменив
// отрисовку каждого, то есть ровно тем, что здесь и сделано, но с оглядкой
// на их собственное поведение.
//
// Цена решения: нет доступности (экранный диктор увидит пустое окно) и нет
// клавиатурной навигации по Tab. Это записано в план; для первой версии
// окно управляется мышью.
//
// Требуются права администратора (создание адаптера Wintun и правка
// маршрутов). Если их нет, приложение перезапускает себя с запросом UAC.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/soways11/masquevpn/internal/clientrun"
	"github.com/soways11/masquevpn/internal/config"
	"github.com/soways11/masquevpn/internal/gui"
)

// Собственные сообщения окна.
const (
	wmState = wmApp + 1 // сменилось состояние (wParam — состояние)
	wmLog   = wmApp + 2 // появилась строка журнала
	wmUp    = wmApp + 3 // туннель поднят
	wmTray  = wmApp + 4 // нажатие на значок в области уведомлений

	// windowClass — имя класса окна; наружу не видно, но должно быть
	// уникальным в процессе.
	windowClass = "masquevpnWindow"
	// appIconName — имя ресурса иконки (cmd/masquevpn-win/winres).
	appIconName = "APP"

	// uiZoom — насколько интерфейс крупнее своего базового размера.
	//
	// Увеличивает всё разом: и окно, и шрифты, и отступы, — потому что
	// умножается на масштаб экрана, а раскладка и кегли заданы в одних и
	// тех же логических точках. Менять сами константы раскладки значило бы
	// править полсотни чисел и следить, чтобы они остались согласованными.
	uiZoom = 1.25

	// stopTimeout — сколько ждать движок при выходе. Пять секунд: обычно
	// уборка занимает доли секунды, а дольше держать человека, который
	// нажал «Выйти», нельзя.
	stopTimeout = 5 * time.Second

	timerTick   = 1 // раз в секунду: счётчики, скорость, время сессии
	tickPeriod  = 1000
	graphPoints = 30 // столбиков в графике — полминуты истории
)

type app struct {
	hwnd  windows.HWND
	res   *resources
	token uintptr
	scale float64

	// Состояние интерфейса. Трогается только из потока окна, поэтому без
	// блокировки: Win32 и так не терпит обращений к окну из чужого потока.
	screen  gui.Screen
	logOpen bool
	scrollY int32
	hot     gui.ItemID
	pressed gui.ItemID

	edit      editors
	addFrom   gui.Screen // экран, с которого открыли добавление
	editing   bool       // правим существующий профиль, а не заводим новый
	editIndex int

	tray        tray
	quitting    bool // выход запрошен явно, а не закрытием окна
	addNotice   string
	addFailed   bool
	addBadField int

	meter     *gui.Meter
	profiles  *config.Profiles
	autostart bool // кеш: спрашивать планировщик на каждую перерисовку нельзя

	// Состояние движка. Его меняет фоновая горутина, поэтому под замком.
	mu       sync.Mutex
	state    gui.State
	lastErr  string
	since    time.Time
	tunAddr  string
	counters clientrun.Counters
	cancel   context.CancelFunc
	// done закрывается, когда движок полностью остановился и вернул сеть
	// в исходное состояние. Нужен при выходе: процесс, завершившийся
	// раньше уборки, оставляет адаптер и маршруты.
	done  chan struct{}
	lines []string
}

var a = &app{meter: gui.NewMeter(graphPoints), scale: 1}

func main() {
	// Сторож. Клиент запускает вторую копию себя, чтобы та прибралась,
	// если его убьют: правило разрешения имён и маршрут-исключение
	// переживают процесс, и снять их изнутри убитого клиента нечем.
	// Разбирается ДО всего остального — окна и UAC ему не нужны, права он
	// наследует от родителя.
	if pid, ok := watchdogPID(); ok {
		_, _ = clientrun.RunWatchdog(pid)
		return
	}

	// Паника при запуске в программе без консоли выглядит как «не
	// открывается»: ни сообщения, ни следа. Перехватываем и оставляем
	// отчёт — иначе причину не узнать ни нам, ни человеку.
	defer guard("запуск")
	traceInit()
	trace("начало")

	// Уже работающая копия: показываем её окно и уходим. Проверка идёт до
	// запроса UAC — иначе человек увидел бы запрос прав ради программы,
	// которая тут же закроется.
	if activateRunning() {
		trace("копия уже работает, показал её окно")
		return
	}

	// Окно и цикл сообщений обязаны жить на одном потоке ОС.
	runtime.LockOSThread()
	setDPIAware()

	if !elevated() {
		trace("нет прав администратора, перезапуск с UAC")
		relaunchElevated()
		return
	}
	trace("права администратора есть")

	// Вторая проверка, уже после повышения прав: две копии, запущенные
	// одновременно, успели бы проскочить проверку по окну обе.
	if !claimSingleInstance() {
		if !activateRunning() {
			messageBox(0, gui.AppName+" уже запущен.\n\nОткройте его значком в области уведомлений.",
				gui.AppName, mbOK|mbIconInfo)
		}
		trace("копия уже работает (мьютекс)")
		return
	}

	token, err := startGDIPlus()
	if err != nil {
		fatal("не удалось запустить отрисовку (GDI+): " + err.Error())
		return
	}
	a.token = token
	defer stopGDIPlus(token)
	trace("GDI+ запущен")

	a.loadProfiles()
	trace(fmt.Sprintf("профилей загружено: %d", len(a.profiles.List)))

	inst := moduleHandle()
	wc := wndClassEx{
		Size:      uint32(unsafe.Sizeof(wndClassEx{})),
		Style:     csDropShadow | csHRedraw | csVRedraw,
		WndProc:   windows.NewCallback(wndProc),
		Instance:  inst,
		ClassName: utf16(windowClass),
		// Фона у класса нет: его стирание вызывало бы мигание поверх нашей
		// отрисовки. Окно целиком закрашивается в WM_PAINT.
		Background: 0,
	}
	// Иконка — из ресурсов программы (winres/, имя APP): та же, что в
	// Проводнике и меню «Пуск». Нет её (собрано без .syso) — стандартная.
	//
	// Маленькая (заголовок, Alt+Tab в списке) грузится отдельно, своего
	// размера: иначе Windows ужимает большую, и на 16 пикселях черепаха
	// превращается в пятно. В ресурсе для малых размеров — своя, крупная
	// обрезка (deploy/icon/make-icons.py).
	icon, _, _ := procLoadIcon.Call(uintptr(inst), uintptr(unsafe.Pointer(utf16(appIconName))))
	if icon == 0 {
		icon, _, _ = procLoadIcon.Call(0, idiApplication)
	}
	small, _, _ := procLoadImage.Call(uintptr(inst), uintptr(unsafe.Pointer(utf16(appIconName))),
		imageIcon, uintptr(systemMetric(smCxSmIcon)), uintptr(systemMetric(smCySmIcon)), 0)
	if small == 0 {
		small = icon
	}
	cursor, _, _ := procLoadCursor.Call(0, idcArrow)
	wc.Icon, wc.IconSm, wc.Cursor = windows.Handle(icon), windows.Handle(small), windows.Handle(cursor)
	if r, _, err := procRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		fatal("не удалось зарегистрировать класс окна: " + err.Error())
		return
	}

	a.scale = dpiScale(0) * uiZoom
	w, h := a.windowSize()
	x := (systemMetric(smCXScreen) - w) / 2
	y := (systemMetric(smCYScreen) - h) / 3 // чуть выше середины: так привычнее
	// WS_POPUP: своя полоса заголовка вместо системной. WS_MINIMIZEBOX
	// оставлен, иначе Windows не сворачивает окно по нашей кнопке.
	a.hwnd = createWindow(windowClass, gui.AppName, wsExAppWindow,
		wsPopup|wsMinimizeBox|wsVisible, x, y, w, h, 0, 0, inst)
	if a.hwnd == 0 {
		fatal("не удалось создать окно")
		return
	}
	a.roundCorners(w, h)
	procShowWindow.Call(uintptr(a.hwnd), swShow)
	procUpdateWindow.Call(uintptr(a.hwnd))
	procSetTimer.Call(uintptr(a.hwnd), timerTick, tickPeriod, 0)
	trace("окно показано, вход в цикл сообщений")

	var m msg
	for {
		r, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
	}
}

// windowSize — размер окна в пикселях для текущего экрана и масштаба.
func (a *app) windowSize() (int32, int32) {
	w := scaled(gui.WinW, a.scale)
	h := scaled(gui.WinH, a.scale)
	switch a.screen {
	case gui.ScreenSettings:
		h = scaled(gui.SettingsH, a.scale)
	case gui.ScreenAdd:
		h = scaled(gui.AddLayout(a.editing).Height, a.scale)
	default:
		// Высота главного экрана зависит от числа профилей и журнала:
		// список профилей растит окно, и считать её отдельно от раскладки
		// значило бы держать два разных ответа на один вопрос.
		h = scaled(gui.MainLayout(a.logOpen, a.profileCount()).Height, a.scale)
	}
	return w, h
}

// resize подгоняет окно под текущий экран, не двигая его левый верхний угол.
func (a *app) resize() {
	w, h := a.windowSize()
	procSetWindowPos.Call(uintptr(a.hwnd), 0, 0, 0, uintptr(w), uintptr(h),
		swpNoZOrder|swpNoActivate|swpNoMove)
	// Форма задана в пикселях и высоту окна не переживает: после смены
	// экрана низ остался бы прямоугольным, а старая форма вдобавок обрезала
	// бы окно по прежней высоте.
	a.roundCorners(w, h)
	a.invalidate()
}

// roundCorners режет окно по скруглённому прямоугольнику.
//
// Нарисовать скругление самим нельзя: за углом окна не наш фон, а чужой
// экран, и вместо скругления получился бы тёмный квадратик. Поэтому форму
// окна задаёт система.
//
// Область после SetWindowRgn принадлежит окну — удалять её нельзя, Windows
// освобождает старую сама при установке новой.
func (a *app) roundCorners(w, h int32) {
	if w <= 0 || h <= 0 {
		return
	}
	d := uintptr(2 * scaled(gui.WinRadius, a.scale)) // диаметр скругления
	// Правая и нижняя границы в GDI не включаются, отсюда +1: без него
	// окно теряло бы крайний столбец и строку пикселей.
	rgn, _, _ := procCreateRoundRectRgn.Call(0, 0, uintptr(w)+1, uintptr(h)+1, d, d)
	if rgn == 0 {
		return // не вышло — окно просто останется прямоугольным
	}
	procSetWindowRgn.Call(uintptr(a.hwnd), rgn, 1) // 1 — перерисовать сразу
}

func (a *app) invalidate() {
	procInvalidateRect.Call(uintptr(a.hwnd), 0, 0)
}

// elevated сообщает, запущены ли мы с правами администратора.
func elevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

// relaunchElevated перезапускает приложение с запросом UAC: без прав
// администратора нельзя ни создать адаптер, ни трогать маршруты.
func relaunchElevated() {
	exe, err := os.Executable()
	if err != nil {
		fatal("не удалось определить путь к программе: " + err.Error())
		return
	}
	args := strings.Join(os.Args[1:], " ")
	r, _, e := procShellExecute.Call(0,
		uintptr(unsafe.Pointer(utf16("runas"))),
		uintptr(unsafe.Pointer(utf16(exe))),
		uintptr(unsafe.Pointer(utf16(args))),
		uintptr(unsafe.Pointer(utf16(filepath.Dir(exe)))),
		swNormal)
	if r <= 32 { // ShellExecute: всё, что ≤32, — ошибка
		messageBox(0, "Нужны права администратора, а запрос не удался:\n"+e.Error(),
			gui.AppName, mbOK|mbIconError)
	}
}

func fatal(s string) {
	messageBox(0, s, gui.AppName, mbOK|mbIconError)
	os.Exit(1)
}

func wndProc(hwnd windows.HWND, message uint32, wParam, lParam uintptr) uintptr {
	// Эта функция вызывается из Windows, и паника в ней не возвращается в
	// Go: процесс падает целиком и молча. Перехват обязателен.
	defer func() {
		if v := recover(); v != nil {
			reportPanic(fmt.Sprintf("обработка сообщения 0x%04X", message), v)
			procPostQuitMessage.Call(1)
		}
	}()

	switch message {
	case wmCreate:
		a.res = newResources(dpiScale(hwnd) * uiZoom)
		a.scale = a.res.scale
		a.createEditors(hwnd)
		a.trayAdd()
		trace("окно создано, поля ввода готовы")
		a.appendLog("готов к подключению")

	case wmCtlColorEdit:
		return a.colorEdit(wParam)

	case wmEraseBkgnd:
		return 1 // фон не стираем: всё закрашивается в WM_PAINT, иначе мигает

	case wmPaint:
		a.onPaint(hwnd)

	case wmMouseMove:
		a.onMouseMove(hwnd, mouseX(lParam), mouseY(lParam))

	case wmMouseLeave:
		if a.hot != gui.ItemNone {
			a.hot = gui.ItemNone
			a.invalidate()
		}

	case wmLButtonDown:
		a.onMouseDown(hwnd, mouseX(lParam), mouseY(lParam))

	case wmLButtonUp:
		a.onMouseUp(mouseX(lParam), mouseY(lParam))

	case wmMouseWheel:
		a.onWheel(int16(wParam >> 16))

	case wmTimer:
		if wParam == timerTick {
			a.tick()
		}

	case wmState, wmLog, wmUp:
		// Значок показывает состояние цветом — это единственное, что видно,
		// когда окно спрятано.
		a.trayUpdate()
		a.invalidate()

	case wmTray:
		a.onTrayMessage(lParam)

	case wmDpiChanged:
		// Окно переехало на экран с другим масштабом: шрифты привязаны к
		// масштабу, поэтому кеш ресурсов пересоздаётся целиком.
		a.scale = dpiScale(hwnd) * uiZoom
		if a.res != nil {
			a.res.release()
		}
		a.res = newResources(a.scale)
		a.releaseEditors()
		a.createEditors(hwnd)
		a.showEditors(a.screen == gui.ScreenAdd)
		if lParam != 0 {
			r := rectAt(lParam)
			procSetWindowPos.Call(uintptr(hwnd), 0,
				uintptr(r.Left), uintptr(r.Top),
				uintptr(r.Right-r.Left), uintptr(r.Bottom-r.Top),
				swpNoZOrder|swpNoActivate)
		}
		a.resize()

	case wmClose:
		// Закрытие окна завершает программу вместе с туннелем.
		//
		// Была и другая версия — крестик прячет в значок, чтобы случайное
		// нажатие не выключало VPN. От неё отказались: «закрыл, а оно
		// работает» сбивает с толку сильнее, чем «закрыл и отключилось».
		// Спрятать окно, не разрывая соединения, по-прежнему можно —
		// щелчком по значку в области уведомлений.
		a.quitting = true
		a.stopAndWait()
		procDestroyWindow.Call(uintptr(hwnd))

	case wmDestroy:
		a.trayRemove()
		procKillTimer.Call(uintptr(hwnd), timerTick)
		if a.res != nil {
			a.res.release()
		}
		a.releaseEditors()
		procPostQuitMessage.Call(0)

	default:
		// Вторая копия просит показать окно. Сообщение зарегистрированное,
		// поэтому его номер известен только в работе и в switch не попадает.
		if message == showMessageID() {
			a.showFromTray()
			return 0
		}
		r, _, _ := procDefWindowProc.Call(uintptr(hwnd), uintptr(message), wParam, lParam)
		return r
	}
	return 0
}

// scaled переводит размер, заданный в «обычных» точках, в пиксели экрана.
func scaled(v int32, sc float64) int32 { return int32(float64(v)*sc + 0.5) }

// ---------- отрисовка ----------

// onPaint рисует окно через промежуточный растр.
//
// Без него каждый закрашенный прямоугольник попадал бы на экран сразу, и
// окно мигало бы при каждом обновлении счётчика: мы перерисовываем его
// целиком раз в секунду.
func (a *app) onPaint(hwnd windows.HWND) {
	var ps paintStruct
	hdc, _, _ := procBeginPaint.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&ps)))
	if hdc == 0 {
		return
	}
	defer procEndPaint.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&ps)))

	var rc rect
	procGetClientRect.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&rc)))
	w, h := rc.Right-rc.Left, rc.Bottom-rc.Top
	if w <= 0 || h <= 0 {
		return
	}

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
		p := &painter{g: g, hdc: windows.Handle(memDC), res: a.res, scale: a.scale}
		gui.Paint(p, a.view(), a.hot, a.pressed, time.Now())
		procGdipDeleteGraphics.Call(g)
	}
	procBitBlt.Call(hdc, 0, 0, uintptr(w), uintptr(h), memDC, 0, 0, srcCopy)
}

// view собирает снимок состояния для отрисовки: под замком берётся всё
// разом, чтобы на экране не встретились счётчики от разных мгновений.
func (a *app) view() gui.View {
	a.mu.Lock()
	v := gui.View{
		Screen:      a.screen,
		State:       a.state,
		Error:       a.lastErr,
		TunAddr:     a.tunAddr,
		Since:       a.since,
		LogOpen:     a.logOpen,
		AddNotice:   a.addNotice,
		AddFailed:   a.addFailed,
		AddBadField: a.addBadField,
		Editing:     a.editing,
		LogLines:    append([]string(nil), a.lines...),
		ScrollY:     a.scrollY,
	}
	counters := a.counters
	a.mu.Unlock()

	if counters != nil {
		st := counters.Stats()
		v.BytesIn, v.BytesOut = st.BytesIn, st.BytesOut
	}
	v.RateIn, v.RateOut = a.meter.Rates()
	v.Bars = a.meter.Bars()

	if pr, ok := a.active(); ok {
		v.Profile, v.Server = pr.Name, pr.Config.Server
		v.KillSwitch = pr.Config.KillSwitch != nil && *pr.Config.KillSwitch
		v.FullTunnel = pr.Config.FullTunnel != nil && *pr.Config.FullTunnel
		v.AllowCount = len(pr.Config.KillSwitchAllow)
	}
	v.Autostart = a.autostart
	for _, pr := range a.profiles.List {
		server := ""
		if pr.Config != nil {
			server = pr.Config.Server
		}
		v.Profiles = append(v.Profiles, gui.ProfileItem{
			Name:     pr.Name,
			Server:   server,
			Selected: strings.EqualFold(pr.Name, a.profiles.Current),
		})
	}
	return v
}

// ---------- мышь ----------

func mouseX(lParam uintptr) int32 { return int32(int16(lParam & 0xffff)) }
func mouseY(lParam uintptr) int32 { return int32(int16(lParam >> 16)) }

// hitTest ищет, на чём стоит курсор. Координаты приходят в пикселях, а
// раскладка живёт в логических точках — здесь единственное место, где они
// встречаются.
func (a *app) hitTest(px, py int32) gui.ItemID {
	x := int32(float64(px)/a.scale + 0.5)
	y := int32(float64(py)/a.scale + 0.5)
	for _, h := range a.hits() {
		if h.Rect.Contains(x, y) {
			return h.ID
		}
	}
	return gui.ItemNone
}

// profileCount — сколько профилей знает окно.
func (a *app) profileCount() int {
	if a.profiles == nil {
		return 0
	}
	return len(a.profiles.List)
}

func (a *app) hits() []gui.Hit {
	if a.screen == gui.ScreenAdd {
		return gui.AddLayout(a.editing).Hits()
	}
	if a.screen == gui.ScreenSettings {
		s := gui.SettingsLayout(len(a.profiles.List))
		return append(s.Hits(), s.ScrollHits(a.scrollY)...)
	}
	return gui.MainLayout(a.logOpen, a.profileCount()).Hits()
}

func (a *app) onMouseMove(hwnd windows.HWND, px, py int32) {
	// Подписка на уход курсора: без неё подсветка останется гореть, когда
	// мышь уедет за окно, — сообщения о движении туда уже не приходят.
	tme := trackMouseEvent{Size: uint32(unsafe.Sizeof(trackMouseEvent{})), Flags: tmeLeave, Track: hwnd}
	procTrackMouseEvent.Call(uintptr(unsafe.Pointer(&tme)))

	if h := a.hitTest(px, py); h != a.hot {
		a.hot = h
		a.invalidate()
	}
}

func (a *app) onMouseDown(hwnd windows.HWND, px, py int32) {
	id := a.hitTest(px, py)
	if id == gui.ItemNone {
		// Пустое место в полосе заголовка — перетаскивание окна. Системного
		// заголовка у нас нет, поэтому просим Windows считать, что нажали
		// именно по нему.
		y := int32(float64(py)/a.scale + 0.5)
		if y < gui.CaptionH {
			procReleaseCapture.Call()
			procSendMessage.Call(uintptr(hwnd), wmNCLButtonDown, htCaption, 0)
		}
		return
	}
	a.pressed = id
	a.invalidate()
}

func (a *app) onMouseUp(px, py int32) {
	id := a.pressed
	a.pressed = gui.ItemNone
	if id == gui.ItemNone {
		return
	}
	// Действие выполняется, только если курсор всё ещё на том же элементе:
	// уводя мышь с кнопки, человек отменяет нажатие.
	if a.hitTest(px, py) == id {
		a.activate(id)
	}
	a.invalidate()
}

func (a *app) onWheel(delta int16) {
	if a.screen != gui.ScreenSettings {
		return
	}
	s := gui.SettingsLayout(len(a.profiles.List))
	max := s.MaxScroll()
	if max == 0 {
		return
	}
	a.scrollY -= int32(delta) / 4 // 120 единиц на «щелчок» колеса — 30 точек
	if a.scrollY < 0 {
		a.scrollY = 0
	}
	if a.scrollY > max {
		a.scrollY = max
	}
	// Курсор не двигался, но под ним теперь другая строка.
	a.hot = gui.ItemNone
	a.invalidate()
}

// ---------- действия ----------

func (a *app) activate(id gui.ItemID) {
	switch id {
	case gui.ItemClose:
		procSendMessage.Call(uintptr(a.hwnd), wmClose, 0, 0)
	case gui.ItemMinimize:
		procShowWindow.Call(uintptr(a.hwnd), swMinimize)
	case gui.ItemSettings:
		a.screen, a.scrollY = gui.ScreenSettings, 0
		a.resize()
	case gui.ItemBack:
		// С экрана добавления возвращаемся туда, откуда его открыли:
		// «плюс» в шапке и строка в настройках ведут в одно место, но
		// высадить человека не там, где он был, — значит его потерять.
		if a.screen == gui.ScreenAdd {
			a.showEditors(false)
			a.screen, a.editing = a.addFrom, false
		} else {
			a.screen = gui.ScreenMain
		}
		a.resize()
	case gui.ItemConnect:
		a.onConnectClicked()
	case gui.ItemLogToggle:
		a.logOpen = !a.logOpen
		a.resize()
	case gui.ItemKillSwitch:
		a.toggleSetting("kill_switch")
	case gui.ItemFullTunnel:
		a.toggleSetting("full_tunnel")
	case gui.ItemAutostart:
		a.toggleAutostart()
	case gui.ItemAllowEdit:
		a.editAllowList()
	case gui.ItemAddProfile:
		a.openAddScreen()
	case gui.ItemPasteLink:
		a.pasteIntoForm()
		a.invalidate()
	case gui.ItemAddConfirm:
		a.confirmAdd()
		a.invalidate()
	case gui.ItemDeleteProfile:
		a.deleteEdited()
		a.invalidate()
	default:
		if i, ok := gui.ProfileIndex(id); ok {
			a.selectProfile(i)
			return
		}
		if i, ok := gui.ProfileMenuIndex(id); ok {
			a.profileMenu(i)
		}
	}
}

func (a *app) onConnectClicked() {
	switch a.currentState() {
	case gui.Off:
		a.start()
	case gui.Connecting, gui.On:
		a.stop()
	}
}

// ---------- движок ----------

func (a *app) currentState() gui.State {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.state
}

func (a *app) setState(s gui.State) {
	a.mu.Lock()
	a.state = s
	if s == gui.Off {
		a.since, a.tunAddr, a.counters = time.Time{}, "", nil
	}
	a.mu.Unlock()
	procPostMessage.Call(uintptr(a.hwnd), wmState, uintptr(s), 0)
}

func (a *app) start() {
	pr, ok := a.active()
	if !ok {
		messageBox(a.hwnd, "Нет ни одного профиля.\n\nСкопируйте ссылку masquevpn://… и добавьте её "+
			"в настройках кнопкой «Добавить по ссылке».", gui.AppName, mbOK|mbIconInfo)
		return
	}
	cfg := pr.Config

	a.mu.Lock()
	a.lastErr = ""
	a.mu.Unlock()
	a.meter.Reset()
	a.setState(gui.Connecting)
	a.appendLog("подключение к " + cfg.Server + " (" + pr.Name + ")")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	a.mu.Lock()
	a.cancel, a.done = cancel, done
	a.mu.Unlock()

	log := slog.New(&guiHandler{app: a, level: levelOf(cfg.LogLevel)})
	hooks := clientrun.Hooks{
		Up: func(addrs []netip.Prefix) {
			a.mu.Lock()
			a.since = time.Now()
			if len(addrs) > 0 {
				a.tunAddr = addrs[0].Addr().String()
			}
			a.mu.Unlock()
			a.setState(gui.On)
		},
		Session: func(c clientrun.Counters) {
			a.mu.Lock()
			a.counters = c
			a.mu.Unlock()
		},
	}
	go func() {
		defer close(done)
		err := clientrun.Run(ctx, cfg, log, hooks)
		if err != nil && ctx.Err() == nil {
			a.appendLog("ошибка: " + err.Error())
			a.mu.Lock()
			a.lastErr = err.Error()
			a.mu.Unlock()
		}
		a.setState(gui.Off)
		a.appendLog("отключено")
	}()
}

func (a *app) stop() {
	a.mu.Lock()
	cancel := a.cancel
	a.cancel = nil
	a.mu.Unlock()
	if cancel == nil {
		return
	}
	a.setState(gui.Stopping)
	cancel()
}

// stopAndWait останавливает туннель и дожидается, пока движок вернёт сеть
// в исходное состояние.
//
// Нужно при выходе: отмена контекста только просит остановиться, а снять
// блокировку, правило разрешения имён, маршруты и сам адаптер движок
// успевает уже после. Процесс, завершившийся раньше, оставил бы всё это
// висеть — ровно тот случай, ради которого написан сторож, но сторож
// нужен для аварий, а не для обычного выхода.
//
// Ожидание с потолком: если движок почему-то не уложился, выходим всё
// равно — дальше приберётся сторож или следующий запуск.
func (a *app) stopAndWait() {
	a.mu.Lock()
	done := a.done
	a.mu.Unlock()

	a.stop()
	if done == nil {
		return
	}
	select {
	case <-done:
	case <-time.After(stopTimeout):
		a.appendLog("движок не остановился за " + stopTimeout.String() + ", выходим")
	}
}

// tick — раз в секунду: снять счётчики, пересчитать скорость, перерисовать.
func (a *app) tick() {
	a.mu.Lock()
	counters := a.counters
	a.mu.Unlock()
	if counters != nil {
		st := counters.Stats()
		a.meter.Observe(st.BytesIn, st.BytesOut, time.Now())
	}
	a.invalidate()
}

// ---------- журнал ----------

const maxLogLines = 400

func (a *app) appendLog(line string) {
	a.mu.Lock()
	a.lines = append(a.lines, time.Now().Format("15:04:05")+"  "+line)
	if len(a.lines) > maxLogLines {
		a.lines = a.lines[len(a.lines)-maxLogLines:]
	}
	a.mu.Unlock()
	if a.hwnd != 0 {
		procPostMessage.Call(uintptr(a.hwnd), wmLog, 0, 0)
	}
}

// guiHandler — приёмник журнала slog: строки идут в окно, а не в консоль.
type guiHandler struct {
	app   *app
	level slog.Level
	attrs []slog.Attr
}

func (h *guiHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level }

func (h *guiHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Message)
	for _, at := range h.attrs {
		fmt.Fprintf(&b, "  %s=%v", at.Key, at.Value)
	}
	r.Attrs(func(at slog.Attr) bool {
		fmt.Fprintf(&b, "  %s=%v", at.Key, at.Value)
		return true
	})
	h.app.appendLog(b.String())
	return nil
}

func (h *guiHandler) WithAttrs(as []slog.Attr) slog.Handler {
	n := *h
	n.attrs = append(append([]slog.Attr(nil), h.attrs...), as...)
	return &n
}

func (h *guiHandler) WithGroup(string) slog.Handler { return h }

func levelOf(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// watchdogPID разбирает служебный аргумент -watchdog <pid>. Своего разбора
// флагов у окна нет, и заводить его ради одного служебного случая незачем.
func watchdogPID() (int, bool) {
	args := os.Args[1:]
	for i, arg := range args {
		if arg != "-"+clientrun.WatchdogFlag && arg != "--"+clientrun.WatchdogFlag {
			continue
		}
		if i+1 >= len(args) {
			return 0, false
		}
		pid, err := strconv.Atoi(args[i+1])
		if err != nil || pid <= 0 {
			return 0, false
		}
		return pid, true
	}
	return 0, false
}
