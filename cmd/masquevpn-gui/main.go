//go:build linux

// Команда masquevpn-gui — оконный клиент masquevpn для Linux.
//
// Тот же движок, что у консольного клиента (internal/clientrun), и тот же
// интерфейс, что у окна Windows: раскладку и отрисовку обе версии берут из
// internal/gui, поэтому «одинаковый дизайн» здесь означает буквально один и
// тот же код, а не старательно повторенный вид.
//
// Разница только в том, чем рисовать и через что показывать:
//
//	Windows   GDI+            →  окно Win32
//	Linux     internal/guiraster (свой растеризатор)  →  окно X11 (xgb)
//
// Требуются права root: TUN, маршруты, nf_tables. Без них окно откроется,
// но подключиться не даст и скажет почему.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jezek/xgb"
	"github.com/jezek/xgb/xproto"

	"github.com/soways11/masquevpn/internal/clientrun"
	"github.com/soways11/masquevpn/internal/config"
	"github.com/soways11/masquevpn/internal/gui"
	"github.com/soways11/masquevpn/internal/guiraster"
)

const (
	// uiZoom — общее увеличение интерфейса, как в Windows-клиенте.
	uiZoom = 1.25

	tickPeriod  = time.Second
	graphPoints = 30
	stopTimeout = 5 * time.Second
)

type app struct {
	win   *window
	fonts *guiraster.FontSet
	scale float64

	// Состояние интерфейса живёт в потоке цикла событий, без замка.
	screen   gui.Screen
	logOpen  bool
	scrollY  int32
	hot      gui.ItemID
	pressed  gui.ItemID
	editing  bool
	editIdx  int
	addFrom  gui.Screen
	fields   [gui.MaxAddFields]string
	focus    int
	notice   string
	failed   bool
	badField int

	// menu — открытое меню; nil, когда меню закрыто. Рисуется слоем поверх
	// окна, а не отдельным окном: в X11 всплывающее окно требует захвата
	// указателя и своей обработки потери фокуса, а выглядит точно так же.
	menu      []gui.MenuItem
	menuAt    gui.Rect
	menuHot   int
	menuOwner int // к какому профилю относится меню

	meter    *gui.Meter
	profiles *config.Profiles

	mu       sync.Mutex
	state    gui.State
	lastErr  string
	since    time.Time
	tunAddr  string
	counters clientrun.Counters
	cancel   context.CancelFunc
	done     chan struct{}
	lines    []string

	// Клавиатура и буфер обмена.
	keymap       []xproto.Keysym
	keysPerCode  byte
	firstKeycode xproto.Keycode
	clipboard    string

	redraw chan struct{}
	quit   bool
}

func main() {
	a := &app{meter: gui.NewMeter(graphPoints), scale: uiZoom, redraw: make(chan struct{}, 1), editIdx: -1}

	fonts, err := guiraster.LoadFonts()
	if err != nil {
		fmt.Fprintln(os.Stderr, "masquevpn:", err)
		os.Exit(1)
	}
	a.fonts = fonts
	defer fonts.Close()

	// Служебный ключ: открыть окно сразу на нужном экране. Нужен для
	// проверки вида под Xvfb, где нечем щёлкать мышью, и стоит он ровно
	// один switch.
	switch screenArg() {
	case "settings":
		a.screen = gui.ScreenSettings
	case "add":
		a.screen = gui.ScreenAdd
	}

	a.loadProfiles()
	a.appendLog("готов к подключению")
	if os.Geteuid() != 0 {
		// Не выходим: окно полезно и без прав — посмотреть профили. Но
		// сказать об этом надо сразу, а не при первой попытке подключиться.
		a.appendLog("нет прав root: подключение работать не будет (sudo masquevpn-gui)")
	}

	w, h := a.windowSize()
	win, err := openWindow(gui.AppName, w, h, a.scale)
	if err != nil {
		fmt.Fprintln(os.Stderr, "masquevpn:", err)
		os.Exit(1)
	}
	a.win = win
	defer win.close()

	a.run()
}

// screenArg разбирает -screen ИМЯ.
func screenArg() string {
	args := os.Args[1:]
	for i, v := range args {
		if (v == "-screen" || v == "--screen") && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// windowSize — размер окна в пикселях для текущего экрана.
func (a *app) windowSize() (int, int) {
	h := gui.MainLayout(a.logOpen, a.profileCount()).Height
	switch a.screen {
	case gui.ScreenSettings:
		h = gui.SettingsH
	case gui.ScreenAdd:
		h = gui.AddLayout(a.editing).Height
	}
	return int(float64(gui.WinW)*a.scale + 0.5), int(float64(h)*a.scale + 0.5)
}

func (a *app) resize() {
	w, h := a.windowSize()
	a.win.resize(w, h)
	a.invalidate()
}

func (a *app) invalidate() {
	select {
	case a.redraw <- struct{}{}:
	default: // перерисовка уже назначена
	}
}

// run — главный цикл: события X, таймер и просьбы перерисовать.
//
// События читает отдельная горутина, потому что WaitForEvent блокирующий, а
// таймер счётчиков должен идти своим чередом.
func (a *app) run() {
	events := make(chan xgb.Event, 32)
	go func() {
		for {
			ev, err := a.win.conn.WaitForEvent()
			if ev == nil && err == nil {
				close(events)
				return
			}
			if ev != nil {
				events <- ev
			}
		}
	}()

	ticker := time.NewTicker(tickPeriod)
	defer ticker.Stop()

	a.paint()
	for !a.quit {
		select {
		case ev, ok := <-events:
			if !ok {
				return
			}
			a.handle(ev)
		case <-ticker.C:
			a.tick()
		case <-a.redraw:
			a.paint()
		}
	}
}

func (a *app) handle(ev xgb.Event) {
	switch e := ev.(type) {
	case xproto.ExposeEvent:
		if e.Count == 0 {
			a.paint()
		}
	case xproto.ButtonPressEvent:
		a.onPress(int32(e.EventX), int32(e.EventY), e.RootX, e.RootY, e.Detail)
	case xproto.ButtonReleaseEvent:
		a.onRelease(int32(e.EventX), int32(e.EventY))
	case xproto.MotionNotifyEvent:
		a.onMotion(int32(e.EventX), int32(e.EventY))
	case xproto.LeaveNotifyEvent:
		if a.hot != gui.ItemNone {
			a.hot = gui.ItemNone
			a.invalidate()
		}
	case xproto.KeyPressEvent:
		a.onKey(e)
	case xproto.SelectionNotifyEvent:
		a.onPaste(e)
	case xproto.SelectionRequestEvent:
		a.onSelectionRequest(e)
	case xproto.ConfigureNotifyEvent:
		a.invalidate()
	case xproto.ClientMessageEvent:
		// Единственное, что нам присылают сообщением, — просьба закрыться.
		if e.Data.Data32[0] == uint32(a.win.atoms.wmDeleteWindow) {
			a.shutdown()
		}
	}
}

// shutdown завершает работу, дождавшись уборки сети.
//
// Как и в Windows: отмена контекста только просит движок остановиться, а
// снять маршруты, правила и адаптер он успевает уже после. Процесс,
// вышедший раньше, оставил бы всё это висеть.
func (a *app) shutdown() {
	a.stopAndWait()
	a.quit = true
}

// ---------- отрисовка ----------

func (a *app) paint() {
	_, h := a.windowSize()
	logical := int32(float64(h)/a.scale + 0.5)

	cv := guiraster.New(gui.WinW, logical, a.scale, a.fonts)
	gui.Paint(cv, a.view(), a.hot, a.pressed, time.Now())
	// Курсор мигает раз в секунду: считаем от часов, чтобы не заводить
	// отдельный таймер ради одной полоски.
	a.paintFields(cv, time.Now().UnixMilli()%1000 < 600)
	if a.menu != nil {
		a.paintMenu(cv)
	}
	a.win.present(cv.Image())
	a.win.conn.Sync()
}

// view собирает снимок состояния для отрисовки.
func (a *app) view() gui.View {
	a.mu.Lock()
	v := gui.View{
		Screen:      a.screen,
		State:       a.state,
		Error:       a.lastErr,
		TunAddr:     a.tunAddr,
		Since:       a.since,
		LogOpen:     a.logOpen,
		LogLines:    append([]string(nil), a.lines...),
		ScrollY:     a.scrollY,
		AddNotice:   a.notice,
		AddFailed:   a.failed,
		AddBadField: a.badField,
		Editing:     a.editing,
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

// point переводит координаты события в логические точки.
func (a *app) point(x, y int32) (int32, int32) {
	return int32(float64(x)/a.scale + 0.5), int32(float64(y)/a.scale + 0.5)
}

func (a *app) hits() []gui.Hit {
	switch a.screen {
	case gui.ScreenAdd:
		return gui.AddLayout(a.editing).Hits()
	case gui.ScreenSettings:
		s := gui.SettingsLayout(a.profileCount())
		return append(s.Hits(), s.ScrollHits(a.scrollY)...)
	default:
		return gui.MainLayout(a.logOpen, a.profileCount()).Hits()
	}
}

func (a *app) hitTest(px, py int32) gui.ItemID {
	x, y := a.point(px, py)
	for _, h := range a.hits() {
		if h.Rect.Contains(x, y) {
			return h.ID
		}
	}
	return gui.ItemNone
}

func (a *app) onMotion(px, py int32) {
	if a.menu != nil {
		x, y := a.point(px, py)
		if hot := a.menuHitTest(x, y); hot != a.menuHot {
			a.menuHot = hot
			a.invalidate()
		}
		return
	}
	if h := a.hitTest(px, py); h != a.hot {
		a.hot = h
		a.invalidate()
	}
}

func (a *app) onPress(px, py int32, rootX, rootY int16, button xproto.Button) {
	if a.menu != nil {
		return // выбор происходит по отпусканию
	}
	if button != 1 {
		return
	}
	id := a.hitTest(px, py)
	if id == gui.ItemNone {
		x, y := a.point(px, py)
		if y < gui.CaptionH {
			// Пустое место в полосе заголовка — перетаскивание окна.
			a.win.startDrag(rootX, rootY)
			return
		}
		// Щелчок по полю ввода переводит в него фокус.
		if a.screen == gui.ScreenAdd {
			if i := fieldAt(a.editing, x, y); i >= 0 {
				a.focus = i
				a.invalidate()
			}
		}
		return
	}
	a.pressed = id
	a.invalidate()
}

func (a *app) onRelease(px, py int32) {
	if a.menu != nil {
		x, y := a.point(px, py)
		if i := a.menuHitTest(x, y); i >= 0 {
			id := a.menu[i].ID
			a.closeMenu()
			a.menuAction(id)
		} else {
			a.closeMenu()
		}
		a.invalidate()
		return
	}
	id := a.pressed
	a.pressed = gui.ItemNone
	if id == gui.ItemNone {
		return
	}
	if a.hitTest(px, py) == id {
		a.activate(id)
	}
	a.invalidate()
}

// fieldAt ищет поле ввода под точкой.
func fieldAt(editing bool, x, y int32) int {
	l := gui.AddLayout(editing)
	for i, f := range l.Fields {
		if f.Box.Contains(x, y) {
			return i
		}
	}
	return -1
}

// ---------- действия ----------

func (a *app) activate(id gui.ItemID) {
	switch id {
	case gui.ItemClose:
		a.shutdown()
	case gui.ItemMinimize:
		a.win.iconify()
	case gui.ItemSettings:
		a.screen, a.scrollY = gui.ScreenSettings, 0
		a.resize()
	case gui.ItemBack:
		if a.screen == gui.ScreenAdd {
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
		a.appendLog("автозапуск в Linux пока не настраивается из окна")
	case gui.ItemAllowEdit:
		a.appendLog("исключения правятся в " + config.DefaultProfilesPath() + " (поле kill_switch_allow)")
	case gui.ItemAddProfile:
		a.openAddScreen()
	case gui.ItemPasteLink:
		a.requestPaste()
	case gui.ItemAddConfirm:
		a.confirmAdd()
	case gui.ItemDeleteProfile:
		a.deleteEdited()
	default:
		if i, ok := gui.ProfileIndex(id); ok {
			a.selectProfile(i)
			return
		}
		if i, ok := gui.ProfileMenuIndex(id); ok {
			a.openProfileMenu(i)
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
	a.invalidate()
}

func (a *app) start() {
	pr, ok := a.active()
	if !ok {
		a.appendLog("нет профилей: добавьте сервер кнопкой «+»")
		return
	}
	if os.Geteuid() != 0 {
		a.mu.Lock()
		a.lastErr = "нужны права root: запустите через sudo"
		a.mu.Unlock()
		a.appendLog("подключение невозможно без прав root")
		a.invalidate()
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
	a.invalidate()
}

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
