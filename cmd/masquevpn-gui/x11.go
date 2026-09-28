//go:build linux

package main

// Окно X11 на чистом Go.
//
// # Почему так
//
// Интерфейс Windows рисует GDI+, здесь — свой растеризатор
// (internal/guiraster): он отдаёт готовую картинку, и от системы нужно
// только окно, события мыши и клавиатуры да способ показать растр. Всё это
// есть в самом протоколе X11, без единой строчки на C.
//
// Альтернативы требовали cgo: GTK, Qt, даже Xlib. Cgo здесь дорог не
// сложностью сборки, а тем, что ломает кросс-сборку — проект собирается
// под четыре платформы из одного места, и заводить ради одного окна
// цепочку системных заголовков было бы несоразмерно.
//
// # Про декорации
//
// Окно просит window manager не рисовать рамку (_MOTIF_WM_HINTS): полоса
// заголовка нарисована своя, как и в Windows, иначе два клиента выглядели
// бы по-разному. Перетаскивание делается через _NET_WM_MOVERESIZE — это
// просьба к WM подвинуть окно, а не попытка двигать его самим: своими
// силами окно дёргалось бы за курсором с задержкой.

import (
	"fmt"
	"image"

	"github.com/jezek/xgb"
	"github.com/jezek/xgb/shape"
	"github.com/jezek/xgb/xproto"

	"github.com/soways11/masquevpn/internal/gui"
)

// window — окно X11 вместе со всем, что нужно для отрисовки.
type window struct {
	conn   *xgb.Conn
	screen *xproto.ScreenInfo
	id     xproto.Window
	gc     xproto.Gcontext
	depth  byte

	atoms struct {
		wmProtocols     xproto.Atom
		wmDeleteWindow  xproto.Atom
		netWMName       xproto.Atom
		utf8String      xproto.Atom
		motifWMHints    xproto.Atom
		netWMMoveResize xproto.Atom
		clipboard       xproto.Atom
		targets         xproto.Atom
		xselData        xproto.Atom
		netWMIcon       xproto.Atom
	}

	// maxChunk — сколько строк растра влезает в один запрос PutImage.
	// Протокол ограничивает длину запроса, и большое окно приходится
	// отдавать полосами.
	maxChunk int

	// shaped — сервер умеет менять форму окна (расширение SHAPE). Без него
	// окно просто останется прямоугольным.
	shaped bool
	// scale — во сколько раз окно крупнее логической раскладки.
	scale float64

	// resizeCursor — курсор «тянуть вверх-вниз» над нижней кромкой; 0 —
	// не создался. resizing — он сейчас стоит.
	resizeCursor xproto.Cursor
	resizing     bool
}

func openWindow(title string, w, h int, scale float64) (*window, error) {
	conn, err := xgb.NewConn()
	if err != nil {
		return nil, fmt.Errorf("не удалось соединиться с X-сервером (переменная DISPLAY): %w", err)
	}
	setup := xproto.Setup(conn)
	screen := setup.DefaultScreen(conn)

	win := &window{conn: conn, screen: screen, depth: screen.RootDepth, scale: scale}

	id, err := xproto.NewWindowId(conn)
	if err != nil {
		return nil, err
	}
	win.id = id

	// Окно по центру экрана, чуть выше середины — как в Windows.
	x := (int(screen.WidthInPixels) - w) / 2
	y := (int(screen.HeightInPixels) - h) / 3

	mask := uint32(xproto.CwBackPixel | xproto.CwEventMask)
	values := []uint32{
		screen.BlackPixel,
		uint32(xproto.EventMaskExposure |
			xproto.EventMaskButtonPress |
			xproto.EventMaskButtonRelease |
			xproto.EventMaskPointerMotion |
			xproto.EventMaskKeyPress |
			xproto.EventMaskStructureNotify |
			xproto.EventMaskLeaveWindow),
	}
	if err := xproto.CreateWindowChecked(conn, screen.RootDepth, id, screen.Root,
		int16(x), int16(y), uint16(w), uint16(h), 0,
		xproto.WindowClassInputOutput, screen.RootVisual, mask, values).Check(); err != nil {
		return nil, err
	}

	gc, err := xproto.NewGcontextId(conn)
	if err != nil {
		return nil, err
	}
	win.gc = gc
	if err := xproto.CreateGCChecked(conn, gc, xproto.Drawable(id),
		xproto.GcForeground, []uint32{screen.BlackPixel}).Check(); err != nil {
		return nil, err
	}

	if err := win.initAtoms(); err != nil {
		return nil, err
	}
	win.setTitle(title)
	win.setIdentity(int(setup.MaximumRequestLength))
	win.hideDecorations()
	win.closeOnDelete()
	win.shaped = shape.Init(conn) == nil
	win.round(w, h)
	win.resizeCursor = win.makeCursor(116) // XC_sb_v_double_arrow

	// Длина запроса считается в четырёхбайтовых словах; вычитаем запас под
	// заголовок самого запроса.
	maxWords := int(setup.MaximumRequestLength)
	win.maxChunk = (maxWords*4 - 64) / (w * 4)
	if win.maxChunk < 1 {
		win.maxChunk = 1
	}

	xproto.MapWindow(conn, id)
	return win, nil
}

func (w *window) initAtoms() error {
	get := func(name string) (xproto.Atom, error) {
		r, err := xproto.InternAtom(w.conn, false, uint16(len(name)), name).Reply()
		if err != nil {
			return 0, err
		}
		return r.Atom, nil
	}
	var err error
	if w.atoms.wmProtocols, err = get("WM_PROTOCOLS"); err != nil {
		return err
	}
	if w.atoms.wmDeleteWindow, err = get("WM_DELETE_WINDOW"); err != nil {
		return err
	}
	if w.atoms.netWMName, err = get("_NET_WM_NAME"); err != nil {
		return err
	}
	if w.atoms.utf8String, err = get("UTF8_STRING"); err != nil {
		return err
	}
	if w.atoms.motifWMHints, err = get("_MOTIF_WM_HINTS"); err != nil {
		return err
	}
	if w.atoms.netWMMoveResize, err = get("_NET_WM_MOVERESIZE"); err != nil {
		return err
	}
	if w.atoms.clipboard, err = get("CLIPBOARD"); err != nil {
		return err
	}
	if w.atoms.targets, err = get("TARGETS"); err != nil {
		return err
	}
	if w.atoms.netWMIcon, err = get("_NET_WM_ICON"); err != nil {
		return err
	}
	w.atoms.xselData, err = get("XSEL_DATA")
	return err
}

// setIdentity называет окно для рабочего стола.
//
// WM_CLASS — по нему панель задач связывает окно с ярлыком masquevpn.desktop
// (а значит, и со значком из темы). _NET_WM_ICON — сам значок, на случай
// окружений, которые ярлык не сопоставят: без него там было бы безликое
// окно «без иконки». Размеры с запасом под крупные экраны; всё, что не
// влезает в один запрос X11, отбрасывается начиная с крупного.
func (w *window) setIdentity(maxWords int) {
	class := gui.AppName + "\x00" + gui.AppName + "\x00"
	xproto.ChangeProperty(w.conn, xproto.PropModeReplace, w.id,
		xproto.AtomWmClass, xproto.AtomString, 8, uint32(len(class)), []byte(class))

	sizes := []int{16, 32, 48, 64, 128}
	var icon []uint32
	for len(sizes) > 0 {
		icon = gui.LogoARGB(sizes...)
		if len(icon)+64 < maxWords {
			break
		}
		sizes = sizes[:len(sizes)-1]
	}
	if len(sizes) == 0 {
		return
	}
	data := make([]byte, len(icon)*4)
	for i, v := range icon {
		xgb.Put32(data[i*4:], v)
	}
	xproto.ChangeProperty(w.conn, xproto.PropModeReplace, w.id,
		w.atoms.netWMIcon, xproto.AtomCardinal, 32, uint32(len(icon)), data)
}

func (w *window) setTitle(title string) {
	xproto.ChangeProperty(w.conn, xproto.PropModeReplace, w.id,
		w.atoms.netWMName, w.atoms.utf8String, 8, uint32(len(title)), []byte(title))
	xproto.ChangeProperty(w.conn, xproto.PropModeReplace, w.id,
		xproto.AtomWmName, xproto.AtomString, 8, uint32(len(title)), []byte(title))
}

// hideDecorations просит WM не рисовать рамку и заголовок.
//
// _MOTIF_WM_HINTS — наследие Motif, но именно его понимают почти все
// менеджеры окон; стандартной замены так и не появилось. Если WM его не
// знает, окно просто получит обычную рамку — неприятно, но работать будет.
func (w *window) hideDecorations() {
	const mwmHintsDecorations = 2
	hints := []uint32{mwmHintsDecorations, 0, 0, 0, 0} // flags, functions, decorations=0, …
	data := make([]byte, len(hints)*4)
	for i, v := range hints {
		xgb.Put32(data[i*4:], v)
	}
	xproto.ChangeProperty(w.conn, xproto.PropModeReplace, w.id,
		w.atoms.motifWMHints, w.atoms.motifWMHints, 32, uint32(len(hints)), data)
}

// closeOnDelete просит WM не убивать соединение при закрытии окна, а
// присылать сообщение: иначе нажатие на «закрыть» оборвало бы программу
// вместе с туннелем, не дав прибраться.
func (w *window) closeOnDelete() {
	data := make([]byte, 4)
	xgb.Put32(data, uint32(w.atoms.wmDeleteWindow))
	xproto.ChangeProperty(w.conn, xproto.PropModeReplace, w.id,
		w.atoms.wmProtocols, xproto.AtomAtom, 32, 1, data)
}

// setSizeHints сообщает менеджеру окон пределы размера: ширина неизменна,
// высота — от minH до maxH. Без подсказок WM растягивал бы окно и вширь.
func (w *window) setSizeHints(width, minH, maxH int) {
	const pMinSize, pMaxSize = 1 << 4, 1 << 5
	hints := make([]uint32, 18)
	hints[0] = pMinSize | pMaxSize
	hints[5], hints[6] = uint32(width), uint32(minH)
	hints[7], hints[8] = uint32(width), uint32(maxH)
	data := make([]byte, len(hints)*4)
	for i, v := range hints {
		xgb.Put32(data[i*4:], v)
	}
	xproto.ChangeProperty(w.conn, xproto.PropModeReplace, w.id,
		xproto.AtomWmNormalHints, xproto.AtomWmSizeHints, 32, uint32(len(hints)), data)
}

// makeCursor создаёт стандартный курсор X по номеру из шрифта «cursor».
func (w *window) makeCursor(glyph uint16) xproto.Cursor {
	font, err := xproto.NewFontId(w.conn)
	if err != nil {
		return 0
	}
	if err := xproto.OpenFontChecked(w.conn, font, uint16(len("cursor")), "cursor").Check(); err != nil {
		return 0
	}
	defer xproto.CloseFont(w.conn, font)
	c, err := xproto.NewCursorId(w.conn)
	if err != nil {
		return 0
	}
	if err := xproto.CreateGlyphCursorChecked(w.conn, c, font, font, glyph, glyph+1,
		0, 0, 0, 0xffff, 0xffff, 0xffff).Check(); err != nil {
		return 0
	}
	return c
}

// setResizeCursor ставит курсор растяжения над нижней кромкой и убирает его
// в остальном окне — иначе не догадаться, что окно тянется.
func (w *window) setResizeCursor(on bool) {
	if w.resizeCursor == 0 || on == w.resizing {
		return
	}
	w.resizing = on
	c := uint32(0) // None — курсор родительского окна
	if on {
		c = uint32(w.resizeCursor)
	}
	xproto.ChangeWindowAttributes(w.conn, w.id, xproto.CwCursor, []uint32{c})
}

// startResize просит менеджер окон растянуть окно за нижний край — тем же
// способом, что и перетаскивание: рамки, за которую он тянул бы сам, у
// окна нет.
func (w *window) startResize(rootX, rootY int16) {
	const moveResizeSizeBottom = 5 // _NET_WM_MOVERESIZE_SIZE_BOTTOM
	w.moveResize(rootX, rootY, moveResizeSizeBottom)
}

// resize меняет размер окна (после смены масштаба или ограничения высоты).
func (w *window) resize(width, height int) {
	xproto.ConfigureWindow(w.conn, w.id,
		xproto.ConfigWindowWidth|xproto.ConfigWindowHeight,
		[]uint32{uint32(width), uint32(height)})
	// Форма задана в пикселях и высоту окна не переживает: после смены
	// экрана низ остался бы прямоугольным, а прежняя форма вдобавок
	// обрезала бы окно по старой высоте.
	w.round(width, height)
}

// round задаёт окну форму со скруглёнными углами.
//
// Радиус масштабируется вместе с интерфейсом: размеры раскладки логические, а
// форма задаётся в пикселях экрана. Без этого при увеличении окна углы
// оставались бы прежними и выглядели бы мельче всего остального.
func (w *window) round(width, height int) {
	if !w.shaped {
		return
	}
	rects := roundedRect(width, height, int(float64(gui.WinRadius)*w.scale+0.5))
	if len(rects) == 0 {
		return
	}
	shape.Rectangles(w.conn, shape.SoSet, shape.SkBounding,
		xproto.ClipOrderingYXBanded, w.id, 0, 0, rects)
}

// startDrag просит менеджер окон подвинуть окно за курсором.
func (w *window) startDrag(rootX, rootY int16) {
	const moveResizeMove = 8 // _NET_WM_MOVERESIZE_MOVE
	w.moveResize(rootX, rootY, moveResizeMove)
}

// moveResize — запрос _NET_WM_MOVERESIZE: подвинуть или растянуть окно.
func (w *window) moveResize(rootX, rootY int16, direction uint32) {
	// Кнопку нужно отпустить до начала перетаскивания, иначе WM не
	// перехватит указатель.
	xproto.UngrabPointer(w.conn, xproto.TimeCurrentTime)

	ev := xproto.ClientMessageEvent{
		Format: 32,
		Window: w.id,
		Type:   w.atoms.netWMMoveResize,
		Data: xproto.ClientMessageDataUnionData32New([]uint32{
			uint32(rootX), uint32(rootY), direction, 1, 1,
		}),
	}
	xproto.SendEvent(w.conn, false, w.screen.Root,
		uint32(xproto.EventMaskSubstructureRedirect|xproto.EventMaskSubstructureNotify),
		string(ev.Bytes()))
}

func (w *window) iconify() {
	// Свернуть — это просьба к WM через корневое окно (ICCCM).
	atom, err := xproto.InternAtom(w.conn, false, uint16(len("WM_CHANGE_STATE")), "WM_CHANGE_STATE").Reply()
	if err != nil {
		return
	}
	const iconicState = 3
	ev := xproto.ClientMessageEvent{
		Format: 32,
		Window: w.id,
		Type:   atom.Atom,
		Data:   xproto.ClientMessageDataUnionData32New([]uint32{iconicState, 0, 0, 0, 0}),
	}
	xproto.SendEvent(w.conn, false, w.screen.Root,
		uint32(xproto.EventMaskSubstructureRedirect|xproto.EventMaskSubstructureNotify),
		string(ev.Bytes()))
}

// present выводит растр на экран.
//
// Байты переставляются из RGBA в порядок X-сервера (обычно BGRX): сервер
// принимает картинку как есть и не переворачивает каналы сам.
func (w *window) present(img *image.RGBA) {
	b := img.Bounds()
	width, height := b.Dx(), b.Dy()
	if width <= 0 || height <= 0 {
		return
	}

	buf := make([]byte, width*4*w.maxChunk)
	for y0 := 0; y0 < height; y0 += w.maxChunk {
		rows := w.maxChunk
		if y0+rows > height {
			rows = height - y0
		}
		for y := 0; y < rows; y++ {
			src := img.PixOffset(b.Min.X, b.Min.Y+y0+y)
			dst := y * width * 4
			for x := 0; x < width; x++ {
				r := img.Pix[src+x*4+0]
				g := img.Pix[src+x*4+1]
				bl := img.Pix[src+x*4+2]
				buf[dst+x*4+0] = bl
				buf[dst+x*4+1] = g
				buf[dst+x*4+2] = r
				buf[dst+x*4+3] = 0xFF
			}
		}
		xproto.PutImage(w.conn, xproto.ImageFormatZPixmap, xproto.Drawable(w.id), w.gc,
			uint16(width), uint16(rows), 0, int16(y0), 0, w.depth, buf[:rows*width*4])
	}
}

func (w *window) close() {
	xproto.DestroyWindow(w.conn, w.id)
	w.conn.Close()
}
