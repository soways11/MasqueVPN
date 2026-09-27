//go:build windows

package main

// Привязки к GDI+ — ровно те, что нужны для отрисовки окна.
//
// # Почему GDI+, а не обычный GDI
//
// Весь дизайн держится на скруглениях: карточки, строки, кнопка-таблетка.
// Обычный GDI рисует их без сглаживания — «лесенкой», и на тёмном фоне это
// видно особенно хорошо. GDI+ сглаживает. При этом gdiplus.dll — часть
// Windows начиная с XP, то есть внешней зависимости не появляется: это та же
// системная библиотека, что user32 и gdi32.
//
// # Ограничение, определившее набор функций
//
// В соглашении вызовов x64 вещественные аргументы на первых четырёх позициях
// передаются в регистрах XMM0–XMM3, а syscall в Go кладёт всё в целочисленные
// RCX/RDX/R8/R9. Значит, любая функция GDI+ с REAL на позиции 1–4 получила бы
// мусор вместо числа — и это не упало бы с ошибкой, а нарисовало бы ерунду.
//
// Поэтому здесь взяты только целочисленные варианты (…I) и функции, у которых
// вещественные параметры стоят пятыми и дальше: те уже передаются через стек,
// и там достаточно положить биты числа.
//
// Из этого вытекает, что перьев (GdipCreatePen1 — REAL вторым аргументом) в
// коде нет вовсе. Рамки рисуются кольцом: внешний и внутренний скруглённые
// контуры складываются в один путь, и чётно-нечётное правило заливки
// оставляет между ними полосу. Заодно это ровно та рамка, что в образце, —
// без полупрозрачных краёв.
//
// Шрифт по той же причине создаётся не через GdipCreateFont (REAL вторым
// аргументом), а из обычного LOGFONT — GdipCreateFontFromLogfontW.

import (
	"image"
	"math"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/soways11/masquevpn/internal/gui"
)

var (
	gdiplus = windows.NewLazySystemDLL("gdiplus.dll")

	procGdiplusStartup  = gdiplus.NewProc("GdiplusStartup")
	procGdiplusShutdown = gdiplus.NewProc("GdiplusShutdown")

	procGdipCreateFromHDC        = gdiplus.NewProc("GdipCreateFromHDC")
	procGdipDeleteGraphics       = gdiplus.NewProc("GdipDeleteGraphics")
	procGdipSetSmoothingMode     = gdiplus.NewProc("GdipSetSmoothingMode")
	procGdipSetTextRenderingHint = gdiplus.NewProc("GdipSetTextRenderingHint")
	procGdipSetPixelOffsetMode   = gdiplus.NewProc("GdipSetPixelOffsetMode")
	procGdipGraphicsClear        = gdiplus.NewProc("GdipGraphicsClear")
	procGdipSetClipRectI         = gdiplus.NewProc("GdipSetClipRectI")
	procGdipResetClip            = gdiplus.NewProc("GdipResetClip")

	procGdipCreateSolidFill          = gdiplus.NewProc("GdipCreateSolidFill")
	procGdipDeleteBrush              = gdiplus.NewProc("GdipDeleteBrush")
	procGdipCreateLineBrushFromRectI = gdiplus.NewProc("GdipCreateLineBrushFromRectI")

	procGdipFillRectangleI = gdiplus.NewProc("GdipFillRectangleI")
	procGdipFillEllipseI   = gdiplus.NewProc("GdipFillEllipseI")
	procGdipFillPath       = gdiplus.NewProc("GdipFillPath")

	procGdipCreatePath      = gdiplus.NewProc("GdipCreatePath")
	procGdipDeletePath      = gdiplus.NewProc("GdipDeletePath")
	procGdipAddPathArcI     = gdiplus.NewProc("GdipAddPathArcI")
	procGdipAddPathLineI    = gdiplus.NewProc("GdipAddPathLineI")
	procGdipClosePathFigure = gdiplus.NewProc("GdipClosePathFigure")
	procGdipStartPathFigure = gdiplus.NewProc("GdipStartPathFigure")

	procGdipCreateFontFromLogfontW   = gdiplus.NewProc("GdipCreateFontFromLogfontW")
	procGdipDeleteFont               = gdiplus.NewProc("GdipDeleteFont")
	procGdipDrawString               = gdiplus.NewProc("GdipDrawString")
	procGdipMeasureString            = gdiplus.NewProc("GdipMeasureString")
	procGdipCreateStringFormat       = gdiplus.NewProc("GdipCreateStringFormat")
	procGdipDeleteStringFormat       = gdiplus.NewProc("GdipDeleteStringFormat")
	procGdipSetStringFormatAlign     = gdiplus.NewProc("GdipSetStringFormatAlign")
	procGdipSetStringFormatLineAlign = gdiplus.NewProc("GdipSetStringFormatLineAlign")

	procGdipCreateBitmapFromScan0 = gdiplus.NewProc("GdipCreateBitmapFromScan0")
	procGdipDisposeImage          = gdiplus.NewProc("GdipDisposeImage")
	procGdipDrawImageRectI        = gdiplus.NewProc("GdipDrawImageRectI")
	procGdipSetInterpolationMode  = gdiplus.NewProc("GdipSetInterpolationMode")

	// Двойная буферизация — обычный GDI.
	procCreateCompatibleDC     = gdi32.NewProc("CreateCompatibleDC")
	procCreateCompatibleBitmap = gdi32.NewProc("CreateCompatibleBitmap")
	procSelectObject           = gdi32.NewProc("SelectObject")
	procBitBlt                 = gdi32.NewProc("BitBlt")
	procDeleteDC               = gdi32.NewProc("DeleteDC")
	procBeginPaint             = user32.NewProc("BeginPaint")
	procEndPaint               = user32.NewProc("EndPaint")
	procGetClientRect          = user32.NewProc("GetClientRect")
	procInvalidateRect         = user32.NewProc("InvalidateRect")
)

// Режимы GDI+.
const (
	smoothingAntiAlias = 4

	// textHintAntiAliasGridFit — сглаживание с подгонкой штрихов под сетку
	// пикселей.
	//
	// Просто AntiAlias подгонки не делает: вертикальные штрихи букв ложатся
	// между пикселями и размазываются на два — мелкий текст от этого рябит.
	// ClearType чётче всех, но раскладывает края по субпикселям, и на
	// тёмном фоне это видно цветной бахромой.
	textHintAntiAliasGridFit = 3

	pixelOffsetHalf     = 2
	fillModeAlternate   = 0
	unitPixel           = 2
	linearGradientVert  = 1
	wrapModeTileFlipXY  = 3
	stringAlignNear     = 0
	stringAlignCenter   = 1
	stringAlignFar      = 2
	stringFormatNoWrap  = 0x1000
	stringFormatNoClip  = 0x4000
	stringFormatNoFitBB = 0x00000004 // NoFitBlackBox: не подрезать по краям
	srcCopy             = 0x00CC0020
	fontStyleRegular    = 0

	// pixelFormat32bppPARGB — BGRA, предумноженный на альфу: тот же
	// порядок данных, что у image.RGBA, только R и B переставлены.
	pixelFormat32bppPARGB = 0x000E200B
	// interpolationNearest: картинка приходит уже в размер места (см.
	// gui.LogoPixels), и любая другая интерполяция её только размыла бы.
	interpolationNearest = 5
)

type gdiplusStartupInput struct {
	Version           uint32
	DebugEventCB      uintptr
	SuppressBGThread  int32
	SuppressExtCodecs int32
}

type rectF struct{ X, Y, W, H float32 }

type paintStruct struct {
	HDC         windows.Handle
	Erase       int32
	Paint       rect
	Restore     int32
	IncUpdate   int32
	RgbReserved [32]byte
}

// startGDIPlus поднимает GDI+ на всё время жизни программы.
func startGDIPlus() (uintptr, error) {
	in := gdiplusStartupInput{Version: 1}
	var token uintptr
	r, _, err := procGdiplusStartup.Call(
		uintptr(unsafe.Pointer(&token)), uintptr(unsafe.Pointer(&in)), 0)
	if r != 0 {
		return 0, err
	}
	return token, nil
}

func stopGDIPlus(token uintptr) {
	if token != 0 {
		procGdiplusShutdown.Call(token)
	}
}

// argb делает из цвета темы непрозрачный ARGB для GDI+.
func argb(c gui.Color) uintptr { return uintptr(0xFF000000 | uint32(c)) }

// f32 упаковывает вещественное число для передачи через стек.
func f32(v float64) uintptr { return uintptr(math.Float32bits(float32(v))) }

// fontKey — ключ кеша шрифтов: гарнитура плюс всё, что влияет на растр.
type fontKey struct {
	family string
	size   int32 // уже в пикселях экрана
	weight int32
}

// painter рисует окно. Живёт одну перерисовку; кеш шрифтов и кистей —
// снаружи, в resources: пересоздавать их шестьдесят раз в секунду незачем.
type painter struct {
	g     uintptr
	hdc   windows.Handle // нужен для создания шрифтов
	res   *resources
	scale float64
}

// painter обязан удовлетворять gui.Canvas: тем же кодом рисуется и окно, и
// проверочный SVG. Если интерфейс разойдётся с реализацией, это увидит
// компилятор, а не человек при запуске.
var _ gui.Canvas = (*painter)(nil)

// Scale — отношение пикселей к логическим точкам.
func (p *painter) Scale() float64 { return p.scale }

// FillPixels закрашивает прямоугольник, заданный прямо в пикселях: так
// рисуется график, которому важно не разъехаться на дробном масштабе.
func (p *painter) FillPixels(x, y, w, h int32, c gui.Color) {
	procGdipFillRectangleI.Call(p.g, p.res.brush(c),
		uintptr(x), uintptr(y), uintptr(w), uintptr(h))
}

// Quad заливает четырёхугольник по точкам в пикселях. Нужен для всего, что
// не прямоугольник и не круг: диагоналей креста, перьев стрелки, уголков.
func (p *painter) Quad(pts [4][2]int32, c gui.Color) {
	var path uintptr
	procGdipCreatePath.Call(fillModeAlternate, uintptr(unsafe.Pointer(&path)))
	if path == 0 {
		return
	}
	defer procGdipDeletePath.Call(path)
	for i := 0; i < len(pts); i++ {
		a, b := pts[i], pts[(i+1)%len(pts)]
		procGdipAddPathLineI.Call(path, uintptr(a[0]), uintptr(a[1]), uintptr(b[0]), uintptr(b[1]))
	}
	procGdipClosePathFigure.Call(path)
	procGdipFillPath.Call(p.g, p.res.brush(c), path)
}

// resources — то, что переживает перерисовку.
type resources struct {
	scale   float64
	fonts   map[fontKey]uintptr
	brushes map[gui.Color]uintptr
	images  map[*image.RGBA]gdipBitmap
	fmtNear uintptr
	fmtCent uintptr
	fmtFar  uintptr
}

func newResources(scale float64) *resources {
	r := &resources{
		scale:   scale,
		fonts:   map[fontKey]uintptr{},
		brushes: map[gui.Color]uintptr{},
		images:  map[*image.RGBA]gdipBitmap{},
	}
	mk := func(align int32) uintptr {
		var f uintptr
		procGdipCreateStringFormat.Call(
			stringFormatNoWrap|stringFormatNoClip|stringFormatNoFitBB, 0,
			uintptr(unsafe.Pointer(&f)))
		if f != 0 {
			procGdipSetStringFormatAlign.Call(f, uintptr(align))
			// По вертикали всё выравнивается по центру своего
			// прямоугольника: так строка стоит на месте, даже когда в ней
			// меняется набор букв (у «Мбит/с» и «бит/с» разные выносы).
			procGdipSetStringFormatLineAlign.Call(f, stringAlignCenter)
		}
		return f
	}
	r.fmtNear, r.fmtCent, r.fmtFar = mk(stringAlignNear), mk(stringAlignCenter), mk(stringAlignFar)
	return r
}

// release освобождает всё, что создано у GDI+. Вызывается при закрытии окна
// и при смене масштаба экрана: шрифты привязаны к масштабу.
func (r *resources) release() {
	for _, f := range r.fonts {
		procGdipDeleteFont.Call(f)
	}
	for _, b := range r.brushes {
		procGdipDeleteBrush.Call(b)
	}
	for _, f := range []uintptr{r.fmtNear, r.fmtCent, r.fmtFar} {
		if f != 0 {
			procGdipDeleteStringFormat.Call(f)
		}
	}
	for _, b := range r.images {
		procGdipDisposeImage.Call(b.h)
	}
	r.images = map[*image.RGBA]gdipBitmap{}
	r.fonts, r.brushes = map[fontKey]uintptr{}, map[gui.Color]uintptr{}
	r.fmtNear, r.fmtCent, r.fmtFar = 0, 0, 0
}

func (r *resources) brush(c gui.Color) uintptr {
	if b, ok := r.brushes[c]; ok {
		return b
	}
	var b uintptr
	procGdipCreateSolidFill.Call(argb(c), uintptr(unsafe.Pointer(&b)))
	r.brushes[c] = b
	return b
}

// font создаёт шрифт через LOGFONT: у GdipCreateFont размер идёт вторым
// аргументом и не доедет (см. заголовок файла).
func (r *resources) font(f gui.Font, hdc windows.Handle) uintptr {
	key := fontKey{f.Family(), int32(f.Size*r.scale + 0.5), int32(f.Weight)}
	if h, ok := r.fonts[key]; ok {
		return h
	}
	lf := logFont{
		Height:  -key.size, // отрицательная высота — размер по кегельной площадке
		Weight:  key.weight,
		CharSet: 204, // RUSSIAN_CHARSET: иначе кириллица может поехать
		Quality: 5,   // CLEARTYPE_QUALITY
	}
	copy(lf.FaceName[:], windows.StringToUTF16(key.family))
	var h uintptr
	procGdipCreateFontFromLogfontW.Call(uintptr(hdc),
		uintptr(unsafe.Pointer(&lf)), uintptr(unsafe.Pointer(&h)))
	r.fonts[key] = h
	return h
}

// gdipBitmap — картинка, перенесённая в GDI+.
//
// Битмап из GdipCreateBitmapFromScan0 пиксели не копирует, а ссылается на
// переданную память. Поэтому буфер хранится рядом с ним и живёт ровно
// столько же: отпусти его сборщик мусора раньше — GDI+ читал бы чужую
// память.
type gdipBitmap struct {
	h   uintptr
	buf []byte
}

// bitmap переносит картинку в GDI+ один раз на указатель. gui.LogoPixels
// отдаёт один и тот же указатель на один размер, так что на каждую
// перерисовку приходится только поиск в карте.
func (r *resources) bitmap(img *image.RGBA) uintptr {
	if b, ok := r.images[img]; ok {
		return b.h
	}
	w, h := img.Bounds().Dx(), img.Bounds().Dy()
	if w <= 0 || h <= 0 {
		return 0
	}
	buf := make([]byte, w*h*4)
	for y := 0; y < h; y++ {
		row := img.Pix[y*img.Stride : y*img.Stride+w*4]
		out := buf[y*w*4 : (y+1)*w*4]
		for i := 0; i < len(row); i += 4 {
			out[i], out[i+1], out[i+2], out[i+3] = row[i+2], row[i+1], row[i], row[i+3]
		}
	}
	var bmp uintptr
	procGdipCreateBitmapFromScan0.Call(uintptr(w), uintptr(h), uintptr(w*4),
		pixelFormat32bppPARGB, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&bmp)))
	if bmp == 0 {
		return 0
	}
	r.images[img] = gdipBitmap{h: bmp, buf: buf}
	return bmp
}

// DrawImage кладёт картинку пиксель в пиксель, с прозрачностью.
func (p *painter) DrawImage(r gui.Rect, img *image.RGBA) {
	if img == nil {
		return
	}
	bmp := p.res.bitmap(img)
	if bmp == 0 {
		return
	}
	procGdipSetInterpolationMode.Call(p.g, interpolationNearest)
	procGdipDrawImageRectI.Call(p.g, bmp, uintptr(p.Px(r.X)), uintptr(p.Px(r.Y)),
		uintptr(img.Bounds().Dx()), uintptr(img.Bounds().Dy()))
}

// px переводит логические точки в пиксели экрана.
func (p *painter) Px(v int32) int32 { return int32(float64(v)*p.scale + 0.5) }

func (p *painter) Clear(c gui.Color) { procGdipGraphicsClear.Call(p.g, argb(c)) }

// fill закрашивает прямоугольник.
func (p *painter) Fill(r gui.Rect, c gui.Color) {
	procGdipFillRectangleI.Call(p.g, p.res.brush(c),
		uintptr(p.Px(r.X)), uintptr(p.Px(r.Y)), uintptr(p.Px(r.W)), uintptr(p.Px(r.H)))
}

// dot рисует круг — индикатор состояния.
func (p *painter) Dot(r gui.Rect, c gui.Color) {
	procGdipFillEllipseI.Call(p.g, p.res.brush(c),
		uintptr(p.Px(r.X)), uintptr(p.Px(r.Y)), uintptr(p.Px(r.W)), uintptr(p.Px(r.H)))
}

// roundPath складывает скруглённый прямоугольник в путь.
func (p *painter) roundPath(path uintptr, x, y, w, h, rad int32) {
	if rad*2 > w {
		rad = w / 2
	}
	if rad*2 > h {
		rad = h / 2
	}
	d := rad * 2
	arc := func(ax, ay int32, start, sweep float64) {
		procGdipAddPathArcI.Call(path, uintptr(ax), uintptr(ay),
			uintptr(d), uintptr(d), f32(start), f32(sweep))
	}
	if rad <= 0 {
		procGdipAddPathLineI.Call(path, uintptr(x), uintptr(y), uintptr(x+w), uintptr(y))
		procGdipAddPathLineI.Call(path, uintptr(x+w), uintptr(y), uintptr(x+w), uintptr(y+h))
		procGdipAddPathLineI.Call(path, uintptr(x+w), uintptr(y+h), uintptr(x), uintptr(y+h))
		procGdipClosePathFigure.Call(path)
		return
	}
	arc(x, y, 180, 90)
	arc(x+w-d, y, 270, 90)
	arc(x+w-d, y+h-d, 0, 90)
	arc(x, y+h-d, 90, 90)
	procGdipClosePathFigure.Call(path)
}

// round заливает скруглённый прямоугольник.
func (p *painter) Round(r gui.Rect, rad int32, c gui.Color) {
	var path uintptr
	procGdipCreatePath.Call(fillModeAlternate, uintptr(unsafe.Pointer(&path)))
	if path == 0 {
		p.Fill(r, c) // без скруглений, но лучше, чем дыра в окне
		return
	}
	defer procGdipDeletePath.Call(path)
	p.roundPath(path, p.Px(r.X), p.Px(r.Y), p.Px(r.W), p.Px(r.H), p.Px(rad))
	procGdipFillPath.Call(p.g, p.res.brush(c), path)
}

// roundGradient заливает скруглённый прямоугольник вертикальным градиентом:
// карточка статуса в образце светлее сверху.
func (p *painter) RoundGradient(r gui.Rect, rad int32, top, bottom gui.Color) {
	x, y, w, h := p.Px(r.X), p.Px(r.Y), p.Px(r.W), p.Px(r.H)
	rc := rect{x, y - 1, x + w, y + h + 1} // на пиксель шире: край градиента иначе обрезается
	var brush uintptr
	procGdipCreateLineBrushFromRectI.Call(uintptr(unsafe.Pointer(&rc)),
		argb(top), argb(bottom), linearGradientVert, wrapModeTileFlipXY,
		uintptr(unsafe.Pointer(&brush)))
	if brush == 0 {
		p.Round(r, rad, top)
		return
	}
	defer procGdipDeleteBrush.Call(brush)

	var path uintptr
	procGdipCreatePath.Call(fillModeAlternate, uintptr(unsafe.Pointer(&path)))
	if path == 0 {
		return
	}
	defer procGdipDeletePath.Call(path)
	p.roundPath(path, x, y, w, h, p.Px(rad))
	procGdipFillPath.Call(p.g, brush, path)
}

// border рисует рамку толщиной w вокруг скруглённого прямоугольника.
//
// Кольцом из двух контуров в одном пути: заливка по чётно-нечётному правилу
// закрашивает то, что между ними. Перо для этого не нужно — см. заголовок.
func (p *painter) Border(r gui.Rect, rad int32, c gui.Color, w int32) {
	var path uintptr
	procGdipCreatePath.Call(fillModeAlternate, uintptr(unsafe.Pointer(&path)))
	if path == 0 {
		return
	}
	defer procGdipDeletePath.Call(path)

	t := p.Px(w)
	if t < 1 {
		t = 1
	}
	x, y, ww, hh, rr := p.Px(r.X), p.Px(r.Y), p.Px(r.W), p.Px(r.H), p.Px(rad)
	p.roundPath(path, x, y, ww, hh, rr)
	procGdipStartPathFigure.Call(path)
	p.roundPath(path, x+t, y+t, ww-2*t, hh-2*t, rr-t)
	procGdipFillPath.Call(p.g, p.res.brush(c), path)
}

func (p *painter) format(a gui.Align) uintptr {
	switch a {
	case gui.AlignCenter:
		return p.res.fmtCent
	case gui.AlignRight:
		return p.res.fmtFar
	default:
		return p.res.fmtNear
	}
}

// text рисует строку внутри прямоугольника.
//
// Разрядка (Font.Track) делается вручную, посимвольно: в GDI+ её нет, а в
// образце все мелкие заглавные подписи разрежены — без этого они выглядят
// сбитыми в кучу и на образец не похожи.
func (p *painter) Text(s string, f gui.Font, r gui.Rect, c gui.Color, a gui.Align) {
	if s == "" {
		return
	}
	if f.Upper {
		s = upper(s)
	}
	font := p.res.font(f, p.hdc)
	if font == 0 {
		return
	}
	if f.Track == 0 {
		p.drawString(s, font, r, c, p.format(a))
		return
	}

	track := p.scale * f.Track
	total := p.trackedWidth(s, font, track)
	x := float64(p.Px(r.X))
	switch a {
	case gui.AlignCenter:
		x += (float64(p.Px(r.W)) - total) / 2
	case gui.AlignRight:
		x += float64(p.Px(r.W)) - total
	}
	for _, ch := range s {
		w := p.charWidth(string(ch), font)
		box := gui.Rect{X: 0, Y: r.Y, W: 0, H: r.H}
		p.drawStringPx(string(ch), font, x, float64(p.Px(box.Y)),
			w+track, float64(p.Px(box.H)), c, p.res.fmtNear)
		x += w + track
	}
}

// trackedWidth — ширина строки с разрядкой, в пикселях.
func (p *painter) trackedWidth(s string, font uintptr, track float64) float64 {
	total := 0.0
	for _, ch := range s {
		total += p.charWidth(string(ch), font) + track
	}
	if total > 0 {
		total -= track // после последней буквы разрядки нет
	}
	return total
}

func (p *painter) charWidth(s string, font uintptr) float64 {
	u := windows.StringToUTF16(s)
	layout := rectF{0, 0, 1 << 14, 1 << 14}
	var bb rectF
	var fitted, lines int32
	procGdipMeasureString.Call(p.g,
		uintptr(unsafe.Pointer(&u[0])), uintptr(len(u)-1), font,
		uintptr(unsafe.Pointer(&layout)), p.res.fmtNear,
		uintptr(unsafe.Pointer(&bb)),
		uintptr(unsafe.Pointer(&fitted)), uintptr(unsafe.Pointer(&lines)))
	return float64(bb.W)
}

// Width измеряет строку целиком — нужно, чтобы поставить что-то рядом с ней.
func (p *painter) Width(s string, f gui.Font) float64 {
	if s == "" {
		return 0
	}
	if f.Upper {
		s = upper(s)
	}
	font := p.res.font(f, p.hdc)
	if font == 0 {
		return 0
	}
	if f.Track != 0 {
		return p.trackedWidth(s, font, p.scale*f.Track)
	}
	return p.charWidth(s, font)
}

func (p *painter) drawString(s string, font uintptr, r gui.Rect, c gui.Color, format uintptr) {
	p.drawStringPx(s, font,
		float64(p.Px(r.X)), float64(p.Px(r.Y)),
		float64(p.Px(r.W)), float64(p.Px(r.H)), c, format)
}

func (p *painter) drawStringPx(s string, font uintptr, x, y, w, h float64, c gui.Color, format uintptr) {
	u := windows.StringToUTF16(s)
	box := rectF{float32(x), float32(y), float32(w), float32(h)}
	procGdipDrawString.Call(p.g,
		uintptr(unsafe.Pointer(&u[0])), uintptr(len(u)-1), font,
		uintptr(unsafe.Pointer(&box)), format, p.res.brush(c))
}

// clip ограничивает отрисовку прямоугольником — для прокручиваемой ленты
// настроек: без этого строки рисовались бы поверх заголовка экрана.
func (p *painter) Clip(r gui.Rect) {
	procGdipSetClipRectI.Call(p.g,
		uintptr(p.Px(r.X)), uintptr(p.Px(r.Y)), uintptr(p.Px(r.W)), uintptr(p.Px(r.H)), 0)
}

func (p *painter) Unclip() { procGdipResetClip.Call(p.g) }

// upper переводит строку в заглавные. Своя, а не strings.ToUpper, — чтобы не
// тащить ради одного места пакет и чтобы поведение было предсказуемым для
// кириллицы и латиницы, которыми подписи и ограничены.
func upper(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			r -= 'a' - 'A'
		case r >= 'а' && r <= 'я':
			r -= 'а' - 'А'
		case r == 'ё':
			r = 'Ё'
		}
		out = append(out, r)
	}
	return string(out)
}
