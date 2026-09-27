// Пакет guiraster — растровая реализация gui.Canvas.
//
// # Зачем
//
// Окно Windows рисует GDI+. На Linux такого нет: ни одной системной
// библиотеки, которая умела бы сглаженные скругления и текст, не потребовав
// при этом cgo и заголовков от GTK или Qt. Поэтому здесь свой растеризатор:
// рисунок собирается в обычный image.RGBA, а система получает уже готовый
// снимок — её дело только показать его на экране.
//
// Такой холст не привязан ни к X11, ни к чему-либо ещё, и это главное его
// свойство: тот же код рисует окно, проверочные картинки в тестах и
// когда-нибудь — экран Android. Проверять его можно здесь же, сравнивая
// PNG с тем, что рисует оконная реализация.
//
// # Что под капотом
//
// Контуры растеризует golang.org/x/image/vector — тот же растеризатор, что
// в стандартном рендере шрифтов Go: сглаживание по покрытию пикселя, без
// сторонних зависимостей с cgo. Текст рисуется через opentype-шрифт,
// найденный в системе; разрядка (Font.Track) делается по глифам, как и в
// GDI+, потому что ни один шрифтовый движок её не предоставляет.
package guiraster

import (
	"image"
	"image/color"
	"image/draw"
	"math"

	"golang.org/x/image/font"
	"golang.org/x/image/math/fixed"
	"golang.org/x/image/vector"

	"github.com/soways11/masquevpn/internal/gui"
)

// Canvas рисует интерфейс в растр.
type Canvas struct {
	img   *image.RGBA
	scale float64
	fonts *FontSet

	// clip — текущее ограничение отрисовки в пикселях. Пустой прямоугольник
	// означает «без ограничения»: клип задаётся редко, и хранить отдельный
	// флаг незачем.
	clip image.Rectangle
}

// New заводит холст размером w×h логических точек с заданным масштабом.
func New(w, h int32, scale float64, fonts *FontSet) *Canvas {
	pw := int(float64(w)*scale + 0.5)
	ph := int(float64(h)*scale + 0.5)
	return &Canvas{
		img:   image.NewRGBA(image.Rect(0, 0, pw, ph)),
		scale: scale,
		fonts: fonts,
	}
}

// Image возвращает готовый растр — его и показывает окно.
func (c *Canvas) Image() *image.RGBA { return c.img }

// Bounds — размер растра в пикселях.
func (c *Canvas) Bounds() image.Rectangle { return c.img.Bounds() }

var _ gui.Canvas = (*Canvas)(nil)

func (c *Canvas) Px(v int32) int32 { return int32(float64(v)*c.scale + 0.5) }
func (c *Canvas) Scale() float64   { return c.scale }
func (c *Canvas) Clip(r gui.Rect)  { c.clip = c.rectPx(r) }
func (c *Canvas) Unclip()          { c.clip = image.Rectangle{} }

// rectPx переводит прямоугольник из логических точек в пиксели.
func (c *Canvas) rectPx(r gui.Rect) image.Rectangle {
	return image.Rect(int(c.Px(r.X)), int(c.Px(r.Y)), int(c.Px(r.Right())), int(c.Px(r.Bottom())))
}

// target — куда рисовать с учётом ограничения.
func (c *Canvas) target() *image.RGBA {
	if c.clip.Empty() {
		return c.img
	}
	sub := c.img.SubImage(c.clip.Intersect(c.img.Bounds()))
	if s, ok := sub.(*image.RGBA); ok {
		return s
	}
	return c.img
}

func rgba(v gui.Color) color.RGBA {
	r, g, b := v.Parts()
	return color.RGBA{R: r, G: g, B: b, A: 255}
}

func (c *Canvas) Clear(v gui.Color) {
	draw.Draw(c.img, c.img.Bounds(), &image.Uniform{rgba(v)}, image.Point{}, draw.Src)
}

func (c *Canvas) Fill(r gui.Rect, v gui.Color) {
	c.FillPixels(c.Px(r.X), c.Px(r.Y), c.Px(r.W), c.Px(r.H), v)
}

func (c *Canvas) FillPixels(x, y, w, h int32, v gui.Color) {
	if w <= 0 || h <= 0 {
		return
	}
	rect := image.Rect(int(x), int(y), int(x+w), int(y+h))
	dst := c.target()
	draw.Draw(dst, rect.Intersect(dst.Bounds()), &image.Uniform{rgba(v)}, image.Point{}, draw.Src)
}

// Round заливает скруглённый прямоугольник.
func (c *Canvas) Round(r gui.Rect, radius int32, v gui.Color) {
	c.fillPath(func(ras *vector.Rasterizer, ox, oy float32) {
		roundRectPath(ras, ox, oy, float32(c.Px(r.X)), float32(c.Px(r.Y)),
			float32(c.Px(r.W)), float32(c.Px(r.H)), float32(c.Px(radius)), false)
	}, &image.Uniform{rgba(v)}, c.rectPx(r))
}

// RoundGradient заливает его вертикальным градиентом.
func (c *Canvas) RoundGradient(r gui.Rect, radius int32, top, bottom gui.Color) {
	box := c.rectPx(r)
	src := &verticalGradient{rect: box, top: rgba(top), bottom: rgba(bottom)}
	c.fillPath(func(ras *vector.Rasterizer, ox, oy float32) {
		roundRectPath(ras, ox, oy, float32(box.Min.X), float32(box.Min.Y),
			float32(box.Dx()), float32(box.Dy()), float32(c.Px(radius)), false)
	}, src, box)
}

// Border рисует рамку толщиной w внутрь прямоугольника.
//
// Кольцом из двух контуров: внешний по часовой стрелке, внутренний против.
// Растеризатор считает по правилу ненулевого обхода, и встречные направления
// гасят друг друга — закрашенной остаётся полоса между ними. Тот же приём,
// что и в оконной реализации, только там его навязывало отсутствие пера.
func (c *Canvas) Border(r gui.Rect, radius int32, v gui.Color, w int32) {
	t := c.Px(w)
	if t < 1 {
		t = 1
	}
	box := c.rectPx(r)
	rad := float32(c.Px(radius))
	c.fillPath(func(ras *vector.Rasterizer, ox, oy float32) {
		roundRectPath(ras, ox, oy, float32(box.Min.X), float32(box.Min.Y),
			float32(box.Dx()), float32(box.Dy()), rad, false)
		roundRectPath(ras, ox, oy, float32(box.Min.X+int(t)), float32(box.Min.Y+int(t)),
			float32(box.Dx()-2*int(t)), float32(box.Dy()-2*int(t)), rad-float32(t), true)
	}, &image.Uniform{rgba(v)}, box)
}

// DrawImage кладёт готовую картинку пиксель в пиксель, смешивая по
// прозрачности: углы плитки логотипа прозрачные.
func (c *Canvas) DrawImage(r gui.Rect, img *image.RGBA) {
	if img == nil {
		return
	}
	dst := c.target()
	at := image.Pt(int(c.Px(r.X)), int(c.Px(r.Y)))
	rect := img.Bounds().Sub(img.Bounds().Min).Add(at).Intersect(dst.Bounds())
	draw.Draw(dst, rect, img, img.Bounds().Min.Add(rect.Min.Sub(at)), draw.Over)
}

// Dot рисует эллипс по описанному прямоугольнику.
func (c *Canvas) Dot(r gui.Rect, v gui.Color) {
	box := c.rectPx(r)
	c.fillPath(func(ras *vector.Rasterizer, ox, oy float32) {
		ellipsePath(ras, ox, oy, box)
	}, &image.Uniform{rgba(v)}, box)
}

// Quad заливает четырёхугольник по точкам в пикселях.
func (c *Canvas) Quad(pts [4][2]int32, v gui.Color) {
	minX, minY := pts[0][0], pts[0][1]
	maxX, maxY := minX, minY
	for _, p := range pts[1:] {
		minX, minY = min32(minX, p[0]), min32(minY, p[1])
		maxX, maxY = max32(maxX, p[0]), max32(maxY, p[1])
	}
	box := image.Rect(int(minX), int(minY), int(maxX)+1, int(maxY)+1)
	c.fillPath(func(ras *vector.Rasterizer, ox, oy float32) {
		ras.MoveTo(float32(pts[0][0])-ox, float32(pts[0][1])-oy)
		for _, p := range pts[1:] {
			ras.LineTo(float32(p[0])-ox, float32(p[1])-oy)
		}
		ras.ClosePath()
	}, &image.Uniform{rgba(v)}, box)
}

// fillPath растеризует контур и кладёт его на холст.
//
// Растеризатор работает в своей системе координат, начиная с нуля, поэтому
// контур строится со смещением на левый верхний угол области — иначе для
// элемента у нижнего края окна пришлось бы заводить растр во весь экран.
func (c *Canvas) fillPath(build func(ras *vector.Rasterizer, ox, oy float32), src image.Image, box image.Rectangle) {
	dst := c.target()
	box = box.Inset(-2) // запас под сглаженный край
	box = box.Intersect(dst.Bounds())
	if box.Empty() {
		return
	}
	ras := vector.NewRasterizer(box.Dx(), box.Dy())
	build(ras, float32(box.Min.X), float32(box.Min.Y))
	ras.Draw(dst, box, src, box.Min)
}

// roundRectPath добавляет в контур скруглённый прямоугольник.
//
// reverse разворачивает обход: так строится внутренний контур кольца.
func roundRectPath(ras *vector.Rasterizer, ox, oy, x, y, w, h, rad float32, reverse bool) {
	if w <= 0 || h <= 0 {
		return
	}
	if rad < 0 {
		rad = 0
	}
	if rad > w/2 {
		rad = w / 2
	}
	if rad > h/2 {
		rad = h / 2
	}
	x, y = x-ox, y-oy

	// Приближение четверти окружности кубической кривой: коэффициент
	// 0.5523 — известная константа, ошибка меньше тысячной радиуса.
	const k = 0.5523
	c := rad * k

	if !reverse {
		ras.MoveTo(x+rad, y)
		ras.LineTo(x+w-rad, y)
		ras.CubeTo(x+w-rad+c, y, x+w, y+rad-c, x+w, y+rad)
		ras.LineTo(x+w, y+h-rad)
		ras.CubeTo(x+w, y+h-rad+c, x+w-rad+c, y+h, x+w-rad, y+h)
		ras.LineTo(x+rad, y+h)
		ras.CubeTo(x+rad-c, y+h, x, y+h-rad+c, x, y+h-rad)
		ras.LineTo(x, y+rad)
		ras.CubeTo(x, y+rad-c, x+rad-c, y, x+rad, y)
		ras.ClosePath()
		return
	}
	ras.MoveTo(x+rad, y)
	ras.CubeTo(x+rad-c, y, x, y+rad-c, x, y+rad)
	ras.LineTo(x, y+h-rad)
	ras.CubeTo(x, y+h-rad+c, x+rad-c, y+h, x+rad, y+h)
	ras.LineTo(x+w-rad, y+h)
	ras.CubeTo(x+w-rad+c, y+h, x+w, y+h-rad+c, x+w, y+h-rad)
	ras.LineTo(x+w, y+rad)
	ras.CubeTo(x+w, y+rad-c, x+w-rad+c, y, x+w-rad, y)
	ras.ClosePath()
}

func ellipsePath(ras *vector.Rasterizer, ox, oy float32, box image.Rectangle) {
	x, y := float32(box.Min.X)-ox, float32(box.Min.Y)-oy
	w, h := float32(box.Dx()), float32(box.Dy())
	rx, ry := w/2, h/2
	cx, cy := x+rx, y+ry
	const k = 0.5523
	ras.MoveTo(cx, y)
	ras.CubeTo(cx+rx*k, y, x+w, cy-ry*k, x+w, cy)
	ras.CubeTo(x+w, cy+ry*k, cx+rx*k, y+h, cx, y+h)
	ras.CubeTo(cx-rx*k, y+h, x, cy+ry*k, x, cy)
	ras.CubeTo(x, cy-ry*k, cx-rx*k, y, cx, y)
	ras.ClosePath()
}

// verticalGradient — источник для градиентной заливки.
type verticalGradient struct {
	rect        image.Rectangle
	top, bottom color.RGBA
}

func (g *verticalGradient) ColorModel() color.Model { return color.RGBAModel }
func (g *verticalGradient) Bounds() image.Rectangle { return g.rect }

func (g *verticalGradient) At(_, y int) color.Color {
	h := g.rect.Dy()
	if h <= 1 {
		return g.top
	}
	t := float64(y-g.rect.Min.Y) / float64(h-1)
	if t < 0 {
		t = 0
	} else if t > 1 {
		t = 1
	}
	mix := func(a, b uint8) uint8 { return uint8(float64(a)*(1-t) + float64(b)*t + 0.5) }
	return color.RGBA{
		R: mix(g.top.R, g.bottom.R),
		G: mix(g.top.G, g.bottom.G),
		B: mix(g.top.B, g.bottom.B),
		A: 255,
	}
}

// Text рисует строку внутри прямоугольника, по вертикали — посередине.
func (c *Canvas) Text(s string, f gui.Font, r gui.Rect, v gui.Color, a gui.Align) {
	if s == "" || c.fonts == nil {
		return
	}
	if f.Upper {
		s = gui.Upper(s)
	}
	face := c.fonts.Face(f, c.scale)
	if face == nil {
		return
	}
	track := fixed.Int26_6(f.Track * c.scale * 64)
	width := measure(face, s, track)

	box := c.rectPx(r)
	x := fixed.I(box.Min.X)
	switch a {
	case gui.AlignCenter:
		x = fixed.I(box.Min.X) + (fixed.I(box.Dx())-width)/2
	case gui.AlignRight:
		x = fixed.I(box.Max.X) - width
	}

	// По вертикали — по середине прямоугольника, считая от высоты прописных
	// букв: выравнивание по базовой линии заставляло бы каждую подпись
	// подбирать отступ руками.
	m := face.Metrics()
	y := fixed.I(box.Min.Y) + (fixed.I(box.Dy())+m.CapHeight)/2

	dst := c.target()
	src := &image.Uniform{rgba(v)}
	prev := rune(-1)
	for _, ch := range s {
		if prev >= 0 {
			x += face.Kern(prev, ch) + track
		}
		dr, mask, maskp, advance, ok := face.Glyph(fixed.Point26_6{X: x, Y: y}, ch)
		if !ok {
			prev = ch
			continue
		}
		draw.DrawMask(dst, dr.Intersect(dst.Bounds()), src, image.Point{}, mask, maskp, draw.Over)
		x += advance
		prev = ch
	}
}

// Width измеряет строку в логических точках.
func (c *Canvas) Width(s string, f gui.Font) float64 {
	if s == "" || c.fonts == nil {
		return 0
	}
	if f.Upper {
		s = gui.Upper(s)
	}
	face := c.fonts.Face(f, c.scale)
	if face == nil {
		return 0
	}
	w := measure(face, s, fixed.Int26_6(f.Track*c.scale*64))
	return float64(w) / 64 / c.scale
}

// measure считает ширину строки с разрядкой.
func measure(face font.Face, s string, track fixed.Int26_6) fixed.Int26_6 {
	var w fixed.Int26_6
	prev := rune(-1)
	for _, ch := range s {
		if prev >= 0 {
			w += face.Kern(prev, ch) + track
		}
		adv, ok := face.GlyphAdvance(ch)
		if !ok {
			prev = ch
			continue
		}
		w += adv
		prev = ch
	}
	return w
}

func min32(a, b int32) int32 {
	if a < b {
		return a
	}
	return b
}

func max32(a, b int32) int32 {
	if a > b {
		return a
	}
	return b
}

// round округляет к ближайшему целому — нужен в паре мест, где считать
// через math.Round дороже читается.
func round(v float64) int { return int(math.Floor(v + 0.5)) }
