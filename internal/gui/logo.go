package gui

// Логотип — черепаха на тёмно-зелёной плитке.
//
// Картинки генерирует deploy/icon/make-icons.py из deploy/icon/source.png,
// здесь они только встраиваются в программу. Две версии, потому что на
// малых размерах полная плитка превращается в зелёное пятно:
//
//   - logo-256.png — плитка целиком, как значок программы;
//   - logo-small-64.png — обрезка по черепахе: она крупнее и читается
//     даже в 16–32 пикселях.
//
// # Почему масштабирует Go, а не холст
//
// Холсту отдаётся уже готовый растр ровно в пиксельный размер места —
// Canvas.DrawImage его не тянет. Так картинка одинакова в GDI+ и в растровом
// холсте Linux: у GDI+ своя интерполяция, и вызывать её пришлось бы с
// вещественными параметрами (см. заголовок cmd/masquevpn-win/gdiplus.go).
// А ещё уменьшение Catmull-Rom заметно чище, чем билинейное у GDI+.

import (
	"bytes"
	_ "embed"
	"image"
	"image/png"
	"sync"

	xdraw "golang.org/x/image/draw"
)

var (
	//go:embed logo/logo-256.png
	logoFullPNG []byte
	//go:embed logo/logo-small-64.png
	logoSmallPNG []byte
)

// LogoSmallMax — до какого размера в пикселях берётся плотная обрезка.
// Та же граница, что у значков программы в make-icons.py (32), с запасом
// под шапку окна: знак там 32 точки, при 150% — 48 пикселей, и черепаха
// во всю плитку читается лучше мелкой в полной.
const LogoSmallMax = 48

var (
	logoOnce  sync.Once
	logoFull  image.Image
	logoSmall image.Image

	logoMu    sync.Mutex
	logoCache = map[int]*image.RGBA{}
)

func decodeLogos() {
	logoFull = mustPNG(logoFullPNG)
	logoSmall = mustPNG(logoSmallPNG)
}

func mustPNG(b []byte) image.Image {
	img, err := png.Decode(bytes.NewReader(b))
	if err != nil {
		// Встроенный файл, проверенный тестом: сюда можно попасть только
		// сборкой из испорченного исходника.
		panic("gui: логотип не читается: " + err.Error())
	}
	return img
}

// LogoPixels — логотип размером px×px пикселей, с прозрачными углами
// (premultiplied RGBA, как image.RGBA и положено).
//
// Результат кешируется по размеру и возвращается один и тот же указатель:
// оконная реализация холста по нему узнаёт, что картинку уже переносила в
// GDI+, и не делает этого на каждой перерисовке. Менять его нельзя.
func LogoPixels(px int) *image.RGBA {
	if px < 1 {
		px = 1
	}
	logoMu.Lock()
	defer logoMu.Unlock()
	if img, ok := logoCache[px]; ok {
		return img
	}
	logoOnce.Do(decodeLogos)
	src := logoFull
	if px <= LogoSmallMax {
		src = logoSmall
	}
	dst := image.NewRGBA(image.Rect(0, 0, px, px))
	xdraw.CatmullRom.Scale(dst, dst.Bounds(), src, src.Bounds(), xdraw.Src, nil)
	logoCache[px] = dst
	return dst
}

// TrayPixels — значок для области уведомлений, n×n пикселей.
//
// Состояние видно без наведения: подключены — черепаха в цвете и зелёная
// точка в правом нижнем углу; нет — черепаха серая и без точки. Одной
// точки на пёстрой картинке мало: в 16 пикселях её легко не заметить, а
// цветная и серая черепаха различаются с первого взгляда.
func TrayPixels(n int, on bool) *image.RGBA {
	src := LogoPixels(n)
	dst := image.NewRGBA(src.Bounds())
	copy(dst.Pix, src.Pix)
	if !on {
		for i := 0; i < len(dst.Pix); i += 4 {
			r, g, b := int(dst.Pix[i]), int(dst.Pix[i+1]), int(dst.Pix[i+2])
			// Яркость по Rec. 601 и приглушение: серая черепаха не должна
			// спорить с соседними значками. Премультиплицированные каналы
			// так и остаются не больше альфы — множители в сумме < 1.
			y := uint8((r*299 + g*587 + b*114) / 1000 * 3 / 4)
			dst.Pix[i], dst.Pix[i+1], dst.Pix[i+2] = y, y, y
		}
		return dst
	}
	// Точка: диаметр — треть значка, с кольцом цвета фона окна, чтобы не
	// сливалась с зелёной черепахой.
	d := float64(n) * 0.40
	ring := float64(n) / 16
	if ring < 1 {
		ring = 1
	}
	cx, cy := float64(n)-d/2, float64(n)-d/2
	disc(dst, cx, cy, d/2, ColorBG)
	disc(dst, cx, cy, d/2-ring, ColorAccent)
	return dst
}

// disc кладёт поверх картинки непрозрачный круг со сглаженным краем.
func disc(img *image.RGBA, cx, cy, r float64, c Color) {
	cr, cg, cb := c.Parts()
	b := img.Bounds()
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			dx, dy := float64(x)+0.5-cx, float64(y)+0.5-cy
			// Покрытие пикселя — по расстоянию до окружности, в пиксель
			// шириной: край без лесенки, но и без размытия.
			cov := r - sqrtf(dx*dx+dy*dy) + 0.5
			if cov <= 0 {
				continue
			}
			if cov > 1 {
				cov = 1
			}
			i := img.PixOffset(x, y)
			p := img.Pix[i : i+4 : i+4]
			blend := func(dst uint8, src uint8) uint8 { return uint8(float64(src)*cov + float64(dst)*(1-cov) + 0.5) }
			p[0], p[1], p[2], p[3] = blend(p[0], cr), blend(p[1], cg), blend(p[2], cb), blend(p[3], 255)
		}
	}
}

func sqrtf(v float64) float64 {
	if v <= 0 {
		return 0
	}
	x := v
	for i := 0; i < 30; i++ {
		x = (x + v/x) / 2
	}
	return x
}

// LogoARGB — логотип в виде, который ждёт свойство _NET_WM_ICON в X11:
// ширина, высота, затем пиксели 0xAARRGGBB без предумножения на альфу.
// Размеры идут подряд; менеджер окон сам выберет подходящий для панели
// задач и переключателя окон.
func LogoARGB(sizes ...int) []uint32 {
	var out []uint32
	for _, n := range sizes {
		img := LogoPixels(n)
		out = append(out, uint32(n), uint32(n))
		for i := 0; i < len(img.Pix); i += 4 {
			r, g, b, a := uint32(img.Pix[i]), uint32(img.Pix[i+1]), uint32(img.Pix[i+2]), uint32(img.Pix[i+3])
			if a > 0 && a < 255 {
				r, g, b = min(r*255/a, 255), min(g*255/a, 255), min(b*255/a, 255)
			}
			out = append(out, a<<24|r<<16|g<<8|b)
		}
	}
	return out
}
