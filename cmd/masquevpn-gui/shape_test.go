//go:build linux

package main

import (
	"math"
	"testing"

	"github.com/soways11/masquevpn/internal/gui"
)

// Форма окна — геометрия, и проверяется как геометрия: пиксель за пикселем
// сравниваем с тем, что даёт скруглённый прямоугольник. Глазами тут видно
// только «углы вроде круглые», а ошибка на пиксель по краю выглядит как
// зазубрина, которую замечаешь последней.

// covered — попадает ли пиксель (x, y) в форму.
func covered(rects []rectSet, x, y int) bool {
	for _, r := range rects {
		if x >= r.x && x < r.x+r.w && y >= r.y && y < r.y+r.h {
			return true
		}
	}
	return false
}

type rectSet struct{ x, y, w, h int }

func shapeOf(w, h, radius int) []rectSet {
	var out []rectSet
	for _, r := range roundedRect(w, h, radius) {
		out = append(out, rectSet{int(r.X), int(r.Y), int(r.Width), int(r.Height)})
	}
	return out
}

func TestRoundedRectMatchesCircle(t *testing.T) {
	const w, h, r = 440, 556, gui.WinRadius
	rects := shapeOf(w, h, r)

	// Внутри окна, вне углов — всё закрыто.
	for _, p := range [][2]int{{w / 2, 0}, {w / 2, h - 1}, {0, h / 2}, {w - 1, h / 2}, {r, r}} {
		if !covered(rects, p[0], p[1]) {
			t.Fatalf("пиксель (%d, %d) не попал в окно — в нём будет дыра", p[0], p[1])
		}
	}
	// Сами углы срезаны.
	for _, p := range [][2]int{{0, 0}, {w - 1, 0}, {0, h - 1}, {w - 1, h - 1}} {
		if covered(rects, p[0], p[1]) {
			t.Fatalf("угловой пиксель (%d, %d) остался — окно не скруглено", p[0], p[1])
		}
	}

	// Построчное сравнение с окружностью: расхождение больше пикселя — это
	// уже видимая зазубрина.
	for y := 0; y < h; y++ {
		want := 0.0
		c := float64(y) + 0.5
		switch {
		case c < r:
			want = r - math.Sqrt(float64(r*r)-(r-c)*(r-c))
		case c > h-r:
			want = r - math.Sqrt(float64(r*r)-(c-(h-r))*(c-(h-r)))
		}
		got := 0
		for got < w && !covered(rects, got, y) {
			got++
		}
		if math.Abs(float64(got)-want) > 1 {
			t.Fatalf("строка %d: срезано %d пикселей, окружность требует %.1f", y, got, want)
		}
		// Форма симметрична: справа срезано столько же.
		right := w - 1
		for right >= 0 && !covered(rects, right, y) {
			right--
		}
		if left := got; w-1-right != left {
			t.Fatalf("строка %d: слева срезано %d, справа %d — окно кривое", y, left, w-1-right)
		}
	}
}

// Полосы не должны пересекаться и обязаны идти сверху вниз: форма
// отправляется как YXBanded, и сервер вправе рассчитывать именно на это.
func TestRoundedRectBandsAreOrdered(t *testing.T) {
	rects := roundedRect(440, 556, gui.WinRadius)
	if len(rects) < 4 {
		t.Fatalf("полос всего %d — на скругление это не похоже", len(rects))
	}
	if len(rects) > 4*gui.WinRadius+2 {
		t.Fatalf("полос %d — слишком дробно для скругления в %d пикселей", len(rects), gui.WinRadius)
	}
	prev := rects[0]
	for _, r := range rects[1:] {
		if int(r.Y) != int(prev.Y)+int(prev.Height) {
			t.Fatalf("полоса с Y=%d идёт после полосы, кончающейся на %d — полосы не подряд",
				r.Y, int(prev.Y)+int(prev.Height))
		}
		prev = r
	}
	if last := int(prev.Y) + int(prev.Height); last != 556 {
		t.Fatalf("последняя полоса кончается на %d вместо высоты окна", last)
	}
}

// Вырожденные случаи не должны давать ни паники, ни пустого окна.
func TestRoundedRectEdgeCases(t *testing.T) {
	if got := roundedRect(0, 100, 10); got != nil {
		t.Fatalf("нулевая ширина дала %d полос", len(got))
	}
	if got := roundedRect(100, 40, 0); len(got) != 1 || got[0].Width != 100 || got[0].Height != 40 {
		t.Fatalf("без скругления ожидался цельный прямоугольник, вышло %+v", got)
	}
	// Радиус больше половины окна — скругление ограничивается, окно остаётся.
	rects := shapeOf(40, 30, 100)
	if !covered(rects, 20, 15) {
		t.Fatal("при огромном радиусе от окна ничего не осталось")
	}
}
