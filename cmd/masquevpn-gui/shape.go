//go:build linux

package main

// Скруглённые углы окна.
//
// Нарисовать их нельзя: за углом окна не наш фон, а чужой экран, и вместо
// скругления получился бы тёмный квадратик. Форму окна задаёт X-сервер —
// расширение SHAPE, то же самое, чем пользуются менеджеры окон.
//
// Форма задаётся списком прямоугольников, а не битовой маской: маску пришлось
// бы рисовать в пиксельной карте запросами к серверу, а список — обычная
// геометрия, которую видно в тесте. Строк в списке порядка двух радиусов
// (около тридцати), это один короткий запрос.

import (
	"math"

	"github.com/jezek/xgb/xproto"
)

// roundedRect раскладывает прямоугольник w×h со скруглением radius в
// горизонтальные полосы. Соседние строки с одинаковым отступом слиты в одну
// полосу: иначе на каждую строку окна приходился бы свой прямоугольник.
//
// radius <= 0 или слишком большой для такого окна — вернётся цельный
// прямоугольник или скругление в половину меньшей стороны: окно без углов
// лучше, чем окно с заведомо кривыми углами.
func roundedRect(w, h, radius int) []xproto.Rectangle {
	if w <= 0 || h <= 0 {
		return nil
	}
	if radius <= 0 {
		return []xproto.Rectangle{{X: 0, Y: 0, Width: uint16(w), Height: uint16(h)}}
	}
	if max := min(w, h) / 2; radius > max {
		radius = max
	}

	var out []xproto.Rectangle
	inset := func(y int) int {
		// Центр пикселя — y+0.5; центры скругляющих окружностей стоят на
		// radius от краёв.
		c := float64(y) + 0.5
		var dy float64
		switch {
		case c < float64(radius):
			dy = float64(radius) - c
		case c > float64(h-radius):
			dy = c - float64(h-radius)
		default:
			return 0
		}
		dx := float64(radius) - math.Sqrt(math.Max(0, float64(radius*radius)-dy*dy))
		return int(math.Round(dx))
	}

	start, cur := 0, inset(0)
	flush := func(end int) {
		if cur*2 >= w {
			return // строка целиком срезана
		}
		out = append(out, xproto.Rectangle{
			X: int16(cur), Y: int16(start),
			Width: uint16(w - 2*cur), Height: uint16(end - start),
		})
	}
	for y := 1; y < h; y++ {
		if in := inset(y); in != cur {
			flush(y)
			start, cur = y, in
		}
	}
	flush(h)
	return out
}
