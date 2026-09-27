package gui

import (
	"testing"
	"time"
)

func TestBytes(t *testing.T) {
	cases := []struct {
		in   uint64
		want string
	}{
		{0, "0 Б"},
		{512, "512 Б"},
		{1024, "1,0 КБ"},
		{1536, "1,5 КБ"},
		{10 * 1024, "10 КБ"}, // с десяти десятые — шум
		{1024 * 1024, "1,0 МБ"},
		{1331439861, "1,2 ГБ"},
		{5 << 40, "5,0 ТБ"},
	}
	for _, c := range cases {
		if got := Bytes(c.in); got != c.want {
			t.Errorf("Bytes(%d) = %q, ожидалось %q", c.in, got, c.want)
		}
	}
}

// TestRateIsBits — скорость показывается в битах: канал меряют так, и путать
// мегабайты с мегабитами — ошибка ровно в восемь раз.
func TestRateIsBits(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{0, "0 бит/с"},
		{100, "800 бит/с"},
		{1000, "8,0 Кбит/с"},
		{125000, "1,0 Мбит/с"}, // 1 Мбит/с — это 125 КБ/с
		{3037500, "24 Мбит/с"}, // 24,3 Мбит/с → с десяти без десятых
		{1250000000, "10 Гбит/с"},
	}
	for _, c := range cases {
		if got := Rate(c.in); got != c.want {
			t.Errorf("Rate(%v) = %q, ожидалось %q", c.in, got, c.want)
		}
	}
	if Rate(125000) == Bytes(125000) {
		t.Error("скорость и объём форматируются одинаково")
	}
}

// TestDecimalComma — разделитель запятая: окно русское, «1.2 ГБ» в нём
// выглядит как недоперевод.
func TestDecimalComma(t *testing.T) {
	for _, s := range []string{Bytes(1536), Rate(1000)} {
		if !containsRune(s, ',') {
			t.Errorf("%q: десятичный разделитель не запятая", s)
		}
		if containsRune(s, '.') {
			t.Errorf("%q: осталась точка", s)
		}
	}
}

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}

func TestDuration(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{0, "00:00"},
		{-time.Second, "00:00"}, // часы на машине могли шагнуть назад
		{42 * time.Second, "00:42"},
		{4*time.Minute + 12*time.Second, "04:12"},
		{time.Hour + 2*time.Minute + 33*time.Second, "1:02:33"},
		{25 * time.Hour, "25:00:00"}, // сутки не обнуляют счётчик сессии
	}
	for _, c := range cases {
		if got := Duration(c.in); got != c.want {
			t.Errorf("Duration(%v) = %q, ожидалось %q", c.in, got, c.want)
		}
	}
}

func TestHost(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "—"},
		{"vpn.example.com:443", "vpn.example.com"},
		{"vpn.example.com", "vpn.example.com"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"2001:db8::1", "2001:db8::1"}, // без порта — трогать нечего
	}
	for _, c := range cases {
		if got := Host(c.in); got != c.want {
			t.Errorf("Host(%q) = %q, ожидалось %q", c.in, got, c.want)
		}
	}
}

func TestEllipsis(t *testing.T) {
	if got := Ellipsis("очень-длинное-имя-профиля", 10); got != "очень-дли…" {
		t.Errorf("Ellipsis = %q", got)
	}
	if got := Ellipsis("коротко", 10); got != "коротко" {
		t.Errorf("короткая строка изменилась: %q", got)
	}
	// Считаем в символах, а не в байтах: в кириллице байт вдвое больше.
	if n := len([]rune(Ellipsis("аааааааааааааааааа", 8))); n != 8 {
		t.Errorf("обрезано до %d символов вместо 8", n)
	}
}

// TestColorMath — осветление и затемнение не выходят за границы байта и
// двигают цвет в нужную сторону: на них держатся состояния наведения.
func TestColorMath(t *testing.T) {
	c := ColorAccent
	if c.Lighten(1) != RGB(255, 255, 255) {
		t.Errorf("полное осветление дало %06X", uint32(c.Lighten(1)))
	}
	if c.Darken(1) != 0 {
		t.Errorf("полное затемнение дало %06X", uint32(c.Darken(1)))
	}
	if c.Lighten(0) != c || c.Darken(0) != c {
		t.Error("нулевое изменение поменяло цвет")
	}
	r1, g1, b1 := c.Lighten(0.2).Parts()
	r0, g0, b0 := c.Parts()
	if r1 < r0 || g1 < g0 || b1 < b0 {
		t.Error("осветление затемнило цвет")
	}
	if got := ColorBG.Mix(ColorText, 1); got != ColorText {
		t.Errorf("смешение с коэффициентом 1 дало %06X", uint32(got))
	}
}
