package gui

// Проверочный холст: тот же рисунок, но в SVG.
//
// Нужен, чтобы отрисовку можно было увидеть, не запуская Windows. Файлы
// кладутся в testdata/ и открываются любым браузером — по ним видно и
// раскладку, и цвета, и состояния кнопок.
//
// Рисует его тот же код, что и окно (Paint), поэтому увиденное здесь — это
// то, что увидит человек, а не отдельная картинка «как задумано».

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type svgCanvas struct {
	b     strings.Builder
	scale float64
	w, h  int32
	clips int
}

func newSVG(w, h int32, scale float64) *svgCanvas {
	s := &svgCanvas{scale: scale, w: w, h: h}
	fmt.Fprintf(&s.b, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" `+
		`viewBox="0 0 %d %d" font-family="Segoe UI, Inter, DejaVu Sans, sans-serif">`,
		int32(float64(w)*scale), int32(float64(h)*scale),
		int32(float64(w)*scale), int32(float64(h)*scale))
	return s
}

func (s *svgCanvas) done() string { return s.b.String() + "</svg>" }

func hex(c Color) string { return fmt.Sprintf("#%06X", uint32(c)) }

func (s *svgCanvas) Px(v int32) int32 { return int32(float64(v)*s.scale + 0.5) }
func (s *svgCanvas) Scale() float64   { return s.scale }

func (s *svgCanvas) Clear(c Color) {
	fmt.Fprintf(&s.b, `<rect x="0" y="0" width="100%%" height="100%%" fill="%s"/>`, hex(c))
}

func (s *svgCanvas) Fill(r Rect, c Color) {
	s.FillPixels(s.Px(r.X), s.Px(r.Y), s.Px(r.W), s.Px(r.H), c)
}

func (s *svgCanvas) FillPixels(x, y, w, h int32, c Color) {
	fmt.Fprintf(&s.b, `<rect x="%d" y="%d" width="%d" height="%d" fill="%s"/>`, x, y, w, h, hex(c))
}

func (s *svgCanvas) Round(r Rect, radius int32, c Color) {
	fmt.Fprintf(&s.b, `<rect x="%d" y="%d" width="%d" height="%d" rx="%d" fill="%s"/>`,
		s.Px(r.X), s.Px(r.Y), s.Px(r.W), s.Px(r.H), s.Px(radius), hex(c))
}

func (s *svgCanvas) RoundGradient(r Rect, radius int32, top, bottom Color) {
	id := fmt.Sprintf("g%d", s.b.Len())
	fmt.Fprintf(&s.b, `<defs><linearGradient id="%s" x1="0" y1="0" x2="0" y2="1">`+
		`<stop offset="0" stop-color="%s"/><stop offset="1" stop-color="%s"/></linearGradient></defs>`,
		id, hex(top), hex(bottom))
	fmt.Fprintf(&s.b, `<rect x="%d" y="%d" width="%d" height="%d" rx="%d" fill="url(#%s)"/>`,
		s.Px(r.X), s.Px(r.Y), s.Px(r.W), s.Px(r.H), s.Px(radius), id)
}

func (s *svgCanvas) Border(r Rect, radius int32, c Color, w int32) {
	t := s.Px(w)
	if t < 1 {
		t = 1
	}
	// Обводка в SVG идёт по центру линии, а у нас — внутрь прямоугольника:
	// поэтому прямоугольник сжимается на половину толщины.
	fmt.Fprintf(&s.b, `<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" rx="%d" `+
		`fill="none" stroke="%s" stroke-width="%d"/>`,
		float64(s.Px(r.X))+float64(t)/2, float64(s.Px(r.Y))+float64(t)/2,
		float64(s.Px(r.W))-float64(t), float64(s.Px(r.H))-float64(t),
		s.Px(radius), hex(c), t)
}

// DrawImage вставляет картинку как data:-URI — файл остаётся самодостаточным.
func (s *svgCanvas) DrawImage(r Rect, img *image.RGBA) {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return
	}
	fmt.Fprintf(&s.b, `<image x="%d" y="%d" width="%d" height="%d" href="data:image/png;base64,%s"/>`,
		s.Px(r.X), s.Px(r.Y), s.Px(r.W), s.Px(r.H), base64.StdEncoding.EncodeToString(buf.Bytes()))
}

func (s *svgCanvas) Dot(r Rect, c Color) {
	fmt.Fprintf(&s.b, `<ellipse cx="%.1f" cy="%.1f" rx="%.1f" ry="%.1f" fill="%s"/>`,
		float64(s.Px(r.X))+float64(s.Px(r.W))/2, float64(s.Px(r.Y))+float64(s.Px(r.H))/2,
		float64(s.Px(r.W))/2, float64(s.Px(r.H))/2, hex(c))
}

func (s *svgCanvas) Quad(pts [4][2]int32, c Color) {
	var b strings.Builder
	for _, p := range pts {
		fmt.Fprintf(&b, "%d,%d ", p[0], p[1])
	}
	fmt.Fprintf(&s.b, `<polygon points="%s" fill="%s"/>`, strings.TrimSpace(b.String()), hex(c))
}

func (s *svgCanvas) Text(str string, f Font, r Rect, c Color, a Align) {
	if str == "" {
		return
	}
	if f.Upper {
		str = upperRu(str)
	}
	anchor, x := "start", s.Px(r.X)
	switch a {
	case AlignCenter:
		anchor, x = "middle", s.Px(r.X)+s.Px(r.W)/2
	case AlignRight:
		anchor, x = "end", s.Px(r.Right())
	}
	y := float64(s.Px(r.Y)) + float64(s.Px(r.H))/2
	weight := "normal"
	if f.Weight >= WeightBold {
		weight = "bold"
	} else if f.Weight >= WeightSemibold {
		weight = "600"
	}
	family := "Segoe UI, Inter, DejaVu Sans, sans-serif"
	if f.Mono {
		family = "Consolas, DejaVu Sans Mono, monospace"
	}
	fmt.Fprintf(&s.b, `<text x="%d" y="%.1f" fill="%s" font-size="%.1f" font-weight="%s" `+
		`font-family="%s" text-anchor="%s" dominant-baseline="central"`,
		x, y, hex(c), f.Size*s.scale, weight, family, anchor)
	if f.Track != 0 {
		fmt.Fprintf(&s.b, ` letter-spacing="%.2f"`, f.Track*s.scale)
	}
	fmt.Fprintf(&s.b, `>%s</text>`, escape(str))
}

// Width — приблизительная ширина: точная требует метрик шрифта, которых на
// проверочном холсте нет. Оценка нужна лишь для того, чтобы поставить
// стрелку рядом с надписью кнопки, и в SVG отличается от окна.
func (s *svgCanvas) Width(str string, f Font) float64 {
	n := float64(len([]rune(str)))
	return n*f.Size*0.55 + n*f.Track
}

func (s *svgCanvas) Clip(r Rect) {
	id := fmt.Sprintf("c%d", s.b.Len())
	fmt.Fprintf(&s.b, `<defs><clipPath id="%s"><rect x="%d" y="%d" width="%d" height="%d"/></clipPath></defs><g clip-path="url(#%s)">`,
		id, s.Px(r.X), s.Px(r.Y), s.Px(r.W), s.Px(r.H), id)
	s.clips++
}

func (s *svgCanvas) Unclip() {
	if s.clips > 0 {
		s.b.WriteString("</g>")
		s.clips--
	}
}

func escape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

// upperRu — заглавные для кириллицы и латиницы; в окне ту же работу делает
// своя функция, здесь повторена, чтобы холст ничего не знал о Windows.
func upperRu(s string) string {
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

// sampleView — состояние для картинок: подключённый туннель с трафиком.
func sampleView() View {
	m := NewMeter(graphPointsForTest)
	t0 := time.Unix(1700000000, 0)
	m.Observe(0, 0, t0)
	traffic := []uint64{120, 400, 260, 900, 640, 1500, 1100, 300, 820, 1700,
		950, 1400, 600, 2100, 1300, 700, 1800, 1000, 450, 1600,
		1200, 2000, 800, 1450, 980, 1750, 520, 1350, 1900, 1100}
	var in, out uint64
	for i, v := range traffic {
		in += v * 900
		out += v * 210
		m.Observe(in, out, t0.Add(time.Duration(i+1)*time.Second))
	}
	rin, rout := m.Rates()
	return View{
		State:      On,
		Profile:    "Основной",
		Server:     "vpn.example.com:443",
		TunAddr:    "10.7.0.4",
		BytesIn:    1331439861,
		BytesOut:   228_500_000,
		RateIn:     rin,
		RateOut:    rout,
		Bars:       m.Bars(),
		Since:      t0.Add(-4*time.Minute - 12*time.Second),
		LogLines:   []string{"14:01:55  подключение к vpn.example.com:443", "14:02:01  туннель поднят"},
		KillSwitch: true,
		FullTunnel: true,
		AllowCount: 3,
		Profiles: []ProfileItem{
			{Name: "Основной", Server: "vpn.example.com:443", Selected: true},
			{Name: "Резервный", Server: "de1.example.net:443"},
		},
	}
}

const graphPointsForTest = 30

// TestRenderScreens рисует экраны в testdata/*.svg.
//
// Это не проверка «как было — так и осталось»: сравнивать картинки побайтно
// значило бы ломать тест на каждую правку отступа. Тест следит за тем, что
// отрисовка вообще проходит целиком и не оставляет незакрытых областей
// обрезки, а файлы нужны человеку — посмотреть глазами.
func TestRenderScreens(t *testing.T) {
	dir := "testdata"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		view func() View
		hot  ItemID
		h    int32
	}{
		{"main-on", sampleView, ItemNone, MainLayout(false, 2).Height},
		{"main-off", func() View {
			v := sampleView()
			v.State, v.TunAddr, v.Since = Off, "", time.Time{}
			v.BytesIn, v.BytesOut, v.RateIn, v.RateOut = 0, 0, 0, 0
			v.Bars = NewMeter(graphPointsForTest).Bars()
			return v
		}, ItemConnect, MainLayout(false, 2).Height},
		{"main-error", func() View {
			// Как в жизни: после неудачи счётчики уже обнулены — сессии,
			// от которой их считать, не существует.
			v := sampleView()
			v.State, v.Error = Off, "соединение с сервером не установлено: время вышло"
			v.TunAddr, v.Since = "", time.Time{}
			v.BytesIn, v.BytesOut, v.RateIn, v.RateOut = 0, 0, 0, 0
			v.Bars = NewMeter(graphPointsForTest).Bars()
			return v
		}, ItemNone, MainLayout(false, 2).Height},
		{"main-log", func() View {
			v := sampleView()
			v.LogOpen = true
			v.LogLines = []string{
				"14:01:55  подключение к vpn.example.com:443",
				"14:01:56  сессия установлена  transport=h3",
				"14:02:01  туннель поднят  addr=10.7.0.4/32",
				"14:02:01  аварийное отключение включено  allow=3",
				"14:02:02  DNS уведён в туннель",
			}
			return v
		}, ItemLogToggle, MainLayout(true, 2).Height},
		{"add", func() View {
			v := sampleView()
			v.Screen = ScreenAdd
			return v
		}, ItemAddConfirm, AddLayout(false).Height},
		{"add-error", func() View {
			v := sampleView()
			v.Screen = ScreenAdd
			v.AddNotice = "Без ключа доступа сервер не пустит: его выдаёт clients add"
			v.AddFailed, v.AddBadField = true, FieldAuthKey+1
			return v
		}, ItemNone, AddLayout(false).Height},
		{"edit", func() View {
			v := sampleView()
			v.Screen, v.Editing = ScreenAdd, true
			return v
		}, ItemNone, AddLayout(true).Height},
		{"settings", func() View {
			v := sampleView()
			v.Screen = ScreenSettings
			return v
		}, ItemKillSwitch, SettingsH},
	}

	for _, c := range cases {
		s := newSVG(WinW, c.h, 2)
		Paint(s, c.view(), c.hot, ItemNone, time.Unix(1700000000, 0))
		if s.clips != 0 {
			t.Errorf("%s: осталось %d незакрытых областей обрезки — часть окна рисовалась бы обрезанной",
				c.name, s.clips)
		}
		out := filepath.Join(dir, c.name+".svg")
		if err := os.WriteFile(out, []byte(s.done()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestPaintDoesNotPanic — отрисовка переживает пустое состояние: ни профиля,
// ни сессии, ни истории. Это первое, что видит человек при первом запуске.
func TestPaintDoesNotPanic(t *testing.T) {
	for _, v := range []View{
		{},
		{Screen: ScreenSettings},
		{State: Connecting, Bars: nil, Profiles: nil},
		{Screen: ScreenSettings, Profiles: make([]ProfileItem, 40)},
	} {
		s := newSVG(WinW, SettingsH, 1)
		Paint(s, v, ItemNone, ItemNone, time.Unix(1700000000, 0))
	}
}

// TestRenderMenu рисует всплывающее меню в testdata/menu.svg — чтобы его
// вид можно было посмотреть, не запуская Windows.
func TestRenderMenu(t *testing.T) {
	items := []MenuItem{
		{Text: "Сделать выбранным"},
		{Separator: true},
		{Text: "Переименовать"},
		{Text: "Изменить"},
		{Text: "Скопировать ссылку " + LinkScheme + "://"},
		{Separator: true},
		{Text: "Удалить профиль", Danger: true},
	}
	longest := 0
	for _, it := range items {
		if n := len([]rune(it.Text)); n > longest {
			longest = n
		}
	}
	m := MenuLayout(items, int32(float64(longest)*FaceRow.Size*0.55))

	s := newSVG(m.W, m.H, 2)
	s.Clear(ColorBG)
	PaintMenu(s, items, m, 3) // подсветка на «Изменить»
	if err := os.WriteFile(filepath.Join("testdata", "menu.svg"), []byte(s.done()), 0o644); err != nil {
		t.Fatal(err)
	}
}
