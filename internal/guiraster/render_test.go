package guiraster

import (
	"image/png"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/soways11/masquevpn/internal/gui"
)

// sampleView — состояние для картинок: подключённый туннель с трафиком.
func sampleView() gui.View {
	m := gui.NewMeter(30)
	t0 := time.Unix(1700000000, 0)
	m.Observe(0, 0, t0)
	var in, out uint64
	for i, v := range []uint64{120, 400, 260, 900, 640, 1500, 1100, 300, 820, 1700} {
		in += v * 900
		out += v * 210
		m.Observe(in, out, t0.Add(time.Duration(i+1)*time.Second))
	}
	rin, rout := m.Rates()
	return gui.View{
		State:      gui.On,
		Profile:    "Основной",
		Server:     "nl.example.net:8443",
		TunAddr:    "10.66.0.4",
		BytesIn:    1331439861,
		BytesOut:   228_500_000,
		RateIn:     rin,
		RateOut:    rout,
		Bars:       m.Bars(),
		Since:      t0.Add(-4*time.Minute - 12*time.Second),
		LogLines:   []string{"22:01:55  подключение к nl.example.net:8443", "22:02:01  туннель поднят"},
		KillSwitch: true,
		AllowCount: 3,
		Profiles: []gui.ProfileItem{
			{Name: "Основной", Server: "nl.example.net:8443", Selected: true},
			{Name: "Резервный", Server: "de1.example.net:443"},
		},
	}
}

// TestRenderPNG рисует экраны в настоящие пиксели.
//
// Это не сравнение с эталоном — оно ломалось бы на каждой правке отступа.
// Тест следит, что отрисовка проходит целиком и на холсте вообще что-то
// появилось, а файлы нужны человеку: открыть и посмотреть, совпадает ли
// вид с окном Windows.
func TestRenderPNG(t *testing.T) {
	fonts, err := LoadFonts()
	if err != nil {
		t.Skip("шрифтов в системе нет:", err)
	}
	defer fonts.Close()

	dir := "testdata"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		view func() gui.View
		h    int32
	}{
		{"main-on", sampleView, gui.DefaultWinH},
		{"main-off", func() gui.View {
			v := sampleView()
			v.State, v.TunAddr, v.Since = gui.Off, "", time.Time{}
			v.BytesIn, v.BytesOut, v.RateIn, v.RateOut = 0, 0, 0, 0
			return v
		}, gui.DefaultWinH},
		{"settings", func() gui.View {
			v := sampleView()
			v.Screen = gui.ScreenSettings
			return v
		}, gui.DefaultWinH},
		{"add", func() gui.View {
			v := sampleView()
			v.Screen = gui.ScreenAdd
			return v
		}, gui.DefaultWinH},
		{"edit-min", func() gui.View {
			v := sampleView()
			v.Screen, v.Editing = gui.ScreenAdd, true
			return v
		}, gui.MinWinH},
		{"log", func() gui.View {
			v := sampleView()
			v.Screen = gui.ScreenLog
			for i := 0; i < 60; i++ {
				v.LogLines = append(v.LogLines, "22:03:1"+string(rune('0'+i%10))+"  переподключение  attempt="+string(rune('0'+i%10))+"  err=порт 443 не отвечает: закрыт по пути или сервер выключен")
			}
			return v
		}, gui.DefaultWinH},
		{"main-many", func() gui.View {
			v := sampleView()
			for i := 0; i < 5; i++ {
				v.Profiles = append(v.Profiles, gui.ProfileItem{Name: "Запасной", Server: "x.example.net:2053"})
			}
			return v
		}, gui.DefaultWinH},
	}

	for _, c := range cases {
		cv := New(gui.WinW, c.h, 2, fonts)
		v := c.view()
		v.Height = c.h
		gui.Paint(cv, v, gui.ItemNone, gui.ItemNone, time.Unix(1700000000, 0))

		img := cv.Image()
		if img.Bounds().Dx() == 0 || img.Bounds().Dy() == 0 {
			t.Fatalf("%s: пустой растр", c.name)
		}
		// Хоть один пиксель должен отличаться от фона — иначе «нарисовали»
		// означало бы «залили одним цветом».
		bg := img.RGBAAt(1, 1)
		different := false
		for y := 0; y < img.Bounds().Dy() && !different; y += 3 {
			for x := 0; x < img.Bounds().Dx(); x += 3 {
				if img.RGBAAt(x, y) != bg {
					different = true
					break
				}
			}
		}
		if !different {
			t.Errorf("%s: на холсте один сплошной цвет", c.name)
		}

		f, err := os.Create(filepath.Join(dir, c.name+".png"))
		if err != nil {
			t.Fatal(err)
		}
		if err := png.Encode(f, img); err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
}
