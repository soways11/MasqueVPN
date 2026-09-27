package gui

import "testing"

// Встроенные картинки читаются, размер — ровно запрошенный, углы плитки
// прозрачные, середина непрозрачна. Последнее ловит случай, когда
// make-icons.py сохранил бы картинку без альфа-канала или наоборот
// целиком прозрачной.
func TestLogoPixels(t *testing.T) {
	for _, px := range []int{16, 32, 40, 48, 49, 64, 96} {
		img := LogoPixels(px)
		if b := img.Bounds(); b.Dx() != px || b.Dy() != px {
			t.Fatalf("%d px: размер %v", px, b)
		}
		if a := img.RGBAAt(0, 0).A; a > 16 {
			t.Errorf("%d px: угол непрозрачен (A=%d) — скругления нет", px, a)
		}
		if a := img.RGBAAt(px/2, px/2).A; a != 255 {
			t.Errorf("%d px: середина полупрозрачна (A=%d)", px, a)
		}
		if LogoPixels(px) != img {
			t.Errorf("%d px: кеш отдал другую картинку — окно перекладывало бы её в GDI+ каждый кадр", px)
		}
	}
}

// Знак в шапке не налезает на слово и не заходит в полосу заголовка.
func TestMainMark(t *testing.T) {
	m := MainLayout(false, 1)
	if overlap(m.Mark, m.Logo) {
		t.Fatalf("знак %v налезает на слово %v", m.Mark, m.Logo)
	}
	if m.Mark.Y < m.Caption.Bar.Bottom() {
		t.Fatalf("знак заходит в полосу заголовка")
	}
	if m.Mark.W != m.Mark.H {
		t.Fatalf("знак не квадратный: %v", m.Mark)
	}
}

// Значок в трее: подключены — есть зелёная точка в углу, нет — черепаха
// серая. Проверяем по пикселям, а не по коду: перепутанные ветки дали бы
// значок, который врёт о состоянии.
func TestTrayPixels(t *testing.T) {
	const n = 32
	on, off := TrayPixels(n, true), TrayPixels(n, false)
	r, g, b := ColorAccent.Parts()
	p := on.RGBAAt(n-7, n-7)
	if p.R != r || p.G != g || p.B != b || p.A != 255 {
		t.Errorf("подключены: в углу %v, а не точка цвета акцента", p)
	}
	for i := 0; i < len(off.Pix); i += 4 {
		if off.Pix[i] != off.Pix[i+1] || off.Pix[i+1] != off.Pix[i+2] {
			t.Fatalf("не подключены: цветной пиксель %v — черепаха должна быть серой", off.Pix[i:i+4])
		}
		if off.Pix[i] > off.Pix[i+3] {
			t.Fatalf("не подключены: канал больше альфы — предумножение сломано")
		}
	}
	// Исходник из кеша не испорчен: серение делается на копии.
	src, colored := LogoPixels(n), false
	for i := 0; i < len(src.Pix); i += 4 {
		if src.Pix[i] != src.Pix[i+1] {
			colored = true
			break
		}
	}
	if !colored {
		t.Fatal("TrayPixels обесцветил закешированный логотип")
	}
}

func TestLogoARGB(t *testing.T) {
	d := LogoARGB(16, 32)
	if len(d) != 2+16*16+2+32*32 {
		t.Fatalf("длина %d", len(d))
	}
	if d[0] != 16 || d[1] != 16 || d[2+256] != 32 {
		t.Fatalf("заголовки размеров не на месте: %d %d %d", d[0], d[1], d[2+256])
	}
	mid := d[2+8*16+8]
	if mid>>24 != 255 {
		t.Fatalf("середина полупрозрачна: %08x", mid)
	}
}
