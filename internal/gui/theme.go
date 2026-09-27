// Пакет gui — дизайн-система и раскладка окна клиента.
//
// # Почему отдельный пакет, а не файлы рядом с окном
//
// Всё, что здесь лежит, не зависит от Windows: цвета, размеры, раскладка,
// форматирование чисел. Значит, это можно проверить тестами на любой машине,
// а не только глазами на живой системе. Ошибки раскладки — «подпись налезла
// на цифру», «карточка вышла за окно» — как раз те, которые глазами
// замечаешь последними, а тестом ловишь сразу.
//
// В cmd/masquevpn-win остаётся только отрисовка: взять прямоугольник отсюда и
// залить его цветом отсюда же.
//
// # Откуда взялись значения
//
// Палитра снята пипеткой с образца (сайт incy), на который показал заказчик.
// Поэтому цвета заданы точными числами, а не «примерно зелёный»: между
// #42D77B и «просто зелёным» разница в том, узнаёт человек свой дизайн или
// нет. Те же числа пойдут в Android-клиент — за этим пакет и заведён.
package gui

// Имя проекта, каким его видит человек.
//
// Одно место на весь интерфейс: имя попадает в логотип, заголовок окна,
// заголовки всех диалогов и подпись внизу — разъехавшись, оно выглядит как
// две разные программы.
//
// LinkScheme здесь повторяет config.LinkScheme; тест следит, чтобы они не
// разошлись. Импортировать config ради одной строки не стоит: этот пакет
// намеренно ничего не знает об устройстве клиента.
const (
	AppName     = "masquevpn"
	AppWordmark = "MASQUEVPN"
	LinkScheme  = "masquevpn"
)

// Color — цвет в виде 0xRRGGBB. Прозрачности нет нигде: окно непрозрачно, а
// полупрозрачность в GDI поверх окна честно не рисуется.
type Color uint32

// Палитра. Названия — по роли, а не по цвету: «поверхность» переживёт смену
// оттенка, «тёмно-зелёный-2» — нет.
const (
	ColorBG        Color = 0x090F0C // фон окна
	ColorCaption   Color = 0x0D1512 // полоса заголовка: светлее фона, видна как полоса
	ColorCaptionLn Color = 0x18261F // черта под заголовком — граница полосы
	ColorSurface   Color = 0x0C1310 // карточки и строки
	ColorSurface2  Color = 0x101713 // блок цифр — на тон светлее карточек
	ColorTile      Color = 0x0A130F // плитки внутри карточки статуса
	ColorCardTop   Color = 0x0A1912 // градиент карточки статуса: верх
	ColorCardBot   Color = 0x0A120E // и низ
	ColorBorder    Color = 0x132D1E // рамка карточки, заметная
	ColorBorderDim Color = 0x16201B // рамка строк, едва видимая
	ColorAccent    Color = 0x42D77B // зелёный акцент
	ColorAccentInk Color = 0x030C07 // текст на акценте
	ColorAccentDim Color = 0x1D4630 // акцент в неактивном состоянии
	ColorText      Color = 0xF2F6F4 // основной текст
	ColorDim       Color = 0x78968F // подписи
	ColorMuted     Color = 0x4B5A53 // совсем служебное: подпись внизу окна
	ColorBar       Color = 0x2E9054 // столбики графика
	ColorBarDim    Color = 0x0B2918 // столбики за пределами истории
	ColorIdleDot   Color = 0x4A5A52 // индикатор, когда не подключены
	ColorDanger    Color = 0xE0603F // ошибка; не красный в лоб — он бы спорил
)

// Lighten осветляет цвет на долю k (0…1). Нужен для наведения мыши: заводить
// на каждое состояние отдельную константу — значит держать три палитры вместо
// одной и ловить их расхождение глазами.
func (c Color) Lighten(k float64) Color {
	r, g, b := c.Parts()
	up := func(v uint8) uint8 {
		n := float64(v) + (255-float64(v))*k
		if n > 255 {
			n = 255
		}
		return uint8(n + 0.5)
	}
	return RGB(up(r), up(g), up(b))
}

// Darken затемняет цвет на долю k (0…1) — для нажатия.
func (c Color) Darken(k float64) Color {
	r, g, b := c.Parts()
	down := func(v uint8) uint8 { return uint8(float64(v)*(1-k) + 0.5) }
	return RGB(down(r), down(g), down(b))
}

// Mix смешивает два цвета: k=0 — c, k=1 — other.
func (c Color) Mix(other Color, k float64) Color {
	r1, g1, b1 := c.Parts()
	r2, g2, b2 := other.Parts()
	m := func(a, b uint8) uint8 { return uint8(float64(a)*(1-k) + float64(b)*k + 0.5) }
	return RGB(m(r1, r2), m(g1, g2), m(b1, b2))
}

// Parts разбирает цвет на составляющие.
func (c Color) Parts() (r, g, b uint8) {
	return uint8(c >> 16), uint8(c >> 8), uint8(c)
}

// RGB собирает цвет из составляющих.
func RGB(r, g, b uint8) Color {
	return Color(uint32(r)<<16 | uint32(g)<<8 | uint32(b))
}

// Шрифты. Размер — в логических точках при 96 dpi; при отрисовке умножается
// на масштаб экрана.
//
// Гарнитура одна — системная Segoe UI: она есть на любой Windows начиная с
// Vista, и ничего скачивать не нужно. Моноширинная — Consolas, для адресов и
// журнала: в пропорциональном шрифте «10.7.0.4» пляшет при каждом обновлении
// счётчика.
const (
	FontUI   = "Segoe UI"
	FontMono = "Consolas"
)

// Начертания шрифтов в окне.
var (
	FaceTitle  = Font{Size: 16, Weight: WeightSemibold} // домен сервера
	FaceButton = Font{Size: 15, Weight: WeightSemibold} // надпись на кнопке
	FaceRow    = Font{Size: 13, Weight: WeightRegular}  // строки списков
	FaceValue  = Font{Size: 14, Weight: WeightSemibold} // числа в плитках
	FaceNumber = Font{Size: 15, Weight: WeightBold}     // крупные цифры
	FaceSmall  = Font{Size: 11, Weight: WeightRegular}  // пояснения под строками
	FaceLabel  = Font{Size: 10, Weight: WeightRegular, Track: 1.6, Upper: true}
	FaceMono   = Font{Size: 13, Weight: WeightRegular, Mono: true}
	FaceLogo   = Font{Size: 14, Weight: WeightBold, Track: 3.2}
	FaceFooter = Font{Size: 10, Weight: WeightRegular}
)

// Толщина начертания в терминах Windows.
const (
	WeightRegular  = 400
	WeightSemibold = 600
	WeightBold     = 700
)

// Font — начертание. Track — разрядка между буквами в точках: в образце все
// мелкие заглавные подписи разрежены, без этого они выглядят сбитыми в кучу.
// Upper означает, что текст рисуется заглавными: так подписи задаются в коде
// по-человечески («Сервер»), а на экране выходят «СЕРВЕР».
type Font struct {
	Size   float64
	Weight int
	Track  float64
	Upper  bool
	Mono   bool
}

// Family возвращает гарнитуру начертания.
func (f Font) Family() string {
	if f.Mono {
		return FontMono
	}
	return FontUI
}
