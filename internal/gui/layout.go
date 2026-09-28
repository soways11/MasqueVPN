package gui

// Раскладка окна: где что лежит.
//
// Все числа — в логических точках при 96 dpi. Умножение на масштаб экрана
// происходит при отрисовке, один раз; здесь масштаба нет вовсе, иначе он
// расползётся по сотне выражений и в каждом можно будет ошибиться.
//
// Раскладка считается заново на каждую перерисовку. Это дешевле, чем кажется
// (полсотни сложений), и снимает целый класс ошибок: нет состояния, которое
// можно забыть обновить при смене размера, числа профилей или экрана.

// Rect — прямоугольник: левый верхний угол, ширина, высота.
type Rect struct{ X, Y, W, H int32 }

// Right и Bottom — правая и нижняя границы (за последним пикселем).
func (r Rect) Right() int32  { return r.X + r.W }
func (r Rect) Bottom() int32 { return r.Y + r.H }

// Contains сообщает, попадает ли точка внутрь.
func (r Rect) Contains(x, y int32) bool {
	return x >= r.X && x < r.Right() && y >= r.Y && y < r.Bottom()
}

// Empty — прямоугольник без площади: так обозначается элемент, которого на
// этом экране нет (свёрнутый журнал, например).
func (r Rect) Empty() bool { return r.W <= 0 || r.H <= 0 }

// Inset сжимает прямоугольник со всех сторон.
func (r Rect) Inset(d int32) Rect {
	return Rect{r.X + d, r.Y + d, r.W - 2*d, r.H - 2*d}
}

// Размеры окна и основные отступы.
//
// Высота окна одна на все экраны и сама не меняется: раньше окно
// подстраивалось под экран (настройки выше подключения, раскрытый журнал
// удлинял его, каждый профиль добавлял строку), и прыгающее под рукой окно
// раздражало сильнее, чем пустое место. Теперь высоту меняет только сам
// человек — потянув нижний край; раскладки получают её параметром и
// раскладывают содержимое в неё, а длинное (профили, журнал, настройки)
// прокручивают или обрезают.
const (
	WinW = 440 // ширина окна; не меняется — клиент не растягивают вширь

	// DefaultWinH — высота окна, пока человек её не менял.
	DefaultWinH = 640
	// MinWinH — ниже окно не сжимается: на этой высоте ещё целиком
	// помещается самый длинный из неподвижных экранов — правка профиля.
	MinWinH = 600
	// MaxWinH — выше тянуть незачем: столько не займёт ни один экран, а
	// окно во весь монитор из клиента VPN делает что-то другое.
	MaxWinH = 1400

	CaptionH = 34 // своя полоса заголовка: системная светлая и спорит с темой
	PadX     = 24 // поля слева и справа
	Radius   = 14 // скругление карточек
	RadiusSm = 12 // скругление строк

	// WinRadius — скругление самого окна. Режется системой (область окна в
	// Windows, расширение SHAPE в X11), а не рисуется: нарисовать угол
	// поверх фона нельзя — за окном чужой экран, а не наш цвет.
	//
	// Больше скругления карточек: угол окна крупнее, и одинаковый радиус
	// рядом с карточкой у края смотрится как ошибка.
	WinRadius = 16
	RowH      = 52 // высота строки списка
	RowGap    = 8

	// footerZone — место под подписью внизу каждого экрана.
	footerZone = 24 + 14 + 16
)

// ClampHeight приводит высоту окна к допустимой: ноль и мусор из файла
// настроек — к умолчанию, остальное — в пределы MinWinH…MaxWinH.
func ClampHeight(h int32) int32 {
	switch {
	case h <= 0:
		return DefaultWinH
	case h < MinWinH:
		return MinWinH
	case h > MaxWinH:
		return MaxWinH
	}
	return h
}

// FooterRect — подпись внизу окна высоты h.
func FooterRect(h int32) Rect { return Rect{PadX, h - 30, ContentW, 14} }

// ResizeEdge — полоса у нижнего края, за которую тянут окно.
const ResizeEdge = 6

// OnResizeEdge сообщает, стоит ли точка (в логических точках) на нижней
// кромке окна высоты h — там, где окно растягивают.
func OnResizeEdge(y, h int32) bool { return y >= h-ResizeEdge && y < h }

// ContentW — ширина содержимого между полями.
const ContentW = WinW - 2*PadX

// LogoMark — сторона знака-черепахи в шапке главного экрана (и на Android).
const LogoMark = 32

// ItemID — то, по чему можно щёлкнуть. Раскладка возвращает их вместе с
// прямоугольниками, а окно только сопоставляет попадание с действием: так
// «где нарисовано» и «куда нажали» не могут разойтись.
type ItemID int

const (
	ItemNone ItemID = iota
	ItemClose
	ItemMinimize
	ItemSettings // шестерёнка
	ItemBack     // назад из настроек, журнала и добавления
	ItemConnect  // главная кнопка
	ItemLog      // строка «Журнал» на главном экране: открыть журнал
	ItemLogCopy  // «Копировать» на экране журнала
	ItemKillSwitch
	ItemAllowEdit // исключения аварийного отключения
	ItemAutostart
	ItemAddProfile
	ItemShowQR
	ItemPasteLink // вставить из буфера в поле ввода
	ItemAddConfirm
	ItemDeleteProfile

	// ItemProfileBase — начало диапазона профилей: ItemProfileBase+i выбирает
	// i-й профиль, ItemProfileMenuBase+i открывает его меню.
	ItemProfileBase     ItemID = 1000
	ItemProfileMenuBase ItemID = 2000
)

// ProfileIndex разбирает идентификатор профиля обратно в номер.
func ProfileIndex(id ItemID) (int, bool) {
	if id >= ItemProfileBase && id < ItemProfileBase+1000 {
		return int(id - ItemProfileBase), true
	}
	return 0, false
}

// ProfileMenuIndex — то же для кнопки меню профиля.
func ProfileMenuIndex(id ItemID) (int, bool) {
	if id >= ItemProfileMenuBase && id < ItemProfileMenuBase+1000 {
		return int(id - ItemProfileMenuBase), true
	}
	return 0, false
}

// Hit — область, отзывающаяся на мышь.
type Hit struct {
	ID   ItemID
	Rect Rect
}

// Caption — общая для обоих экранов полоса заголовка.
type Caption struct {
	Bar Rect
	// Line — черта по нижнему краю полосы. Без неё заголовок сливался с
	// окном: одного оттенка мало, чтобы глаз увидел границу.
	Line     Rect
	Minimize Rect
	Close    Rect
	// Drag — область, за которую окно таскают. Кнопки из неё вычтены: иначе
	// нажатие на «закрыть» превращалось бы в перетаскивание.
	Drag Rect
}

func captionLayout() Caption {
	const btnW, btnH, btnTop, edge = 36, 26, 4, 6
	close := Rect{WinW - edge - btnW, btnTop, btnW, btnH}
	minim := Rect{close.X - btnW, btnTop, btnW, btnH}
	return Caption{
		Bar:      Rect{0, 0, WinW, CaptionH},
		Line:     Rect{0, CaptionH - 1, WinW, 1},
		Minimize: minim,
		Close:    close,
		Drag:     Rect{0, 0, minim.X, CaptionH},
	}
}

// Main — раскладка экрана подключения.
//
// Порядок сверху вниз: состояние, кнопка, скорости, счётчики, профили,
// журнал. Кнопка стоит вторым сверху не из-за красоты — это единственное,
// ради чего окно открывают, и искать её под сводкой странно.
//
// Карточки с сервером, адресом в туннеле и графиком здесь больше нет.
// График показывал форму нагрузки, но рядом с двумя цифрами скоростей он
// говорил то же самое дважды; адрес в туннеле нужен раз в месяц и остался
// в журнале, а сервер виден в списке профилей — там, где его и выбирают.
type Main struct {
	Caption Caption
	Height  int32 // высота окна, для которой посчитана раскладка

	Mark Rect // черепаха — знак программы
	Logo Rect // слово MASQUEVPN
	Plus Rect // добавить сервер
	Gear Rect

	StatusDot  Rect
	StatusText Rect
	Session    Rect // время сессии, прижато вправо

	Button Rect

	TileDown Rect
	TileUp   Rect

	Stats     Rect
	StatCells [3]Rect

	SectProfiles Rect
	Profiles     []Rect
	ProfileMenus []Rect // кнопка «…» в строке профиля
	MoreProfiles Rect   // «ещё N — в настройках»; пусто, когда влезли все

	LogRow Rect // строка «Журнал»: открывает экран журнала

	Footer Rect
}

// MainLayout считает раскладку экрана подключения для n профилей в окне
// высоты h.
//
// Строка журнала прижата к низу, профили занимают место между цифрами и ею
// — сколько влезет. Не влезшие остаются в настройках, где список
// прокручивается, а здесь о них напоминает строка «ещё N — в настройках».
// Окно ради них больше не растёт.
func MainLayout(n int, h int32) Main {
	var m Main
	h = ClampHeight(h)
	m.Height = h
	m.Caption = captionLayout()

	const headY, headH = 48, 40
	m.Gear = Rect{WinW - PadX - 30, headY + (headH-30)/2, 30, 30}
	// «Плюс» слева от шестерёнки: добавление сервера — то, с чего начинают,
	// и искать его в настройках человек не обязан.
	m.Plus = Rect{m.Gear.X - 8 - 30, m.Gear.Y, 30, 30}
	// Знак — та же черепаха, что на значке программы: окно узнаётся как
	// «то самое» с панели задач. Слово идёт следом и тянется до «плюса».
	m.Mark = Rect{PadX, headY + (headH-LogoMark)/2, LogoMark, LogoMark}
	m.Logo = Rect{m.Mark.Right() + 10, headY, 0, headH}
	m.Logo.W = m.Plus.X - 12 - m.Logo.X

	m.StatusDot = Rect{PadX, 105, 6, 6}
	m.StatusText = Rect{m.StatusDot.Right() + 8, 100, 240, 14}
	m.Session = Rect{PadX + ContentW - 80, 100, 80, 14}

	m.Button = Rect{PadX, 126, ContentW, 48}

	const tileH, tileGap int32 = 54, 10
	tileW := (ContentW - tileGap) / 2
	tileY := m.Button.Bottom() + 16
	m.TileDown = Rect{PadX, tileY, tileW, tileH}
	m.TileUp = Rect{PadX + tileW + tileGap, tileY, ContentW - tileW - tileGap, tileH}

	m.Stats = Rect{PadX, m.TileDown.Bottom() + 12, ContentW, 62}
	cellW := m.Stats.W / 3
	for i := range m.StatCells {
		w := cellW
		if i == 2 { // последней достаётся остаток: 392/3 не делится нацело
			w = m.Stats.W - 2*cellW
		}
		m.StatCells[i] = Rect{m.Stats.X + int32(i)*cellW, m.Stats.Y, w, m.Stats.H}
	}

	y := m.Stats.Bottom() + 18
	m.SectProfiles = Rect{PadX, y, ContentW, 14}
	y += 14 + 10

	m.LogRow = Rect{PadX, h - footerZone - 52, ContentW, 52}
	room := m.LogRow.Y - 8 - y // место под строки профилей
	fit := int(room / (RowH + RowGap))
	shown := min(n, fit)
	if shown < n {
		// Не влезли все — нужна строка «ещё N», и под неё уходит место.
		shown = max(int((room-20-RowGap)/(RowH+RowGap)), 0)
	}
	m.Profiles = make([]Rect, shown)
	m.ProfileMenus = make([]Rect, shown)
	for i := 0; i < shown; i++ {
		m.Profiles[i] = Rect{PadX, y, ContentW, RowH}
		// Кнопка меню лежит внутри строки, у правого края: у неё своё
		// действие, поэтому и своя область попадания.
		m.ProfileMenus[i] = Rect{PadX + ContentW - 44, y + (RowH-30)/2, 36, 30}
		y += RowH + RowGap
	}
	if n > shown {
		m.MoreProfiles = Rect{PadX, y, ContentW, 20}
	}
	m.Footer = FooterRect(h)
	return m
}

// Hits перечисляет области экрана, отзывающиеся на мышь. Порядок важен:
// первое совпадение выигрывает, поэтому мелкие кнопки идут раньше крупных
// областей, внутри которых лежат.
func (m Main) Hits() []Hit {
	hits := []Hit{
		{ItemClose, m.Caption.Close},
		{ItemMinimize, m.Caption.Minimize},
		{ItemSettings, m.Gear},
		{ItemAddProfile, m.Plus},
		{ItemConnect, m.Button},
	}
	// Кнопки меню идут раньше строк: они лежат внутри, и первое совпадение
	// выигрывает — иначе «…» выбирало бы профиль вместо открытия меню.
	for i, r := range m.ProfileMenus {
		hits = append(hits, Hit{ItemProfileMenuBase + ItemID(i), r})
	}
	// Профиль выбирается нажатием на строку — это главное, ради чего
	// список вынесен на первый экран.
	for i, r := range m.Profiles {
		hits = append(hits, Hit{ItemProfileBase + ItemID(i), r})
	}
	if !m.MoreProfiles.Empty() {
		hits = append(hits, Hit{ItemSettings, m.MoreProfiles})
	}
	return append(hits, Hit{ItemLog, m.LogRow})
}

// Log — раскладка экрана журнала.
//
// Журнал — отдельный экран, а не раскрывающийся под профилями блок: в блок
// помещалось десять строк, а окно при раскрытии вырастало вдвое. Здесь он
// занимает всё окно, прокручивается колесом и копируется одной кнопкой —
// именно это с ним и делают, когда что-то не работает.
type Log struct {
	Caption Caption
	Back    Rect
	Title   Rect
	Copy    Rect
	Box     Rect // рамка со строками
	Footer  Rect
}

// LogLineH — высота строки журнала.
const LogLineH = 17

// LogLayout считает раскладку журнала в окне высоты h.
func LogLayout(h int32) Log {
	var l Log
	h = ClampHeight(h)
	l.Caption = captionLayout()
	const headY, headH = 48, 40
	l.Back = Rect{PadX, headY + (headH-30)/2, 30, 30}
	l.Title = Rect{l.Back.Right() + 12, headY, 160, headH}
	l.Copy = Rect{PadX + ContentW - 120, headY + (headH-32)/2, 120, 32}
	l.Box = Rect{PadX, 100, ContentW, h - footerZone - 100 + 8}
	l.Footer = FooterRect(h)
	return l
}

// Hits перечисляет области экрана журнала.
func (l Log) Hits() []Hit {
	return []Hit{
		{ItemClose, l.Caption.Close},
		{ItemMinimize, l.Caption.Minimize},
		{ItemBack, l.Back},
		{ItemLogCopy, l.Copy},
	}
}

// Rows — сколько строк журнала помещается в рамку.
func (l Log) Rows() int { return max(int((l.Box.H-24)/LogLineH), 0) }

// LogWindow выбирает, какие строки журнала показать: хвост, сдвинутый на
// scroll строк вверх. Возвращает показанные строки, номер первой из них и
// всего строк после переноса; scroll приводится к допустимому.
//
// Прокрутка считается от конца, а не от начала: журнал читают снизу, и
// новая запись, пришедшая, пока человек смотрит в самый низ, должна
// появиться сразу, а не ждать, пока он докрутит.
//
// chars — сколько знаков помещается в строку (см. LogChars); ноль —
// расчётное значение для экрана без измерений.
func LogWindow(lines []string, rows, chars int, scroll int32) (shown []string, first, total int, clamped int32) {
	if chars <= 0 {
		chars = maxLogLineChars
	}
	wrapped := WrapLog(lines, chars)
	total = len(wrapped)
	maxScroll := int32(max(total-rows, 0))
	clamped = min(max(scroll, 0), maxScroll)
	end := total - int(clamped)
	first = max(end-rows, 0)
	return wrapped[first:end], first, total, clamped
}

// Settings — раскладка экрана настроек.
//
// Число профилей заранее неизвестно, поэтому высота содержимого плавает и
// экран прокручивается. Прокрутку считает окно; здесь всё выкладывается в
// одну ленту от нуля, а смещение применяется при отрисовке.
type Settings struct {
	Caption Caption
	Back    Rect
	Title   Rect

	// Viewport — окно просмотра, внутри которого лента прокручивается.
	Viewport  Rect
	ContentH  int32 // полная высота ленты
	SectGuard Rect  // заголовок «Защита» и далее — в координатах ленты

	KillSwitch Rect
	Allow      Rect

	SectProfiles Rect
	Profiles     []Rect
	ProfileMenus []Rect
	AddProfile   Rect

	SectSystem Rect
	Autostart  Rect

	Footer Rect
}

// SettingsLayout считает раскладку настроек для n профилей в окне высоты h.
func SettingsLayout(n int, h int32) Settings {
	var s Settings
	h = ClampHeight(h)
	s.Caption = captionLayout()

	const headY, headH = 48, 40
	s.Back = Rect{PadX, headY + (headH-30)/2, 30, 30}
	s.Title = Rect{s.Back.Right() + 12, headY, 240, headH}

	s.Viewport = Rect{0, 96, WinW, h - 96 - 30}

	y := int32(0)
	sect := func(at *Rect) {
		*at = Rect{PadX, y, ContentW, 14}
		y += 14 + 10
	}
	row := func(at *Rect) {
		*at = Rect{PadX, y, ContentW, RowH}
		y += RowH + RowGap
	}

	sect(&s.SectGuard)
	row(&s.KillSwitch)
	row(&s.Allow)
	y += 12

	sect(&s.SectProfiles)
	s.Profiles = make([]Rect, n)
	s.ProfileMenus = make([]Rect, n)
	for i := 0; i < n; i++ {
		row(&s.Profiles[i])
		// Кнопка меню лежит внутри строки, у правого края: у неё своё
		// действие, поэтому и своя область попадания.
		r := s.Profiles[i]
		s.ProfileMenus[i] = Rect{r.Right() - 44, r.Y + (r.H-30)/2, 36, 30}
	}
	row(&s.AddProfile)
	y += 12

	sect(&s.SectSystem)
	row(&s.Autostart)

	s.ContentH = y
	s.Footer = FooterRect(h)
	return s
}

// Hits перечисляет области настроек. Координаты строк — в ленте; смещение
// прокрутки вычитается вызывающим, чтобы раскладка не знала о прокрутке.
func (s Settings) Hits() []Hit {
	hits := []Hit{
		{ItemClose, s.Caption.Close},
		{ItemMinimize, s.Caption.Minimize},
		{ItemBack, s.Back},
	}
	return hits
}

// ScrollHits — области внутри прокручиваемой ленты, уже сдвинутые на offset и
// обрезанные окном просмотра: то, что уехало за край, нажиматься не должно.
func (s Settings) ScrollHits(offset int32) []Hit {
	var hits []Hit
	add := func(id ItemID, r Rect) {
		if r.Empty() {
			return
		}
		r.Y = r.Y + s.Viewport.Y - offset
		if r.Bottom() <= s.Viewport.Y || r.Y >= s.Viewport.Bottom() {
			return
		}
		hits = append(hits, Hit{id, r})
	}
	for i := range s.ProfileMenus { // раньше строк: лежат внутри них
		add(ItemProfileMenuBase+ItemID(i), s.ProfileMenus[i])
	}
	for i := range s.Profiles {
		add(ItemProfileBase+ItemID(i), s.Profiles[i])
	}
	add(ItemKillSwitch, s.KillSwitch)
	add(ItemAllowEdit, s.Allow)
	add(ItemAddProfile, s.AddProfile)
	add(ItemAutostart, s.Autostart)
	return hits
}

// MaxScroll — насколько лента может уехать вверх. Ноль означает, что
// содержимое помещается целиком и прокручивать нечего.
func (s Settings) MaxScroll() int32 {
	if s.ContentH <= s.Viewport.H {
		return 0
	}
	return s.ContentH - s.Viewport.H
}

// Toggle — прямоугольник переключателя у правого края строки.
func Toggle(row Rect) Rect {
	const w, h = 38, 21
	return Rect{row.Right() - 15 - w, row.Y + (row.H-h)/2, w, h}
}

// Add — раскладка экрана добавления сервера.
//
// Три поля — ровно те, что выдаёт сервер: адрес, ключ и идентификатор.
// Ничего больше вводить не нужно, остальное клиент подставляет умолчаниями
// (см. claude/stage1-clients.md).
//
// Поля здесь не рисуются: под каждое оставлено место для настоящего
// системного элемента ввода. Нарисовать его вручную значило бы написать
// маленький текстовый редактор, и первая же попытка вставить ключ показала
// бы, чего он не умеет.
type Add struct {
	Caption Caption
	Back    Rect
	Title   Rect

	// Fields — подписи и рамки полей, сверху вниз. При добавлении их три,
	// при правке добавляется четвёртое — имя профиля.
	Fields []AddField

	// Edit — правим существующий профиль, а не заводим новый.
	Editing bool

	Paste   Rect
	Confirm Rect
	Delete  Rect // «Удалить профиль»; пусто при добавлении
	Notice  Rect
	Footer  Rect

	Height int32 // высота окна, для которой посчитана раскладка
	// ContentBottom — где кончается содержимое; окно ниже этого плюс
	// подпись сжимать нельзя (см. MinWinH).
	ContentBottom int32
}

// AddField — одно поле формы: подпись над рамкой и сама рамка.
type AddField struct {
	Label Rect
	Box   Rect
}

// AddFieldIndex — какое поле в Fields за что отвечает.
const (
	FieldServer = iota
	FieldAuthKey
	FieldClientID
	// FieldName — имя профиля. Идёт последним и необязательно: пустое
	// означает «назвать по домену сервера».
	FieldName

	// MaxAddFields — сколько полей бывает на экране максимум.
	MaxAddFields = FieldName + 1
)

// AddFieldTitles — подписи полей. Здесь же, чтобы окно и тесты брали их из
// одного места, а не повторяли строки.
var AddFieldTitles = [MaxAddFields]string{
	"Адрес сервера",
	"Ключ доступа",
	"Идентификатор клиента",
	"Имя профиля",
}

// EditInset — отступ настоящего поля ввода внутри нарисованной рамки.
const EditInset = 12

// AddLayout считает раскладку экрана добавления или правки в окне высоты h.
//
// Содержимое неподвижно и от высоты не зависит — под ним стоят настоящие
// поля ввода, двигать которые при каждом изменении окна незачем; от высоты
// зависит только подпись внизу. Раскладка плотная: правка профиля (четыре
// поля и кнопка удаления) обязана поместиться в MinWinH.
func AddLayout(editing bool, h int32) Add {
	var a Add
	h = ClampHeight(h)
	a.Caption = captionLayout()
	a.Editing = editing

	const headY, headH = 48, 40
	a.Back = Rect{PadX, headY + (headH-30)/2, 30, 30}
	a.Title = Rect{a.Back.Right() + 12, headY, 260, headH}

	a.Fields = make([]AddField, MaxAddFields)

	y := int32(96)
	for i := range a.Fields {
		a.Fields[i].Label = Rect{PadX, y, ContentW, 14}
		a.Fields[i].Box = Rect{PadX, y + 20, ContentW, 42}
		y = a.Fields[i].Box.Bottom() + 14
	}

	a.Paste = Rect{PadX, y + 2, 210, 40}
	// Удаление живёт на экране правки, а не только в меню: правка и
	// удаление — действия над одним и тем же профилем, и искать второе в
	// другом месте незачем. Кнопка обычная, а не опасно-красная: спросит
	// подтверждение она сама. Стоит в одном ряду со вставкой — так правка
	// помещается в окно наименьшей высоты.
	if editing {
		a.Delete = Rect{a.Paste.Right() + 12, a.Paste.Y, ContentW - a.Paste.W - 12, 40}
	}
	a.Confirm = Rect{PadX, a.Paste.Bottom() + 14, ContentW, 48}
	a.Notice = Rect{PadX, a.Confirm.Bottom() + 12, ContentW, 32}
	a.ContentBottom = a.Notice.Bottom()
	a.Height = h
	a.Footer = FooterRect(h)
	return a
}

// Edit возвращает прямоугольник самого поля ввода внутри рамки.
func (a Add) Edit(box Rect) Rect { return box.Inset(EditInset) }

// Hits перечисляет области экрана добавления.
func (a Add) Hits() []Hit {
	hits := []Hit{
		{ItemClose, a.Caption.Close},
		{ItemMinimize, a.Caption.Minimize},
		{ItemBack, a.Back},
		{ItemPasteLink, a.Paste},
		{ItemAddConfirm, a.Confirm},
	}
	if !a.Delete.Empty() {
		hits = append(hits, Hit{ItemDeleteProfile, a.Delete})
	}
	return hits
}

// ---------- всплывающее меню ----------

// MenuItem — пункт меню. Пустой Text означает разделитель.
type MenuItem struct {
	ID        ItemID
	Text      string
	Danger    bool // действие, которое не отменить: удаление
	Separator bool
}

// Menu — раскладка всплывающего меню.
//
// Меню рисуется своим окном, а не системным: стандартное всегда светлое и
// посреди тёмного интерфейса выглядит чужим. Цена — вся его механика
// (наведение, выбор, закрытие по щелчку мимо) написана вручную.
type Menu struct {
	W, H  int32
	Items []Rect // прямоугольники пунктов; у разделителей нулевая высота
}

// Метрики меню.
const (
	MenuItemH    = 34
	MenuSepH     = 9
	MenuPadV     = 6  // поля сверху и снизу
	MenuPadX     = 14 // отступ текста от края
	MenuMinW     = 180
	MenuMaxW     = 320
	MenuRadius   = 10
	MenuSepInset = 10 // насколько разделитель уже меню
	MenuSlack    = 8  // запас ширины поверх измеренного текста
)

// MenuLayout считает раскладку меню. textW — ширина самой длинной надписи
// в логических точках; её измеряет тот, кто умеет мерить шрифт.
func MenuLayout(items []MenuItem, textW int32) Menu {
	// Запас поверх измеренного текста: измерение идёт по шрифту экрана, а
	// рисуется тем же шрифтом с разрядкой ноль — расхождение в пару точек
	// обрезало бы последний знак самого длинного пункта.
	m := Menu{W: textW + 2*MenuPadX + MenuSlack, Items: make([]Rect, len(items))}
	if m.W < MenuMinW {
		m.W = MenuMinW
	}
	if m.W > MenuMaxW {
		m.W = MenuMaxW
	}

	y := int32(MenuPadV)
	for i, it := range items {
		if it.Separator || it.Text == "" {
			m.Items[i] = Rect{0, y, m.W, 0} // высота ноль: нажимать нечего
			y += MenuSepH
			continue
		}
		m.Items[i] = Rect{0, y, m.W, MenuItemH}
		y += MenuItemH
	}
	m.H = y + MenuPadV
	return m
}

// Hit ищет пункт под точкой. Возвращает -1, если там разделитель или поле.
func (m Menu) Hit(x, y int32) int {
	for i, r := range m.Items {
		if r.H > 0 && y >= r.Y && y < r.Bottom() && x >= 0 && x < m.W {
			return i
		}
	}
	return -1
}
