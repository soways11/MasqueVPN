package gui

import "time"

// State — состояние клиента, каким его видит человек.
type State int

const (
	Off State = iota
	Connecting
	On
	Stopping
)

// Status — надпись в карточке. Слова выбраны так, чтобы отвечать на вопрос
// «закрыт ли мой трафик прямо сейчас», а не описывать внутреннее устройство:
// «сессия установлена» человеку ничего не говорит.
func (s State) Status() string {
	switch s {
	case Connecting:
		return "Подключение"
	case On:
		return "Соединение защищено"
	case Stopping:
		return "Отключение"
	default:
		return "Нет подключения"
	}
}

// Button — надпись на главной кнопке.
func (s State) Button() string {
	switch s {
	case Connecting:
		return "Отмена"
	case On:
		return "Отключить"
	case Stopping:
		return "Отключение…"
	default:
		return "Подключиться"
	}
}

// Accent сообщает, рисовать ли кнопку залитой. Залита она только там, где
// нажатие — обычное дело: подключиться. Отмена и отключение — действия
// с последствиями, их кнопка обведённая, чтобы не нажимались случайно.
func (s State) Accent() bool { return s == Off }

// DotColor — цвет индикатора рядом со статусом.
func (s State) DotColor() Color {
	switch s {
	case On:
		return ColorAccent
	case Connecting, Stopping:
		return ColorAccent.Mix(ColorIdleDot, 0.45)
	default:
		return ColorIdleDot
	}
}

// View — всё, что нужно для отрисовки окна. Собирается в потоке окна из
// состояния приложения; отрисовка ничего не знает ни о движке, ни о
// блокировках.
type View struct {
	Screen Screen
	State  State

	// Error — короткое человеческое объяснение, почему не подключились.
	// Пусто, когда всё в порядке.
	Error string

	Profile string // имя выбранного профиля
	Server  string // «домен:порт» как в конфигурации
	TunAddr string // адрес, выданный сервером

	BytesIn  uint64
	BytesOut uint64
	RateIn   float64 // байт/с
	RateOut  float64
	Bars     []float64 // история, 0…1
	Since    time.Time // когда подняли туннель; нулевое время — не подняли

	LogOpen  bool
	LogLines []string

	// Настройки, какими их видно на втором экране.
	KillSwitch bool
	AllowCount int
	FullTunnel bool
	Autostart  bool
	Profiles   []ProfileItem
	ScrollY    int32

	// AddNotice — что показать под формой добавления: подсказка о формате
	// или причина, по которой вставленное не подошло.
	AddNotice string
	AddFailed bool
	// AddBadField — номер поля с ошибкой, считая с единицы; ноль означает,
	// что ошибка не привязана к полю (или её нет).
	AddBadField int
	// Editing — экран открыт для правки существующего профиля.
	Editing bool
}

// Screen — какой из экранов показан.
type Screen int

const (
	ScreenMain Screen = iota
	ScreenSettings
	ScreenAdd
)

// ProfileItem — строка в списке профилей.
type ProfileItem struct {
	Name     string
	Server   string
	Selected bool
}

// Session возвращает длительность сессии на момент now.
func (v View) Session(now time.Time) time.Duration {
	if v.Since.IsZero() {
		return 0
	}
	return now.Sub(v.Since)
}

// StatusColor — цвет надписи о состоянии. Ошибка окрашивается отдельно:
// «Нет подключения» после неудачной попытки и «нет подключения, потому что мы
// его и не начинали» — разные вещи.
func (v View) StatusColor() Color {
	if v.State == Off && v.Error != "" {
		return ColorDanger
	}
	if v.State == On {
		return ColorAccent
	}
	return ColorDim
}

// StatusText — надпись о состоянии с учётом ошибки.
func (v View) StatusText() string {
	if v.State == Off && v.Error != "" {
		return "Не подключилось"
	}
	return v.State.Status()
}
