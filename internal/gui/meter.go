package gui

import "time"

// Meter — счётчик скорости и история для графика.
//
// Движок отдаёт только нарастающие итоги (сколько всего байт прошло), а в
// окне нужна скорость. Разница берётся по времени между опросами, а не по
// «раз в секунду опрашиваем — значит делим на единицу»: таймер Windows не
// обещает точного периода, и при подвисшем окне скорость показалась бы
// выше настоящей.
type Meter struct {
	hist  []float64 // байт/с, от старых к новым
	inB   uint64
	outB  uint64
	at    time.Time
	start bool

	rateIn  float64
	rateOut float64
}

// NewMeter заводит счётчик с историей на n отсчётов.
func NewMeter(n int) *Meter {
	if n < 1 {
		n = 1
	}
	return &Meter{hist: make([]float64, n)}
}

// Observe принимает нарастающие итоги на момент at.
func (m *Meter) Observe(in, out uint64, at time.Time) {
	defer func() {
		m.inB, m.outB, m.at, m.start = in, out, at, true
	}()

	// Первый замер задаёт точку отсчёта: скорости за «нулевое время» не
	// бывает, а поделить на неё — получить бесконечность на экране.
	if !m.start {
		return
	}
	dt := at.Sub(m.at).Seconds()
	if dt <= 0 {
		return
	}
	// Счётчики уехали назад — значит сессия сменилась (переподключение).
	// Считать разницу от чужой сессии нельзя: вышел бы всплеск на графике.
	if in < m.inB || out < m.outB {
		m.rateIn, m.rateOut = 0, 0
		m.push(0)
		return
	}
	m.rateIn = float64(in-m.inB) / dt
	m.rateOut = float64(out-m.outB) / dt
	m.push(m.rateIn + m.rateOut)
}

func (m *Meter) push(v float64) {
	copy(m.hist, m.hist[1:])
	m.hist[len(m.hist)-1] = v
}

// Rates возвращает последнюю измеренную скорость, байт/с.
func (m *Meter) Rates() (in, out float64) { return m.rateIn, m.rateOut }

// Bars возвращает историю, приведённую к 0…1 по собственному максимуму.
//
// Масштаб относительный, а не абсолютный: канал у всех разный, и график,
// привязанный к гигабиту, на домашнем интернете всегда был бы полоской у
// нуля. Относительный показывает форму нагрузки — а именно её и смотрят.
func (m *Meter) Bars() []float64 {
	out := make([]float64, len(m.hist))
	max := 0.0
	for _, v := range m.hist {
		if v > max {
			max = v
		}
	}
	if max <= 0 {
		return out
	}
	for i, v := range m.hist {
		out[i] = v / max
	}
	return out
}

// Reset забывает всё: новая сессия — новый график.
func (m *Meter) Reset() {
	for i := range m.hist {
		m.hist[i] = 0
	}
	m.inB, m.outB, m.start = 0, 0, false
	m.rateIn, m.rateOut = 0, 0
}
