package gui

import (
	"testing"
	"time"
)

// TestMeterRateFromDelta — скорость считается по разнице счётчиков и
// настоящему прошедшему времени, а не по «предполагаемой секунде».
func TestMeterRateFromDelta(t *testing.T) {
	m := NewMeter(10)
	t0 := time.Unix(1700000000, 0)
	m.Observe(0, 0, t0)
	if in, out := m.Rates(); in != 0 || out != 0 {
		t.Errorf("первый замер дал скорость %v/%v, ожидались нули", in, out)
	}

	m.Observe(1000, 500, t0.Add(time.Second))
	if in, out := m.Rates(); in != 1000 || out != 500 {
		t.Errorf("скорость %v/%v, ожидалось 1000/500", in, out)
	}

	// Таймер опоздал вдвое — скорость вдвое меньше, а не та же.
	m.Observe(3000, 1500, t0.Add(3*time.Second))
	if in, _ := m.Rates(); in != 1000 {
		t.Errorf("при двухсекундном промежутке скорость %v, ожидалась 1000", in)
	}
}

// TestMeterSameInstant — два замера в одно мгновение не должны делить на
// ноль: таймер Windows умеет срабатывать дважды подряд.
func TestMeterSameInstant(t *testing.T) {
	m := NewMeter(4)
	t0 := time.Unix(1700000000, 0)
	m.Observe(0, 0, t0)
	m.Observe(100, 100, t0.Add(time.Second))
	before, _ := m.Rates()
	m.Observe(200, 200, t0.Add(time.Second))
	after, _ := m.Rates()
	if before != after {
		t.Errorf("замер без прошедшего времени изменил скорость: %v → %v", before, after)
	}
}

// TestMeterCountersReset — переподключение обнуляет счётчики сессии; разница
// от чужой сессии дала бы всплеск на графике и ложную скорость.
func TestMeterCountersReset(t *testing.T) {
	m := NewMeter(6)
	t0 := time.Unix(1700000000, 0)
	m.Observe(10_000, 10_000, t0)
	m.Observe(20_000, 20_000, t0.Add(time.Second))
	m.Observe(100, 100, t0.Add(2*time.Second)) // сессия сменилась
	if in, out := m.Rates(); in != 0 || out != 0 {
		t.Errorf("после сброса счётчиков скорость %v/%v, ожидались нули", in, out)
	}
	// И дальше считается от новой сессии, а не от старого итога.
	m.Observe(1100, 1100, t0.Add(3*time.Second))
	if in, _ := m.Rates(); in != 1000 {
		t.Errorf("после сброса скорость %v, ожидалась 1000", in)
	}
}

// TestMeterBarsRelative — график масштабируется по собственному максимуму:
// абсолютная шкала на домашнем канале была бы полоской у нуля.
func TestMeterBarsRelative(t *testing.T) {
	m := NewMeter(4)
	t0 := time.Unix(1700000000, 0)
	m.Observe(0, 0, t0)
	for i, v := range []uint64{100, 300, 200} {
		m.Observe(v*uint64(i+1), 0, t0.Add(time.Duration(i+1)*time.Second))
	}
	bars := m.Bars()
	if len(bars) != 4 {
		t.Fatalf("столбиков %d, ожидалось 4", len(bars))
	}
	max := 0.0
	for _, b := range bars {
		if b < 0 || b > 1 {
			t.Errorf("столбик вне 0…1: %v", b)
		}
		if b > max {
			max = b
		}
	}
	if max != 1 {
		t.Errorf("наибольший столбик %v, ожидалась единица", max)
	}
	// Тишина — ровный ноль, а не деление на ноль.
	idle := NewMeter(3)
	idle.Observe(0, 0, t0)
	idle.Observe(0, 0, t0.Add(time.Second))
	for _, b := range idle.Bars() {
		if b != 0 {
			t.Errorf("при нулевом трафике столбик %v", b)
		}
	}
}

// TestMeterHistoryScrolls — история едет влево, новое приходит справа.
func TestMeterHistoryScrolls(t *testing.T) {
	m := NewMeter(3)
	t0 := time.Unix(1700000000, 0)
	m.Observe(0, 0, t0)
	m.Observe(300, 0, t0.Add(time.Second))   // 300 Б/с
	m.Observe(400, 0, t0.Add(2*time.Second)) // 100 Б/с
	bars := m.Bars()
	if bars[len(bars)-1] >= bars[len(bars)-2] {
		t.Errorf("последний замер не оказался справа: %v", bars)
	}
	m.Observe(400, 0, t0.Add(3*time.Second)) // тишина
	if bars := m.Bars(); bars[len(bars)-1] != 0 {
		t.Errorf("тишина не встала последней: %v", bars)
	}
}

func TestMeterReset(t *testing.T) {
	m := NewMeter(4)
	t0 := time.Unix(1700000000, 0)
	m.Observe(0, 0, t0)
	m.Observe(5000, 5000, t0.Add(time.Second))
	m.Reset()
	if in, out := m.Rates(); in != 0 || out != 0 {
		t.Errorf("после сброса скорость %v/%v", in, out)
	}
	for _, b := range m.Bars() {
		if b != 0 {
			t.Error("после сброса на графике остались столбики")
		}
	}
	// И первый замер после сброса снова задаёт точку отсчёта.
	m.Observe(9000, 9000, t0.Add(2*time.Second))
	if in, _ := m.Rates(); in != 0 {
		t.Errorf("первый замер после сброса дал скорость %v", in)
	}
}

// TestStateWords — надписи состояний не повторяются и не пустые: по ним
// человек понимает, закрыт ли трафик.
func TestStateWords(t *testing.T) {
	seenStatus := map[string]bool{}
	seenButton := map[string]bool{}
	for _, s := range []State{Off, Connecting, On, Stopping} {
		if s.Status() == "" || s.Button() == "" {
			t.Errorf("состояние %d без надписи", s)
		}
		if seenStatus[s.Status()] {
			t.Errorf("надпись %q повторяется у разных состояний", s.Status())
		}
		if seenButton[s.Button()] {
			t.Errorf("кнопка %q повторяется у разных состояний", s.Button())
		}
		seenStatus[s.Status()], seenButton[s.Button()] = true, true
	}
	if !Off.Accent() {
		t.Error("кнопка подключения не выделена акцентом")
	}
	if On.Accent() || Connecting.Accent() {
		t.Error("отключение и отмена выделены как обычное действие")
	}
	if On.DotColor() != ColorAccent {
		t.Error("при поднятом туннеле индикатор не зелёный")
	}
	if Off.DotColor() == On.DotColor() {
		t.Error("индикатор одинаков при подключении и без него")
	}
}

// TestViewStatusError — неудачная попытка отличается от «просто не
// подключались»: молчание после ошибки человек читает как «всё нормально».
func TestViewStatusError(t *testing.T) {
	ok := View{State: Off}
	bad := View{State: Off, Error: "сервер не отвечает"}
	if ok.StatusText() == bad.StatusText() {
		t.Error("ошибка не отличается от обычного отключённого состояния")
	}
	if bad.StatusColor() != ColorDanger {
		t.Error("ошибка не выделена цветом")
	}
	if ok.StatusColor() == ColorDanger {
		t.Error("обычное отключение покрашено как ошибка")
	}
	// Ошибка предыдущей попытки не должна светиться при новой.
	if (View{State: Connecting, Error: "старая"}).StatusColor() == ColorDanger {
		t.Error("старая ошибка красит идущее подключение")
	}
}

func TestViewSession(t *testing.T) {
	now := time.Unix(1700000000, 0)
	if d := (View{}).Session(now); d != 0 {
		t.Errorf("без сессии насчитано %v", d)
	}
	v := View{Since: now.Add(-90 * time.Second)}
	if d := v.Session(now); d != 90*time.Second {
		t.Errorf("длительность %v, ожидалось 90с", d)
	}
}
