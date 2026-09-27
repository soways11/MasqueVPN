package obfuscation

import (
	"math"
	"testing"
	"time"

	"github.com/soways11/masquevpn/internal/masque"
)

func TestPaddingBuckets(t *testing.T) {
	sh := New(Config{Buckets: []int{1350, 128, 512}}) // намеренно не по порядку
	cases := map[int]int{
		0:    128,
		1:    128,
		128:  128,
		129:  512,
		512:  512,
		513:  1350,
		1350: 1350,
		1400: 1400, // больше максимального ведра — не паддится
	}
	for in, want := range cases {
		if got := sh.Pad(in); got != want {
			t.Errorf("Pad(%d)=%d, want %d", in, got, want)
		}
	}
}

// TestPaddingHidesSizes: реальные размеры пакетов разнообразны, а после паддинга
// на выходе остаётся лишь несколько значений — это и есть измеримый эффект.
func TestPaddingHidesSizes(t *testing.T) {
	sh := New(Config{Buckets: []int{128, 512, 1024, 1350}})
	out := map[int]struct{}{}
	for n := 20; n <= 1350; n++ {
		out[sh.Pad(n)] = struct{}{}
	}
	if len(out) != 4 {
		t.Fatalf("после паддинга %d уникальных размеров, ожидалось 4", len(out))
	}
	for size := range out {
		found := false
		for _, b := range []int{128, 512, 1024, 1350} {
			if b == size {
				found = true
			}
		}
		if !found {
			t.Errorf("выходной размер %d не совпадает ни с одним ведром", size)
		}
	}
}

func TestJitterBoundsAndSelectivity(t *testing.T) {
	const jmax = 5 * time.Millisecond
	seq := []float64{0, 0.25, 0.5, 0.999}
	i := 0
	rng := rngFunc{
		float64:  func() float64 { v := seq[i%len(seq)]; i++; return v },
		intn:     func(n int) int { return 0 },
		expFloat: func() float64 { return 1 },
	}
	sh := New(Config{JitterMax: jmax, JitterMaxPacketLen: 100}, withRNG(rng))

	// Крупный пакет — без джиттера.
	if d := sh.Delay(200); d != 0 {
		t.Fatalf("крупный пакет получил джиттер %v", d)
	}
	// Мелкие — в пределах [0, jmax) и с разными значениями.
	seen := map[time.Duration]struct{}{}
	for k := 0; k < 4; k++ {
		d := sh.Delay(50)
		if d < 0 || d >= jmax {
			t.Fatalf("джиттер %v вне [0,%v)", d, jmax)
		}
		seen[d] = struct{}{}
	}
	if len(seen) < 3 {
		t.Fatalf("джиттер даёт лишь %d уникальных значений", len(seen))
	}
}

func TestCoverConfig(t *testing.T) {
	idx := 0
	rng := rngFunc{
		float64:  func() float64 { return 0 },
		intn:     func(n int) int { v := idx % n; idx++; return v },
		expFloat: func() float64 { return 1 },
	}
	sh := New(Config{CoverMeanInterval: 200 * time.Millisecond, CoverSizes: []int{100, 200, 300}}, withRNG(rng))
	if sh.Cover == nil || sh.Cover.Next == nil {
		t.Fatal("cover не сконфигурирован")
	}
	got := map[int]struct{}{}
	for k := 0; k < 3; k++ {
		got[sh.Cover.Size()] = struct{}{}
	}
	if len(got) != 3 {
		t.Fatalf("cover-размеры: %d уникальных, ожидалось 3", len(got))
	}
}

func TestEmptyConfigIsNil(t *testing.T) {
	if sh := New(Config{}); sh != nil {
		t.Fatal("пустой Config должен давать nil Shaping")
	}
}

func TestChromeLikeProfile(t *testing.T) {
	sh := New(ChromeLike())
	if sh == nil || sh.Pad == nil || sh.Delay == nil || sh.Cover == nil {
		t.Fatal("ChromeLike должен задавать паддинг, джиттер и cover")
	}
	if sh.Pad(2000) != 2000 {
		t.Fatal("пакет крупнее вёдер не должен паддиться")
	}
}

// TestCoverIntervalsAreNotMetronome — измеримое доказательство, что мы убрали
// метроном. У постоянного периода коэффициент вариации (σ/μ) равен 0;
// у пуассоновского потока он около 1. Проверяем разброс на выборке.
func TestCoverIntervalsAreNotMetronome(t *testing.T) {
	const mean = 100 * time.Millisecond
	next := CoverInterval(mean)

	const n = 500
	vals := make([]float64, n)
	uniq := map[time.Duration]struct{}{}
	var sum float64
	for i := 0; i < n; i++ {
		d := next()
		if d <= 0 {
			t.Fatalf("неположительный интервал %v", d)
		}
		if d > 5*mean {
			t.Fatalf("интервал %v превышает потолок 5·mean", d)
		}
		uniq[d] = struct{}{}
		vals[i] = float64(d)
		sum += vals[i]
	}
	avg := sum / n
	var varsum float64
	for _, v := range vals {
		varsum += (v - avg) * (v - avg)
	}
	cv := math.Sqrt(varsum/n) / avg
	t.Logf("среднее=%v, коэффициент вариации=%.2f, уникальных значений=%d", time.Duration(avg), cv, len(uniq))

	// Постоянный период дал бы cv = 0 и 1 уникальное значение.
	if cv < 0.4 {
		t.Fatalf("коэффициент вариации %.2f — интервалы слишком регулярны (метроном)", cv)
	}
	if len(uniq) < n/2 {
		t.Fatalf("лишь %d уникальных интервалов из %d", len(uniq), n)
	}
	// Среднее должно держаться около заданного (потолок 5·mean его слегка занижает).
	if avg < 0.5*float64(mean) || avg > 1.5*float64(mean) {
		t.Fatalf("среднее %v далеко от заданного %v", time.Duration(avg), mean)
	}
}

func TestKeepAliveIsRandomized(t *testing.T) {
	base, spread := 15*time.Second, 5*time.Second
	uniq := map[time.Duration]struct{}{}
	for i := 0; i < 200; i++ {
		d := KeepAlivePeriod(base, spread)
		if d < base-spread || d > base+spread {
			t.Fatalf("период %v вне диапазона ±%v от %v", d, spread, base)
		}
		uniq[d] = struct{}{}
	}
	t.Logf("уникальных периодов keep-alive: %d", len(uniq))
	if len(uniq) < 50 {
		t.Fatalf("keep-alive почти постоянен: %d уникальных значений", len(uniq))
	}
	// Нулевой разброс — осознанно постоянный период.
	if d := KeepAlivePeriod(base, 0); d != base {
		t.Fatalf("при spread=0 ожидался ровно base, получено %v", d)
	}
}

// TestCloudGamingAsymmetry — профиль облачного гейминга должен быть
// АСИММЕТРИЧНЫМ: вверх типичный пакет мелкий (ввод игрока), вниз — крупный
// (видеокадр). Симметричный профиль видеозвонка на трафик VPN не похож.
func TestCloudGamingAsymmetry(t *testing.T) {
	up := New(CloudGamingUpstream())
	down := New(CloudGamingDownstream())

	// Главное различие — НИЖНЯЯ граница. Крошечный пакет вверх остаётся мелким,
	// а вниз раздувается до размера видеокадра: так TCP-подтверждения внутри
	// туннеля перестают быть различимы на фоне «видео».
	upFloor, downFloor := up.Pad(1), down.Pad(1)
	t.Logf("пакет 1 байт: вверх -> %d, вниз -> %d", upFloor, downFloor)
	if upFloor >= downFloor {
		t.Fatalf("профиль не асимметричен: нижняя граница вверх %d, вниз %d", upFloor, downFloor)
	}
	if downFloor < 512 {
		t.Errorf("нисходящая нижняя граница %d — слишком мелко для видеопотока", downFloor)
	}
	if upFloor > 128 {
		t.Errorf("восходящая нижняя граница %d — слишком крупно для ввода игрока", upFloor)
	}

	// При этом крупные пакеты нормализуются в обе стороны, а не торчат как есть.
	for name, sh := range map[string]*masque.Shaping{"вверх": up, "вниз": down} {
		got := sh.Pad(900)
		if got <= 900 {
			t.Errorf("%s: пакет 900 байт не нормализован (остался %d)", name, got)
		}
		if got > 1350 {
			t.Errorf("%s: пакет дополнен до %d — рискует не влезть в датаграмму", name, got)
		}
	}

	for name, sh := range map[string]*masque.Shaping{"upstream": up, "downstream": down} {
		if sh.Cover == nil || sh.Cover.Next == nil {
			t.Fatalf("%s: cover не сконфигурирован", name)
		}
		seen := map[time.Duration]struct{}{}
		for i := 0; i < 50; i++ {
			seen[sh.Cover.Next()] = struct{}{}
		}
		if len(seen) < 25 {
			t.Errorf("%s: интервалы cover слишком регулярны (%d уникальных из 50)", name, len(seen))
		}
	}
}
