// Package obfuscation строит политики маскировки трафика для masque.Shaping:
// нормализация размеров датаграмм (паддинг по «вёдрам»), джиттер таймингов и
// маскирующий (cover) трафик в простое.
//
// Что это ломает у DPI:
//   - паддинг по фиксированным размерам разрывает соответствие между длиной
//     IP-пакета внутри туннеля и длиной QUIC-датаграммы снаружи;
//   - джиттер на мелких пакетах смазывает характерный ритм «запрос/ACK»;
//   - cover-трафик убирает «тишину» в паузах, по которой различимы фазы сессии.
//
// Пороговые размеры паддинга не должны превышать полезную ёмкость QUIC-датаграммы
// на пути (обычно ~1200–1350 байт). Слишком большой порог приведёт к
// DatagramTooLargeError при отправке.
package obfuscation

import (
	"math/rand/v2"
	"sort"
	"time"

	"github.com/soways11/masquevpn/internal/masque"
)

// rngFunc — источник случайности (для детерминизма в тестах).
type rngFunc struct {
	float64  func() float64 // [0,1)
	intn     func(n int) int
	expFloat func() float64 // экспоненциальное распределение, среднее 1
}

func defaultRNG() rngFunc {
	return rngFunc{
		float64:  rand.Float64,
		intn:     func(n int) int { return rand.IntN(n) },
		expFloat: rand.ExpFloat64,
	}
}

// Config описывает желаемую маскировку. Нулевой Config → nil-Shaping (без изменений).
type Config struct {
	// Buckets — набор целевых размеров полезной нагрузки IP-пакета (байт).
	// Пакет добивается паддингом до наименьшего ведра, которое его вмещает.
	// Пакет крупнее самого большого ведра не паддится.
	Buckets []int

	// JitterMax — максимальная задержка отправки. 0 — без джиттера.
	JitterMax time.Duration
	// JitterMaxPacketLen — джиттер применяется только к пакетам не длиннее этого
	// значения (мелкие управляющие пакеты). 0 — ко всем.
	JitterMaxPacketLen int

	// CoverMeanInterval — СРЕДНИЙ интервал между попытками отправить cover.
	// Фактические паузы распределены экспоненциально (пуассоновский поток), а не
	// постоянны: постоянный период сам по себе был бы признаком туннеля.
	// 0 — cover-трафик выключен.
	CoverMeanInterval time.Duration
	// CoverSizes — размеры cover-датаграмм; выбирается случайный. По умолчанию Buckets.
	CoverSizes []int
	// CoverUnderLoad — слать cover и под нагрузкой, а не только в простое.
	// Иначе появление cover само размечает наблюдателю границы активности.
	CoverUnderLoad bool
}

// options позволяют подменить RNG в тестах.
type options struct{ rng rngFunc }

// Option — необязательный параметр New.
type Option func(*options)

// withRNG используется в тестах.
func withRNG(r rngFunc) Option { return func(o *options) { o.rng = r } }

// New строит masque.Shaping по конфигурации. Возвращает nil, если маскировка
// не сконфигурирована (все поля пусты).
func New(cfg Config, opts ...Option) *masque.Shaping {
	o := options{rng: defaultRNG()}
	for _, fn := range opts {
		fn(&o)
	}

	var sh masque.Shaping
	empty := true

	if len(cfg.Buckets) > 0 {
		buckets := append([]int(nil), cfg.Buckets...)
		sort.Ints(buckets)
		sh.Pad = func(n int) int { return padToBucket(n, buckets) }
		empty = false
	}

	if cfg.JitterMax > 0 {
		maxLen := cfg.JitterMaxPacketLen
		jmax := cfg.JitterMax
		rng := o.rng
		sh.Delay = func(n int) time.Duration {
			if maxLen > 0 && n > maxLen {
				return 0
			}
			return time.Duration(rng.float64() * float64(jmax))
		}
		empty = false
	}

	if cfg.CoverMeanInterval > 0 {
		sizes := cfg.CoverSizes
		if len(sizes) == 0 {
			sizes = cfg.Buckets
		}
		if len(sizes) == 0 {
			sizes = []int{1200}
		}
		sizes = append([]int(nil), sizes...)
		rng := o.rng
		mean := cfg.CoverMeanInterval
		sh.Cover = &masque.CoverConfig{
			Next:   func() time.Duration { return expInterval(rng, mean) },
			Size:   func() int { return sizes[rng.intn(len(sizes))] },
			Always: cfg.CoverUnderLoad,
		}
		empty = false
	}

	if empty {
		return nil
	}
	return &sh
}

// padToBucket возвращает наименьшее ведро >= n; если n больше всех, возвращает n.
func padToBucket(n int, sortedBuckets []int) int {
	for _, b := range sortedBuckets {
		if b >= n {
			return b
		}
	}
	return n
}

// ChromeLike — эвристический профиль: несколько крупных «вёдер», лёгкий джиттер
// на мелких пакетах и cover-трафик в простое. Значения подобраны как разумный
// старт, а не как измеренный отпечаток конкретной версии Chrome.
func ChromeLike() Config {
	return Config{
		Buckets:            []int{128, 512, 1024, 1350},
		JitterMax:          3 * time.Millisecond,
		JitterMaxPacketLen: 128,
		CoverMeanInterval:  500 * time.Millisecond,
		CoverSizes:         []int{128, 512, 1024, 1350},
		CoverUnderLoad:     true,
	}
}

// expInterval возвращает паузу из экспоненциального распределения со средним mean
// (пуассоновский поток событий). Значение ограничено сверху 5·mean, чтобы редкий
// длинный «хвост» не оставлял канал без прикрытия на минуты.
func expInterval(rng rngFunc, mean time.Duration) time.Duration {
	d := time.Duration(rng.expFloat() * float64(mean))
	if d > 5*mean {
		d = 5 * mean
	}
	if d <= 0 {
		d = time.Millisecond
	}
	return d
}

// CoverInterval отдаёт генератор пуассоновских пауз со средним mean.
// Годится и для masque.CoverBrowsing.Next.
func CoverInterval(mean time.Duration) func() time.Duration {
	rng := defaultRNG()
	return func() time.Duration { return expInterval(rng, mean) }
}

// KeepAlivePeriod возвращает случайный период keep-alive в пределах ±spread от
// base. Постоянный период (у нас было ровно 15 с) — это метроном, одинаковый у
// всех клиентов сборки, то есть готовый признак для классификатора.
func KeepAlivePeriod(base, spread time.Duration) time.Duration {
	if spread <= 0 {
		return base
	}
	delta := time.Duration(rand.Int64N(int64(2*spread))) - spread
	d := base + delta
	if d < time.Second {
		d = time.Second
	}
	return d
}

// CloudGamingUpstream — профиль восходящего (клиент→сервер) трафика облачного
// гейминга: ровный поток мелких пакетов. Под него хорошо маскируются и
// управляющие пакеты, и TCP-подтверждения внутри туннеля, которые иначе выдают
// характерный ритм «запрос/ACK».
func CloudGamingUpstream() Config {
	return Config{
		// Мелкие «вёдра» плюс одно крупное: типичный пакет вверх маленький,
		// но редкая крупная отправка тоже должна нормализоваться, а не торчать.
		Buckets:            []int{64, 128, 256, 1350},
		JitterMax:          2 * time.Millisecond,
		JitterMaxPacketLen: 128,
		CoverMeanInterval:  300 * time.Millisecond,
		CoverSizes:         []int{64, 128, 256},
		CoverUnderLoad:     true,
	}
}

// CloudGamingDownstream — профиль нисходящего (сервер→клиент) трафика: тяжёлый
// видеопоток, крупные датаграммы. Асимметрия здесь не случайна — именно так
// выглядит облачный гейминг, и именно так же выглядит VPN, через который качают.
func CloudGamingDownstream() Config {
	return Config{
		// Нижняя граница высокая: видеопоток не состоит из крошечных пакетов,
		// поэтому мелочь (например, TCP-подтверждения внутри туннеля) раздувается
		// до размера видеокадра и перестаёт быть различимой.
		Buckets:           []int{512, 1024, 1350},
		CoverMeanInterval: 400 * time.Millisecond,
		CoverSizes:        []int{512, 1024, 1350},
		CoverUnderLoad:    true,
	}
}

// ---------- расписание отправки датаграмм (C2) ----------

// PacingConfig описывает расписание, по которому упаковщик шлёт датаграммы.
// Смысл — в том, чтобы поток датаграмм задавался профилем, а не тем, что
// происходит внутри туннеля (см. masque.Pacing).
type PacingConfig struct {
	// MeanInterval — средний интервал между датаграммами (фактические
	// паузы случайные). 0 — расписание выключено.
	MeanInterval time.Duration
	// Sizes — целевые размеры полезной нагрузки; выбирается случайный.
	Sizes []int
	// Idle — слать датаграммы и в простое (иначе тишина внутри туннеля
	// остаётся видна снаружи).
	Idle bool
	// Burst — порог очереди в байтах, после которого расписание уступает
	// пропускной способности. 0 — значение по умолчанию.
	Burst int
}

// NewPacing строит masque.Pacing по конфигурации; nil, если расписание выключено.
func NewPacing(cfg PacingConfig, opts ...Option) *masque.Pacing {
	if cfg.MeanInterval <= 0 {
		return nil
	}
	o := options{rng: defaultRNG()}
	for _, fn := range opts {
		fn(&o)
	}
	sizes := append([]int(nil), cfg.Sizes...)
	p := &masque.Pacing{
		Interval: func() time.Duration { return expInterval(o.rng, cfg.MeanInterval) },
		Idle:     cfg.Idle,
		Burst:    cfg.Burst,
	}
	if len(sizes) > 0 {
		p.Size = func() int { return sizes[o.rng.intn(len(sizes))] }
	}
	return p
}

// CloudGamingPacingUpstream — расписание восходящего потока облачного
// гейминга: частые мелкие датаграммы (ввод игрока). В простое поток не
// прекращается — именно поэтому пауза внутри туннеля снаружи не видна.
// Цена: около 70 кбит/с фонового трафика.
func CloudGamingPacingUpstream() PacingConfig {
	return PacingConfig{
		MeanInterval: 16 * time.Millisecond, // ~60 датаграмм в секунду
		Sizes:        []int{64, 128, 256},
		Idle:         true,
	}
}

// CloudGamingPacingDownstream — расписание нисходящего потока: крупные
// датаграммы видеопотока. Idle выключен: гнать полмегабита видео в простое
// с сервера на каждого клиента слишком дорого, это включается осознанно.
func CloudGamingPacingDownstream() PacingConfig {
	return PacingConfig{
		MeanInterval: 16 * time.Millisecond,
		Sizes:        []int{512, 1024, 1350},
	}
}
