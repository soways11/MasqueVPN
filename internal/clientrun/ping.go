package clientrun

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/soways11/masquevpn/internal/client"
	"github.com/soways11/masquevpn/internal/config"
	"github.com/soways11/masquevpn/internal/gui"
)

// Пинг профилей для окон Linux и Windows: одна логика на оба клиента.
// Сама проверка — client.Ping: сессия CONNECT-IP и HTTP GET на example.com
// через туннель.
//
// Табло хранит итог последней проверки каждого профиля, не даёт запустить
// вторую проверку того же профиля, пока идёт первая, и пишет итог в журнал
// окна — причину неудачи на кнопке не уместить, а в журнале её прочтут.

// PingTimeout — предел одной проверки профиля целиком: сессия (со всеми
// портами), разрешение имени и сам запрос.
const PingTimeout = 30 * time.Second

// pingParallel — сколько профилей проверять одновременно при «Пинг всех».
// Не все сразу: десяток одновременных рукопожатий забьёт медленный канал, и
// времена выйдут хуже настоящих.
const pingParallel = 4

// PingFunc — сама проверка; подменяется в тестах.
type PingFunc func(ctx context.Context, cfg *config.Client) (client.PingResult, error)

// PingBoard — итоги пинга профилей. Методы безопасны из любых горутин.
type PingBoard struct {
	ping     PingFunc
	onChange func()       // перерисовать окно
	log      func(string) // строка в журнал окна

	mu   sync.Mutex
	res  map[string]pingEntry // ключ — имя профиля в нижнем регистре
	all  bool                 // идёт «Пинг всех»
	wg   sync.WaitGroup
	stop context.CancelFunc
	ctx  context.Context
}

type pingEntry struct {
	state gui.PingState
	rtt   time.Duration
	gen   int // номер проверки: итог устаревшей не затирает свежий
}

// NewPingBoard — табло с настоящей проверкой (client.Ping с опциями этой ОС).
func NewPingBoard(onChange func(), log func(string)) *PingBoard {
	return newPingBoard(func(ctx context.Context, cfg *config.Client) (client.PingResult, error) {
		return client.Ping(ctx, cfg, PingOptions(cfg), client.DefaultPingTarget)
	}, onChange, log)
}

func newPingBoard(f PingFunc, onChange func(), log func(string)) *PingBoard {
	if onChange == nil {
		onChange = func() {}
	}
	if log == nil {
		log = func(string) {}
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &PingBoard{ping: f, onChange: onChange, log: log, res: map[string]pingEntry{}, ctx: ctx, stop: cancel}
}

func pingKey(name string) string { return strings.ToLower(name) }

// Get — итог для профиля: состояние и время.
func (b *PingBoard) Get(name string) (gui.PingState, time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e := b.res[pingKey(name)]
	return e.state, e.rtt
}

// AllBusy — идёт ли «Пинг всех».
func (b *PingBoard) AllBusy() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.all
}

// Fill проставляет итоги в строки профилей для отрисовки.
func (b *PingBoard) Fill(v *gui.View) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i := range v.Profiles {
		e := b.res[pingKey(v.Profiles[i].Name)]
		v.Profiles[i].Ping, v.Profiles[i].RTT = e.state, e.rtt
	}
	v.PingingAll = b.all
}

// Forget стирает итог профиля: его удалили или поменяли адрес, и старое
// время про него уже не говорит. Идущая проверка доложит в журнал, но на
// кнопку не попадёт.
func (b *PingBoard) Forget(name string) {
	b.mu.Lock()
	// Номер поколения растёт, чтобы запоздалый итог узнал, что устарел.
	k := pingKey(name)
	b.res[k] = pingEntry{gen: b.res[k].gen + 1}
	b.mu.Unlock()
	b.onChange()
}

// Ping запускает проверку профиля в фоне. Если она уже идёт — ничего не
// делает. Возвращается сразу.
func (b *PingBoard) Ping(p config.Profile) {
	p = detach(p)
	gen, ok := b.begin(p)
	if !ok {
		return
	}
	b.onChange()
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		b.run(p, gen)
	}()
}

// PingAll проверяет все профили, не больше pingParallel разом. Пока идёт,
// повторное нажатие ничего не делает.
func (b *PingBoard) PingAll(list []config.Profile) {
	b.mu.Lock()
	if b.all || len(list) == 0 {
		b.mu.Unlock()
		return
	}
	b.all = true
	b.mu.Unlock()

	type job struct {
		p   config.Profile
		gen int
	}
	var jobs []job
	for _, p := range list {
		p = detach(p)
		if gen, ok := b.begin(p); ok {
			jobs = append(jobs, job{p, gen})
		}
	}
	b.onChange()
	b.log(fmt.Sprintf("пинг всех профилей: %d", len(list)))

	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		sem := make(chan struct{}, pingParallel)
		var wg sync.WaitGroup
		var okN, failN int
		var cmu sync.Mutex
		for _, j := range jobs {
			sem <- struct{}{}
			wg.Add(1)
			go func() {
				defer func() { <-sem; wg.Done() }()
				ok := b.run(j.p, j.gen)
				cmu.Lock()
				if ok {
					okN++
				} else {
					failN++
				}
				cmu.Unlock()
			}()
		}
		wg.Wait()
		b.mu.Lock()
		b.all = false
		b.mu.Unlock()
		if b.ctx.Err() == nil {
			b.log(fmt.Sprintf("пинг всех: ответили %d из %d", okN, okN+failN))
		}
		b.onChange()
	}()
}

// detach — копия конфигурации для фоновой проверки: окно правит профили в
// своём потоке (переключатели меняют поля на месте), и проверка не должна
// читать то, что в этот момент пишут.
func detach(p config.Profile) config.Profile {
	if p.Config != nil {
		c := *p.Config
		p.Config = &c
	}
	return p
}

// begin помечает профиль «проверяется». false — уже проверяется или
// проверять нечего.
func (b *PingBoard) begin(p config.Profile) (int, bool) {
	if p.Config == nil {
		return 0, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	k := pingKey(p.Name)
	e := b.res[k]
	if e.state == gui.PingBusy {
		return 0, false
	}
	e.gen++
	e.state = gui.PingBusy
	b.res[k] = e
	return e.gen, true
}

// run — одна проверка; итог в табло и журнал. Сообщает, ответил ли сервер.
func (b *PingBoard) run(p config.Profile, gen int) bool {
	ctx, cancel := context.WithTimeout(b.ctx, PingTimeout)
	res, err := b.ping(ctx, p.Config)
	cancel()

	b.mu.Lock()
	k := pingKey(p.Name)
	e := b.res[k]
	fresh := e.gen == gen
	if fresh {
		if err == nil {
			e.state, e.rtt = gui.PingOK, res.RTT
		} else {
			e.state, e.rtt = gui.PingFail, 0
		}
		b.res[k] = e
	}
	b.mu.Unlock()

	switch {
	case b.ctx.Err() != nil:
		// Окно закрывается — докладывать некому.
	case err == nil:
		b.log(fmt.Sprintf("пинг %s: %s — GET %s через туннель, %s (порт %s)",
			p.Name, gui.FormatRTT(res.RTT), res.Target, res.Status, res.Port))
	default:
		b.log(fmt.Sprintf("пинг %s: нет ответа — %s", p.Name, PingReason(err)))
	}
	b.onChange()
	return err == nil
}

// PingReason — причина неудачи для журнала: срок вышел — так и говорим.
func PingReason(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "время вышло"
	}
	return err.Error()
}

// Close прерывает идущие проверки и ждёт их.
func (b *PingBoard) Close() {
	b.stop()
	b.wg.Wait()
}
