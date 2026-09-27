package netsetup

// Следы, которые клиент оставляет в системе, и уборка за упавшим клиентом.
//
// # Зачем понадобилось
//
// Аварийное отключение (kill switch) переделано так, что умирает вместе с
// процессом: его фильтры живут в динамической сессии WFP. А вот остальное,
// что клиент правит в системе, само не исчезает:
//
//   - правило разрешения имён (NRPT) — оно в реестре;
//   - маршрут-исключение к адресу сервера — он на ФИЗИЧЕСКОМ интерфейсе и
//     переживает исчезновение адаптера туннеля.
//
// Снимает их сам клиент при выходе. Снятой задаче выходить нечем.
//
// Получалась асимметрия, которая на живой машине и проявилась: самая
// опасная часть убиралась сама, а более тихая оставалась. Правило NRPT на
// суффикс «.» уводит ВЕСЬ системный DNS на резолвер за туннелем; без
// туннеля запросы идут к нему напрямую, а публичные резолверы у российских
// провайдеров сплошь и рядом фильтруются. Снаружи это выглядит как «интернет
// работает, а часть соединений почему-то не устанавливается» — и догадаться
// неоткуда.
//
// Убирать это при следующем запуске клиента мало: между крахом и запуском
// может пройти сколько угодно времени.
//
// # Как решено
//
// Клиент записывает свои следы в файл состояния, а уборка (Cleanup) читает
// его и снимает всё разом — без конфигурации и без поднятого туннеля.
// Маршруты иначе не найти: они живут в памяти процесса, и после краха
// опознать среди системных маршрутов свои не по чему.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
)

// leftovers — то, что клиент поставил в системе и обязан убрать.
type leftovers struct {
	// Routes — маршруты на ЧУЖИХ интерфейсах (исключения к серверу и к
	// резолверам прикрытия DNS). Маршруты на самом туннеле не храним: они
	// исчезают вместе с адаптером.
	Routes []savedRoute `json:"routes,omitempty"`
	// NRPT — стоит ли наше правило разрешения имён.
	NRPT bool `json:"nrpt,omitempty"`
}

type savedRoute struct {
	LUID uint64 `json:"luid"`
	Dst  string `json:"dst"`
	Hop  string `json:"hop,omitempty"`
}

var leftoversMu sync.Mutex

// leftoversPath — файл состояния в ProgramData: он переживает перезапуск и
// доступен только администратору, как и сами правки сети.
func leftoversPath() string {
	dir := os.Getenv("ProgramData")
	if dir == "" {
		dir = `C:\ProgramData`
	}
	return filepath.Join(dir, "masquevpn", "leftovers.json")
}

// legacyLeftoversPath — файл состояния до переименования проекта. Уборка
// читает и его: следы, оставленные прежней версией, никуда не делись, а
// правило разрешения имён, брошенное без присмотра, уводит весь системный
// DNS в никуда.
func legacyLeftoversPath() string {
	dir := os.Getenv("ProgramData")
	if dir == "" {
		dir = `C:\ProgramData`
	}
	return filepath.Join(dir, "govpn", "leftovers.json")
}

// legacyLeftovers читает следы, оставленные версией до переименования.
func legacyLeftovers() leftovers {
	var l leftovers
	b, err := os.ReadFile(legacyLeftoversPath())
	if err != nil {
		return l
	}
	_ = json.Unmarshal(b, &l)
	return l
}

func loadLeftovers() leftovers {
	var l leftovers
	b, err := os.ReadFile(leftoversPath())
	if err != nil {
		return l
	}
	// Битый файл — не повод падать: уборка и так делается «на всякий
	// случай», а пустое состояние означает лишь, что маршруты придётся
	// оставить системе.
	_ = json.Unmarshal(b, &l)
	return l
}

func storeLeftovers(l leftovers) {
	path := leftoversPath()
	if l.NRPT || len(l.Routes) > 0 {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return
		}
		if b, err := json.Marshal(l); err == nil {
			_ = os.WriteFile(path, b, 0o600)
		}
		return
	}
	// Следов не осталось — файл тоже не нужен.
	_ = os.Remove(path)
}

func rememberRoute(luid uint64, dst netip.Prefix, hop netip.Addr) {
	leftoversMu.Lock()
	defer leftoversMu.Unlock()
	l := loadLeftovers()
	r := savedRoute{LUID: luid, Dst: dst.String()}
	if hop.IsValid() {
		r.Hop = hop.String()
	}
	for _, have := range l.Routes {
		if have == r {
			return
		}
	}
	l.Routes = append(l.Routes, r)
	storeLeftovers(l)
}

func forgetRoute(luid uint64, dst netip.Prefix) {
	leftoversMu.Lock()
	defer leftoversMu.Unlock()
	l := loadLeftovers()
	out := l.Routes[:0]
	for _, r := range l.Routes {
		if r.LUID == luid && r.Dst == dst.String() {
			continue
		}
		out = append(out, r)
	}
	l.Routes = out
	storeLeftovers(l)
}

func rememberNRPT(on bool) {
	leftoversMu.Lock()
	defer leftoversMu.Unlock()
	l := loadLeftovers()
	l.NRPT = on
	storeLeftovers(l)
}

// CleanupReport — что именно убрано. Возвращается, чтобы клиент мог сказать
// об этом в журнале: молчаливая уборка чужих настроек хуже громкой.
type CleanupReport struct {
	KillSwitch bool
	NRPT       bool
	Routes     int
}

// Empty сообщает, что убирать было нечего.
func (r CleanupReport) Empty() bool { return !r.KillSwitch && !r.NRPT && r.Routes == 0 }

func (r CleanupReport) String() string {
	if r.Empty() {
		return "следов прошлого запуска нет"
	}
	return fmt.Sprintf("убрано: аварийное отключение=%v, правило имён=%v, маршрутов=%d",
		r.KillSwitch, r.NRPT, r.Routes)
}

// Cleanup снимает всё, что клиент мог оставить в системе после аварийного
// завершения: блокировку WFP, правило разрешения имён и маршруты-исключения
// на чужих интерфейсах.
//
// Работает без конфигурации и без поднятого туннеля — этим она и ценна:
// пользователю после краха достаточно запустить клиента (уборка идёт при
// старте) или дать одну команду.
//
// Безвредна, когда убирать нечего.
func Cleanup() (CleanupReport, error) {
	var rep CleanupReport
	var errs []error

	if active, err := KillSwitchActive(); err == nil && active {
		if err := KillSwitchOff(); err != nil {
			errs = append(errs, err)
		} else {
			rep.KillSwitch = true
		}
	} else if err != nil {
		// Состояние прочитать не удалось — пробуем снять вслепую: лишний
		// вызов безвреден, а оставленная блокировка режет сеть.
		if err := KillSwitchOff(); err != nil {
			errs = append(errs, err)
		}
	}

	if servers, err := CurrentNRPT(); err == nil && len(servers) > 0 {
		if err := removeNRPT(); err != nil {
			errs = append(errs, err)
		} else {
			rep.NRPT = true
			flushDNSCache()
		}
	}

	leftoversMu.Lock()
	l := loadLeftovers()
	l.Routes = append(l.Routes, legacyLeftovers().Routes...)
	leftoversMu.Unlock()
	for _, r := range l.Routes {
		dst, err := netip.ParsePrefix(r.Dst)
		if err != nil {
			continue
		}
		var hop netip.Addr
		if r.Hop != "" {
			hop, _ = netip.ParseAddr(r.Hop)
		}
		// Маршрута может уже не быть (интерфейс исчез, система прибрала
		// сама) — это не ошибка уборки.
		if err := delRoute(route{luid: r.LUID, dst: dst, hop: hop}); err == nil {
			rep.Routes++
		}
	}

	leftoversMu.Lock()
	storeLeftovers(leftovers{})
	// Файл прежней версии удаляется целиком: маршруты из него уже сняты, а
	// оставленный файл при следующей уборке заставил бы снимать их снова.
	_ = os.Remove(legacyLeftoversPath())
	leftoversMu.Unlock()

	return rep, errors.Join(errs...)
}
