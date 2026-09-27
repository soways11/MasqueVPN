package netsetup

// Аварийное отключение (kill switch) на Windows Filtering Platform.
//
// Зачем. При штатном отключении клиент снимает маршруты сам. Но если он
// падает — краш, kill процесса, выключение по питанию, — адаптер Wintun
// исчезает вместе со своими маршрутами, и система молча возвращается к
// обычному шлюзу. Отказ туннеля ОТКРЫВАЕТ трафик вместо того, чтобы его
// закрыть. Для VPN это худший из отказов: пользователь считает, что защищён,
// а идёт напрямую, и узнать об этом можно только постфактум.
//
// Пока защита включена, наружу выпускается только то, что нужно самому
// туннелю (адрес сервера), плюс локальная сеть и петля. Всё остальное
// блокируется в ядре, где живёт WFP, независимо от маршрутизации.
//
// # Почему WFP, а не маршруты
//
// Маршрут-заглушка на Windows ненадёжна: система может не принять маршрут к
// недостижимому шлюзу, а новый шлюз от DHCP переопределит его. WFP фильтрует
// в момент установления соединения (ALE_AUTH_CONNECT). Так делает и WireGuard.
//
// # Главное решение: динамическая сессия, а не персистентные фильтры
//
// Первая версия ставила фильтры персистентными — чтобы «отказ закрывает
// трафик» выполнялось и после перезагрузки. Снималось это удалением подслоя
// по фиксированному GUID.
//
// Так делать нельзя, и это выяснилось на живой машине: Windows НЕ удаляет
// подслой, пока в нём есть фильтры (FWP_E_IN_USE), — снятие молча не делало
// ничего. Машина осталась без сети, и перезагрузка не помогала, потому что
// фильтры были персистентными. Сеть пришлось чинить руками.
//
// Теперь и подслой, и фильтры создаются в ДИНАМИЧЕСКОЙ сессии WFP. Такие
// объекты живут ровно столько, сколько открыт дескриптор движка, — то есть
// пока жив процесс клиента. Упал процесс, убили задачу, выключили питание —
// WFP снимает всё сама. Запереть машину невозможно в принципе.
//
// Плата названа прямо: при падении клиента трафик ОТКРЫВАЕТСЯ (fail-open),
// а не остаётся закрытым. Это сознательный размен — «пользователь на минуту
// без VPN» против «пользователь без интернета до переустановки системы».
// Режим «пережить крах процесса» возможен, но только отдельным явным флагом,
// и его здесь нет.
//
// Отсюда же устройство API: KillSwitchArm возвращает объект, ДЕРЖАЩИЙ
// дескриптор движка. Пока объект жив — жива блокировка; Disarm закрывает
// дескриптор, и WFP убирает фильтры. Ставить и забывать нельзя.
//
// # Что осталось от прежней версии
//
// KillSwitchOff — аварийный выход (`vpnclient -killswitch-off`). Он работает
// без поднятого туннеля и без конфигурации и убирает ПЕРСИСТЕНТНЫЕ остатки,
// которые мог оставить клиент старой версии: перечисляет фильтры, удаляет
// наши по ключу подслоя и только потом сам подслой — в том порядке, в
// котором это вообще возможно.
//
// # Мера против того, чтобы запереть пользователя без сети
//
// Всё применяется одной транзакцией WFP. Она атомарна: либо встаёт весь
// согласованный набор (блокировка ВМЕСТЕ с разрешениями), либо не встаёт
// ничего. «Блок без разрешений» физически невозможен.
//
// Раскладка каждой структуры WFP проверяется ассертом размера на этапе
// компиляции (см. константы _ ниже) — против чисел из SDK. Смещение,
// сдвинутое на байт, не соберётся, а не молча отрежет не то.

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	fwpuclnt                = windows.NewLazySystemDLL("fwpuclnt.dll")
	procFwpmEngineOpen0     = fwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0    = fwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmTransBegin0     = fwpuclnt.NewProc("FwpmTransactionBegin0")
	procFwpmTransCommit0    = fwpuclnt.NewProc("FwpmTransactionCommit0")
	procFwpmTransAbort0     = fwpuclnt.NewProc("FwpmTransactionAbort0")
	procFwpmSubLayerAdd0    = fwpuclnt.NewProc("FwpmSubLayerAdd0")
	procFwpmSubLayerDel0    = fwpuclnt.NewProc("FwpmSubLayerDeleteByKey0")
	procFwpmFilterAdd0      = fwpuclnt.NewProc("FwpmFilterAdd0")
	procFwpmSubLayerByKey   = fwpuclnt.NewProc("FwpmSubLayerGetByKey0")
	procFwpmFilterEnumBegin = fwpuclnt.NewProc("FwpmFilterCreateEnumHandle0")
	procFwpmFilterEnum      = fwpuclnt.NewProc("FwpmFilterEnum0")
	procFwpmFilterEnumEnd   = fwpuclnt.NewProc("FwpmFilterDestroyEnumHandle0")
	procFwpmFilterDeleteID  = fwpuclnt.NewProc("FwpmFilterDeleteById0")
	procFwpmFreeMemory0     = fwpuclnt.NewProc("FwpmFreeMemory0")
)

// GUID нашего подслоя. Фиксированный: по нему снятие находит и убирает всё
// разом, в том числе оставшееся от упавшего клиента. Не менялся при
// переименовании проекта — поэтому фильтры прежней версии снимаются так же.
var subLayerKey = windows.GUID{
	Data1: 0x8f4e2b10, Data2: 0x9c7a, Data3: 0x4d6e,
	Data4: [8]byte{0xb2, 0x11, 0x67, 0x76, 0x76, 0x76, 0x67, 0x01},
}

// Слои ALE, где принимается решение об исходящем соединении.
var (
	layerAleAuthConnectV4 = windows.GUID{
		Data1: 0xc38d57d1, Data2: 0x05a7, Data3: 0x4c33,
		Data4: [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}}
	layerAleAuthConnectV6 = windows.GUID{
		Data1: 0x4a72393b, Data2: 0x319f, Data3: 0x44bc,
		Data4: [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}}
	condIPLocalInterface = windows.GUID{
		Data1: 0x4cd62a49, Data2: 0x59c3, Data3: 0x4969,
		Data4: [8]byte{0xb7, 0xf3, 0xbd, 0xa5, 0xd3, 0x28, 0x90, 0xa4}}
	condIPRemoteAddress = windows.GUID{
		Data1: 0xb235ae9a, Data2: 0x1d64, Data3: 0x49b8,
		Data4: [8]byte{0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45}}
)

const (
	fwpEmpty       = 0
	fwpUint8       = 1
	fwpUint64      = 4
	fwpV4AddrMask  = 0x100
	fwpV6AddrMask  = 0x101
	fwpMatchEqual  = 0
	actionBlock    = 0x00000001 | 0x00001000 // FWP_ACTION_BLOCK | _FLAG_TERMINATING
	actionPermit   = 0x00000002 | 0x00001000 // FWP_ACTION_PERMIT | _FLAG_TERMINATING
	subLayerWeight = 0xffff                  // выше пользовательских правил
	weightPermit   = 15                      // разрешения важнее блокировки
	weightBlock    = 1

	rpcAuthnWinNT = 10 // RPC_C_AUTHN_WINNT

	// FWPM_SESSION_FLAG_DYNAMIC: всё, что создано в этой сессии, живёт ровно
	// пока открыт её дескриптор. На этом флаге и держится вся безопасность
	// здешней конструкции — см. шапку файла.
	sessionFlagDynamic = 0x00000001

	// «Объекта нет» WFP сообщает двумя кодами.
	errCodeSublayerGone = 0x80320003 // FWP_E_SUBLAYER_NOT_FOUND
	errCodeFilterGone   = 0x80320007 // FWP_E_FILTER_NOT_FOUND

	// Сколько фильтров запрашивать за один шаг перечисления.
	filterEnumBatch = 64
)

// ---- структуры WFP. Размеры проверены ассертами ниже (64-bit LLP64). ----

type fwpByteBlob struct {
	size uint32
	_    uint32
	data *uint8
}

type fwpmDisplayData0 struct {
	name        *uint16
	description *uint16
}

type fwpValue0 struct {
	typ   uint32
	_     uint32
	value uintptr // мелкие int — как есть; крупные — указатель
}

type fwpConditionValue0 struct {
	typ   uint32
	_     uint32
	value uintptr
}

type fwpmFilterCondition0 struct {
	fieldKey       windows.GUID
	matchType      uint32
	_              uint32
	conditionValue fwpConditionValue0
}

type fwpmAction0 struct {
	typ        uint32
	filterType windows.GUID
}

// fwpmSession0 — FWPM_SESSION0. Нужна только ради флага «динамическая».
type fwpmSession0 struct {
	sessionKey           windows.GUID
	displayData          fwpmDisplayData0
	flags                uint32
	txnWaitTimeoutInMSec uint32
	processID            uint32
	_                    uint32
	sid                  uintptr
	username             *uint16
	kernelMode           uint32
	_                    uint32
}

type fwpmSubLayer0 struct {
	subLayerKey  windows.GUID
	displayData  fwpmDisplayData0
	flags        uint32
	_            uint32
	providerKey  *windows.GUID
	providerData fwpByteBlob
	weight       uint16
	_            [6]byte
}

type fwpmFilter0 struct {
	filterKey           windows.GUID
	displayData         fwpmDisplayData0
	flags               uint32
	_                   uint32
	providerKey         *windows.GUID
	providerData        fwpByteBlob
	layerKey            windows.GUID
	subLayerKey         windows.GUID
	weight              fwpValue0
	numFilterConditions uint32
	_                   uint32
	filterCondition     *fwpmFilterCondition0
	action              fwpmAction0
	_                   uint32 // выравнивание перед union (UINT64)
	providerContextKey  windows.GUID
	reserved            *windows.GUID
	filterID            uint64
	effectiveWeight     fwpValue0
}

// Ассерты размера: если раскладка «поехала», выражение переполнит uintptr и
// сборка остановится — на любой платформе, потому что unsafe.Sizeof
// вычисляется во время компиляции. Числа — sizeof соответствующих структур
// SDK на 64-битной Windows.
const (
	_ = uint(unsafe.Sizeof(fwpValue0{}) - 16)
	_ = uint(16 - unsafe.Sizeof(fwpValue0{}))
	_ = uint(unsafe.Sizeof(fwpmFilterCondition0{}) - 40)
	_ = uint(40 - unsafe.Sizeof(fwpmFilterCondition0{}))
	_ = uint(unsafe.Sizeof(fwpmSubLayer0{}) - 72)
	_ = uint(72 - unsafe.Sizeof(fwpmSubLayer0{}))
	_ = uint(unsafe.Sizeof(fwpmFilter0{}) - 200)
	_ = uint(200 - unsafe.Sizeof(fwpmFilter0{}))
	_ = uint(unsafe.Sizeof(fwpmSession0{}) - 72)
	_ = uint(72 - unsafe.Sizeof(fwpmSession0{}))
)

// v4AddrMask и v6AddrMask — значения условия «адрес принадлежит подсети».
type fwpV4AddrAndMask struct {
	addr uint32 // порядок хоста
	mask uint32
}

type fwpV6AddrAndMask struct {
	addr         [16]byte
	prefixLength uint8
	_            [3]byte
}

// KillSwitch — включённая блокировка. Держит дескриптор движка WFP: пока
// объект жив, жива и блокировка; закрылся дескриптор (Disarm или смерть
// процесса) — WFP убрала фильтры.
type KillSwitch struct {
	mu sync.Mutex
	h  windows.Handle // 0 — уже снято
}

// ErrKillSwitchClosed — операция над уже снятой блокировкой.
var ErrKillSwitchClosed = errors.New("netsetup: аварийное отключение уже снято")

// KillSwitchArm включает аварийное отключение: наружу пропускаются только
// туннель (по интерфейсу), петля, локальная сеть и перечисленные в allow
// адреса; всё прочее исходящее блокируется.
//
// В allow обязан быть адрес VPN-сервера — иначе после разрыва не
// переподключиться. Туда же идёт всё остальное, что мы сами уводим мимо
// туннеля: резолверы прикрытия DNS (их запросы должны выглядеть как запросы
// обычной машины, то есть идти к провайдеру, а не в туннель) и адреса из
// kill_switch_allow в конфигурации.
//
// Без этого списка kill switch резал наши же меры: прикрытие DNS упиралось в
// собственную блокировку, а любое стороннее соединение мимо туннеля —
// например, другой прокси-клиент — переставало работать, и причину
// приходилось искать снаружи.
//
// Возвращённый объект НУЖНО держать: блокировка живёт ровно столько, сколько
// открыт его дескриптор.
func KillSwitchArm(tunLUID uint64, allow []netip.Prefix) (*KillSwitch, error) {
	// Остатки от клиента старой версии (персистентные) динамическая сессия не
	// перекроет — убираем их до установки своих.
	_ = KillSwitchOff()

	h, err := engineOpenDynamic()
	if err != nil {
		return nil, err
	}
	k := &KillSwitch{h: h}
	if err := k.apply(tunLUID, allow, false); err != nil {
		engineClose(h)
		return nil, err
	}
	return k, nil
}

// Reapply переставляет блокировку на новый список разрешённых адресов, не
// снимая её.
//
// Нужен дважды: имя сервера могло переехать при переподключении (наружу
// пропускается конкретный адрес), и список пополняется уже после поднятия
// туннеля — резолверы прикрытия DNS известны только там.
//
// Прежние фильтры удаляются и новые ставятся В ОДНОЙ транзакции — «без
// блокировки» между ними не бывает.
func (k *KillSwitch) Reapply(tunLUID uint64, allow []netip.Prefix) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.h == 0 {
		return ErrKillSwitchClosed
	}
	return k.applyLocked(tunLUID, allow, true)
}

// Disarm снимает блокировку, закрывая дескриптор: WFP убирает динамические
// фильтры и подслой сама. Повторный вызов безвреден.
func (k *KillSwitch) Disarm() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.h == 0 {
		return nil
	}
	h := k.h
	k.h = 0
	engineClose(h)
	return nil
}

// Active сообщает, стоит ли блокировка (для самопроверки).
func (k *KillSwitch) Active() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.h != 0
}

func (k *KillSwitch) apply(tunLUID uint64, allow []netip.Prefix, replace bool) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.applyLocked(tunLUID, allow, replace)
}

func (k *KillSwitch) applyLocked(tunLUID uint64, allow []netip.Prefix, replace bool) error {
	if r, _, _ := procFwpmTransBegin0.Call(uintptr(k.h), 0); r != 0 {
		return fmt.Errorf("netsetup: FwpmTransactionBegin0: 0x%x", r)
	}
	committed := false
	defer func() {
		if !committed {
			// Откат: не встаёт ничего, и машина не остаётся с блокировкой
			// без разрешений.
			procFwpmTransAbort0.Call(uintptr(k.h))
		}
	}()

	if replace {
		if err := deleteOurFilters(k.h); err != nil {
			return err
		}
	} else if err := addSubLayer(k.h); err != nil {
		return err
	}

	for _, spec := range filterPlan(tunLUID, allow) {
		if err := addFilter(k.h, spec); err != nil {
			return fmt.Errorf("%s: %w", spec.name, err)
		}
	}

	if r, _, _ := procFwpmTransCommit0.Call(uintptr(k.h)); r != 0 {
		return fmt.Errorf("netsetup: FwpmTransactionCommit0: 0x%x", r)
	}
	committed = true
	return nil
}

// KillSwitchOff — аварийный выход: снимает блокировку, оставшуюся от клиента
// СТАРОЙ версии, который ставил фильтры персистентными. Работает без
// конфигурации и без поднятого туннеля (`vpnclient -killswitch-off`), и
// безопасен, когда снимать нечего.
//
// Порядок важен: подслой не удаляется, пока в нём есть фильтры
// (FWP_E_IN_USE). Именно на этом первая версия и заперла машину — удаляла
// подслой, молча получала отказ и считала, что сняла. Поэтому сначала
// перечисляются фильтры и удаляются наши, и только потом сам подслой.
func KillSwitchOff() error {
	h, err := engineOpen()
	if err != nil {
		return err
	}
	defer engineClose(h)

	if err := deleteOurFilters(h); err != nil {
		return err
	}
	r, _, _ := procFwpmSubLayerDel0.Call(uintptr(h), uintptr(unsafe.Pointer(&subLayerKey)))
	if r != 0 && !wfpNotFound(uint32(r)) {
		return fmt.Errorf("netsetup: удаление подслоя: 0x%x", r)
	}
	return nil
}

// KillSwitchActive сообщает, стоит ли сейчас наш подслой. Видит и чужую
// сессию: объекты WFP видны всем, динамические просто исчезают вместе с
// сессией-владельцем.
func KillSwitchActive() (bool, error) {
	h, err := engineOpen()
	if err != nil {
		return false, err
	}
	defer engineClose(h)
	var out uintptr
	r, _, _ := procFwpmSubLayerByKey.Call(
		uintptr(h), uintptr(unsafe.Pointer(&subLayerKey)), uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		if out != 0 {
			procFwpmFreeMemory0.Call(uintptr(unsafe.Pointer(&out)))
		}
		return true, nil
	}
	if wfpNotFound(uint32(r)) {
		return false, nil
	}
	return false, fmt.Errorf("netsetup: FwpmSubLayerGetByKey0: 0x%x", r)
}

// deleteOurFilters удаляет все фильтры нашего подслоя. Перечисляются все
// фильтры движка (шаблон отбора по подслою WFP не поддерживает), и берутся
// те, у кого subLayerKey наш.
func deleteOurFilters(h windows.Handle) error {
	var enum windows.Handle
	r, _, _ := procFwpmFilterEnumBegin.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&enum)))
	if r != 0 {
		if wfpNotFound(uint32(r)) {
			return nil
		}
		return fmt.Errorf("netsetup: FwpmFilterCreateEnumHandle0: 0x%x", r)
	}
	defer procFwpmFilterEnumEnd.Call(uintptr(h), uintptr(enum))

	var ids []uint64
	for {
		var entries **fwpmFilter0
		var n uint32
		r, _, _ := procFwpmFilterEnum.Call(
			uintptr(h), uintptr(enum), filterEnumBatch,
			uintptr(unsafe.Pointer(&entries)), uintptr(unsafe.Pointer(&n)))
		if r != 0 {
			return fmt.Errorf("netsetup: FwpmFilterEnum0: 0x%x", r)
		}
		if n == 0 {
			break
		}
		list := unsafe.Slice(entries, n)
		for _, f := range list {
			if f != nil && f.subLayerKey == subLayerKey {
				ids = append(ids, f.filterID)
			}
		}
		procFwpmFreeMemory0.Call(uintptr(unsafe.Pointer(&entries)))
		if n < filterEnumBatch {
			break
		}
	}

	for _, id := range ids {
		r, _, _ := procFwpmFilterDeleteID.Call(uintptr(h), uintptr(id))
		if r != 0 && !wfpNotFound(uint32(r)) {
			return fmt.Errorf("netsetup: FwpmFilterDeleteById0(%d): 0x%x", id, r)
		}
	}
	return nil
}

// wfpNotFound — «такого объекта нет». WFP сообщает об этом двумя разными
// кодами, и оба надо считать отсутствием: иначе снятие несуществующей
// блокировки выглядит как ошибка, и на ней спотыкается самопроверка.
func wfpNotFound(code uint32) bool {
	return code == errCodeSublayerGone || code == errCodeFilterGone
}

// engineOpen открывает движок с обычной сессией: объекты переживают закрытие.
// Нужен только для уборки за старой версией и для чтения состояния.
func engineOpen() (windows.Handle, error) {
	return engineOpenSession(nil)
}

// engineOpenDynamic открывает движок с ДИНАМИЧЕСКОЙ сессией: всё созданное в
// ней исчезнет, как только дескриптор закроется — в том числе если процесс
// умрёт, не закрыв его.
func engineOpenDynamic() (windows.Handle, error) {
	name, _ := windows.UTF16PtrFromString("masquevpn kill switch")
	s := &fwpmSession0{
		displayData: fwpmDisplayData0{name: name},
		flags:       sessionFlagDynamic,
	}
	return engineOpenSession(s)
}

func engineOpenSession(s *fwpmSession0) (windows.Handle, error) {
	var h windows.Handle
	var sp uintptr
	if s != nil {
		sp = uintptr(unsafe.Pointer(s))
	}
	r, _, _ := procFwpmEngineOpen0.Call(
		0,             // serverName: локально
		rpcAuthnWinNT, // authnService
		0,             // authIdentity
		sp,            // session
		uintptr(unsafe.Pointer(&h)),
	)
	if r != 0 {
		return 0, fmt.Errorf("netsetup: FwpmEngineOpen0: 0x%x", r)
	}
	return h, nil
}

func engineClose(h windows.Handle) {
	procFwpmEngineClose0.Call(uintptr(h))
}
func addSubLayer(h windows.Handle) error {
	name, _ := windows.UTF16PtrFromString("masquevpn kill switch")
	sl := fwpmSubLayer0{
		subLayerKey: subLayerKey,
		displayData: fwpmDisplayData0{name: name},
		// Без FWPM_SUBLAYER_FLAG_PERSISTENT: подслой должен исчезнуть вместе
		// с сессией. Персистентный и заперал машину — его нельзя было
		// удалить, пока в нём оставались фильтры.
		weight: subLayerWeight,
	}
	if r, _, _ := procFwpmSubLayerAdd0.Call(
		uintptr(h), uintptr(unsafe.Pointer(&sl)), 0); r != 0 {
		return fmt.Errorf("netsetup: FwpmSubLayerAdd0: 0x%x", r)
	}
	return nil
}

// filterSpec — одно правило: разрешение или блокировка, с условиями.
type filterSpec struct {
	name       string
	layer      windows.GUID
	action     uint32
	weight     uint8
	conditions []fwpmFilterCondition0
	// pin держит вспомогательные значения (LUID, adr-mask) живыми, пока
	// условия указывают на них.
	pin []any
}

// filterPlan строит весь набор фильтров для v4 и v6.
func filterPlan(tunLUID uint64, allow []netip.Prefix) []filterSpec {
	var specs []filterSpec

	for _, layer := range []windows.GUID{layerAleAuthConnectV4, layerAleAuthConnectV6} {
		v6 := layer == layerAleAuthConnectV6

		// 1. Всё, что уже уходит через интерфейс туннеля, — можно.
		luid := tunLUID
		specs = append(specs, filterSpec{
			name:  "permit-tunnel",
			layer: layer, action: actionPermit, weight: weightPermit,
			conditions: []fwpmFilterCondition0{condUint64(condIPLocalInterface, &luid)},
			pin:        []any{&luid},
		})

		// 2. Петля и локальные диапазоны — чтобы не отрезать саму машину и
		//    её сеть. В интернет из них всё равно не выйти.
		for _, p := range localPrefixes(v6) {
			specs = append(specs, permitPrefix(layer, "permit-local", p))
		}

		// 3. Разрешённые адреса: сам сервер (иначе не переподключиться
		//    после разрыва), резолверы прикрытия DNS и то, что задал
		//    пользователь.
		for _, p := range allow {
			if !p.IsValid() || p.Addr().Is6() != v6 {
				continue
			}
			specs = append(specs, permitPrefix(layer, "permit-allow", p))
		}

		// 4. Всё прочее исходящее — блок. Это и есть защита от утечки.
		specs = append(specs, filterSpec{
			name:  "block-all",
			layer: layer, action: actionBlock, weight: weightBlock,
		})
	}
	return specs
}

// localPrefixes — диапазоны, которые kill switch не трогает: петля, частные
// сети, link-local, multicast. Машина остаётся видимой в своей сети, а выйти
// в интернет через них нельзя.
func localPrefixes(v6 bool) []netip.Prefix {
	if v6 {
		return []netip.Prefix{
			netip.MustParsePrefix("::1/128"),   // петля
			netip.MustParsePrefix("fc00::/7"),  // ULA
			netip.MustParsePrefix("fe80::/10"), // link-local
			netip.MustParsePrefix("ff00::/8"),  // multicast
		}
	}
	return []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),        // петля
		netip.MustParsePrefix("10.0.0.0/8"),         // частная
		netip.MustParsePrefix("172.16.0.0/12"),      // частная
		netip.MustParsePrefix("192.168.0.0/16"),     // частная
		netip.MustParsePrefix("169.254.0.0/16"),     // link-local
		netip.MustParsePrefix("224.0.0.0/4"),        // multicast
		netip.MustParsePrefix("255.255.255.255/32"), // broadcast
	}
}

func permitPrefix(layer windows.GUID, name string, p netip.Prefix) filterSpec {
	if p.Addr().Is6() {
		m := &fwpV6AddrAndMask{prefixLength: uint8(p.Bits())}
		m.addr = p.Addr().As16()
		return filterSpec{
			name: name, layer: layer, action: actionPermit, weight: weightPermit,
			conditions: []fwpmFilterCondition0{condV6Mask(condIPRemoteAddress, m)},
			pin:        []any{m},
		}
	}
	m := &fwpV4AddrAndMask{
		addr: beToHost(p.Addr().As4()),
		mask: prefixMask4(p.Bits()),
	}
	return filterSpec{
		name: name, layer: layer, action: actionPermit, weight: weightPermit,
		conditions: []fwpmFilterCondition0{condV4Mask(condIPRemoteAddress, m)},
		pin:        []any{m},
	}
}

func addFilter(h windows.Handle, spec filterSpec) error {
	name, _ := windows.UTF16PtrFromString("masquevpn " + spec.name)
	f := fwpmFilter0{
		displayData: fwpmDisplayData0{name: name},
		// Без FWPM_FILTER_FLAG_PERSISTENT — см. addSubLayer.
		layerKey:    spec.layer,
		subLayerKey: subLayerKey,
		weight:      fwpValue0{typ: fwpUint8, value: uintptr(spec.weight)},
		action:      fwpmAction0{typ: spec.action},
	}
	if len(spec.conditions) > 0 {
		f.numFilterConditions = uint32(len(spec.conditions))
		f.filterCondition = &spec.conditions[0]
	}
	var id uint64
	r, _, _ := procFwpmFilterAdd0.Call(
		uintptr(h), uintptr(unsafe.Pointer(&f)), 0, uintptr(unsafe.Pointer(&id)))
	// keep pins alive across the call
	_ = spec.pin
	if r != 0 {
		return fmt.Errorf("FwpmFilterAdd0: 0x%x", r)
	}
	return nil
}

// ---- построители условий ----

func condUint64(field windows.GUID, v *uint64) fwpmFilterCondition0 {
	return fwpmFilterCondition0{
		fieldKey:  field,
		matchType: fwpMatchEqual,
		conditionValue: fwpConditionValue0{
			typ:   fwpUint64,
			value: uintptr(unsafe.Pointer(v)),
		},
	}
}

func condV4Mask(field windows.GUID, m *fwpV4AddrAndMask) fwpmFilterCondition0 {
	return fwpmFilterCondition0{
		fieldKey:  field,
		matchType: fwpMatchEqual,
		conditionValue: fwpConditionValue0{
			typ:   fwpV4AddrMask,
			value: uintptr(unsafe.Pointer(m)),
		},
	}
}

func condV6Mask(field windows.GUID, m *fwpV6AddrAndMask) fwpmFilterCondition0 {
	return fwpmFilterCondition0{
		fieldKey:  field,
		matchType: fwpMatchEqual,
		conditionValue: fwpConditionValue0{
			typ:   fwpV6AddrMask,
			value: uintptr(unsafe.Pointer(m)),
		},
	}
}
