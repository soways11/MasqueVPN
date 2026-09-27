//go:build windows

package tun

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TUN на Windows — через Wintun.
//
// Своего /dev/net/tun у Windows нет: чтобы получать и отдавать IP-пакеты,
// нужен драйвер. Wintun — драйвер от авторов WireGuard, подписанный и
// распространяемый одним файлом wintun.dll (сам драйвер лежит внутри неё и
// ставится при создании адаптера). Альтернатива — TAP-драйвер OpenVPN, но он
// работает на канальном уровне: пришлось бы самим отвечать на ARP и снимать
// заголовки Ethernet, ради того же результата.
//
// Привязки написаны здесь, а не взяты готовым пакетом, сознательно: сборка
// проекта идёт без доступа к сети, а весь нужный интерфейс — четырнадцать
// функций. Заодно не тянем зависимость ради тонкой обёртки над DLL.
//
// Требуются права администратора: Wintun ставит драйвер и создаёт адаптер.

const (
	// ringCapacity — размер кольцевого буфера драйвера. Допустимы степени
	// двойки от 128 КиБ до 64 МиБ. 4 МиБ — как у WireGuard: хватает, чтобы
	// пережить всплеск, и не отъедает память зря.
	ringCapacity = 0x400000
	// defaultAdapterName — имя адаптера, когда его не задали в конфигурации.
	defaultAdapterName = "masquevpn"
	// tunnelType — как адаптер называется в списке сетевых устройств.
	tunnelType = "masquevpn"
)

// legacyAdapterNames — как адаптер назывался до переименования проекта:
// «govpn» по умолчанию в самом Wintun-коде и «govpn0» — умолчание из
// конфигурации, которое на деле и доходило до адаптера. Адаптер,
// оставшийся от убитого клиента, живёт до перезагрузки, и без уборки в
// списке сетевых подключений копились бы оба.
var legacyAdapterNames = []string{"govpn", "govpn0"}

// Коды ошибок Windows, которые тут важны по существу.
const (
	errorNoMoreItems      = windows.Errno(259) // ERROR_NO_MORE_ITEMS: кольцо пусто
	errorBufferOverflow   = windows.Errno(111) // ERROR_BUFFER_OVERFLOW: кольцо переполнено
	errorInvalidParameter = windows.Errno(87)  // ERROR_INVALID_PARAMETER
	errorHandleEOF        = windows.Errno(38)  // ERROR_HANDLE_EOF: сессия закрыта
	waitObject0           = uintptr(0)         // WAIT_OBJECT_0
	infinite              = uint32(0xFFFFFFFF) // INFINITE
	maxPacketSize         = 0xFFFF             // потолок Wintun на пакет
)

// wintunDLL — загруженная библиотека и нужные нам функции.
type wintunDLL struct {
	dll *windows.DLL

	createAdapter        *windows.Proc
	closeAdapter         *windows.Proc
	openAdapter          *windows.Proc // может отсутствовать в старой DLL
	getAdapterLUID       *windows.Proc
	getDriverVersion     *windows.Proc
	startSession         *windows.Proc
	endSession           *windows.Proc
	getReadWaitEvent     *windows.Proc
	receivePacket        *windows.Proc
	releaseReceivePacket *windows.Proc
	allocateSendPacket   *windows.Proc
	sendPacket           *windows.Proc
}

var (
	loadOnce sync.Once
	loaded   *wintunDLL
	loadErr  error
)

// loadWintun загружает wintun.dll: сначала рядом с исполняемым файлом (так
// программу и распространяют), затем по обычному пути поиска Windows.
func loadWintun() (*wintunDLL, error) {
	loadOnce.Do(func() {
		var dll *windows.DLL
		if exe, err := os.Executable(); err == nil {
			near := filepath.Join(filepath.Dir(exe), "wintun.dll")
			if _, err := os.Stat(near); err == nil {
				dll, loadErr = windows.LoadDLL(near)
			}
		}
		if dll == nil {
			dll, loadErr = windows.LoadDLL("wintun.dll")
		}
		if dll == nil {
			loadErr = fmt.Errorf("tun: не найдена wintun.dll (%w); положите её рядом с программой — "+
				"файл берётся с https://www.wintun.net, каталог bin/amd64", loadErr)
			return
		}
		w := &wintunDLL{dll: dll}
		for _, f := range []struct {
			name string
			dst  **windows.Proc
		}{
			{"WintunCreateAdapter", &w.createAdapter},
			{"WintunCloseAdapter", &w.closeAdapter},
			{"WintunGetAdapterLUID", &w.getAdapterLUID},
			{"WintunGetRunningDriverVersion", &w.getDriverVersion},
			{"WintunStartSession", &w.startSession},
			{"WintunEndSession", &w.endSession},
			{"WintunGetReadWaitEvent", &w.getReadWaitEvent},
			{"WintunReceivePacket", &w.receivePacket},
			{"WintunReleaseReceivePacket", &w.releaseReceivePacket},
			{"WintunAllocateSendPacket", &w.allocateSendPacket},
			{"WintunSendPacket", &w.sendPacket},
		} {
			p, err := dll.FindProc(f.name)
			if err != nil {
				loadErr = fmt.Errorf("tun: в wintun.dll нет %s: %w", f.name, err)
				return
			}
			*f.dst = p
		}
		// Открытие существующего адаптера нужно только для уборки за
		// прежним именем, поэтому отсутствие функции — не повод не
		// запускаться: старая wintun.dll просто не даст прибрать.
		if p, err := dll.FindProc("WintunOpenAdapter"); err == nil {
			w.openAdapter = p
		}
		loaded = w
	})
	return loaded, loadErr
}

// removeAdapter удаляет адаптер по имени, если он существует.
func (w *wintunDLL) removeAdapter(name string) {
	if w.openAdapter == nil {
		return
	}
	name16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return
	}
	adapter, _, _ := w.openAdapter.Call(uintptr(unsafe.Pointer(name16)))
	if adapter == 0 {
		return // адаптера нет — обычный случай
	}
	w.closeAdapter.Call(adapter)
}

var procMoveMemory = windows.NewLazySystemDLL("kernel32.dll").NewProc("RtlMoveMemory")

// copyMemory копирует n байт между памятью Go и кольцевым буфером драйвера.
func copyMemory(dst, src, n uintptr) { procMoveMemory.Call(dst, src, n) }

// device — адаптер Wintun и открытая на нём сессия.
type device struct {
	w       *wintunDLL
	adapter uintptr
	session uintptr
	read    windows.Handle // событие «в кольце что-то есть»
	quit    windows.Handle // наше событие, чтобы прервать ожидание при Close

	name string
	mtu  int
	luid uint64

	mu     sync.RWMutex // держит сессию живой, пока идут чтение и запись
	closed atomic.Bool
}

// Open создаёт адаптер Wintun и открывает на нём сессию.
// Требуются права администратора.
func Open(name string, mtu int) (Device, error) {
	if name == "" {
		name = defaultAdapterName
	}
	if mtu <= 0 {
		mtu = DefaultMTU
	}
	w, err := loadWintun()
	if err != nil {
		return nil, err
	}
	name16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	type16, err := windows.UTF16PtrFromString(tunnelType)
	if err != nil {
		return nil, err
	}
	// Адаптер мог остаться от убитого клиента: Wintun удаляет его при
	// закрытии, а убитый процесс закрыть не успевает. Тогда создание нового
	// с тем же именем упирается в старый, и человек видит «не удалось
	// создать адаптер» на ровном месте.
	//
	// Снимаем и тот, что под прежним именем проекта: иначе в списке
	// сетевых подключений копились бы оба.
	w.removeAdapter(name)
	for _, old := range legacyAdapterNames {
		if name != old {
			w.removeAdapter(old)
		}
	}

	adapter, _, e := w.createAdapter.Call(
		uintptr(unsafe.Pointer(name16)), uintptr(unsafe.Pointer(type16)), 0)
	if adapter == 0 {
		return nil, fmt.Errorf("tun: не удалось создать адаптер %q: %w "+
			"(нужны права администратора)", name, e)
	}
	d := &device{w: w, adapter: adapter, name: name, mtu: mtu}

	w.getAdapterLUID.Call(adapter, uintptr(unsafe.Pointer(&d.luid)))

	session, _, e := w.startSession.Call(adapter, ringCapacity)
	if session == 0 {
		w.closeAdapter.Call(adapter)
		return nil, fmt.Errorf("tun: не удалось открыть сессию: %w", e)
	}
	d.session = session

	ev, _, _ := w.getReadWaitEvent.Call(session)
	d.read = windows.Handle(ev)

	quit, err := windows.CreateEvent(nil, 1, 0, nil) // ручной сброс, изначально не взведено
	if err != nil {
		w.endSession.Call(session)
		w.closeAdapter.Call(adapter)
		return nil, fmt.Errorf("tun: событие остановки: %w", err)
	}
	d.quit = quit
	return d, nil
}

// FromFD на Windows неприменим: дескрипторов TUN здесь не бывает.
func FromFD(fd int, name string, mtu int) (Device, error) {
	return nil, errors.New("tun: приём готового дескриптора на Windows не поддерживается")
}

func (d *device) Name() string { return d.name }
func (d *device) MTU() int     { return d.mtu }

// LUID — идентификатор интерфейса для IP Helper API (адреса, маршруты, DNS).
// Имя интерфейса в Windows не уникально и меняется, LUID — нет.
func (d *device) LUID() uint64 { return d.luid }

// DriverVersion — версия работающего драйвера Wintun (для журнала).
func (d *device) DriverVersion() uint32 {
	v, _, _ := d.w.getDriverVersion.Call()
	return uint32(v)
}

// Read ждёт пакет из системы и копирует его в b.
//
// Wintun отдаёт указатель внутрь кольцевого буфера, поэтому пакет нужно
// скопировать и сразу вернуть место драйверу: пока оно занято, кольцо не
// движется.
func (d *device) Read(b []byte) (int, error) {
	for {
		if d.closed.Load() {
			return 0, ErrClosed
		}
		n, err := d.receive(b)
		switch {
		case err == nil:
			return n, nil
		case errors.Is(err, errorNoMoreItems):
			// Кольцо пусто — ждём либо пакета, либо закрытия.
			ev, err := windows.WaitForMultipleObjects(
				[]windows.Handle{d.read, d.quit}, false, infinite)
			if err != nil {
				return 0, err
			}
			if ev != uint32(waitObject0) { // сработало d.quit
				return 0, ErrClosed
			}
		case errors.Is(err, errorHandleEOF), errors.Is(err, errorInvalidParameter):
			return 0, ErrClosed
		default:
			return 0, err
		}
	}
}

func (d *device) receive(b []byte) (int, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed.Load() {
		return 0, ErrClosed
	}
	var size uint32
	ptr, _, e := d.w.receivePacket.Call(d.session, uintptr(unsafe.Pointer(&size)))
	if ptr == 0 {
		return 0, e
	}
	defer d.w.releaseReceivePacket.Call(d.session, ptr)
	if int(size) > len(b) {
		// Пакет крупнее буфера: молча обрезать нельзя — это испорченные
		// данные. Отбрасываем и говорим об этом.
		return 0, fmt.Errorf("tun: пакет %d байт не помещается в буфер %d", size, len(b))
	}
	// Копируем через RtlMoveMemory: указатель ведёт внутрь кольца драйвера,
	// а не в память Go, и превращать его в unsafe.Pointer было бы ровно тем
	// случаем, от которого предостерегает go vet.
	copyMemory(uintptr(unsafe.Pointer(&b[0])), ptr, uintptr(size))
	return int(size), nil
}

// Write отдаёт пакет системе.
func (d *device) Write(b []byte) (int, error) {
	if len(b) == 0 || len(b) > maxPacketSize {
		return 0, fmt.Errorf("tun: недопустимый размер пакета %d", len(b))
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed.Load() {
		return 0, ErrClosed
	}
	ptr, _, e := d.w.allocateSendPacket.Call(d.session, uintptr(len(b)))
	if ptr == 0 {
		if errors.Is(e, errorBufferOverflow) {
			// Кольцо переполнено: система не успевает забирать. Отбрасываем,
			// как это делает любой сетевой интерфейс при переполнении
			// очереди, — рвать туннель из-за этого нельзя.
			return len(b), nil
		}
		return 0, fmt.Errorf("tun: очередь отправки: %w", e)
	}
	copyMemory(ptr, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	d.w.sendPacket.Call(d.session, ptr)
	return len(b), nil
}

// Close закрывает сессию и удаляет адаптер. Заблокированный Read
// возвращается с ErrClosed.
func (d *device) Close() error {
	if d.closed.Swap(true) {
		return nil
	}
	windows.SetEvent(d.quit) // будим ожидающего в Read
	d.mu.Lock()              // ждём, пока чтение и запись отпустят сессию
	defer d.mu.Unlock()
	d.w.endSession.Call(d.session)
	d.w.closeAdapter.Call(d.adapter)
	windows.CloseHandle(d.quit)
	return nil
}
