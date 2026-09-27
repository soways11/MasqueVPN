//go:build windows

// Package netsetup — системная настройка сети для туннеля.
//
// Реализация для Windows: адреса, MTU, маршруты и DNS ставятся через
// IP Helper API (iphlpapi.dll), без вызова netsh и PowerShell — по тем же
// соображениям, что и на Linux: в целевом окружении внешних утилит может не
// быть, а их вывод пришлось бы разбирать текстом.
//
// Интерфейс здесь задаётся не именем, а LUID: имя в Windows не уникально,
// его меняет пользователь, а LUID живёт вместе с адаптером. Имя мы всё же
// принимаем — и переводим в LUID, — чтобы вызывающий код выглядел одинаково
// на всех платформах.
//
// # Чем полный туннель отличается от Linux
//
// На Linux пакеты самого туннеля не уходят в туннель благодаря метке сокета
// (SO_MARK) и отдельной таблице маршрутизации. В Windows пометить сокет
// нечем, поэтому применяется тот же приём, что у WireGuard и OpenVPN:
// маршрут-исключение к адресу сервера через ПРЕЖНИЙ шлюз плюс две половины
// адресного пространства (0.0.0.0/1 и 128.0.0.0/1) через туннель. Половины
// длиннее маршрута по умолчанию, поэтому побеждают они, а сам маршрут по
// умолчанию остаётся нетронутым — это заметно упрощает возврат системы в
// исходное состояние.
package netsetup

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")

	procConvertInterfaceAliasToLuid = iphlpapi.NewProc("ConvertInterfaceAliasToLuid")
	procConvertInterfaceLuidToGuid  = iphlpapi.NewProc("ConvertInterfaceLuidToGuid")
	procCreateUnicastIPAddressEntry = iphlpapi.NewProc("CreateUnicastIpAddressEntry")
	procDeleteUnicastIPAddressEntry = iphlpapi.NewProc("DeleteUnicastIpAddressEntry")
	procInitializeUnicastIPEntry    = iphlpapi.NewProc("InitializeUnicastIpAddressEntry")
	procGetIPInterfaceEntry         = iphlpapi.NewProc("GetIpInterfaceEntry")
	procSetIPInterfaceEntry         = iphlpapi.NewProc("SetIpInterfaceEntry")
	procCreateIPForwardEntry2       = iphlpapi.NewProc("CreateIpForwardEntry2")
	procDeleteIPForwardEntry2       = iphlpapi.NewProc("DeleteIpForwardEntry2")
	procInitializeIPForwardEntry    = iphlpapi.NewProc("InitializeIpForwardEntry")
	procGetBestRoute2               = iphlpapi.NewProc("GetBestRoute2")
	procSetInterfaceDNSSettings     = iphlpapi.NewProc("SetInterfaceDnsSettings")

	dnsapi            = windows.NewLazySystemDLL("dnsapi.dll")
	procFlushResolver = dnsapi.NewProc("DnsFlushResolverCache")
)

// ErrUnsupported — то, чего на этой платформе нет.
var ErrUnsupported = errors.New("netsetup: не поддерживается на Windows")

// IPv6Available — в Windows IPv6 включён всегда (отключается только правкой
// реестра и перезагрузкой), так что отдельной проверки нет.
func IPv6Available() bool { return true }

// MarkSocket на Windows неприменим: пометки сокета здесь нет, трафик туннеля
// уводит мимо себя маршрут-исключение (см. FullTunnel).
func MarkSocket(syscall.RawConn, uint32) error { return nil }

// ---------- адреса семейств ----------

const (
	afINET  = 2
	afINET6 = 23
)

// sockaddrInet — SOCKADDR_INET: объединение sockaddr_in и sockaddr_in6,
// 28 байт. Заполняем побайтно, чтобы не зависеть от выравнивания структур Go.
type sockaddrInet [28]byte

func toSockaddr(a netip.Addr) sockaddrInet {
	var s sockaddrInet
	switch {
	case a.Is4():
		*(*uint16)(unsafe.Pointer(&s[0])) = afINET
		b := a.As4()
		copy(s[4:8], b[:]) // sin_port(2) + sin_addr(4) с 4-го байта
	case a.Is6():
		*(*uint16)(unsafe.Pointer(&s[0])) = afINET6
		b := a.As16()
		copy(s[8:24], b[:]) // sin6_flowinfo(4) занимает 4..8
		if z := a.Zone(); z != "" {
			// Зона (scope id) нам не нужна: адреса туннеля глобальные.
			_ = z
		}
	}
	return s
}

func fromSockaddr(s sockaddrInet) (netip.Addr, bool) {
	switch *(*uint16)(unsafe.Pointer(&s[0])) {
	case afINET:
		var b [4]byte
		copy(b[:], s[4:8])
		return netip.AddrFrom4(b), true
	case afINET6:
		var b [16]byte
		copy(b[:], s[8:24])
		return netip.AddrFrom16(b), true
	}
	return netip.Addr{}, false
}

func family(a netip.Addr) uint16 {
	if a.Is4() {
		return afINET
	}
	return afINET6
}

// ---------- структуры IP Helper API ----------
//
// Раскладка повторяет netioapi.h для x64. Поля-заполнители расставлены
// явно: ошибка здесь означает порчу памяти, поэтому смещения перечислены в
// комментариях и проверяются тестом размеров.

type mibUnicastIPAddressRow struct {
	Address            sockaddrInet // 0
	_                  [4]byte      // 28: выравнивание LUID
	InterfaceLUID      uint64       // 32
	InterfaceIndex     uint32       // 40
	PrefixOrigin       uint32       // 44
	SuffixOrigin       uint32       // 48
	ValidLifetime      uint32       // 52
	PreferredLifetime  uint32       // 56
	OnLinkPrefixLength uint8        // 60
	SkipAsSource       uint8        // 61
	_                  [2]byte      // 62
	DadState           uint32       // 64
	_                  [4]byte      // 68: выравнивание структуры до 8
}

type ipAddressPrefix struct {
	Prefix       sockaddrInet // 0
	PrefixLength uint8        // 28
	_            [3]byte      // 29
}

type mibIPForwardRow2 struct {
	InterfaceLUID        uint64          // 0
	InterfaceIndex       uint32          // 8
	DestinationPrefix    ipAddressPrefix // 12
	NextHop              sockaddrInet    // 44
	SitePrefixLength     uint8           // 72
	_                    [3]byte         // 73
	ValidLifetime        uint32          // 76
	PreferredLifetime    uint32          // 80
	Metric               uint32          // 84
	Protocol             uint32          // 88
	Loopback             uint8           // 92
	AutoconfigureAddress uint8           // 93
	Publish              uint8           // 94
	Immortal             uint8           // 95
	Age                  uint32          // 96
	Origin               uint32          // 100
}

type mibIPInterfaceRow struct {
	Family                               uint16     // 0
	_                                    [6]byte    // 2
	InterfaceLUID                        uint64     // 8
	InterfaceIndex                       uint32     // 16
	MaxReassemblySize                    uint32     // 20
	InterfaceIdentifier                  uint64     // 24
	MinRouterAdvertisementInterval       uint32     // 32
	MaxRouterAdvertisementInterval       uint32     // 36
	AdvertisingEnabled                   uint8      // 40
	ForwardingEnabled                    uint8      // 41
	WeakHostSend                         uint8      // 42
	WeakHostReceive                      uint8      // 43
	UseAutomaticMetric                   uint8      // 44
	UseNeighborUnreachabilityDetection   uint8      // 45
	ManagedAddressConfigurationSupported uint8      // 46
	OtherStatefulConfigurationSupported  uint8      // 47
	AdvertiseDefaultRoute                uint8      // 48
	_                                    [3]byte    // 49
	RouterDiscoveryBehavior              uint32     // 52
	DadTransmits                         uint32     // 56
	BaseReachableTime                    uint32     // 60
	RetransmitTime                       uint32     // 64
	PathMtuDiscoveryTimeout              uint32     // 68
	LinkLocalAddressBehavior             uint32     // 72
	LinkLocalAddressTimeout              uint32     // 76
	ZoneIndices                          [16]uint32 // 80
	SitePrefixLength                     uint32     // 144
	Metric                               uint32     // 148
	NlMtu                                uint32     // 152
	Connected                            uint8      // 156
	SupportsWakeUpPatterns               uint8      // 157
	SupportsNeighborDiscovery            uint8      // 158
	SupportsRouterDiscovery              uint8      // 159
	ReachableTime                        uint32     // 160
	TransmitOffload                      uint8      // 164
	ReceiveOffload                       uint8      // 165
	DisableDefaultRoutes                 uint8      // 166
	_                                    [1]byte    // 167
}

func winErr(r uintptr) error {
	if r == 0 {
		return nil
	}
	return windows.Errno(r)
}

// ---------- интерфейс ----------

// LUIDForName переводит имя интерфейса в LUID.
func LUIDForName(name string) (uint64, error) {
	n16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	var luid uint64
	r, _, _ := procConvertInterfaceAliasToLuid.Call(
		uintptr(unsafe.Pointer(n16)), uintptr(unsafe.Pointer(&luid)))
	if err := winErr(r); err != nil {
		return 0, fmt.Errorf("netsetup: интерфейс %q не найден: %w", name, err)
	}
	return luid, nil
}

// ConfigureInterface назначает адреса и MTU. name — имя адаптера.
func ConfigureInterface(name string, mtu int, addrs []netip.Prefix) error {
	luid, err := LUIDForName(name)
	if err != nil {
		return err
	}
	return ConfigureInterfaceLUID(luid, mtu, addrs)
}

// ConfigureInterfaceLUID — то же по LUID (его отдаёт адаптер Wintun).
func ConfigureInterfaceLUID(luid uint64, mtu int, addrs []netip.Prefix) error {
	for _, p := range addrs {
		if err := addAddress(luid, p); err != nil {
			return err
		}
	}
	if mtu <= 0 {
		return nil
	}
	fams := []uint16{afINET}
	if hasFamily(addrs, false) {
		fams = append(fams, afINET6)
	}
	for _, f := range fams {
		if err := setMTU(luid, f, uint32(mtu)); err != nil {
			return err
		}
	}
	return nil
}

func hasFamily(addrs []netip.Prefix, v4 bool) bool {
	for _, p := range addrs {
		if p.Addr().Is4() == v4 {
			return true
		}
	}
	return false
}

func addAddress(luid uint64, p netip.Prefix) error {
	var row mibUnicastIPAddressRow
	procInitializeUnicastIPEntry.Call(uintptr(unsafe.Pointer(&row)))
	row.Address = toSockaddr(p.Addr())
	row.InterfaceLUID = luid
	row.OnLinkPrefixLength = uint8(p.Bits())
	// Бессрочный адрес: иначе Windows снимет его по истечении времени жизни.
	row.ValidLifetime = 0xffffffff
	row.PreferredLifetime = 0xffffffff
	// Адрес задан вручную (а не получен по DHCP) — так его видит система.
	row.PrefixOrigin = 1 // IpPrefixOriginManual
	row.SuffixOrigin = 1 // IpSuffixOriginManual
	// Пропускаем проверку на дубликат: на туннеле она только задерживает
	// готовность адреса.
	row.DadState = 4 // IpDadStatePreferred

	r, _, _ := procCreateUnicastIPAddressEntry.Call(uintptr(unsafe.Pointer(&row)))
	if err := winErr(r); err != nil && !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		return fmt.Errorf("netsetup: адрес %s: %w", p, err)
	}
	return nil
}

func delAddress(luid uint64, p netip.Prefix) error {
	var row mibUnicastIPAddressRow
	procInitializeUnicastIPEntry.Call(uintptr(unsafe.Pointer(&row)))
	row.Address = toSockaddr(p.Addr())
	row.InterfaceLUID = luid
	row.OnLinkPrefixLength = uint8(p.Bits())
	r, _, _ := procDeleteUnicastIPAddressEntry.Call(uintptr(unsafe.Pointer(&row)))
	if err := winErr(r); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) &&
		!errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return fmt.Errorf("netsetup: снятие адреса %s: %w", p, err)
	}
	return nil
}

// ReplaceAddresses меняет адреса интерфейса: сначала добавляет новые, потом
// снимает старые — чтобы не остаться без адреса ни на мгновение.
func ReplaceAddresses(name string, old, new []netip.Prefix) error {
	luid, err := LUIDForName(name)
	if err != nil {
		return err
	}
	return ReplaceAddressesLUID(luid, old, new)
}

// ReplaceAddressesLUID — то же по LUID.
func ReplaceAddressesLUID(luid uint64, old, new []netip.Prefix) error {
	for _, p := range new {
		if err := addAddress(luid, p); err != nil {
			return err
		}
	}
	for _, p := range old {
		if contains(new, p) {
			continue
		}
		if err := delAddress(luid, p); err != nil {
			return err
		}
	}
	return nil
}

func contains(ps []netip.Prefix, p netip.Prefix) bool {
	for _, x := range ps {
		if x == p {
			return true
		}
	}
	return false
}

// setMTU ставит MTU интерфейса и проверяет, что он применился: ошибка в
// раскладке структуры иначе осталась бы незамеченной.
func setMTU(luid uint64, fam uint16, mtu uint32) error {
	row, err := getIPInterface(luid, fam)
	if err != nil {
		return err
	}
	row.NlMtu = mtu
	// SitePrefixLength для IPv4 обязан быть нулевым, иначе вызов отвергается.
	if fam == afINET {
		row.SitePrefixLength = 0
	}
	// Своя метрика поменьше: маршруты туннеля должны побеждать.
	row.UseAutomaticMetric = 0
	row.Metric = 1
	r, _, _ := procSetIPInterfaceEntry.Call(uintptr(unsafe.Pointer(row)))
	if err := winErr(r); err != nil {
		return fmt.Errorf("netsetup: MTU %d: %w", mtu, err)
	}
	if back, err := getIPInterface(luid, fam); err == nil && back.NlMtu != mtu {
		return fmt.Errorf("netsetup: MTU не применился: запрошено %d, стоит %d", mtu, back.NlMtu)
	}
	return nil
}

func getIPInterface(luid uint64, fam uint16) (*mibIPInterfaceRow, error) {
	row := &mibIPInterfaceRow{Family: fam, InterfaceLUID: luid}
	r, _, _ := procGetIPInterfaceEntry.Call(uintptr(unsafe.Pointer(row)))
	if err := winErr(r); err != nil {
		return nil, fmt.Errorf("netsetup: чтение настроек интерфейса: %w", err)
	}
	return row, nil
}

// ---------- маршруты ----------

// route — добавленный нами маршрут, чтобы снять его при выходе.
type route struct {
	luid uint64
	dst  netip.Prefix
	hop  netip.Addr
}

func addRoute(luid uint64, dst netip.Prefix, hop netip.Addr, metric uint32) error {
	var row mibIPForwardRow2
	procInitializeIPForwardEntry.Call(uintptr(unsafe.Pointer(&row)))
	row.InterfaceLUID = luid
	row.DestinationPrefix.Prefix = toSockaddr(dst.Addr())
	row.DestinationPrefix.PrefixLength = uint8(dst.Bits())
	if hop.IsValid() {
		row.NextHop = toSockaddr(hop)
	} else {
		// Маршрут «на интерфейс»: следующий узел — нулевой адрес того же
		// семейства.
		row.NextHop = toSockaddr(unspecified(dst.Addr()))
	}
	row.Metric = metric
	row.Protocol = 3 // MIB_IPPROTO_NETMGMT: маршрут добавлен вручную
	r, _, _ := procCreateIPForwardEntry2.Call(uintptr(unsafe.Pointer(&row)))
	if err := winErr(r); err != nil && !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		return fmt.Errorf("netsetup: маршрут %s: %w", dst, err)
	}
	return nil
}

func delRoute(r route) error {
	var row mibIPForwardRow2
	procInitializeIPForwardEntry.Call(uintptr(unsafe.Pointer(&row)))
	row.InterfaceLUID = r.luid
	row.DestinationPrefix.Prefix = toSockaddr(r.dst.Addr())
	row.DestinationPrefix.PrefixLength = uint8(r.dst.Bits())
	if r.hop.IsValid() {
		row.NextHop = toSockaddr(r.hop)
	} else {
		row.NextHop = toSockaddr(unspecified(r.dst.Addr()))
	}
	res, _, _ := procDeleteIPForwardEntry2.Call(uintptr(unsafe.Pointer(&row)))
	if err := winErr(res); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) &&
		!errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return fmt.Errorf("netsetup: снятие маршрута %s: %w", r.dst, err)
	}
	return nil
}

func unspecified(a netip.Addr) netip.Addr {
	if a.Is4() {
		return netip.AddrFrom4([4]byte{})
	}
	return netip.AddrFrom16([16]byte{})
}

// AddRoutes добавляет маршруты через интерфейс (раздельный туннель).
func AddRoutes(name string, routes []netip.Prefix) error {
	luid, err := LUIDForName(name)
	if err != nil {
		return err
	}
	return AddRoutesLUID(luid, routes)
}

// AddRoutesLUID — то же по LUID.
func AddRoutesLUID(luid uint64, routes []netip.Prefix) error {
	for _, r := range routes {
		if err := addRoute(luid, r, netip.Addr{}, 0); err != nil {
			return err
		}
	}
	return nil
}

// BestRoute сообщает, через какой интерфейс и какой следующий узел система
// сейчас ходит к адресу. Нужен, чтобы увести трафик самого туннеля мимо
// туннеля.
func BestRoute(dst netip.Addr) (luid uint64, hop netip.Addr, err error) {
	var row mibIPForwardRow2
	var best sockaddrInet
	src := toSockaddr(unspecified(dst))
	d := toSockaddr(dst)
	r, _, _ := procGetBestRoute2.Call(
		0, 0, // без привязки к интерфейсу
		uintptr(unsafe.Pointer(&src)),
		uintptr(unsafe.Pointer(&d)),
		0, // без ограничений по параметрам
		uintptr(unsafe.Pointer(&row)),
		uintptr(unsafe.Pointer(&best)),
	)
	if err := winErr(r); err != nil {
		return 0, netip.Addr{}, fmt.Errorf("netsetup: нет маршрута к %s: %w", dst, err)
	}
	h, _ := fromSockaddr(row.NextHop)
	if h.IsValid() && h.IsUnspecified() {
		h = netip.Addr{} // сервер в локальной сети: маршрут «на интерфейс»
	}
	return row.InterfaceLUID, h, nil
}

// FullTunnel заворачивает в туннель весь трафик.
//
// Половины 0.0.0.0/1 и 128.0.0.0/1 длиннее маршрута по умолчанию и потому
// побеждают его, не заменяя: исходная маршрутизация системы остаётся на
// месте, и снять туннель — значит просто убрать свои маршруты.
type FullTunnel struct {
	// LUID — интерфейс туннеля.
	LUID uint64
	// Server — адрес VPN-сервера: к нему нужен маршрут МИМО туннеля, иначе
	// пакеты самого туннеля уйдут в туннель.
	Server netip.Addr
	// IPv6 — заворачивать ли IPv6.
	IPv6 bool

	mu     sync.Mutex
	halves []route
	bypass []route
}

// Up включает полный туннель.
func (f *FullTunnel) Up() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.Server.IsValid() {
		if err := f.bypassLocked(f.Server); err != nil {
			return fmt.Errorf("маршрут-исключение к серверу: %w", err)
		}
	}

	halves := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/1"),
		netip.MustParsePrefix("128.0.0.0/1"),
	}
	if f.IPv6 {
		halves = append(halves,
			netip.MustParsePrefix("::/1"),
			netip.MustParsePrefix("8000::/1"))
	}
	for _, h := range halves {
		if err := addRoute(f.LUID, h, netip.Addr{}, 0); err != nil {
			f.downLocked()
			return err
		}
		f.halves = append(f.halves, route{luid: f.LUID, dst: h})
	}
	return nil
}

// Bypass уводит мимо туннеля трафик к указанным адресам. Нужен прикрытию
// DNS: его запросы должны уходить к резолверам провайдера как до подключения,
// иначе они не прикрытие, а обычный туннельный трафик. На Linux ту же роль
// играет метка сокета, на Windows пометить сокет нечем.
func (f *FullTunnel) Bypass(ips []netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	var errs []error
	for _, ip := range ips {
		if err := f.bypassLocked(ip); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// SetServer меняет маршрут-исключение, если сервер переехал на другой адрес
// (переразрешение имени при переподключении).
func (f *FullTunnel) SetServer(ip netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !ip.IsValid() || ip == f.Server {
		return nil
	}
	old := f.Server
	f.Server = ip
	if err := f.bypassLocked(ip); err != nil {
		f.Server = old
		return err
	}
	// Прежний маршрут снимаем только после того, как новый встал.
	for i, r := range f.bypass {
		if r.dst.Addr() == old {
			_ = delRoute(r)
			f.bypass = append(f.bypass[:i], f.bypass[i+1:]...)
			break
		}
	}
	return nil
}

// bypassLocked добавляет маршрут к адресу мимо туннеля — через тот
// интерфейс и шлюз, которыми система пользовалась до нас.
func (f *FullTunnel) bypassLocked(ip netip.Addr) error {
	bits := 32
	if ip.Is6() {
		bits = 128
	}
	dst := netip.PrefixFrom(ip, bits)
	for _, r := range f.bypass {
		if r.dst == dst {
			return nil
		}
	}
	outLUID, hop, err := BestRoute(ip)
	if err != nil {
		return err
	}
	if outLUID == f.LUID {
		return fmt.Errorf("netsetup: путь к %s уже идёт через туннель", ip)
	}
	r := route{luid: outLUID, dst: dst, hop: hop}
	if err := addRoute(r.luid, r.dst, r.hop, 0); err != nil {
		return err
	}
	f.bypass = append(f.bypass, r)
	// Маршрут лежит на ЧУЖОМ интерфейсе и переживёт исчезновение адаптера
	// туннеля. Если клиент не доживёт до Down, убрать его сможет только
	// уборка — а найти среди системных маршрутов свой ей не по чему.
	// Поэтому запоминаем (см. leftovers_windows.go).
	rememberRoute(r.luid, r.dst, r.hop)
	return nil
}

// Down снимает всё, что добавил Up.
func (f *FullTunnel) Down() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.downLocked()
}

func (f *FullTunnel) downLocked() error {
	var errs []error
	all := append(append([]route(nil), f.halves...), f.bypass...)
	for i := len(all) - 1; i >= 0; i-- {
		if err := delRoute(all[i]); err != nil {
			errs = append(errs, err)
		}
	}
	for _, r := range f.bypass {
		forgetRoute(r.luid, r.dst)
	}
	f.halves, f.bypass = nil, nil
	return errors.Join(errs...)
}

// ---------- DNS ----------

type dnsInterfaceSettings struct {
	Version             uint32
	_                   [4]byte
	Flags               uint64
	Domain              *uint16
	NameServer          *uint16
	SearchList          *uint16
	RegistrationEnabled uint32
	RegisterAdapterName uint32
	EnableLLMNR         uint32
	QueryAdapterName    uint32
	ProfileNameServer   *uint16
}

const (
	dnsSettingVersion1   = 1
	dnsSettingNameServer = 0x0000000000000001
	dnsSettingIPv6       = 0x0000000000000002 // DNS_SETTING_FLAG_IPV6
)

// SetDNSOn ставит серверы DNS на интерфейс и возвращает функцию возврата.
func SetDNSOn(luid uint64, servers []netip.Addr) (func() error, error) {
	guid, err := guidForLUID(luid)
	if err != nil {
		return nil, err
	}
	apply := func(v6 bool, list string) error {
		var ptr *uint16
		if list != "" {
			p, err := windows.UTF16PtrFromString(list)
			if err != nil {
				return err
			}
			ptr = p
		}
		s := dnsInterfaceSettings{
			Version:    dnsSettingVersion1,
			Flags:      dnsSettingNameServer,
			NameServer: ptr,
		}
		if v6 {
			s.Flags |= dnsSettingIPv6
		}
		r, _, _ := procSetInterfaceDNSSettings.Call(
			uintptr(unsafe.Pointer(guid)), uintptr(unsafe.Pointer(&s)))
		return winErr(r)
	}

	var v4, v6 []string
	for _, a := range servers {
		if a.Is4() {
			v4 = append(v4, a.String())
		} else {
			v6 = append(v6, a.String())
		}
	}
	if err := apply(false, strings.Join(v4, ",")); err != nil {
		return nil, fmt.Errorf("netsetup: DNS: %w", err)
	}
	if len(v6) > 0 {
		if err := apply(true, strings.Join(v6, ",")); err != nil {
			return nil, fmt.Errorf("netsetup: DNS IPv6: %w", err)
		}
	}
	flushDNS()
	return func() error {
		// Снимаем свои серверы: адаптер всё равно исчезнет вместе с
		// туннелем, но оставлять настройки нельзя, если он переживёт выход.
		err := apply(false, "")
		if len(v6) > 0 {
			if e := apply(true, ""); err == nil {
				err = e
			}
		}
		flushDNS()
		return err
	}, nil
}

func flushDNS() { procFlushResolver.Call() }

func guidForLUID(luid uint64) (*windows.GUID, error) {
	var guid windows.GUID
	r, _, _ := procConvertInterfaceLuidToGuid.Call(
		uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&guid)))
	if err := winErr(r); err != nil {
		return nil, fmt.Errorf("netsetup: GUID интерфейса: %w", err)
	}
	return &guid, nil
}

// SystemResolvers возвращает серверы DNS, которыми система пользуется сейчас
// (нужны прикрытию DNS — оно ходит к ним мимо туннеля).
func SystemResolvers() ([]netip.Addr, error) {
	size := uint32(15000)
	for range 3 {
		buf := make([]byte, size)
		aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC,
			windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|
				windows.GAA_FLAG_SKIP_FRIENDLY_NAME,
			0, aa, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("netsetup: список адаптеров: %w", err)
		}
		var out []netip.Addr
		seen := map[netip.Addr]bool{}
		for ; aa != nil; aa = aa.Next {
			if aa.OperStatus != windows.IfOperStatusUp {
				continue
			}
			for d := aa.FirstDnsServerAddress; d != nil; d = d.Next {
				a, ok := sockaddrToAddr(d.Address)
				if !ok || seen[a] || !UsableResolver(a) {
					continue
				}
				seen[a] = true
				out = append(out, a)
			}
		}
		if len(out) == 0 {
			return nil, errors.New("netsetup: система не сообщила ни одного резолвера")
		}
		return out, nil
	}
	return nil, errors.New("netsetup: не удалось получить список адаптеров")
}

func sockaddrToAddr(sa windows.SocketAddress) (netip.Addr, bool) {
	if sa.Sockaddr == nil {
		return netip.Addr{}, false
	}
	switch sa.Sockaddr.Addr.Family {
	case windows.AF_INET:
		p := (*windows.RawSockaddrInet4)(unsafe.Pointer(sa.Sockaddr))
		return netip.AddrFrom4(p.Addr), true
	case windows.AF_INET6:
		p := (*windows.RawSockaddrInet6)(unsafe.Pointer(sa.Sockaddr))
		return netip.AddrFrom16(p.Addr), true
	}
	return netip.Addr{}, false
}
