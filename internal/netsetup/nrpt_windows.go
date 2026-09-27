package netsetup

import (
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// NRPT — таблица правил разрешения имён (Name Resolution Policy Table).
//
// Зачем она нужна, хотя резолвер уже прописан на интерфейсе туннеля.
// Начиная с Windows 8.1 система разрешает имена «умно»: один и тот же
// запрос уходит СРАЗУ ВО ВСЕ интерфейсы, и берётся первый пришедший ответ.
// Поставить резолвер на туннель недостаточно — домашний роутер отвечает
// быстрее, потому что он в двух шагах, а публичный резолвер за туннелем.
// Снаружи это выглядит идеально: трафик идёт через сервер, а список
// посещённых сайтов целиком остаётся у провайдера.
//
// Проверяется это только со стороны: служба, отвечающая, какой резолвер
// пришёл к ней за именем, называет провайдера. Никакая локальная команда
// утечки не покажет — Windows честно рапортует, что на туннеле стоит наш
// резолвер.
//
// NRPT Windows сделала именно для VPN: правило на суффикс «.» перекрывает
// рассылку по интерфейсам и отправляет все имена туда, куда сказано. Так
// делает и WireGuard.
//
// Правило живёт в реестре и снимается при отключении. Если клиент рухнет,
// не успев прибраться, правило останется — и это не безобидно: весь DNS
// системы продолжит уходить на резолвер за туннелем, которого больше нет.
// Снаружи выглядит как «интернет работает, а часть соединений не
// устанавливается», причём публичные резолверы у российских провайдеров
// ещё и фильтруются. Поймано на живой машине 24.09.2026.
//
// Поэтому правило снимается тремя путями: при штатном отключении, при
// следующем запуске (старое удаляется до создания нового) и аварийной
// уборкой netsetup.Cleanup, которой не нужны ни конфигурация, ни туннель.
const nrptRoot = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`

// nrptKey — имя нашего правила. Постоянное, чтобы забытое правило от
// упавшего клиента можно было найти и убрать.
const nrptKey = `masquevpn-full-tunnel`

// legacyNRPTKey — имя правила до переименования проекта. Снимается вместе
// с нынешним: правило, брошенное прежней версией, уводило бы все имена
// в DNS туннеля и после обновления.
const legacyNRPTKey = `govpn-full-tunnel`

// SetNRPT направляет разрешение всех имён в указанные серверы и возвращает
// функцию отката.
func SetNRPT(servers []netip.Addr) (func() error, error) {
	if len(servers) == 0 {
		return func() error { return nil }, nil
	}
	// Забытое правило от предыдущего запуска убираем до создания нового:
	// иначе их станет два, и какое победит — вопрос удачи.
	_ = removeNRPT()

	list := make([]string, 0, len(servers))
	for _, s := range servers {
		list = append(list, s.String())
	}

	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, nrptRoot+`\`+nrptKey, registry.SET_VALUE)
	if err != nil {
		return nil, fmt.Errorf("netsetup: NRPT: %w", err)
	}
	defer k.Close()

	// "." — суффикс, под который подходит любое имя.
	if err := k.SetStringsValue("Name", []string{"."}); err != nil {
		return nil, fmt.Errorf("netsetup: NRPT Name: %w", err)
	}
	if err := k.SetStringValue("GenericDNSServers", strings.Join(list, ";")); err != nil {
		return nil, fmt.Errorf("netsetup: NRPT GenericDNSServers: %w", err)
	}
	// 0x8 — «использовать указанные серверы»; без этого поле серверов
	// молча игнорируется, и правило не делает ничего.
	if err := k.SetDWordValue("ConfigOptions", 0x8); err != nil {
		return nil, fmt.Errorf("netsetup: NRPT ConfigOptions: %w", err)
	}
	if err := k.SetDWordValue("Version", 1); err != nil {
		return nil, fmt.Errorf("netsetup: NRPT Version: %w", err)
	}
	if err := k.SetStringValue("IPSECCARestriction", ""); err != nil {
		return nil, fmt.Errorf("netsetup: NRPT IPSECCARestriction: %w", err)
	}

	// Служба разрешения имён перечитывает таблицу при сбросе кэша; без
	// этого правило вступит в силу не сразу и не предсказуемо.
	flushDNSCache()

	// Правило переживёт смерть процесса, поэтому оно записывается в список
	// следов: уборка снимет его, даже если клиента убили (см.
	// leftovers_windows.go).
	rememberNRPT(true)

	return func() error {
		err := removeNRPT()
		flushDNSCache()
		rememberNRPT(false)
		return err
	}, nil
}

func removeNRPT() error {
	_ = registry.DeleteKey(registry.LOCAL_MACHINE, nrptRoot+`\`+legacyNRPTKey)
	err := registry.DeleteKey(registry.LOCAL_MACHINE, nrptRoot+`\`+nrptKey)
	if err == registry.ErrNotExist {
		return nil
	}
	if err != nil {
		return fmt.Errorf("netsetup: снятие NRPT: %w", err)
	}
	return nil
}

func flushDNSCache() {
	if err := procFlushResolver.Find(); err != nil {
		return
	}
	_, _, _ = procFlushResolver.Call()
}

// CurrentNRPT возвращает серверы из нашего правила. Пустой список означает,
// что правила нет. Нужна самопроверке: поставить правило и не проверить,
// что оно читается обратно и снимается, — значит проверить намерение, а не
// результат.
func CurrentNRPT() ([]netip.Addr, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptRoot+`\`+nrptKey, registry.QUERY_VALUE)
	if err == registry.ErrNotExist {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("netsetup: чтение NRPT: %w", err)
	}
	defer k.Close()
	raw, _, err := k.GetStringValue("GenericDNSServers")
	if err != nil {
		return nil, fmt.Errorf("netsetup: чтение NRPT: %w", err)
	}
	var out []netip.Addr
	for _, s := range strings.Split(raw, ";") {
		if s == "" {
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("netsetup: в правиле NRPT не адрес: %q", s)
		}
		out = append(out, a)
	}
	return out, nil
}
