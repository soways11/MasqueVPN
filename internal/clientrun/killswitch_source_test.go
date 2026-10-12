package clientrun

import (
	"os"
	"strings"
	"testing"
)

// Обвязка аварийного отключения и сторож на Linux исполняются только на живой
// машине. Стережём их решения чтением исходника.

func ksReadSource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("не прочитать %s: %v", name, err)
	}
	return string(b)
}

// ksLive — только живой код, без строк-комментариев: иначе закомментированный
// вызов обманул бы стража.
func ksLive(src string) string {
	var b strings.Builder
	for _, line := range strings.Split(src, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

func ksMustContain(t *testing.T, src, sub, why string) {
	t.Helper()
	if !strings.Contains(ksLive(src), sub) {
		t.Errorf("в живом коде нет %q — %s", sub, why)
	}
}

func TestWatchdogLinuxDecisions(t *testing.T) {
	src := ksReadSource(t, "watchdog_linux.go")

	// Смерть родителя ловим по смене getppid (усыновление init'ом), сравнивая
	// с ИСХОДНЫМ pid: переиспользование pid не обманет. Мутация: опрашивать
	// «жив ли процесс с этим pid» — и чужой процесс с тем же pid обманет.
	ksMustContain(t, src, "os.Getppid()", "смерть родителя — по смене getppid")
	// Сторож в своей сессии, чтобы крах клиента/убийство группы его не задели.
	ksMustContain(t, src, "Setsid", "сторож должен быть в своей сессии")
	// И собственно уборка после смерти родителя.
	ksMustContain(t, src, "netsetup.Cleanup()", "сторож обязан прибраться после смерти клиента")
}

func TestKillSwitchLinuxWiring(t *testing.T) {
	src := ksReadSource(t, "run_linux.go")

	// Уборка следов прошлого запуска — в начале Run, безусловно.
	ksMustContain(t, src, "netsetup.Cleanup()", "следы прошлого запуска убираются при старте")

	// Блокировка поднимается и снимается.
	ksMustContain(t, src, "netsetup.KillSwitchArm(dev.Name(), fwmark, allow)", "блокировка поднимается после полного туннеля")
	ksMustContain(t, src, "ks.Disarm()", "при штатном выходе блокировка снимается")

	// Таблица поднимается при полном туннеле БЕЗУСЛОВНО, а не по флагу
	// kill_switch: иначе трафик сокета, привязанного к адаптеру
	// (SO_BINDTODEVICE), уходит мимо туннеля — маршрутами это не
	// закрывается (см. netsetup/fulltunnel_linux.go). Мутация: вернуть
	// обрамление `if cfg.KillSwitch != nil && *cfg.KillSwitch {` вокруг
	// KillSwitchArm — и лазейка откроется снова.
	if strings.Contains(ksLive(src), "if cfg.KillSwitch != nil && *cfg.KillSwitch {") {
		t.Error("поднятие таблицы снова под флагом kill_switch: при выключенном " +
			"флаге трафик сокета, привязанного к адаптеру, уйдёт мимо туннеля")
	}
	ksMustContain(t, src, "strict := cfg.KillSwitch != nil", "флаг kill_switch решает строгость, а не сам факт перехвата")

	// Fail-open: сторож запускается ТОЛЬКО когда не fail-closed, а
	// fail-closed возможен лишь при явно включённом kill_switch — иначе
	// выключенный флаг оставлял бы сеть закрытой после краха. Мутации:
	// запускать сторожа всегда (fail-closed перестанет держать блокировку)
	// или убрать strict из условия (сеть запрётся без спроса).
	ksMustContain(t, src, "failClosed := strict && cfg.KillSwitchFailClosed != nil", "fail-closed — только при явном kill_switch")
	ksMustContain(t, src, "if !failClosed {", "сторож — только при fail-open")
	ksMustContain(t, src, "StartWatchdog()", "fail-open опирается на сторожа")

	// Резолверы прикрытия добавляются в разрешённые атомарным Reapply.
	ksMustContain(t, src, "ks.Reapply(allow)", "резолверы прикрытия разрешаются после их запуска")
}
