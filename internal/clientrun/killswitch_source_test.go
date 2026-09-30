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

	// Fail-open: сторож запускается ТОЛЬКО когда не fail-closed. Мутации:
	// запускать всегда (fail-closed перестанет держать блокировку после краха)
	// или не запускать никогда (fail-open перестанет прибираться).
	ksMustContain(t, src, "failClosed := cfg.KillSwitchFailClosed != nil", "режим определяется флагом kill_switch_fail_closed")
	ksMustContain(t, src, "if !failClosed {", "сторож — только при fail-open")
	ksMustContain(t, src, "StartWatchdog()", "fail-open опирается на сторожа")

	// Резолверы прикрытия добавляются в разрешённые атомарным Reapply.
	ksMustContain(t, src, "ks.Reapply(allow)", "резолверы прикрытия разрешаются после их запуска")
}
