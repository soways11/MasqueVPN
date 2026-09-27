package netsetup

import (
	"os"
	"strings"
	"testing"
)

// Страж уборки за упавшим клиентом.
//
// Код исполняется только на Windows, а следить за ним надо отовсюду. Цена
// ошибки здесь измерена на живой машине 24.09.2026: после снятия задачи
// клиента kill switch снялся сам (он в динамической сессии WFP), а правило
// разрешения имён осталось — и весь системный DNS продолжил уходить на
// резолвер за туннелем, которого больше нет. Выглядело это как «интернет
// работает, а часть соединений не устанавливается», и догадаться было
// неоткуда.
//
// Тест читает исходники и проверяет, что следы, переживающие процесс,
// по-прежнему записываются и убираются.
func TestCleanupCoversLeftovers(t *testing.T) {
	src := readSource(t, "leftovers_windows.go")
	nrpt := readSource(t, "nrpt_windows.go")
	net := readSource(t, "netsetup_windows.go")
	run := readSource(t, "../clientrun/run_windows.go")
	cli := readSource(t, "../../cmd/vpnclient/main.go")

	t.Run("уборка снимает все три следа", func(t *testing.T) {
		body := section(src, "func Cleanup()")
		if body == "" {
			t.Fatal("не найдена Cleanup")
		}
		for what, needle := range map[string]string{
			"блокировку WFP":          "KillSwitchOff",
			"правило разрешения имён": "removeNRPT",
			"маршруты":                "delRoute",
		} {
			if !hasCall(body, needle) {
				t.Errorf("Cleanup не убирает %s (нет вызова %s)", what, needle)
			}
		}
		if !hasCall(body, "flushDNSCache") {
			t.Error("Cleanup не сбрасывает кэш имён — снятое правило будет действовать ещё какое-то время")
		}
	})

	t.Run("следы записываются там, где появляются", func(t *testing.T) {
		if !hasCall(nrpt, "rememberNRPT(true)") {
			t.Error("SetNRPT не записывает правило в список следов — уборке нечего будет снимать")
		}
		if !hasCall(nrpt, "rememberNRPT(false)") {
			t.Error("откат NRPT не вычёркивает правило из списка следов")
		}
		if !hasCall(section(net, "func (f *FullTunnel) bypassLocked("), "rememberRoute") {
			t.Error("маршрут-исключение не записывается: после краха его не найти — " +
				"он лежит на чужом интерфейсе и переживает исчезновение адаптера")
		}
		if !hasCall(section(net, "func (f *FullTunnel) downLocked("), "forgetRoute") {
			t.Error("штатное снятие маршрута не вычёркивает его из списка следов")
		}
	})

	t.Run("уборка идёт при каждом запуске клиента", func(t *testing.T) {
		if !hasCall(run, "netsetup.Cleanup()") {
			t.Fatal("клиент не убирает следы при старте")
		}
		// И именно безусловно: прежняя версия снимала блокировку только
		// когда аварийное отключение не просили, а правило имён не трогала
		// вовсе.
		i := strings.Index(run, "netsetup.Cleanup()")
		before := run[:i]
		if j := strings.LastIndex(before, "if "); j >= 0 {
			cond := before[j:]
			if strings.Contains(cond, "cfg.KillSwitch") {
				t.Error("уборка при старте спрятана под условие cfg.KillSwitch")
			}
		}
	})

	t.Run("за клиентом следит сторож", func(t *testing.T) {
		// Уборки при старте и команды мало: между крахом и следующим
		// запуском система сидит на резолвере, которого нет. Снять следы
		// можно только ПОСЛЕ смерти клиента — значит нужен второй процесс.
		wd := readSource(t, "../clientrun/watchdog_windows.go")
		if !hasCall(wd, "netsetup.Cleanup()") {
			t.Error("сторож не убирает следы")
		}
		if !hasCall(wd, "windows.WaitForSingleObject") {
			t.Error("сторож не ждёт завершения клиента")
		}
		if !hasCall(wd, "DETACHED_PROCESS") {
			t.Error("сторож входит в группу процессов клиента — «снять задачу» убьёт и его")
		}
		if !hasCall(run, "StartWatchdog()") {
			t.Error("клиент не запускает сторожа при поднятии полного туннеля")
		}
		// И оба бинарника должны уметь быть сторожем: клиент запускает
		// копию СЕБЯ, а не соседний файл.
		if !hasCall(cli, "clientrun.RunWatchdog(") {
			t.Error("vpnclient не умеет работать сторожем")
		}
		gui := readSource(t, "../../cmd/masquevpn-win/main.go")
		if !hasCall(gui, "clientrun.RunWatchdog(") {
			t.Error("окно не умеет работать сторожем — запущенное из него оно прибираться не будет")
		}
	})

	t.Run("есть аварийная команда без конфигурации", func(t *testing.T) {
		if !strings.Contains(cli, `flag.Bool("cleanup"`) {
			t.Error("нет флага -cleanup")
		}
		if !strings.Contains(cli, `flag.Bool("killswitch-off"`) {
			t.Error("пропало прежнее имя -killswitch-off: оно записано в инструкциях")
		}
		if !hasCall(cli, "netsetup.Cleanup()") {
			t.Error("аварийная команда не вызывает полную уборку")
		}
	})
}

func readSource(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// hasCall ищет вызов в ЖИВОМ коде, а не в комментарии.
//
// Обычный поиск подстроки этим обманывается: закомментированная строка
// по-прежнему содержит текст вызова, и страж молча перестаёт стеречь.
// Проверено мутацией — без этого разбора она проходила.
func hasCall(src, call string) bool {
	for _, line := range strings.Split(src, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") {
			continue
		}
		if i := strings.Index(t, "//"); i >= 0 {
			t = t[:i]
		}
		if strings.Contains(t, call) {
			return true
		}
	}
	return false
}
