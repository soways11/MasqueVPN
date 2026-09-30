//go:build linux

package clientrun

// Сторож: процесс, который убирает за клиентом, если тот не дожил до выхода.
//
// # Зачем на Linux
//
// Аварийная блокировка (nftables, killswitch_linux.go) и подменённый
// /etc/resolv.conf переживают смерть клиента: правила живут в ядре, файл — на
// диске. Снять их может только код, который выполнится ПОСЛЕ смерти процесса, а
// внутри убитого клиента такого места нет (defer не выполнится, обработчик
// сигнала не позовут при SIGKILL). Уборка при следующем запуске помогает, но
// между крахом и запуском машина стоит с закрытой сетью (fail-open теряется)
// или с DNS несуществующего туннеля.
//
// Поэтому клиент, подняв защиту, запускает вторую копию себя с флагом
// -watchdog <pid>. Она ничего не делает, только ждёт смерти родителя и зовёт
// Cleanup. При штатном выходе клиент убирает сам и гасит сторожа.
//
// # Как ловим смерть родителя
//
// Сторож — прямой потомок клиента. Когда клиент умирает, сторожа усыновляет
// init/systemd, и getppid() перестаёт быть pid клиента. Сравниваем именно с
// исходным pid, а не «жив ли процесс с этим pid», поэтому переиспользование pid
// не обманет. Сторож запускается в своей сессии (Setsid), чтобы «убить группу»
// клиента (или его собственный крах) не задели и сторожа.

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/soways11/masquevpn/internal/netsetup"
)

// WatchdogFlag — имя флага, которым запускается сторож.
const WatchdogFlag = "watchdog"

// StartWatchdog запускает сторожа, следящего за текущим процессом. Возвращает
// функцию остановки: её вызывают при ШТАТНОМ выходе, когда клиент уже прибрался.
func StartWatchdog() (stop func(), err error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(exe, "-"+WatchdogFlag, fmt.Sprint(os.Getpid()))
	// Своя сессия: сторож не в группе процессов клиента.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	proc := cmd.Process
	return func() {
		if proc != nil {
			_ = proc.Kill()
			_, _ = proc.Wait()
		}
	}, nil
}

// RunWatchdog — тело сторожа: дождаться смерти родителя pid и прибраться.
func RunWatchdog(pid int) (netsetup.CleanupReport, error) {
	for os.Getppid() == pid {
		time.Sleep(500 * time.Millisecond)
	}
	return netsetup.Cleanup()
}
