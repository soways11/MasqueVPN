//go:build linux

// Package netnstest запускает тесты в собственном сетевом пространстве имён.
//
// Тесты TUN и netlink меняют настоящую сеть: создают интерфейсы, маршруты,
// правила и таблицы nf_tables. Чтобы не трогать сеть машины, тестовый бинарник
// перезапускает сам себя с CLONE_NEWNET — без внешних утилит (unshare, ip).
// Без root тесты пропускаются.
package netnstest

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink"
)

const envMarker = "MASQUEVPN_IN_NETNS"

// Main — замена m.Run() в TestMain.
func Main(m *testing.M) {
	if os.Getenv(envMarker) == "1" {
		if lo, err := netlink.LinkByName("lo"); err == nil {
			_ = netlink.LinkSetUp(lo)
		}
		os.Exit(m.Run())
	}
	if os.Geteuid() != 0 {
		// Тесты сами вызовут Require и пропустятся.
		os.Exit(m.Run())
	}
	cmd := exec.Command("/proc/self/exe", os.Args[1:]...)
	cmd.Env = append(os.Environ(), envMarker+"=1")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		fmt.Fprintln(os.Stderr, "netnstest: не удалось создать netns:", err)
		os.Exit(1)
	}
	os.Exit(0)
}

// Require пропускает тест, если он запущен не в отдельном netns.
func Require(t testing.TB) {
	t.Helper()
	if os.Getenv(envMarker) != "1" {
		t.Skip("нужен root: тест выполняется в отдельном network namespace")
	}
}
