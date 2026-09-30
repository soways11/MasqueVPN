//go:build linux

package netsetup

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// Уборка DNS не зависит от уборки блокировки: ошибка nftables не должна
// оставить машину с DNS упавшего туннеля. А отсутствие прав на nftables
// (запуск не от root) — не ошибка, а оговорка в отчёте: снять root-таблицу
// без прав всё равно нельзя. Так было найдено CI, где тесты идут не от root:
// уборка падала на netlink и не возвращала resolv.conf.
func TestCleanupDNSDespiteKillSwitchError(t *testing.T) {
	for _, c := range []struct {
		name      string
		ksErr     error
		wantErr   bool
		unchecked bool
	}{
		{"нет прав", fmt.Errorf("netlink receive: %w", unix.EPERM), false, true},
		{"другая ошибка", errors.New("netlink: сломалось"), true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			old := ResolvConf
			ResolvConf = filepath.Join(dir, "resolv.conf")
			oldRemove := removeKillSwitch
			removeKillSwitch = func() (bool, error) { return false, c.ksErr }
			t.Cleanup(func() { ResolvConf, removeKillSwitch = old, oldRemove })

			const original = "nameserver 192.168.1.1\n"
			if err := os.WriteFile(ResolvConf, []byte(original), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := SetDNS([]netip.Addr{netip.MustParseAddr("1.1.1.1")}); err != nil {
				t.Fatal(err)
			}

			rep, err := Cleanup()
			if (err != nil) != c.wantErr {
				t.Fatalf("ошибка %v, ждали ошибку=%v", err, c.wantErr)
			}
			if !rep.DNS {
				t.Fatal("DNS не восстановлен из-за ошибки блокировки")
			}
			if got, _ := os.ReadFile(ResolvConf); string(got) != original {
				t.Fatalf("resolv.conf: %q", got)
			}
			if rep.KillSwitchUnchecked != c.unchecked {
				t.Fatalf("отметка «не проверена» = %v", rep.KillSwitchUnchecked)
			}
			if c.unchecked && !strings.Contains(rep.String(), "нужен root") {
				t.Fatalf("отчёт молчит о непроверенной блокировке: %s", rep)
			}
		})
	}
}
