//go:build linux

package netsetup

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Уборка после упавшего клиента: DNS туннеля не должен оставаться в системе
// до следующего запуска.
func TestCleanupRestoresDNSAfterCrash(t *testing.T) {
	dir := t.TempDir()
	old := ResolvConf
	ResolvConf = filepath.Join(dir, "resolv.conf")
	t.Cleanup(func() { ResolvConf = old })

	const original = "nameserver 192.168.1.1\n"
	if err := os.WriteFile(ResolvConf, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	// Клиент подменил DNS — и «упал», не вызвав восстановление.
	if _, err := SetDNS([]netip.Addr{netip.MustParseAddr("1.1.1.1")}); err != nil {
		t.Fatal(err)
	}

	rep, err := Cleanup()
	if err != nil {
		t.Fatal(err)
	}
	if !rep.DNS || !strings.Contains(rep.String(), "DNS") {
		t.Fatalf("уборка ничего не сделала: %+v", rep)
	}
	got, _ := os.ReadFile(ResolvConf)
	if string(got) != original {
		t.Fatalf("resolv.conf после уборки: %q, ожидался исходный", got)
	}

	// Повторная уборка — нечего убирать, и это не ошибка.
	if rep, err := Cleanup(); err != nil || !rep.Empty() {
		t.Fatalf("повторная уборка: %+v %v", rep, err)
	}
}

// Давняя резервная копия рядом с уже чужим resolv.conf — не трогаем: иначе
// затёрли бы настройку, сделанную после падения клиента.
func TestCleanupLeavesForeignResolvConf(t *testing.T) {
	dir := t.TempDir()
	old := ResolvConf
	ResolvConf = filepath.Join(dir, "resolv.conf")
	t.Cleanup(func() { ResolvConf = old })

	const fresh = "nameserver 10.0.0.53\n"
	os.WriteFile(ResolvConf, []byte(fresh), 0o644)
	os.WriteFile(ResolvConf+backupSuffix, []byte("nameserver 8.8.8.8\n"), 0o644)

	if _, err := Cleanup(); err == nil {
		t.Fatal("уборка молча прошла над чужим resolv.conf")
	}
	got, _ := os.ReadFile(ResolvConf)
	if string(got) != fresh {
		t.Fatalf("чужой resolv.conf затёрт: %q", got)
	}
}

// Клиент версии до переименования упал и оставил resolv.conf со своей
// меткой и копию с суффиксом .govpn-backup. Обновлённая уборка обязана их
// узнать и вернуть оригинал — иначе после обновления DNS туннеля остался
// бы в системе навсегда.
func TestCleanupRestoresLegacyBackup(t *testing.T) {
	dir := t.TempDir()
	old := ResolvConf
	ResolvConf = filepath.Join(dir, "resolv.conf")
	t.Cleanup(func() { ResolvConf = old })

	const original = "nameserver 192.168.1.1\n"
	os.WriteFile(ResolvConf, []byte(legacyDNSMarker+" на время работы туннеля\nnameserver 1.1.1.1\n"), 0o644)
	os.WriteFile(ResolvConf+legacyBackupSuffix, []byte(original), 0o644)

	// Резолверы системы берутся из копии, а не из подменённого файла.
	if got, err := SystemResolvers(); err != nil || len(got) != 1 || got[0].String() != "192.168.1.1" {
		t.Fatalf("резолверы при подмене прежней версией: %v %v", got, err)
	}
	rep, err := Cleanup()
	if err != nil || !rep.DNS {
		t.Fatalf("прежняя копия не восстановлена: %+v %v", rep, err)
	}
	if got, _ := os.ReadFile(ResolvConf); string(got) != original {
		t.Fatalf("resolv.conf: %q", got)
	}
}
