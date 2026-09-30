package main

import (
	"os"
	"strings"
	"testing"
)

// Окно на Linux обязано уметь быть сторожем: клиент запускает копию СЕБЯ
// (os.Executable) с -watchdog <pid>, и у тех, кто пользуется окном, этой
// копией оказывается masquevpn-gui. Без ветки сторожа копия открыла бы второе
// окно и не сняла бы аварийную блокировку после краха.
//
// Мутации, которые роняют тест: убрать ветку сторожа; перенести её ниже
// загрузки шрифтов и открытия окна (сторожу без дисплея нельзя трогать X11);
// закомментировать вызов.

func TestGUIIsWatchdog(t *testing.T) {
	b, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	var live strings.Builder
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		live.WriteString(line + "\n")
	}
	src := live.String()

	main := strings.Index(src, "func main() {")
	if main < 0 {
		t.Fatal("нет func main")
	}
	body := src[main:]
	wd := strings.Index(body, "clientrun.RunWatchdog(pid)")
	if wd < 0 {
		t.Fatal("окно не умеет быть сторожем: нет вызова clientrun.RunWatchdog(pid) в main")
	}
	for _, later := range []string{"guiraster.LoadFonts()", "openWindow("} {
		if i := strings.Index(body, later); i >= 0 && i < wd {
			t.Errorf("ветка сторожа должна идти ДО %s: сторожу не нужен дисплей", later)
		}
	}
	if !strings.Contains(src, "func watchdogPID() (int, bool)") {
		t.Error("нет разбора служебного -watchdog <pid>")
	}
}
