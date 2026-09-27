//go:build windows

package main

// Отчёт о падении.
//
// Программа собрана без консоли (-H=windowsgui). Значит, любая паника — это
// просто молча не открывшееся окно: ни сообщения, ни кода возврата, ни
// строчки в журнале. Человек видит, что «не запускается», и сказать об этом
// может только так.
//
// Поэтому паника перехватывается в двух местах и оба раза оставляет след:
// файл рядом с программой и окно с первой строкой ошибки.
//
// Второе место — оконная процедура. Она вызывается из Windows, и паника в
// ней не разматывается обратно в Go: процесс падает целиком, без вывода.
// Перехват внутри неё обязателен, и это не перестраховка — один такой
// случай стоит вечера разбирательств.

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/soways11/masquevpn/internal/gui"
)

// crashFile — куда писать отчёт: рядом с программой, чтобы его не пришлось
// искать. В ProgramData было бы «правильнее», но человек, у которого не
// запускается программа, ищет файл там, где лежит она сама.
func crashFile() string {
	exe, err := os.Executable()
	if err != nil {
		return "masquevpn-crash.txt"
	}
	return filepath.Join(filepath.Dir(exe), "masquevpn-crash.txt")
}

// reportPanic записывает отчёт и показывает окно с сообщением.
//
// where — что делала программа: по нему видно, упала она при запуске или
// уже в работе, а это первое, что нужно знать.
func reportPanic(where string, v any) {
	stack := debug.Stack()
	report := fmt.Sprintf("%s\n%s: %v\n\nверсия: %s\n\n%s\n",
		time.Now().Format(time.RFC3339), where, v, buildInfo(), stack)
	_ = os.WriteFile(crashFile(), []byte(report), 0o600)

	messageBox(0, fmt.Sprintf("%s не смог продолжить работу.\n\n%v\n\nПодробности записаны в файл:\n%s",
		gui.AppName, v, crashFile()), gui.AppName, mbOK|mbIconError)
}

// guard перехватывает панику в обычной горутине.
func guard(where string) {
	if v := recover(); v != nil {
		reportPanic(where, v)
		os.Exit(1)
	}
}

// Трассировка запуска: по шагам, в файл рядом с программой.
//
// Включается ключом -trace и нужна ровно в одном случае — когда окно не
// появляется и непонятно, дошло ли дело до него. Паника оставляет отчёт
// сама, но если процесс убит снаружи (антивирусом, политикой), отчёта не
// будет: останется след из шагов, оборванный на последнем.
var traceEnabled bool

func traceInit() {
	for _, a := range os.Args[1:] {
		if a == "-trace" || a == "--trace" {
			traceEnabled = true
		}
	}
	if traceEnabled {
		_ = os.WriteFile(tracePath(), []byte(time.Now().Format(time.RFC3339)+
			" запуск, "+buildInfo()+"\n"), 0o600)
	}
}

func tracePath() string {
	exe, err := os.Executable()
	if err != nil {
		return "masquevpn-trace.txt"
	}
	return filepath.Join(filepath.Dir(exe), "masquevpn-trace.txt")
}

func trace(step string) {
	if !traceEnabled {
		return
	}
	f, err := os.OpenFile(tracePath(), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s\n", time.Now().Format("15:04:05.000"), step)
}

// buildInfo — из чего собрана программа. В отчёте о падении это первое,
// что спрашивают: та ли это версия, о которой речь.
func buildInfo() string {
	info := []string{"masquevpn"}
	if exe, err := os.Executable(); err == nil {
		if st, err := os.Stat(exe); err == nil {
			info = append(info, "файл от "+st.ModTime().Format("2006-01-02 15:04"))
		}
	}
	return strings.Join(info, ", ")
}
