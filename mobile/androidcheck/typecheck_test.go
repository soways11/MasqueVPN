package androidcheck

// Проверка типов Kotlin без Android SDK.
//
// Компилятор Kotlin берётся с GitHub (он там публикуется), привязка ядра —
// из gobind (чистый Go), а вместо android.jar — заглушки из stubs/: только
// те классы и методы, которые вызывает приложение, с настоящими сигнатурами.
// R.java генерируется здесь же из res/.
//
// Что это ловит: опечатки в своих именах, Long вместо Int там, где gomobile
// превратил int в long, nullable там, где нужен не-null, неверное число
// аргументов у методов ядра, забытый импорт. Что не ловит: ошибку в самой
// заглушке — если метод Android описан в stubs/ неверно, проверка поверит
// заглушке. Поэтому заглушки держатся минимальными и повторяют документацию
// Android буква в букву, а окончательное слово — за настоящей сборкой.
//
// Тест тяжёлый и требует трёх вещей снаружи, поэтому без них пропускается:
//
//	KOTLINC=/путь/kotlinc/bin/kotlinc      (github.com/JetBrains/kotlin/releases)
//	GOBIND=/путь/gobind                     (см. mobile/core/BINDINGS.md)
//	GOMOBILE_SRC=/путь/к/исходникам/golang/mobile  (для go/Seq.java)
//
//	KOTLINC=… GOBIND=… GOMOBILE_SRC=… go test ./mobile/androidcheck -run TypeCheck -v

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestKotlinTypeCheck(t *testing.T) {
	kotlinc, gobind, mobileSrc := os.Getenv("KOTLINC"), os.Getenv("GOBIND"), os.Getenv("GOMOBILE_SRC")
	if kotlinc == "" || gobind == "" || mobileSrc == "" {
		t.Skip("нужны KOTLINC, GOBIND и GOMOBILE_SRC — см. комментарий в начале файла")
	}
	work := t.TempDir()

	// 1. Привязка ядра к Java — та же, что соберёт gomobile bind.
	bindOut := filepath.Join(work, "bind")
	run(t, "", "env", "GOTOOLCHAIN=local", gobind, "-lang=java", "-outdir="+bindOut,
		"github.com/soways11/masquevpn/mobile/core")
	seq, err := os.ReadFile(filepath.Join(mobileSrc, "bind", "java", "Seq.java"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bindOut, "java", "go", "Seq.java"), seq, 0o644); err != nil {
		t.Fatal(err)
	}

	// 2. R.java из ресурсов.
	res, _ := collect(t)
	rDir := filepath.Join(work, "r", "io", "masquevpn", "android")
	if err := os.MkdirAll(rDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rDir, "R.java"), []byte(rJava(res)), 0o644); err != nil {
		t.Fatal(err)
	}

	// 3. Заглушки Android + привязка + R → классы.
	var javaFiles []string
	for _, root := range []string{"stubs", filepath.Join(bindOut, "java"), filepath.Join(work, "r")} {
		filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() && strings.HasSuffix(p, ".java") {
				javaFiles = append(javaFiles, p)
			}
			return nil
		})
	}
	classes := filepath.Join(work, "classes")
	run(t, "", append([]string{"javac", "-nowarn", "-proc:none", "-d", classes}, javaFiles...)...)

	// 4. Kotlin против всего этого.
	var kt []string
	for p := range kotlinFiles(t) {
		kt = append(kt, p)
	}
	sort.Strings(kt)
	out, err := exec.Command(kotlinc, append([]string{"-cp", classes, "-d", filepath.Join(work, "kt"),
		"-jvm-target", "17", "-nowarn"}, kt...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("Kotlin не компилируется:\n%s", out)
	}
	t.Logf("Kotlin скомпилирован против заглушек Android и привязки ядра (%d файлов)", len(kt))
}

// rJava — класс R с тем, что объявлено в res/. Значения идентификаторов
// условные: проверяется только, что имя существует и какого оно типа.
func rJava(res resources) string {
	var b strings.Builder
	b.WriteString("package io.masquevpn.android;\npublic final class R {\n")
	types := make([]string, 0, len(res))
	for typ := range res {
		types = append(types, typ)
	}
	sort.Strings(types)
	n := 0x7f000000
	for _, typ := range types {
		fmt.Fprintf(&b, "  public static final class %s {\n", typ)
		names := make([]string, 0, len(res[typ]))
		for name := range res[typ] {
			names = append(names, strings.ReplaceAll(name, ".", "_"))
		}
		sort.Strings(names)
		for _, name := range names {
			n++
			fmt.Fprintf(&b, "    public static final int %s = %d;\n", name, n)
		}
		b.WriteString("  }\n")
	}
	b.WriteString("}\n")
	return b.String()
}

func run(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		// gobind жалуется на отсутствие golang.org/x/mobile/bind — это про
		// go-шную обвязку, Java-часть при этом создаётся.
		if strings.Contains(args[len(args)-1], "mobile/core") && strings.Contains(string(out), "mobile/bind") {
			return
		}
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
}
