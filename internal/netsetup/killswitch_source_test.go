package netsetup

import (
	"strings"
	"testing"
)

// Аварийное отключение на Linux исполняется только на живой машине с nftables,
// а стеречь его решения надо отовсюду. Поэтому тест читает исходник и проверяет
// именно то, чем закрывается утечка и запирание сети. Каждая проверка снабжена
// мутацией, которая её роняет.

// ksLive оставляет только живой код: строки-комментарии отбрасываются, иначе
// закомментированная строка по-прежнему «содержала бы» проверяемый вызов, и
// страж молча перестал бы стеречь (проект уже ловил это мутацией, см. hasCall).
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

func mustContain(t *testing.T, src, sub, why string) {
	t.Helper()
	if !strings.Contains(ksLive(src), sub) {
		t.Errorf("в живом коде нет %q — %s", sub, why)
	}
}

func TestKillSwitchLinuxDecisions(t *testing.T) {
	src := readSource(t, "killswitch_linux.go")

	// Политика цепочки — drop: всё, что явно не разрешили, роняется. Мутация:
	// ChainPolicyAccept — и блокировка перестаёт блокировать.
	mustContain(t, src, "ChainPolicyDrop", "цепочка должна ронять всё по умолчанию")
	mustContain(t, src, "ChainHookOutput", "фильтруем исходящий трафик")
	mustContain(t, src, "expr.VerdictAccept", "разрешающие правила пропускают явным accept")

	// Помеченный сокет клиента (QUIC к серверу и DNS-прикрытие идут с меткой):
	// без этого правила клиент не достучится до сервера под собственной
	// блокировкой. Мутация: убрать правило по метке.
	mustContain(t, src, "MetaKeyMARK", "помеченный сокет клиента должен проходить")

	// Уже установленные соединения и связанные с ними. Мутация: убрать ct.
	mustContain(t, src, "CtStateBitESTABLISHED", "established должен проходить")
	mustContain(t, src, "CtStateBitRELATED", "related должен проходить")

	// Петля и туннель.
	mustContain(t, src, `ifname("lo")`, "петля должна проходить")
	mustContain(t, src, "ifname(k.iface)", "трафик в туннель должен проходить")

	// Совпадение именно по адресу НАЗНАЧЕНИЯ (daddr), а не источника: смещения
	// поля 16/4 для IPv4 и 24/16 для IPv6. Мутация: взять saddr (12/8) — и
	// разрешения лягут не по той стороне пакета.
	mustContain(t, src, "var off, l uint32 = 16, 4", "IPv4-разрешения — по адресу назначения")
	mustContain(t, src, "unix.NFPROTO_IPV6, 24, 16", "IPv6-разрешения — по адресу назначения")

	// Reapply атомарен: очистка цепочки и новые правила в одной транзакции
	// (FlushChain + AddRule + Flush), политика drop при этом сохраняется.
	// Мутация: заменить FlushChain на снятие/поднятие таблицы — появится
	// промежуток «drop без разрешений» либо «без блокировки».
	mustContain(t, src, "c.FlushChain(ch)", "Reapply меняет правила атомарно, не снимая политику")

	// Имя своей таблицы — чужие правила не трогаем.
	mustContain(t, src, `killSwitchTable = "masquevpn_ks"`, "блокировка живёт в своей таблице")
}

func TestKillSwitchLinuxCleanup(t *testing.T) {
	src := readSource(t, "netsetup_linux.go")

	// Уборка снимает аварийную блокировку — иначе упавший клиент запер бы сеть.
	// Мутация: убрать вызов из Cleanup.
	if !strings.Contains(src, "func Cleanup()") {
		t.Fatal("нет Cleanup — уборка следов обязательна")
	}
	cleanup := src[strings.Index(src, "func Cleanup()"):]
	mustContain(t, cleanup, "removeKillSwitch()",
		"Cleanup обязан снимать аварийную блокировку, а не только чинить DNS")
	mustContain(t, src, "var removeKillSwitch = removeKillSwitchTable",
		"в Cleanup должна идти настоящая функция снятия, подмена — только в тестах")

	// Прежняя команда снятия тоже реально снимает таблицу.
	mustContain(t, src, "func KillSwitchOff()", "команда снятия должна остаться")
}
