package netsetup

import (
	"os"
	"strings"
	"testing"
)

// Страж конструкции аварийного отключения.
//
// Код ниже исполняется только на Windows, а проверять его надо отовсюду:
// ошибка здесь стоит дороже обычной. Первая версия kill switch ставила
// ПЕРСИСТЕНТНЫЕ фильтры WFP и снимала их удалением подслоя. На живой машине
// это заперло пользователя без сети, и перезагрузка не помогала: Windows не
// удаляет подслой, пока в нём есть фильтры (FWP_E_IN_USE), — снятие молча не
// делало ничего, а фильтры переживали ребут.
//
// Тест читает исходник и следит, чтобы те решения, которыми это лечилось, не
// вернулись назад по недосмотру. Обычным тестом их не поймать: для этого
// нужен настоящий WFP.
func TestKillSwitchConstruction(t *testing.T) {
	b, err := os.ReadFile("killswitch_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)

	t.Run("фильтры и подслой не персистентны", func(t *testing.T) {
		// Флаг FWPM_*_FLAG_PERSISTENT (0x00000001) не должен ни объявляться,
		// ни попадать в поля flags структур подслоя и фильтра.
		for _, bad := range []string{"flagPersistent", "FLAG_PERSISTENT = 0x"} {
			if strings.Contains(src, bad) {
				t.Errorf("в коде снова есть %q — персистентные фильтры переживают "+
					"перезагрузку и запирают машину без сети", bad)
			}
		}
	})

	t.Run("движок открывается динамической сессией", func(t *testing.T) {
		if !strings.Contains(src, "sessionFlagDynamic = 0x00000001") {
			t.Error("нет флага динамической сессии — на нём держится всё: объекты " +
				"WFP должны исчезать вместе с процессом клиента")
		}
		if !strings.Contains(src, "flags:       sessionFlagDynamic") {
			t.Error("флаг динамической сессии не попадает в FWPM_SESSION0")
		}
		if !strings.Contains(src, "func KillSwitchArm(") {
			t.Error("нет KillSwitchArm — блокировка должна возвращать объект, " +
				"держащий дескриптор движка, иначе её некому снять")
		}
		if strings.Contains(src, "func KillSwitchOn(") {
			t.Error("вернулся KillSwitchOn: «поставил и забыл» означает, что " +
				"блокировку никто не держит, и снимать её нечем")
		}
	})

	t.Run("снятие удаляет фильтры до подслоя", func(t *testing.T) {
		off := section(src, "func KillSwitchOff()")
		if off == "" {
			t.Fatal("не найдена KillSwitchOff")
		}
		iFilters := strings.Index(off, "deleteOurFilters")
		iSubLayer := strings.Index(off, "procFwpmSubLayerDel0")
		switch {
		case iFilters < 0:
			t.Error("KillSwitchOff не удаляет фильтры — подслой не уйдёт, пока они есть")
		case iSubLayer < 0:
			t.Error("KillSwitchOff не удаляет подслой")
		case iFilters > iSubLayer:
			t.Error("подслой удаляется раньше фильтров: Windows ответит FWP_E_IN_USE, " +
				"и снятие снова окажется пустышкой")
		}
	})

	t.Run("оба кода отсутствия считаются отсутствием", func(t *testing.T) {
		for _, code := range []string{"0x80320003", "0x80320007"} {
			if !strings.Contains(src, code) {
				t.Errorf("код %s не учтён: снятие несуществующей блокировки будет "+
					"выглядеть ошибкой и ронять самопроверку", code)
			}
		}
	})

	t.Run("разрешения не ограничены сервером", func(t *testing.T) {
		// Первая версия пропускала наружу только адрес сервера. На живой
		// машине это молча обрубило стороннее прокси-соединение, а заодно
		// упёрлось бы прикрытие DNS: его запросы обязаны идти к резолверу
		// провайдера мимо туннеля, иначе они не прикрытие.
		if !strings.Contains(src, "func KillSwitchArm(tunLUID uint64, allow []netip.Prefix)") {
			t.Error("KillSwitchArm не принимает список разрешённых адресов")
		}
		if !strings.Contains(src, "func filterPlan(tunLUID uint64, allow []netip.Prefix)") {
			t.Error("filterPlan не принимает список разрешённых адресов")
		}
		run := readSource(t, "../clientrun/run_windows.go")
		if !hasCall(run, "cfg.KillSwitchAllowed()") {
			t.Error("клиент не читает kill_switch_allow из конфигурации")
		}
		// И список дополняется резолверами прикрытия уже после поднятия
		// туннеля — раньше их адреса неизвестны. Ищем именно пополнение
		// списка: просто «есть вызов Reapply ниже по файлу» ловится на
		// переустановке при переезде сервера, это проверено мутацией.
		if !hasCall(run, "ksAllow = append(ksAllow, allowList(resolvers") {
			t.Error("резолверы прикрытия DNS не попадают в список разрешённых — " +
				"их запросы упрутся в собственную блокировку")
		}
	})

	t.Run("применение идёт одной транзакцией", func(t *testing.T) {
		if !strings.Contains(src, "procFwpmTransBegin0") ||
			!strings.Contains(src, "procFwpmTransAbort0") ||
			!strings.Contains(src, "procFwpmTransCommit0") {
			t.Error("нет транзакции WFP: блокировка может встать без разрешений, " +
				"и машина останется без сети")
		}
	})
}

// section возвращает тело функции от её заголовка до закрывающей скобки в
// начале строки.
func section(src, header string) string {
	i := strings.Index(src, header)
	if i < 0 {
		return ""
	}
	rest := src[i:]
	if j := strings.Index(rest, "\n}\n"); j >= 0 {
		return rest[:j]
	}
	return rest
}
