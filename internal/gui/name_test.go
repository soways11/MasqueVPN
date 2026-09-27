package gui

import (
	"strings"
	"testing"

	"github.com/soways11/masquevpn/internal/config"
)

// TestLinkSchemeMatchesConfig — схема, которую окно пишет на кнопке, должна
// совпадать с той, что разбирает клиент.
//
// Пакет gui намеренно ничего не знает об устройстве клиента и держит схему
// своей строкой. Цена этого — возможность разойтись: на кнопке будет
// написано одно, а приниматься будет другое. Тест закрывает именно её.
func TestLinkSchemeMatchesConfig(t *testing.T) {
	if LinkScheme != config.LinkScheme {
		t.Errorf("в окне схема %q, а клиент принимает %q", LinkScheme, config.LinkScheme)
	}
}

// TestAppNameConsistent — имя не должно разъехаться между логотипом и
// подписями: две разные надписи читаются как две разные программы.
func TestAppNameConsistent(t *testing.T) {
	if !strings.EqualFold(AppName, AppWordmark) {
		t.Errorf("логотип %q и имя %q — разные слова", AppWordmark, AppName)
	}
	if AppWordmark != upperRu(AppWordmark) {
		t.Errorf("логотип %q набран не заглавными", AppWordmark)
	}
	if !strings.HasPrefix(LinkScheme, strings.ToLower(AppName)) {
		t.Errorf("схема ссылки %q не связана с именем %q", LinkScheme, AppName)
	}
}

// TestWordmarkFits — имя длиннее прежнего, и оно рисуется с разрядкой:
// проверяем, что логотип не упирается в шестерёнку.
func TestWordmarkFits(t *testing.T) {
	m := MainLayout(false, 2)
	// Логотипу отведено место до первой кнопки в шапке, а не вся его
	// ширина: кнопок там теперь две.
	avail := m.Plus.X - m.Logo.X - 12
	fits(t, "логотип", AppWordmark, FaceLogo, avail)
	fits(t, "подпись окна", AppName+" · MASQUE CONNECT-IP", FaceFooter, m.Footer.W)
	fits(t, "кнопка добавления", "+  Добавить по ссылке "+LinkScheme+"://", FaceRow,
		SettingsLayout(1).AddProfile.W-2*15)
}
