package config

import "testing"

// TestDefaultServerProfileIsStock закрепляет легенду «Caddy»: по умолчанию
// (и при явном "stock") сервер отдаёт транспортные параметры quic-go, то есть
// профиль не подставляется (nil). Мутация: вернуть Captured()/CDNLike() в
// ветке умолчания — тест падает.
func TestDefaultServerProfileIsStock(t *testing.T) {
	for _, name := range []string{"", "stock"} {
		c := &Server{ServerProfile: name}
		p, err := c.Profile()
		if err != nil {
			t.Fatalf("server_profile %q: %v", name, err)
		}
		if p != nil {
			t.Errorf("server_profile %q: ожидался nil (stock/Caddy), получен %+v", name, *p)
		}
	}
	// cloudflare остаётся выбираемым и непустым — на случай сравнения.
	c := &Server{ServerProfile: "cloudflare"}
	p, err := c.Profile()
	if err != nil {
		t.Fatalf("cloudflare: %v", err)
	}
	if p == nil {
		t.Fatal("server_profile cloudflare: ожидался профиль, получен nil")
	}
	// неизвестное имя — ошибка
	if _, err := (&Server{ServerProfile: "nope"}).Profile(); err == nil {
		t.Error("неизвестный server_profile должен давать ошибку")
	}
}
