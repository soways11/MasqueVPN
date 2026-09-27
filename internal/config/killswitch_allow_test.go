package config

import (
	"net/netip"
	"testing"
)

// TestKillSwitchAllowed — разбор списка исключений аварийного отключения.
//
// Поле появилось после того, как kill switch на живой машине молча обрубил
// стороннее прокси-соединение: наружу он пропускал только адрес сервера, а
// узнать об этом можно было лишь снаружи. Принимать надо и адрес, и подсеть —
// иначе пользователю придётся перечислять адреса по одному.
func TestKillSwitchAllowed(t *testing.T) {
	c := &Client{KillSwitchAllow: []string{
		"203.0.113.7",
		"198.51.100.0/24",
		"2001:db8::1",
		"2001:db8:1::/48",
	}}
	got, err := c.KillSwitchAllowed()
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("203.0.113.7/32"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("2001:db8::1/128"),
		netip.MustParsePrefix("2001:db8:1::/48"),
	}
	if len(got) != len(want) {
		t.Fatalf("разобрано %d записей, ожидалось %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("запись %d: %v, ожидалось %v", i, got[i], want[i])
		}
	}
}

// Мусор должен отвергаться при чтении конфигурации, а не превращаться в
// молча пропущенную строку: пользователь считал бы, что исключение работает.
func TestKillSwitchAllowedRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"не адрес", "1.2.3", "1.2.3.4/33", ""} {
		c := &Client{KillSwitchAllow: []string{bad}}
		if _, err := c.KillSwitchAllowed(); err == nil {
			t.Errorf("%q принято как адрес", bad)
		}
	}
}

// Пустой список — не ошибка: исключения нужны не всем.
func TestKillSwitchAllowedEmpty(t *testing.T) {
	c := &Client{}
	got, err := c.KillSwitchAllowed()
	if err != nil || len(got) != 0 {
		t.Fatalf("пустой список: %v (%v)", got, err)
	}
}

// TestKillSwitchDefault — аварийное отключение включено по умолчанию при
// полном туннеле и не включается при раздельном.
//
// Поле — указатель именно ради этого: обычный bool не отличал бы «не
// задано» от «выключено», и выключить включённое по умолчанию было бы
// нечем, а старые конфигурации молча поменяли бы смысл.
func TestKillSwitchDefault(t *testing.T) {
	yes, no := true, false

	full := &Client{FullTunnel: &yes}
	full.Defaults()
	if full.KillSwitch == nil || !*full.KillSwitch {
		t.Error("при полном туннеле аварийное отключение должно быть включено по умолчанию")
	}

	split := &Client{FullTunnel: &no}
	split.Defaults()
	if split.KillSwitch == nil || *split.KillSwitch {
		t.Error("при раздельном туннеле аварийное отключение не должно включаться: " +
			"оно отрезало бы трафик, который сознательно оставлен вне туннеля")
	}

	// Явное выключение уважается — иначе включённое по умолчанию нечем было
	// бы отменить.
	off := &Client{FullTunnel: &yes, KillSwitch: &no}
	off.Defaults()
	if off.KillSwitch == nil || *off.KillSwitch {
		t.Error("явный false перебит умолчанием")
	}

	// И умолчание полного туннеля тоже включает защиту: full_tunnel не задан,
	// но по умолчанию он true.
	bare := &Client{}
	bare.Defaults()
	if bare.KillSwitch == nil || !*bare.KillSwitch {
		t.Error("в конфигурации из трёх полей аварийное отключение оказалось выключено")
	}
}
