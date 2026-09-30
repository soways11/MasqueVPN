package gui

import (
	"testing"
	"time"
)

func TestFormatRTT(t *testing.T) {
	for _, c := range []struct {
		d    time.Duration
		want string
	}{
		{0, "<1 мс"},
		{900 * time.Microsecond, "<1 мс"},
		{42 * time.Millisecond, "42 мс"},
		{999 * time.Millisecond, "999 мс"},
		{1234 * time.Millisecond, "1,2 с"},
		{9999 * time.Millisecond, "9,9 с"},
		{12 * time.Second, ">10 с"},
	} {
		if got := FormatRTT(c.d); got != c.want {
			t.Errorf("FormatRTT(%v) = %q, ждали %q", c.d, got, c.want)
		}
	}
}

func TestPingLabel(t *testing.T) {
	for _, c := range []struct {
		p     ProfileItem
		label string
		color Color
	}{
		{ProfileItem{}, "пинг", ColorDim},
		{ProfileItem{Ping: PingBusy}, "…", ColorDim},
		{ProfileItem{Ping: PingOK, RTT: 38 * time.Millisecond}, "38 мс", ColorAccent},
		{ProfileItem{Ping: PingFail}, "нет", ColorDanger},
	} {
		if c.p.PingLabel() != c.label || c.p.PingColor() != c.color {
			t.Errorf("%+v: %q/%v", c.p, c.p.PingLabel(), c.p.PingColor())
		}
	}
	if (View{}).PingAllLabel() != "Пинг всех" || (View{PingingAll: true}).PingAllLabel() != "Пинг…" {
		t.Error("надпись «Пинг всех»")
	}
}
