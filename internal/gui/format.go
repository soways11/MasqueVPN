package gui

import (
	"fmt"
	"strings"
	"time"
)

// Форматирование чисел для окна.
//
// Числа в интерфейсе читают краем глаза, поэтому здесь всюду три значащие
// цифры и запятая как десятичный разделитель: «1,24 ГБ» читается сразу, а
// «1331439861 B» приходится разбирать.

// Bytes форматирует объём: 1,24 ГБ.
func Bytes(n uint64) string {
	const k = 1024
	switch {
	case n < k:
		return fmt.Sprintf("%d Б", n)
	case n < k*k:
		return decimal(float64(n)/k, "КБ")
	case n < k*k*k:
		return decimal(float64(n)/(k*k), "МБ")
	case n < k*k*k*k:
		return decimal(float64(n)/(k*k*k), "ГБ")
	default:
		return decimal(float64(n)/(k*k*k*k), "ТБ")
	}
}

// Rate форматирует скорость, заданную в байтах в секунду, как биты в
// секунду: провайдеры, роутеры и сам человек меряют канал в мегабитах, и
// показывать рядом мегабайты — значит заставить его делить на восемь.
//
// Приставки здесь десятичные (1000), а не двоичные: мегабит — это ровно
// миллион бит, так считают все, кто продаёт каналы.
func Rate(bytesPerSec float64) string {
	bits := bytesPerSec * 8
	switch {
	case bits < 1000:
		return fmt.Sprintf("%.0f бит/с", bits)
	case bits < 1000*1000:
		return decimal(bits/1000, "Кбит/с")
	case bits < 1000*1000*1000:
		return decimal(bits/(1000*1000), "Мбит/с")
	default:
		return decimal(bits/(1000*1000*1000), "Гбит/с")
	}
}

// decimal печатает число с одним знаком после запятой, но только пока оно
// меньше десяти: «9,8 МБ» полезно, «938,4 МБ» — нет, там десятые уже шум.
func decimal(v float64, unit string) string {
	if v < 10 {
		return strings.Replace(fmt.Sprintf("%.1f %s", v, unit), ".", ",", 1)
	}
	return fmt.Sprintf("%.0f %s", v, unit)
}

// Duration форматирует длительность сессии: 04:12, а за час — 1:02:33.
func Duration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	total := int(d / time.Second)
	h, m, s := total/3600, (total/60)%60, total%60
	if h > 0 {
		return fmt.Sprintf("%d:%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("%02d:%02d", m, s)
}

// Host отрезает у «домен:порт» порт: в карточке важен домен, а порт почти
// всегда 443 и только занимает место. Адреса IPv6 в скобках остаются целыми.
func Host(server string) string {
	if server == "" {
		return "—"
	}
	if i := strings.LastIndex(server, ":"); i > 0 && !strings.Contains(server[i:], "]") {
		if !strings.Contains(server[:i], ":") || strings.HasSuffix(server[:i], "]") {
			return strings.Trim(server[:i], "[]")
		}
	}
	return server
}

// Ellipsis укорачивает строку до n знаков, ставя в конце многоточие. Нужен
// для длинных доменов и имён профилей: обрезать по краю окна значило бы, что
// человек не понимает, обрезано оно или так и есть.
func Ellipsis(s string, n int) string {
	r := []rune(s)
	if n <= 1 || len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
