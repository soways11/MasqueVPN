//go:build !windows && !linux

package clientrun

import "github.com/soways11/masquevpn/internal/netsetup"

// WatchdogFlag — см. реализацию для Windows.
const WatchdogFlag = "watchdog"

// StartWatchdog — заглушка: сторож нужен только на Windows, где правило
// разрешения имён и маршрут-исключение переживают смерть процесса. На Linux
// маршруты и правила лежат в своей таблице, а сокет помечается меткой —
// после аварии их перезаписывает следующий запуск.
func StartWatchdog() (func(), error) { return func() {}, nil }

// RunWatchdog — заглушка.
func RunWatchdog(int) (netsetup.CleanupReport, error) { return netsetup.CleanupReport{}, nil }
