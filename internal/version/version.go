// Package version — версия сборки masquevpn.
//
// Задаётся при сборке установщиков и пакетов (deploy/*):
//
//	go build -ldflags "-X github.com/soways11/masquevpn/internal/version.Version=1.0.0"
//
// Без флага — «dev»: так видно, что бинарник собран вручную, а не из релиза.
// Версию печатают `vpnserver version`, `vpnclient -version`, а окна и сервер
// пишут её в журнал при запуске — первое, что спрашивают, разбирая жалобу.
package version

// Version — версия сборки (без «v»).
var Version = "dev"

// LDFlag — флаг компоновщика, задающий версию v (для скриптов сборки).
const LDFlag = "-X github.com/soways11/masquevpn/internal/version.Version="
