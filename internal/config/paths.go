package config

import "os"

// Каталоги сервера и клиента без окна на Linux.
//
// До переименования проекта всё лежало в /etc/govpn и /var/lib/govpn. На
// серверах, поставленных тогда, так и лежит, и обновлённая программа
// обязана их находить: иначе обновление превращалось бы в «сервер не
// запускается, конфигурации нет». Установщик (deploy/vps/install.sh)
// переносит каталоги на новое место, но программа не рассчитывает, что
// перенос уже был.
const (
	EtcDir          = "/etc/masquevpn"
	LegacyEtcDir    = "/etc/govpn"
	VarLibDir       = "/var/lib/masquevpn"
	LegacyVarLibDir = "/var/lib/govpn"
)

// DefaultServerConfig — файл конфигурации сервера по умолчанию.
func DefaultServerConfig() string {
	return preferExisting(EtcDir+"/server.json", LegacyEtcDir+"/server.json")
}

// DefaultClientConfig — файл конфигурации клиента без окна по умолчанию.
func DefaultClientConfig() string {
	return preferExisting(EtcDir+"/client.json", LegacyEtcDir+"/client.json")
}

// defaultACMECache — каталог кэша ACME, если в конфигурации он не задан.
// Прежний каталог в приоритете, пока нового нет: там ключ аккаунта и уже
// выпущенные сертификаты, и заводить их заново — лишние запросы к
// удостоверяющему центру с его лимитами.
func defaultACMECache() string {
	return preferExisting(DefaultACMECache, LegacyVarLibDir+"/acme")
}

// preferExisting возвращает cur, если он есть или если нет и legacy;
// иначе — legacy.
func preferExisting(cur, legacy string) string {
	if _, err := os.Stat(cur); err == nil {
		return cur
	}
	if _, err := os.Stat(legacy); err == nil {
		return legacy
	}
	return cur
}
