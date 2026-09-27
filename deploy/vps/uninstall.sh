#!/bin/sh
# Удаление сервера masquevpn: снимает всё, что поставил install.sh.
#
#   sudo ./uninstall.sh          — убрать службу и бинарник, данные оставить
#   sudo ./uninstall.sh --purge  — убрать и данные тоже
#
# По умолчанию /etc/masquevpn и /var/lib/masquevpn остаются: там реестр клиентов и
# сертификаты. Потерять их означает отключить всех клиентов и перезаказать
# сертификат, а у Let's Encrypt лимиты — так что стирать их молча нельзя.
set -eu

[ "$(id -u)" = "0" ] || { echo "нужен root" >&2; exit 1; }
say() { echo "==> $*"; }

# Служба — под нынешним именем и под прежним (govpn), если сервер ставился
# до переименования и install.sh с тех пор не запускался.
for svc in masquevpn govpn; do
    if systemctl list-unit-files 2>/dev/null | grep -q "^$svc\.service"; then
        say "останавливаю службу $svc"
        systemctl stop "$svc" || true
        systemctl disable "$svc" >/dev/null 2>&1 || true
        rm -f "/etc/systemd/system/$svc.service"
        systemctl daemon-reload
    fi
done

rm -f /usr/local/bin/vpnserver
say "бинарник и служба удалены"

# Таблицу NAT сервер снимает сам при остановке; если он не успел, убираем.
for t in masquevpn govpn; do
    if command -v nft >/dev/null 2>&1 && nft list table inet "$t" >/dev/null 2>&1; then
        nft delete table inet "$t" || true
        say "таблица nftables inet $t удалена"
    fi
done

if [ "${1:-}" = "--purge" ]; then
    rm -rf /etc/masquevpn /var/lib/masquevpn /etc/govpn /var/lib/govpn
    say "данные удалены: реестр клиентов и сертификаты"
else
    say "данные оставлены: /etc/masquevpn и /var/lib/masquevpn"
    echo "   (там реестр клиентов и сертификаты; --purge удалит и их)"
fi
