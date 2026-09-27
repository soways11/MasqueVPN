#!/bin/sh
# Диагностика сервера masquevpn: собирает в один файл всё, что нужно увидеть,
# чтобы понять, работает ли он и что именно не так.
#
#   sudo ./diag.sh          → diag.log рядом со скриптом
#
# Секретов не собирает: ключи клиентов, содержимое clients.json и кэш ACME
# сюда не попадают — только имена, состояния и числа.
set -u

here=$(cd "$(dirname "$0")" && pwd)
OUT="$here/diag.log"
: > "$OUT"

section() { printf '\n==== %s ====\n' "$1" >> "$OUT"; }

# Домен нужен почти всем проверкам. В режиме ACME он записан в конфигурации,
# а когда сертификат берётся из файлов — только в самом сертификате.
domain_of() {
    d=$(sed -n 's/.*"domains": *\["\([^"]*\)".*/\1/p' /etc/masquevpn/server.json 2>/dev/null)
    if [ -z "$d" ]; then
        c=$(sed -n 's/.*"cert_file": *"\([^"]*\)".*/\1/p' /etc/masquevpn/server.json 2>/dev/null)
        [ -n "$c" ] && d=$(openssl x509 -in "$c" -noout -subject 2>/dev/null |
            sed -n 's/.*CN *= *\([^,]*\).*/\1/p')
    fi
    echo "$d"
}
DOMAIN=$(domain_of)
CERTFILE=$(sed -n 's/.*"cert_file": *"\([^"]*\)".*/\1/p' /etc/masquevpn/server.json 2>/dev/null)
run() { printf '$ %s\n' "$*" >> "$OUT"; "$@" >> "$OUT" 2>&1; printf '\n' >> "$OUT"; }

printf '==== masquevpn diag, %s ====\n' "$(date -Is)" >> "$OUT"

section "система"
run uname -a
run sh -c 'head -2 /etc/os-release'
run sh -c 'nproc; free -m | head -2'

section "служба"
run systemctl is-enabled masquevpn
run systemctl is-active masquevpn
run systemctl status masquevpn --no-pager -l
run sh -c '/usr/local/bin/vpnserver -config /etc/masquevpn/server.json -check'

section "журнал (последние 200 строк)"
run journalctl -u masquevpn -n 200 --no-pager

section "конфигурация (без ключей)"
# Реестр клиентов не показываем — в нём ключи. Только сколько записей.
run sh -c 'sed -e "s/\"auth_key\".*/\"auth_key\": <скрыто>/" /etc/masquevpn/server.json'
run sh -c 'grep -c "\"id\"" /etc/masquevpn/clients.json 2>/dev/null | sed "s/^/клиентов в реестре: /"'
run sh -c '/usr/local/bin/vpnserver clients list -config /etc/masquevpn/server.json 2>&1 | sed "s/[A-Za-z0-9+\/]\{40,\}=*/<скрыто>/g"'

section "порты"
# UDP/443 — это сам туннель. TCP/443 может быть и чужим: masquevpn умеет стоять
# рядом с nginx, и тогда TCP не его.
run sh -c 'echo "--- UDP (транспорт туннеля, должен быть за vpnserver) ---";
           ss -lnup 2>/dev/null | grep -E "[:.]443 " || echo "НИКТО НЕ СЛУШАЕТ UDP/443 — туннель работать не будет"'
run sh -c 'echo "--- TCP (может быть занят соседом, это допустимо) ---";
           ss -lntp 2>/dev/null | grep -E "[:.]443 " || echo "на TCP/443 никого"'

section "сеть"
run ip -br addr
run ip route
run ip -6 route
run sh -c 'ip link show 2>&1 | grep -A1 -E "masquevpn|govpn"'
run sh -c 'cat /proc/sys/net/ipv4/ip_forward'
run sh -c 'nft list table inet masquevpn 2>&1 | head -40; nft list table inet govpn 2>/dev/null | head -5'

section "MTU внешнего интерфейса"
run sh -c 'ip route get 1.1.1.1 2>/dev/null | head -1'
run sh -c 'dev=$(ip route get 1.1.1.1 2>/dev/null | sed -n "s/.* dev \([^ ]*\).*/\1/p"); ip link show "$dev" 2>&1'

section "сертификат"
run sh -c 'echo "домен: '"$DOMAIN"'"'
run sh -c 'ls -la /var/lib/masquevpn/acme 2>&1 | sed "s/ [0-9]\{4,\} / <размер> /"'
# Когда сертификат берётся из файлов, смотреть надо на файл: именно его
# обновляет certbot и именно его сервер перечитывает.
run sh -c 'c="'"$CERTFILE"'"; [ -n "$c" ] || { echo "сертификат из ACME, файла нет"; exit 0; }
           ls -la "$c" 2>&1
           openssl x509 -in "$c" -noout -subject -issuer -dates 2>&1'
run sh -c 'echo | openssl s_client -connect 127.0.0.1:443 -servername "'"$DOMAIN"'" 2>/dev/null |
             openssl x509 -noout -subject -issuer -dates 2>&1'

section "ответ самому себе по TCP (в режиме соседа это ЕГО сайт — так и должно быть)"
run sh -c 'd="'"$DOMAIN"'";
           curl -sS -k -I --max-time 10 --resolve "$d:443:127.0.0.1" "https://$d/" 2>&1 | head -20'

section "простукивание: CONNECT не должен отдавать документ"
run sh -c 'd="'"$DOMAIN"'";
           curl -sS -k -i --max-time 10 -X CONNECT --resolve "$d:443:127.0.0.1" "https://$d/" 2>&1 | head -15'

section "DNS: как сервер видит свой домен"
run sh -c 'getent ahostsv4 "'"$DOMAIN"'" 2>&1 | head -3'
run sh -c 'curl -fsS --max-time 10 https://api.ipify.org 2>&1; echo'

echo "готово: $OUT"
echo
echo "Посмотрите его сами (секретов там нет) и положите в папку,"
echo "подключённую к переписке, — дальше разберу я."
