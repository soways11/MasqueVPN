#!/bin/sh
# Установка сервера masquevpn.
#
#   sudo ./install.sh ВАШ.ДОМЕН почта@пример.рф [--production]
#
#       Свой сертификат: masquevpn занимает 443 и по UDP (туннель), и по TCP
#       (проверка Let's Encrypt и обычный HTTPS). По умолчанию выдача идёт
#       на STAGING: лимиты мягкие, сертификат невалидный, но проверяется
#       весь путь. Убедившись, повторить с --production.
#
#   sudo ./install.sh ВАШ.ДОМЕН --cert /путь/fullchain.pem --key /путь/privkey.pem
#
#       Рядом с чужим веб-сервером. TCP/443 остаётся за ним, masquevpn берёт
#       только UDP/443 и готовый сертификат из файлов. Обновление
#       сертификата подхватывается без перезапуска.
#
# Скрипт ничего не делает молча и до первого изменения проверяет то, на чём
# установка обычно и спотыкается: права, архитектуру, занятые порты и A-запись
# домена. Упереться в понятную ошибку дешевле, чем разбираться потом по журналу.
set -eu

DOMAIN=""
EMAIL=""
MODE="staging"
CERT=""
KEY=""
COVER=""

while [ $# -gt 0 ]; do
    case "$1" in
        --production) MODE="--production" ;;
        --cover) COVER="${2:-}"; shift ;;
        --cert) CERT="${2:-}"; shift ;;
        --key)  KEY="${2:-}";  shift ;;
        -*) echo "неизвестный ключ: $1" >&2; exit 2 ;;
        *)
            if [ -z "$DOMAIN" ]; then DOMAIN="$1"
            elif [ -z "$EMAIL" ]; then EMAIL="$1"
            fi
            ;;
    esac
    shift
done

die() { echo "ОШИБКА: $*" >&2; exit 1; }
say() { echo "==> $*"; }

[ -n "$DOMAIN" ] || die "не задан домен.  Запуск: sudo sh install.sh ВАШ.ДОМЕН почта@пример.рф [--production]
     либо рядом с чужим веб-сервером:
     sudo sh install.sh ВАШ.ДОМЕН --cert /путь/fullchain.pem --key /путь/privkey.pem"
[ "$(id -u)" = "0" ] || die "нужен root: sudo sh install.sh ..."

# Режим определяется тем, дали ли готовый сертификат.
if [ -n "$CERT" ] || [ -n "$KEY" ]; then
    OWN_CERT=yes
    [ -n "$CERT" ] && [ -n "$KEY" ] || die "--cert и --key задаются вместе"
    [ -f "$CERT" ] || die "нет файла сертификата: $CERT"
    [ -f "$KEY" ]  || die "нет файла ключа: $KEY"
else
    OWN_CERT=no
    [ -n "$EMAIL" ] || die "не задана почта (на неё Let's Encrypt шлёт письма об истечении)"
fi

here=$(cd "$(dirname "$0")" && pwd)

# ---------- архитектура ----------
case "$(uname -m)" in
    x86_64|amd64)  BIN=vpnserver-amd64 ;;
    aarch64|arm64) BIN=vpnserver-arm64 ;;
    *) die "архитектура $(uname -m) не поддерживается этим пакетом (есть amd64 и arm64)" ;;
esac
[ -f "$here/$BIN" ] || die "рядом со скриптом нет $BIN"
say "архитектура $(uname -m), беру $BIN"

# ---------- порты ----------
# Занятый 443 — самая частая причина неудачи: там обычно уже стоит nginx,
# Caddy или другая панель. Обнаружить это до установки, а не после.
busy() {
    if command -v ss >/dev/null 2>&1; then
        ss -lnH "$1" 2>/dev/null | awk '{print $5}' | grep -qE "[:.]443$"
    else
        return 1
    fi
}
# UDP/443 — это сам транспорт туннеля, без него никак.
if busy -u; then
    echo "UDP/443 занят:" >&2
    ss -lnup 2>/dev/null | grep -E "[:.]443 " >&2 || true
    die "освободите UDP/443 — это и есть транспорт туннеля (QUIC)."
fi

# TCP/443 нужен только своему сертификату: проверка Let's Encrypt приходит
# по TCP. Если там уже чужой веб-сервер — это не беда, а даже удобно: он
# станет сайтом-прикрытием. Но тогда сертификат нужен готовый.
if busy -t; then
    if [ "$OWN_CERT" = "no" ]; then
        echo "TCP/443 занят:" >&2
        ss -lntp 2>/dev/null | grep -E "[:.]443 " >&2 || true
        die "там уже чужой веб-сервер, и проверку Let's Encrypt провести нечем.
     Два выхода:
       1) оставить его и дать masquevpn готовый сертификат (тот же, что у него):
            sudo sh install.sh $DOMAIN --cert /etc/letsencrypt/live/$DOMAIN/fullchain.pem \\
                                       --key  /etc/letsencrypt/live/$DOMAIN/privkey.pem
          masquevpn возьмёт только UDP/443, TCP останется за ним;
       2) освободить TCP/443 и ставить с выдачей сертификата."
    fi
    say "TCP/443 занят чужим веб-сервером — беру только UDP/443, сертификат из файлов"
    TCP_BUSY=yes
else
    TCP_BUSY=no
    say "порты 443/tcp и 443/udp свободны"
fi

# ---------- A-запись ----------
# Если домен не указывает сюда, Let's Encrypt откажет, а лимит на неудачные
# проверки потратится. Лучше остановиться здесь.
myip=""
for u in https://api.ipify.org https://ifconfig.me/ip; do
    myip=$(curl -fsS --max-time 10 "$u" 2>/dev/null) && break
done
if [ -n "$myip" ]; then
    resolved=""
    if command -v getent >/dev/null 2>&1; then
        resolved=$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk '{print $1; exit}')
    fi
    if [ -z "$resolved" ]; then
        echo "ПРЕДУПРЕЖДЕНИЕ: не удалось разрешить $DOMAIN — проверьте A-запись сами" >&2
    elif [ "$resolved" != "$myip" ]; then
        if [ "$OWN_CERT" = "yes" ]; then
            echo "ПРЕДУПРЕЖДЕНИЕ: A-запись $DOMAIN ведёт на $resolved, а этот сервер — $myip." >&2
            echo "     Сертификат уже есть, так что установка пройдёт, но клиент сюда не попадёт." >&2
        else
            die "A-запись $DOMAIN ведёт на $resolved, а этот сервер — $myip.
     Пока они не совпадут, Let's Encrypt сертификат не выдаст."
        fi
    else
        say "A-запись $DOMAIN → $myip, совпадает"
    fi
else
    echo "ПРЕДУПРЕЖДЕНИЕ: не удалось узнать внешний адрес — A-запись не проверена" >&2
fi

# ---------- сайт-прикрытие ----------
# Тонкость, которую легко пропустить. Снаружи домен один, а отвечают на него
# двое: чужой веб-сервер по TCP и masquevpn по UDP (HTTP/3). Если masquevpn покажет
# свой встроенный сайт, у одного домена окажется два разных содержимого —
# по TCP одно, по QUIC другое. Для того, кто ищет туннели, это готовый
# признак. Поэтому в этом режиме masquevpn должен показывать тот же сайт, а взять
# его можно только с локального порта: тот, что на 443, занят TLS соседа.
if [ "$OWN_CERT" = "yes" ] && [ -z "$COVER" ]; then
    if ss -lnt 2>/dev/null | grep -qE "127\.0\.0\.1:8080 "; then
        COVER="http://127.0.0.1:8080"
        say "нашёл сайт на 127.0.0.1:8080 — он и будет прикрытием"
    else
        cat >&2 <<EOF

ПРЕДУПРЕЖДЕНИЕ: сайт-прикрытия нет, будет показан встроенный.

     По TCP ваш домен отдаёт сайт соседнего веб-сервера, а по HTTP/3 отдаст
     наш встроенный — разное содержимое на одном домене заметно.
     Чтобы этого не было, добавьте соседу локальный порт с тем же сайтом
     (443 при этом не трогается):

         server {
             listen 127.0.0.1:8080;
             server_name $DOMAIN;
             ... тот же root/proxy_pass, что и в блоке на 443 ...
         }

     и переустановите с ключом  --cover http://127.0.0.1:8080
EOF
    fi
fi

# ---------- что будет сделано ----------
# До этого места скрипт только смотрел. Дальше он меняет систему, поэтому
# сначала показывает, что именно, — на чужом сервере иначе нельзя.
if [ "$OWN_CERT" = "yes" ]; then
    PORTS="443/udp — и только его; TCP остаётся за соседом"
    CERT_WHERE="$CERT
                  (обновление подхватывается без перезапуска)"
    ACME_LINE=""
else
    PORTS="443/tcp и 443/udp"
    CERT_WHERE="Let's Encrypt, режим ${MODE#--}"
    ACME_LINE="  /var/lib/masquevpn/acme/                  ключ аккаунта и сертификаты
"
fi
if [ -n "$COVER" ]; then
    COVER_LINE="  Сайт-прикрытие: $COVER"
else
    COVER_LINE="  Сайт-прикрытие: встроенный"
fi
cat <<EOF

Проверки пройдены. Будет сделано:

  /usr/local/bin/vpnserver              бинарник сервера
  /etc/masquevpn/server.json                конфигурация (домен $DOMAIN)
  /etc/masquevpn/clients.json               реестр клиентов, первый клиент
$ACME_LINE  /etc/systemd/system/masquevpn.service     служба, запуск при загрузке

  Порты:          $PORTS
  Сертификат:     $CERT_WHERE
$COVER_LINE

  Создаётся своя таблица nftables (inet masquevpn) — существующие правила
  не трогаются.  Отменить всё: sudo sh $here/uninstall.sh

EOF
if [ "${MASQUEVPN_YES:-${GOVPN_YES:-}}" != "1" ]; then
    printf "Продолжить? [y/N] "
    read -r answer
    case "$answer" in
        y|Y|yes|да) ;;
        *) echo "отменено"; exit 1 ;;
    esac
fi

# ---------- переезд с прежнего имени ----------
# До переименования проекта сервер жил в /etc/govpn и /var/lib/govpn со
# службой govpn.service. Переносим всё на новое место один раз, сохранив
# копию: в /etc/govpn лежит реестр со всеми ключами, и потерять его —
# отключить всех клиентов разом.
if [ -d /etc/govpn ] && [ ! -L /etc/govpn ] && [ ! -e /etc/masquevpn ]; then
    say "найдена установка под прежним именем (govpn) — переношу на masquevpn"
    ts=$(date +%s)
    backup="/root/govpn-backup-$ts.tar.gz"
    dirs="/etc/govpn"
    if [ -d /var/lib/govpn ]; then dirs="$dirs /var/lib/govpn"; fi
    # shellcheck disable=SC2086
    (umask 077 && tar -czf "$backup" $dirs)
    say "  копия прежних данных: $backup (там ключи всех клиентов)"
    systemctl stop govpn 2>/dev/null || true
    systemctl disable govpn >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/govpn.service
    mv /etc/govpn /etc/masquevpn
    if [ -d /var/lib/govpn ] && [ ! -e /var/lib/masquevpn ]; then
        mv /var/lib/govpn /var/lib/masquevpn
    fi
    # Пути внутри конфигурации — на новое место; копия рядом.
    cp -p /etc/masquevpn/server.json "/etc/masquevpn/server.json.bak.$ts"
    sed -i 's#/etc/govpn/#/etc/masquevpn/#g; s#/var/lib/govpn/#/var/lib/masquevpn/#g' \
        /etc/masquevpn/server.json
    # Старые команды из заметок и инструкций продолжают работать.
    ln -s /etc/masquevpn /etc/govpn
    systemctl daemon-reload
    say "  перенесено; имя туннельного интерфейса в конфигурации оставлено прежним"
fi

# ---------- установка ----------

say "ставлю бинарник в /usr/local/bin/vpnserver"
install -m 0755 "$here/$BIN" /usr/local/bin/vpnserver
mkdir -p /etc/masquevpn /var/lib/masquevpn
chmod 0700 /etc/masquevpn /var/lib/masquevpn
if [ "$OWN_CERT" = "no" ]; then
    mkdir -p /var/lib/masquevpn/acme && chmod 0700 /var/lib/masquevpn/acme
fi

# Часть конфигурации, которой режимы и отличаются: откуда сертификат и
# занимать ли TCP.
if [ "$OWN_CERT" = "yes" ]; then
    CERT_BLOCK="  \"cert_file\": \"$CERT\",
  \"key_file\": \"$KEY\","
    # TCP отдан соседу. Он же показывает сайт, отвечает на проверки
    # Let's Encrypt и обновляет тот самый сертификат, который мы читаем.
    TCP_BLOCK='  "tcp": { "disabled": true },'
else
    CERT_BLOCK=""
    TCP_BLOCK='  "tcp": { "listen": ":443" },'
fi
if [ -n "$COVER" ]; then
    COVER_BLOCK="  \"fallback_proxy\": \"$COVER\","
else
    COVER_BLOCK=""
fi

DIRECTORY=""
if [ "$OWN_CERT" = "yes" ]; then
    ACME_BLOCK=""
    say "сертификат из файлов: $CERT"
    say "обновление подхватывается без перезапуска — certbot можно не трогать"
elif [ "$MODE" != "--production" ]; then
    DIRECTORY='
  "directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory",'
    say "режим STAGING: сертификат будет невалидным, зато лимиты мягкие"
else
    say "режим PRODUCTION: настоящий Let's Encrypt"
fi
if [ "$OWN_CERT" = "no" ]; then
    ACME_BLOCK="  \"acme\": {
    \"domains\": [\"$DOMAIN\"],
    \"email\": \"$EMAIL\",$DIRECTORY
    \"cache_dir\": \"/var/lib/masquevpn/acme\"
  },"
fi

if [ -f /etc/masquevpn/server.json ]; then
    say "конфигурация уже есть, не трогаю: /etc/masquevpn/server.json"
else
    say "пишу /etc/masquevpn/server.json"
    cat > /etc/masquevpn/server.json <<EOF
{
  "listen": ":443",
$ACME_BLOCK$CERT_BLOCK

  "clients_file": "/etc/masquevpn/clients.json",

  "tun": { "name": "masquevpn0", "mtu": 1280 },
  "pool4": "10.66.0.0/24",

  "nat": { "out_interface": "" },
  "shaping": "cloud-gaming-down",
  "packing": { "window": "300us" },
  "server_profile": "cloudflare",

  "fallback_site": {
    "title": "Nimbus Lab",
    "description": "Realtime delivery for applications that cannot wait.",
    "contact": "hello@$DOMAIN"
  },
$COVER_BLOCK
$TCP_BLOCK

  "limits": {
    "max_sessions": 256,
    "max_sessions_per_ip": 8,
    "idle_timeout": "10m"
  },
  "log_level": "info"
}
EOF
    chmod 0600 /etc/masquevpn/server.json
fi

# ---------- профиль транспортных параметров ----------
# В конфигурациях, написанных до 24.09.2026, стоит "cdn" — эвристика,
# выдуманные числа порядков величин. Теперь в бинарник зашит профиль, снятый
# с живого сервера (www.cloudflare.com). Без этой замены переустановка кода
# ничего бы не поменяла: старый конфиг мы не перезаписываем, а значит и
# профиль остался бы прежним.
if grep -q '"server_profile"[[:space:]]*:[[:space:]]*"cdn"' /etc/masquevpn/server.json 2>/dev/null; then
    cp -p /etc/masquevpn/server.json "/etc/masquevpn/server.json.bak.$(date +%s)"
    sed -i 's/"server_profile"[[:space:]]*:[[:space:]]*"cdn"/"server_profile": "cloudflare"/' \
        /etc/masquevpn/server.json
    say "профиль сервера: эвристика cdn заменена на снятый с живого сервера"
    say "  (копия прежней конфигурации — /etc/masquevpn/server.json.bak.*)"
fi

/usr/local/bin/vpnserver -config /etc/masquevpn/server.json -check \
    || die "конфигурация не прошла проверку"

# ---------- первый клиент ----------
if [ -f /etc/masquevpn/clients.json ]; then
    say "реестр клиентов уже есть, нового не завожу"
else
    say "завожу первого клиента"
    # Ключ и ссылка — только в файлы (0600), не в терминал: вывод терминала
    # оседает в истории, журналах панелей хостинга и записях сессий.
    /usr/local/bin/vpnserver clients add -file /etc/masquevpn/clients.json \
        -name "first" -server "$DOMAIN:443" -out /etc/masquevpn/client-first.json
    chmod 0600 /etc/masquevpn/clients.json
fi

# ---------- служба ----------
say "ставлю службу systemd"
cat > /etc/systemd/system/masquevpn.service <<'EOF'
[Unit]
Description=masquevpn server (MASQUE CONNECT-IP)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/vpnserver -config /etc/masquevpn/server.json
Restart=on-failure
RestartSec=2
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable masquevpn >/dev/null 2>&1 || true
systemctl restart masquevpn

# ---------- ждём сертификат ----------
if [ "$OWN_CERT" = "yes" ]; then
    say "проверяю, что служба держится (15 секунд)"
    sleep 5
    systemctl is-active --quiet masquevpn || {
        echo "--- журнал ---" >&2
        journalctl -u masquevpn --since "-2 min" --no-pager >&2 || true
        die "служба остановилась"
    }
    sleep 10
    systemctl is-active --quiet masquevpn || {
        echo "--- журнал ---" >&2
        journalctl -u masquevpn --since "-2 min" --no-pager >&2 || true
        die "служба остановилась не сразу — смотрите журнал выше"
    }
    say "служба работает"
    i=90
else
say "жду, пока сервер поднимется и возьмёт сертификат (до 90 секунд)"
i=0
fi
while [ $i -lt 90 ]; do
    if journalctl -u masquevpn --since "-2 min" 2>/dev/null | grep -q "сертификат получен"; then
        say "сертификат получен"
        break
    fi
    if ! systemctl is-active --quiet masquevpn; then
        echo "--- журнал ---" >&2
        journalctl -u masquevpn --since "-2 min" --no-pager >&2 || true
        die "служба остановилась"
    fi
    i=$((i + 3))
    sleep 3
done

echo
say "готово. Что дальше:"
echo "   журнал:        journalctl -u masquevpn -f"
echo "   клиенты:       vpnserver clients list -config /etc/masquevpn/server.json"
echo "   доступ первого клиента: /etc/masquevpn/client-first.link (ссылка = ключ, не пересылайте открыто)"
echo "   диагностика:   sudo sh $here/diag.sh"
if [ "$OWN_CERT" = "no" ] && [ "$MODE" != "--production" ]; then
    echo
    echo "   Сейчас STAGING. Убедившись, что всё работает, повторите:"
    echo "     sudo rm /etc/masquevpn/server.json && sudo sh $here/install.sh $DOMAIN $EMAIL --production"
fi
