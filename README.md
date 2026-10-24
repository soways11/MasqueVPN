# masquevpn

VPN на **MASQUE**: туннель CONNECT-IP ([RFC 9484](https://www.rfc-editor.org/rfc/rfc9484))
поверх HTTP/3 и QUIC. Через туннель идёт весь трафик устройства на уровне IP.
Снаружи соединение выглядит как браузер, открывающий сайт по HTTP/3, — это
тот же протокол, что у Cloudflare WARP и iCloud Private Relay.

Сервер — Linux-VPS, ставится одним скриптом. Клиенты — свои приложения для
Windows, Linux и Android.

## Почему masquevpn

masquevpn — это HTTP/3 (RFC 9484): отрезать его по протоколу без collateral
damage нельзя.

- QUIC с fingerprint Chrome; ServerHello и transport parameters как у Caddy;
  паддинг, shaping, cover-трафик.
- Active probing → настоящий сайт, уникальный для каждой инсталляции.
- L3-туннель, а не прокси.
- Fallback по UDP-портам на лету, kill switch (WFP / nftables).
- Ключ на клиента, квоты, multi-device, импорт по `masquevpn://`.

Ограничения: нужен UDP — если сеть режет его целиком, masquevpn не
подключится. Независимый аудит безопасности не проводился.

## Состав

| часть | где | что |
|---|---|---|
| сервер | `cmd/vpnserver` | MASQUE-прокси, реестр клиентов с ключом на каждого, ACME-сертификат, сайт-прикрытие |
| Windows | `cmd/masquevpn-win` | окно (Win32/GDI+), установщик NSIS в `deploy/windows` |
| Linux | `cmd/masquevpn-gui`, `cmd/vpnclient` | окно (X11) и клиент без окна, пакет `.deb` в `deploy/linux` |
| Android | `mobile/` | ядро на Go (gomobile) и приложение на Kotlin |
| общее | `internal/` | протокол, маскировка, ротация, настройка сети, форма профилей, дизайн окон |

Подробно — [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md); репозиторий и релизы — [docs/github.md](docs/github.md).

## Установка

Сервер — Linux-VPS с systemd (Ubuntu/Debian, amd64 или arm64), root и
домен с A-записью на IP сервера. Команды выполняются на сервере под root.

**1. Скачать последний релиз**

```sh
curl -fsSL https://github.com/soways11/MasqueVPN/releases/latest/download/masquevpn-vps.tar.gz | tar xz -C /tmp
```

**2. Проверить домен** — оба адреса должны совпасть:

```sh
getent hosts ДОМЕН; curl -4 -s ifconfig.me; echo
```

**3. Установить**

Рядом с веб-сервером (x-ui, nginx — TCP/443 занят): masquevpn берёт только
UDP и готовый сертификат из файлов, продление подхватывает сам.

```sh
sh /tmp/masquevpn-vps/install.sh ДОМЕН \
  --cert /root/cert/ДОМЕН/fullchain.pem \
  --key  /root/cert/ДОМЕН/privkey.pem \
  --ports 8443,2053,2083
```

Отдельный сервер (TCP/443 свободен): сертификат Let's Encrypt masquevpn
выпустит сам — сначала тестовый, затем боевой:

```sh
sh /tmp/masquevpn-vps/install.sh ДОМЕН почта@пример
rm /etc/masquevpn/server.json && sh /tmp/masquevpn-vps/install.sh ДОМЕН почта@пример --production
```

`--ports` — UDP-порты: первый основной, остальные запасные (клиент
переключается сам, если провайдер режет порт). Без него —
443, 8443, 2053, 2083, 2087, 2096.

**4. Проверить**

```sh
systemctl status masquevpn --no-pager | head -5
ss -lnup | grep vpnserver
```

Если у хостера есть свой файрвол в панели — открыть там эти UDP-порты
(ufw/firewalld на машине скрипт открывает сам).

**5. Выдать доступ**

Первый клиент заведён при установке:

```sh
cat /etc/masquevpn/client-first.link
```

Следующие — по одному на устройство:

```sh
vpnserver clients add -config /etc/masquevpn/server.json -name Телефон -server ДОМЕН:8443 -out /root/phone.json
cat /root/phone.link
```

Ссылку `masquevpn://…` вставить в клиенте: «+» → «Вставить» → «Добавить».
Клиенты для Windows, Linux и Android — в
[Releases](https://github.com/soways11/MasqueVPN/releases/latest).

**Обслуживание**

| что | команда |
|---|---|
| журнал | `journalctl -u masquevpn -f` |
| клиенты | `vpnserver clients list -config /etc/masquevpn/server.json` |
| отключить клиента | `vpnserver clients disable -config /etc/masquevpn/server.json -id ID` (ID — из `list`) |
| копия реестра | `vpnserver clients backup -config /etc/masquevpn/server.json -out /root/clients-backup.json` |
| диагностика | `sh /tmp/masquevpn-vps/diag.sh` |
| обновить | шаги 1 и 3 заново — настройки и клиенты сохраняются |
| удалить | `sh /tmp/masquevpn-vps/uninstall.sh` |

Подробности — `deploy/vps/README.txt`. Сборка из исходников, тесты и
выпуск релиза — [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) и
[docs/github.md](docs/github.md).

## Безопасность

- Ключи клиентов (`clients.json`), профили, ссылки `masquevpn://…`, ключ
  подписи APK в репозиторий не попадают — см. `.gitignore`. Ссылка
  `masquevpn://` и есть ключ доступа: пересылать её только защищённым путём.
- Уязвимость — сообщайте приватно (Security → Report a vulnerability),
  не открытым issue.

## Лицензия

[MIT](LICENSE). Тексты лицензий чужого кода, входящего в программы, —
[THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt) (собирается
`sh deploy/third-party-notices.sh`, лежит и в каждом установщике и пакете).

## Сторонний код

- `third_party/uquic` — форк [refraction-networking/uquic](https://github.com/refraction-networking/uquic)
  (MIT), изменения описаны в `third_party/uquic/MASQUEVPN-PATCH.md`.
- `deploy/windows/wintun/amd64/wintun.dll` — [Wintun](https://www.wintun.net)
  от WireGuard LLC, неизменённый, по лицензии `deploy/windows/wintun/LICENSE.txt`.
