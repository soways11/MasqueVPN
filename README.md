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

## Сборка

Нужен Go 1.24+.

```sh
go build ./...                                          # всё
go test ./...                                           # тесты
sudo go test -tags e2e ./test/e2e/                      # сквозной стенд (root, netns)
```

| что | команда | результат |
|---|---|---|
| установщик Windows | `sh deploy/windows/build-installer.sh 1.0.0` (нужен `nsis`) | `dist/masquevpn-setup-1.0.0.exe` |
| пакет Linux | `sh deploy/linux/build-deb.sh amd64 1.0.0` | `dist/masquevpn_1.0.0_amd64.deb` |
| сервер для VPS | `VERSION=1.0.0 sh deploy/vps/build.sh` | `dist/masquevpn-vps.tar.gz` |
| APK | `mobile/build-apk.ps1` (Windows) или `mobile/build-apk.sh` | см. [docs/android-apk.md](docs/android-apk.md) |

Версия сборки: `vpnserver version`, `masquevpn-cli -version`; окна и сервер
пишут её в журнал при запуске.

Релиз собирает GitHub Actions по тегу `v*` — черновиком, со всеми
файлами выше и `SHA256SUMS` (`.github/workflows/release.yml`).

## Сервер

```sh
VERSION=1.0.0 sh deploy/vps/build.sh
scp dist/masquevpn-vps.tar.gz root@СЕРВЕР:/tmp/
ssh root@СЕРВЕР 'cd /tmp && tar xzf masquevpn-vps.tar.gz && cd masquevpn-vps && sh install.sh ДОМЕН почта@пример'
```

Подробности и режим «рядом с чужим веб-сервером» — `deploy/vps/README.txt`.
Сервер, поставленный до переименования проекта (govpn), install.sh
переносит сам, сохранив копию данных.

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
