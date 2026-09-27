# masquevpn

VPN на **MASQUE**: туннель CONNECT-IP ([RFC 9484](https://www.rfc-editor.org/rfc/rfc9484))
поверх HTTP/3 и QUIC. Снаружи соединение выглядит как обычный браузер,
открывающий сайт по HTTP/3: отпечаток ClientHello браузера, паддинг и
фоновые запросы, сервер без доступа отвечает как обычный веб-сайт.

Клиенты — Windows, Linux и Android; сервер — Linux (VPS).

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
| установщик Windows | `sh deploy/windows/build-installer.sh 0.2.0` (нужен `nsis`) | `dist/masquevpn-setup-0.2.0.exe` |
| пакет Linux | `sh deploy/linux/build-deb.sh amd64 0.2.0` | `dist/masquevpn_0.2.0_amd64.deb` |
| сервер для VPS | `sh deploy/vps/build.sh` | `dist/masquevpn-vps.tar.gz` |
| APK | `mobile/build-apk.ps1` (Windows) или `mobile/build-apk.sh` | см. [docs/android-apk.md](docs/android-apk.md) |

Релиз собирает GitHub Actions по тегу `v*` — черновиком, со всеми
файлами выше и `SHA256SUMS` (`.github/workflows/release.yml`).

## Сервер

```sh
sh deploy/vps/build.sh
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

## Сторонний код

- `third_party/uquic` — форк [refraction-networking/uquic](https://github.com/refraction-networking/uquic)
  (MIT), изменения описаны в `third_party/uquic/MASQUEVPN-PATCH.md`.
- `deploy/windows/wintun/amd64/wintun.dll` — [Wintun](https://www.wintun.net)
  от WireGuard LLC, неизменённый, по лицензии `deploy/windows/wintun/LICENSE.txt`.
