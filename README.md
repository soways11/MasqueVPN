# MasqueVPN

VPN на **MASQUE / CONNECT-IP (RFC 9484)** через HTTP/3 и QUIC. Клиенты для Windows, Linux и Android, сервер — Linux-VPS с `systemd`.

## Установка на сервер — одна команда

Нужны **root**, домен с A-записью на IP VPS и доступные UDP-порты. Все команды выполняются **непосредственно на сервере**. В примерах замените `ДОМЕН` и `email@example.com` своими данными.

**Вариант 1. Свободный TCP/443** (обычный отдельный VPS). Установщик сам получает рабочий сертификат Let's Encrypt; тестовый этап не нужен:

```sh
curl -fsSL https://github.com/soways11/MasqueVPN/releases/latest/download/masquevpn-vps.tar.gz | tar xz -C /tmp && MASQUEVPN_YES=1 sh /tmp/masquevpn-vps/install.sh ДОМЕН email@example.com --production && cat /etc/masquevpn/client-first.link
```

**Вариант 2. TCP/443 занят nginx, x-ui или другим веб-сервером.** Используется уже имеющийся сертификат, а MasqueVPN слушает UDP. Укажите действительные пути к файлам:

```sh
curl -fsSL https://github.com/soways11/MasqueVPN/releases/latest/download/masquevpn-vps.tar.gz | tar xz -C /tmp && MASQUEVPN_YES=1 sh /tmp/masquevpn-vps/install.sh ДОМЕН --cert /etc/letsencrypt/live/ДОМЕН/fullchain.pem --key /etc/letsencrypt/live/ДОМЕН/privkey.pem && cat /etc/masquevpn/client-first.link
```

По умолчанию сервер использует UDP-порты **443, 8443, 2053, 2083, 2087, 2096** (занятые пропускаются). При необходимости можно добавить `--ports 8443,2053,2083` в параметры установки. Если у хостера есть внешний файрвол в панели управления, разрешите в нём выбранные UDP-порты. При работе рядом с чужим веб-сервером можно также задать `--cover http://127.0.0.1:8080`, если там доступен тот же сайт.

## Подключить клиент

В конце команды выводится первая ссылка `masquevpn://…`. Скопируйте её и в [приложении для Windows, Linux или Android](https://github.com/soways11/MasqueVPN/releases/latest) выберите **«+» → «Вставить» → «Добавить»**.

Для дополнительного устройства создайте отдельную ссылку **на сервере** (замените `ДОМЕН`):

```sh
vpnserver clients add -config /etc/masquevpn/server.json -name Телефон -server ДОМЕН:443 -out /root/phone.json && cat /root/phone.link
```

Ссылка содержит ключ доступа: не публикуйте её. Повторный запуск установщика обновляет сервер и сохраняет клиентские настройки.

## Возможности и ограничения

- IP-туннель через QUIC, запасные UDP-порты и аварийная блокировка трафика на клиенте.
- Отдельные ключи доступа для устройств; для VPN необходим проходящий UDP-трафик.
- Независимый аудит безопасности не проводился. Подробности — [SECURITY.md](SECURITY.md).
- Сборка и архитектура — [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md); дополнительные параметры VPS — [deploy/vps/README.txt](deploy/vps/README.txt).

## Лицензия

[MIT](LICENSE). Лицензии сторонних компонентов — [THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt).

