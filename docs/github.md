# Репозиторий на GitHub

## Первая отправка

Нужны [Git](https://git-scm.com/download/win) и [GitHub CLI](https://cli.github.com/).

```powershell
cd C:\masquevpn\github\masquevpn
git init -b main
git add -A
git status            # проверить, что нет clients.json, profiles.json, *.jks, *.link
git commit -m "masquevpn: первая версия"
gh auth login
gh repo create masquevpn --private --source . --push
```

`--private` — осознанно: код маскировки в открытом доступе — готовая
подсказка тем, кто пишет правила блокировки. Открыть репозиторий можно
позже одним переключателем; закрыть обратно — нет, копии останутся.

## Настройки (Settings)

- **Branches → Add rule** для `main`: изменения только через pull request,
  обязательны зелёные проверки CI, без force-push.
- **Code security:** Secret scanning и Push protection — GitHub сам
  остановит коммит с похожей на ключ строкой.
- **Secrets and variables → Actions** — для подписанного APK в релизе:
  - `ANDROID_KEYSTORE_B64` — `[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\masquevpn-keys\masquevpn-release.jks"))`
  - `ANDROID_KEYSTORE_PASSWORD` — пароль ключа
  - `ANDROID_KEY_ALIAS` — `masquevpn`

## Что делают проверки

| workflow | когда | что |
|---|---|---|
| CI | каждый push в main и pull request | gitleaks, gofmt, vet (Linux и Windows), тесты, race, сквозной стенд под root, тесты и сборка на Windows, проверки Android и отладочный APK |
| Release | тег `v*` (`git tag v0.3.0; git push --tags`) | установщик Windows, два `.deb`, пакет для VPS, подписанный APK, `SHA256SUMS` — всё в черновик релиза |

Первый прогон на Windows — первый раз, когда тесты идут на настоящей
Windows (раньше — кросс-компиляция и Wine): если там что-то красное,
это находка, а не поломка настройки.

## Перед каждым коммитом

```sh
gitleaks dir . --config .gitleaks.toml     # секреты
go vet ./... && go test ./...
```
