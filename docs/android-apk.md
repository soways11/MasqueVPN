# Сборка APK с ключом подписи

Три захода: один раз поставить инструменты, один раз создать ключ, дальше —
одна команда на сборку. Команды — для Windows PowerShell; на Linux и macOS
то же делает `mobile/build-apk.sh [--release]`.

## 1. Инструменты (один раз)

- **Go 1.24+** — [go.dev/dl](https://go.dev/dl/).
- **Android Studio** — [developer.android.com/studio](https://developer.android.com/studio).
  В SDK Manager:
  - **SDK Platforms:** Android 15 (API 35);
  - **SDK Tools:** NDK (Side by side), Android SDK Build-Tools,
    Android SDK Command-line Tools.
- **JDK 17–21.** Свежая Android Studio носит Java 25, на которой Gradle 8.11
  и Android Gradle Plugin 8.7 не запускаются (ошибка из одной строки
  «What went wrong: 25.0.3»). Поставить рядом JDK 21:
  `winget install EclipseAdoptium.Temurin.21.JDK`.

**Пути без кириллицы.** Сборщик Android на Windows не принимает путь проекта
с кириллицей, а компилятор NDK ломается на SDK по такому пути:

- исходники — в `C:\masquevpn`, а не в `C:\Users\Иван\...`;
- SDK — в латинскую папку: Settings → Languages & Frameworks → Android SDK →
  Edit → например `C:\Android\Sdk`.

Скрипт проверяет всё это сам и говорит, что не так.

## 2. Ключ подписи (один раз)

```powershell
cd C:\masquevpn
powershell -ExecutionPolicy Bypass -File mobile\make-keystore.ps1
```

- Пароль — не меньше 8 знаков, **только латиница, цифры и знаки** (PKCS12
  в Java кириллицу не принимает).
- Ключ: `C:\masquevpn-keys\masquevpn-release.jks`, вне папки проекта.
- Рядом с проектом появится `mobile\android\keystore.properties` — его читает
  сборка; в репозиторий он не попадает.
- Существующий ключ скрипт не перезаписывает никогда.

**Сразу сделайте копию `.jks` и запишите пароль.** Android ставит обновление
поверх только с той же подписью: потеря ключа или пароля — людям придётся
удалить приложение вместе с профилями и поставить заново. Утечка ключа
вместе с паролем — кто угодно выпустит «обновление», которое телефон примет.

## 3. Сборка

```powershell
powershell -ExecutionPolicy Bypass -File mobile\build-apk.ps1 -Release
```

Результат: `mobile\android\app\build\outputs\apk\release\app-release.apk`.

- `-SkipCore` — не пересобирать ядро на Go, если менялось только приложение.
  Если исходники ядра новее готового `core.aar`, скрипт пересоберёт его всё
  равно.
- Без `-Release` — отладочная сборка, подписанная временным ключом этой
  машины: для проверки на своём телефоне, но не для раздачи.

### Проверка подписи

```powershell
$env:JAVA_HOME = "C:\Program Files\Eclipse Adoptium\jdk-21..."   # любой JDK
$bt = Get-ChildItem "$env:ANDROID_HOME\build-tools" | Sort-Object Name | Select-Object -Last 1
& "$($bt.FullName)\apksigner.bat" verify --print-certs mobile\android\app\build\outputs\apk\release\app-release.apk
```

Должно быть `Signer #1 certificate DN: CN=masquevpn`. SHA-256 сертификата
стоит записать: у всех будущих версий он обязан совпадать.

## 4. Следующие версии

Перед выпуском обновления увеличить `versionCode` в
`mobile/android/app/build.gradle.kts` (или передать
`-PversionCode=… -PversionName=…`): Android не ставит поверх APK с тем же
или меньшим номером. В GitHub Actions это делается само — см.
`.github/workflows/release.yml` (ключ кладётся в секреты репозитория).

## Частые ошибки

| сообщение | что делать |
|---|---|
| «Выполнение сценариев отключено» | запускать через `powershell -ExecutionPolicy Bypass -File …` |
| «Путь к проекту содержит не-латинские буквы» | распаковать в `C:\masquevpn` |
| «Android SDK лежит по пути с кириллицей» | перенести SDK (шаг 1) или `$env:ANDROID_HOME = "C:\путь"` |
| «В SDK нет Android 15 (API 35)» | SDK Manager → SDK Platforms → Android 15 |
| «Не найден NDK» | SDK Manager → SDK Tools → NDK (Side by side) |
| «Нужен JDK 17–21» / «What went wrong: 25.0.3» | поставить Temurin 21 (шаг 1) и открыть новое окно PowerShell |
| «Нет ключа подписи» | шаг 2 |
| на телефоне «Приложение не установлено» | стоит версия с другим ключом (отладочная) — удалить её; или не увеличен `versionCode` |
