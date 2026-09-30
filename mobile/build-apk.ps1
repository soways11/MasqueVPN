# Полная сборка Android-клиента под Windows: ядро (core.aar) и приложение
# (APK) одной командой. То же, что build-apk.sh, для PowerShell.
#
# Один раз поставить:
#   - Go 1.24 или новее (тот же, что собирает сервер и окна)
#   - Android Studio, в ней SDK Manager:
#       • Android SDK Platform 35
#       • NDK (Side by side) — любой из последних
#       • Android SDK Build-Tools
#
# Запуск из корня репозитория:
#   powershell -ExecutionPolicy Bypass -File mobile\build-apk.ps1
#
# Готовый APK:
#   mobile\android\app\build\outputs\apk\debug\app-debug.apk
#
# Релизный, подписанный своим ключом (сначала один раз make-keystore.ps1):
#   powershell -ExecutionPolicy Bypass -File mobile\build-apk.ps1 -Release
#   → mobile\android\app\build\outputs\apk\release\app-release.apk
#
# -SkipCore — не пересобирать ядро, взять готовый mobile\android\app\libs\core.aar
# (когда менялось только приложение или упал шаг Gradle).
param([switch]$Release, [switch]$SkipCore)
$ErrorActionPreference = "Stop"

$root = Resolve-Path (Join-Path $PSScriptRoot "..")

# Путь с кириллицей (C:\Users\Иван\...) Android Gradle Plugin на Windows
# отвергает сам, а компилятор NDK на нём ломается непредсказуемо. Лучше
# сказать сразу, чем через десять минут сборки.
if ("$root" -match '[^\x00-\x7F]') {
    throw "Путь к проекту содержит не-латинские буквы: $root`nРаспакуйте исходники в папку с латинским путём, например C:\masquevpn, и запустите оттуда."
}

# Нужен JDK с компилятором javac: Gradle собирает приложение, а gomobile
# bind сам компилирует Java-обвязку ядра.
#
# Версия — строго 17–21. Gradle 8.11 и Android Gradle Plugin 8.7, на которых
# собирается приложение, на Java 22+ не запускаются: свежая Android Studio
# носит Java 25, и Gradle падает с одной строкой «What went wrong: 25.0.3».
# Поэтому JDK из Android Studio подходит не всегда, и ищем среди всех.
function Test-Jdk([string]$d) { $d -and (Test-Path (Join-Path $d "bin\javac.exe")) }
function Get-JavaMajor([string]$d) {
    $r = Join-Path $d "release"
    if (Test-Path $r) {
        $m = Select-String -Path $r -Pattern 'JAVA_VERSION="(1\.)?(\d+)' | Select-Object -First 1
        if ($m) { return [int]$m.Matches[0].Groups[2].Value }
    }
    return 0
}
$candidates = @()
if ($env:JAVA_HOME) { $candidates += $env:JAVA_HOME }
$candidates += Get-ChildItem -Directory -ErrorAction SilentlyContinue -Path @(
    # Отдельно поставленные JDK: Temurin, Oracle, Microsoft, Zulu, Corretto, Liberica.
    (Join-Path $env:ProgramFiles "Eclipse Adoptium\jdk-*"),
    (Join-Path $env:ProgramFiles "Java\jdk*"),
    (Join-Path $env:ProgramFiles "Microsoft\jdk-*"),
    (Join-Path $env:ProgramFiles "Zulu\zulu*"),
    (Join-Path $env:ProgramFiles "Amazon Corretto\jdk*"),
    (Join-Path $env:ProgramFiles "BellSoft\*"),
    # JDK из Android Studio, где бы она ни стояла.
    (Join-Path $env:ProgramFiles "Android\*\jbr"),
    (Join-Path $env:ProgramFiles "*Android Studio*\jbr"),
    (Join-Path $env:LOCALAPPDATA "Programs\*\jbr"),
    (Join-Path $env:LOCALAPPDATA "JetBrains\Toolbox\apps\*\*\jbr"),
    "C:\*\jbr",
    "C:\*\*\jbr"
) | ForEach-Object { $_.FullName }
$jdks = $candidates | Where-Object { Test-Jdk $_ } | Select-Object -Unique
$good = $jdks | Where-Object { (Get-JavaMajor $_) -ge 17 -and (Get-JavaMajor $_) -le 21 } |
    Sort-Object { Get-JavaMajor $_ } -Descending | Select-Object -First 1
if (-not $good) {
    $seen = ($jdks | ForEach-Object { "  $_ (Java $(Get-JavaMajor $_))" }) -join "`n"
    if (-not $seen) { $seen = "  — ни одного" }
    throw "Нужен JDK 17–21, а найдены:`n$seen`nПоставьте JDK 21 одной командой и откройте новое окно PowerShell:`n  winget install EclipseAdoptium.Temurin.21.JDK`n(или скачайте с https://adoptium.net/temurin/releases/?version=21). Android Studio он не мешает."
}
$env:JAVA_HOME = $good
# gomobile ищет javac в PATH, а не через JAVA_HOME — кладём JDK первым.
$env:PATH = "$(Join-Path $env:JAVA_HOME 'bin');$env:PATH"
if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    throw "Не найден Go. Поставьте с https://go.dev/dl/ (1.24 или новее) и откройте новое окно PowerShell."
}

# Где SDK. Android Studio по умолчанию ставит его в профиль пользователя —
# у пользователя с русским именем это путь с кириллицей, на котором NDK ломается.
# Поэтому сначала смотрим C:\Android\Sdk: туда его и советуем перенести.
# Кандидаты по порядку: явно заданный, частые латинские места, место по
# умолчанию. Берётся первый, где есть установленные платформы, — пустая
# папка от прежней установки не должна перебить настоящий SDK.
if (-not $env:ANDROID_HOME -and $env:ANDROID_SDK_ROOT) { $env:ANDROID_HOME = $env:ANDROID_SDK_ROOT }
if (-not $env:ANDROID_HOME) {
    $env:ANDROID_HOME = @(
        "C:\Android\Sdk",
        "C:\Android",
        "C:\androidstudio",
        "C:\android-sdk",
        "C:\AndroidSdk",
        (Join-Path $env:LOCALAPPDATA "Android\Sdk")
    ) | Where-Object { Test-Path (Join-Path $_ "platforms") } | Select-Object -First 1
}
if (-not $env:ANDROID_HOME -or -not (Test-Path $env:ANDROID_HOME)) {
    throw "Не найден Android SDK. Поставьте Android Studio или задайте ANDROID_HOME."
}
$fixSdk = "В Android Studio: Settings → Languages & Frameworks → Android SDK → Edit (рядом с Android SDK Location) → C:\Android\Sdk, затем поставьте туда нужные пакеты.`nЕсли SDK уже перенесён в другую папку — укажите её перед запуском: `$env:ANDROID_HOME = `"C:\путь\к\sdk`""
if ("$($env:ANDROID_HOME)" -match '[^\x00-\x7F]') {
    throw "Android SDK лежит по пути с кириллицей: $($env:ANDROID_HOME)`nКомпилятор NDK на таком пути ломается.`n$fixSdk"
}
if (-not (Test-Path (Join-Path $env:ANDROID_HOME "platforms\android-35"))) {
    throw "В SDK нет Android 15 (API 35), под который собирается приложение.`nSDK Manager → SDK Platforms → Android 15.0 (`"VanillaIceCream`") → Apply."
}
# NDK — последний установленный.
if (-not $env:ANDROID_NDK_HOME) {
    $ndk = Get-ChildItem (Join-Path $env:ANDROID_HOME "ndk") -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name | Select-Object -Last 1
    if (-not $ndk) {
        throw "Не найден NDK в $($env:ANDROID_HOME). SDK Manager → SDK Tools → NDK (Side by side) → Apply."
    }
    $env:ANDROID_NDK_HOME = $ndk.FullName
}

# Временные файлы и кеши — тоже на латинский путь. По умолчанию они в
# профиле пользователя (C:\Users\Иван\AppData\...), а через них идут
# исходники, которые компилирует NDK: gomobile собирает обвязку во
# временной папке, cgo кладёт промежуточные файлы в кеш Go.
$cache = "C:\masquevpn-cache"
foreach ($d in "tmp", "go-build", "gradle") {
    New-Item -ItemType Directory -Force (Join-Path $cache $d) | Out-Null
}
$env:TEMP = $env:TMP = $env:GOTMPDIR = Join-Path $cache "tmp"
$env:GOCACHE = Join-Path $cache "go-build"
$env:GRADLE_USER_HOME = Join-Path $cache "gradle"
if ("$(go env GOMODCACHE)" -match '[^\x00-\x7F]') {
    $env:GOMODCACHE = Join-Path $cache "gomod"
}

Write-Host "SDK: $($env:ANDROID_HOME)"
Write-Host "NDK: $($env:ANDROID_NDK_HOME)"
if ($env:JAVA_HOME) { Write-Host "Java: $($env:JAVA_HOME)" }

# Версия gomobile закреплена — см. build-aar.sh.
$gomobileVersion = "v0.0.0-20260209203831-923679eb55af"
# gomobile и gobind ставятся в GOPATH\bin, которого может не быть в PATH.
$env:PATH = "$env:PATH;$(go env GOPATH)\bin"
if (-not (Get-Command gomobile -ErrorAction SilentlyContinue)) {
    Write-Host "==> ставлю gomobile $gomobileVersion"
    go install "golang.org/x/mobile/cmd/gomobile@$gomobileVersion"
    if ($LASTEXITCODE -ne 0) { throw "не удалось поставить gomobile" }
    go install "golang.org/x/mobile/cmd/gobind@$gomobileVersion"
    if ($LASTEXITCODE -ne 0) { throw "не удалось поставить gobind" }
}
gomobile init

$libs = Join-Path $root "mobile\android\app\libs"
New-Item -ItemType Directory -Force $libs | Out-Null
# -SkipCore — только если готовое ядро свежее исходников. Иначе в APK
# уехало бы старое ядро с новым приложением: так однажды исправление в Go
# не попало на телефон, хотя APK был собран заново.
$aar = Join-Path $libs "core.aar"
if ($SkipCore -and (Test-Path $aar)) {
    $built = (Get-Item $aar).LastWriteTime
    $newer = Get-ChildItem -Recurse -File -Include *.go, go.mod, go.sum -Path @(
        (Join-Path $root "internal"), (Join-Path $root "mobile\core"), (Join-Path $root "third_party"),
        (Join-Path $root "go.mod"), (Join-Path $root "go.sum")
    ) -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt $built } | Select-Object -First 1
    if ($newer) {
        Write-Host "==> -SkipCore не применяю: исходники ядра новее core.aar ($($newer.FullName))"
        $SkipCore = $false
    }
}
if ($SkipCore -and (Test-Path $aar)) {
    Write-Host "==> шаг 1/2: ядро — беру готовое $aar"
} else {
Write-Host "==> шаг 1/2: ядро (gomobile bind -> core.aar)"
Push-Location $root
# go get ниже правит go.mod и go.sum (добавляет golang.org/x/mobile и тянет
# за ним свежие x/sys, x/tools…). Серверу и окнам это не нужно, а попав в
# коммит, это тихо сменило бы зависимости всего проекта. Поэтому оба файла
# сохраняются и возвращаются как были — даже если сборка упадёт.
$modBackup = Join-Path $env:TEMP "masquevpn-go.mod.bak"
$sumBackup = Join-Path $env:TEMP "masquevpn-go.sum.bak"
Copy-Item (Join-Path $root "go.mod") $modBackup -Force
Copy-Item (Join-Path $root "go.sum") $sumBackup -Force
try {
    # gomobile bind ищет golang.org/x/mobile/bind в зависимостях нашего
    # модуля; в go.mod его нет — добавляем на время сборки.
    go get "golang.org/x/mobile/bind@$gomobileVersion"
    if ($LASTEXITCODE -ne 0) { throw "go get golang.org/x/mobile/bind не удался" }
    gomobile bind -target="android/arm64,android/arm,android/amd64" -androidapi 24 `
        -tags utls -o (Join-Path $libs "core.aar") ./mobile/core
    if ($LASTEXITCODE -ne 0) { throw "gomobile bind не удался" }
} finally {
    Copy-Item $modBackup (Join-Path $root "go.mod") -Force
    Copy-Item $sumBackup (Join-Path $root "go.sum") -Force
    Pop-Location
}
}

$task, $apk = "assembleDebug", (Join-Path $root "mobile\android\app\build\outputs\apk\debug\app-debug.apk")
if ($Release) {
    # Без ключа Gradle молча соберёт неподписанный APK, который телефон не
    # поставит. Лучше остановиться здесь и сказать, что делать.
    if (-not (Test-Path (Join-Path $root "mobile\android\keystore.properties"))) {
        throw "Нет ключа подписи. Один раз: powershell -ExecutionPolicy Bypass -File mobile\make-keystore.ps1"
    }
    $task, $apk = "assembleRelease", (Join-Path $root "mobile\android\app\build\outputs\apk\release\app-release.apk")
}
# Старый APK не должен сойти за новый, если сборка тихо не дойдёт до конца.
Remove-Item $apk -ErrorAction SilentlyContinue

Write-Host "==> шаг 2/2: приложение (gradlew $task)"
Push-Location (Join-Path $root "mobile\android")
try {
    .\gradlew.bat $task
    if ($LASTEXITCODE -ne 0) { throw "сборка Gradle не удалась — смотрите вывод выше" }
} finally { Pop-Location }

if (Test-Path $apk) {
    Write-Host ""
    Write-Host "готово: $apk"
    Write-Host "Перенесите его на телефон и установите (разрешите установку из неизвестных источников)."
} else {
    throw "APK не найден там, где ожидался: $apk"
}
