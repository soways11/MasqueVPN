# Ключ подписи релизных APK masquevpn. Делается ОДИН раз.
#
#   powershell -ExecutionPolicy Bypass -File mobile\make-keystore.ps1
#
# Что получится:
#   C:\masquevpn-keys\masquevpn-release.jks   — сам ключ (вне папки проекта:
#                                               перераспаковка исходников его
#                                               не сотрёт);
#   mobile\android\keystore.properties        — где ключ и пароль к нему; его
#                                               читает сборка.
#
# ВАЖНО. Android ставит обновление поверх, только если оно подписано тем же
# ключом. Потеряли ключ или пароль — выпустить обновление будет нельзя:
# людям придётся удалить приложение (вместе с профилями) и поставить заново.
# Поэтому сразу после создания скопируйте .jks на флешку или в облако и
# запишите пароль туда, где он не потеряется.
$ErrorActionPreference = "Stop"

$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$dir = "C:\masquevpn-keys"
$jks = Join-Path $dir "masquevpn-release.jks"
$props = Join-Path $root "mobile\android\keystore.properties"
$alias = "masquevpn"

# keytool — из Java, что идёт с Android Studio.
$java = $env:JAVA_HOME
if (-not $java) {
    $java = @(
        (Join-Path $env:ProgramFiles "Android\Android Studio\jbr"),
        (Join-Path $env:LOCALAPPDATA "Programs\Android Studio\jbr")
    ) | Where-Object { Test-Path (Join-Path $_ "bin\keytool.exe") } | Select-Object -First 1
}
$keytool = if ($java) { Join-Path $java "bin\keytool.exe" } else { "" }
if (-not $keytool -or -not (Test-Path $keytool)) {
    throw "Не найден keytool. Поставьте Android Studio (в ней есть Java) или задайте JAVA_HOME."
}

# Существующий ключ не перезаписывается НИКОГДА: новый ключ — это потеря
# возможности обновлять уже установленные приложения.
$exists = Test-Path $jks
if ($exists) {
    Write-Host "Ключ уже есть: $jks — новый создаваться не будет."
    Write-Host "Введите его пароль, чтобы записать keystore.properties для сборки."
}

function Read-Password([string]$prompt) {
    $s = Read-Host $prompt -AsSecureString
    $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
}

$pass = Read-Password "Пароль ключа (не меньше 8 знаков, латиница, цифры, знаки)"
if ($pass.Length -lt 8) { throw "Пароль короче 8 знаков." }
# Хранилище PKCS12 в Java принимает только ASCII: с кириллицей keytool
# падает с «Password is not ASCII».
if ($pass -match '[^\x20-\x7E]') { throw "В пароле только латиница, цифры и знаки — кириллицу Java для ключа не принимает." }
# Пароль — через переменную окружения, а не в командной строке: её видно в
# списке процессов, а Windows PowerShell 5.1 вдобавок портит в аргументах
# кавычки.
$env:MASQUE_KS_PASS = $pass
if (-not $exists) {
    if ($pass -ne (Read-Password "Ещё раз")) { throw "Пароли не совпали." }
    New-Item -ItemType Directory -Force $dir | Out-Null
    # PKCS12: у ключа и хранилища один пароль. В имени владельца — только
    # название программы: сертификат виден любому, кто откроет APK.
    & $keytool -genkeypair -noprompt -storetype PKCS12 -keystore $jks `
        -alias $alias -keyalg RSA -keysize 4096 -validity 10000 `
        -dname "CN=masquevpn" -storepass:env MASQUE_KS_PASS -keypass:env MASQUE_KS_PASS
    if ($LASTEXITCODE -ne 0) { throw "keytool не смог создать ключ." }
} else {
    & $keytool -list -keystore $jks -storepass:env MASQUE_KS_PASS -alias $alias *> $null
    if ($LASTEXITCODE -ne 0) { throw "Пароль не подходит к $jks." }
}
Remove-Item Env:MASQUE_KS_PASS

# .properties читается в ISO-8859-1 и понимает «\» как начало escape:
# обратную косую черту удваиваем, всё не-латинское (путь может быть любым)
# пишем \uXXXX — иначе значение дошло бы до сборки искажённым.
function Escape([string]$v) {
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $v.ToCharArray()) {
        if ($ch -eq '\') { [void]$sb.Append('\\') }
        elseif ([int]$ch -gt 126 -or [int]$ch -lt 32) { [void]$sb.Append(('\u{0:x4}' -f [int]$ch)) }
        else { [void]$sb.Append($ch) }
    }
    $sb.ToString()
}
$lines = @(
    "# Release signing key for masquevpn. Never commit this file (it is in .gitignore).",
    "storeFile=$(Escape ($jks -replace '\\', '/'))",
    "storePassword=$(Escape $pass)",
    "keyAlias=$alias",
    "keyPassword=$(Escape $pass)"
)
[IO.File]::WriteAllLines($props, $lines, [Text.Encoding]::ASCII)

Write-Host ""
Write-Host "готово."
Write-Host "  ключ:      $jks"
Write-Host "  настройки: $props"
Write-Host ""
Write-Host "СЕЙЧАС скопируйте $jks в надёжное место (флешка, облако) и сохраните пароль."
Write-Host "Без них обновить приложение у людей будет нельзя."
Write-Host ""
Write-Host "Сборка подписанного APK:"
Write-Host "  powershell -ExecutionPolicy Bypass -File mobile\build-apk.ps1 -Release"
