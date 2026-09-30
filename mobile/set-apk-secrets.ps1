# Записывает секреты подписи APK в репозиторий GitHub (для release.yml).
#
#   powershell -ExecutionPolicy Bypass -File mobile\set-apk-secrets.ps1
#
# Пароль и псевдоним берутся из mobile\android\keystore.properties, который
# сделал make-keystore.ps1, и ДО записи проверяются keytool на самом ключе.
# Пароль не печатается и не попадает в историю PowerShell.
param(
    [string]$Props = "",
    [string]$Repo = ""
)
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$candidates = @()
if ($Props) { $candidates += $Props }
$candidates += (Join-Path $root "mobile\android\keystore.properties")
$candidates += "C:\masquevpn\mobile\android\keystore.properties"
$Props = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $Props) {
    throw "Не найден keystore.properties. Укажите путь: -Props C:\путь\keystore.properties"
}
Write-Host "настройки ключа: $Props"

# --- разбор .properties (make-keystore.ps1 пишет ASCII, \ удвоен, прочее — \uXXXX) ---
function Unescape([string]$v) {
    $sb = New-Object System.Text.StringBuilder
    $i = 0
    while ($i -lt $v.Length) {
        $c = $v[$i]
        if ($c -eq '\' -and $i + 1 -lt $v.Length) {
            $n = $v[$i + 1]
            if ($n -eq 'u' -and $i + 5 -lt $v.Length) {
                [void]$sb.Append([char][Convert]::ToInt32($v.Substring($i + 2, 4), 16))
                $i += 6
                continue
            }
            [void]$sb.Append($n)
            $i += 2
            continue
        }
        [void]$sb.Append($c)
        $i++
    }
    $sb.ToString()
}
$kv = @{}
foreach ($line in Get-Content -LiteralPath $Props) {
    if ($line -match '^\s*[#!]' -or $line -notmatch '=') { continue }
    $k, $v = $line -split '=', 2
    $kv[$k.Trim()] = Unescape $v
}
foreach ($need in "storeFile", "storePassword", "keyAlias") {
    if (-not $kv[$need]) { throw "В $Props нет $need" }
}
$jks = $kv["storeFile"] -replace '/', '\'
$alias = $kv["keyAlias"]
if (-not (Test-Path -LiteralPath $jks)) { throw "Нет файла ключа: $jks" }
Write-Host "ключ:            $jks"
Write-Host "псевдоним:       $alias"

# --- keytool ---
$keytool = $null
if ($env:JAVA_HOME -and (Test-Path "$env:JAVA_HOME\bin\keytool.exe")) { $keytool = "$env:JAVA_HOME\bin\keytool.exe" }
if (-not $keytool) {
    # Любой JDK подойдёт: keytool читает PKCS12 во всех версиях.
    $keytool = @(
        "C:\Program Files\Eclipse Adoptium\*\bin\keytool.exe",
        "C:\Program Files\Java\*\bin\keytool.exe",
        "C:\Program Files\Microsoft\jdk*\bin\keytool.exe",
        "C:\Program Files\Zulu\*\bin\keytool.exe",
        "C:\Program Files\Android\Android Studio\jbr\bin\keytool.exe"
    ) | ForEach-Object { Resolve-Path $_ -ErrorAction SilentlyContinue } |
        Select-Object -First 1 -ExpandProperty Path
}
if (-not $keytool) {
    $cmd = Get-Command keytool -ErrorAction SilentlyContinue
    if ($cmd) { $keytool = $cmd.Source }
}
if (-not $keytool) { throw "Не найден keytool. Поставьте JDK: winget install EclipseAdoptium.Temurin.21.JDK" }

# --- проверка пароля и псевдонима на самом ключе ---
$env:MASQUE_KS_PASS = $kv["storePassword"]
# PowerShell 5.1 при Stop превращает любую строку stderr (например,
# «Picked up JAVA_TOOL_OPTIONS») в исключение — на время вызова Continue.
$ErrorActionPreference = "Continue"
try {
    $out = & $keytool -list -keystore $jks -storepass:env MASQUE_KS_PASS -alias $alias 2>&1
    $ok = ($LASTEXITCODE -eq 0)
} finally {
    Remove-Item Env:\MASQUE_KS_PASS -ErrorAction SilentlyContinue
    $ErrorActionPreference = "Stop"
}
if (-not $ok) {
    Write-Host ($out | Out-String)
    throw "Ключ не открылся этим паролем/псевдонимом — секреты НЕ записаны. Проверьте $Props."
}
Write-Host "пароль и псевдоним подходят к ключу"

# --- запись секретов ---
# Значения — через --body из переменной: в историю PowerShell попадает
# только имя переменной, а не пароль, и нет перевода строки на конце,
# который PowerShell дописывает при передаче через конвейер.
$repoArgs = @()
if ($Repo) { $repoArgs = @("-R", $Repo) }
$b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($jks))
$pass = $kv["storePassword"]
# Windows PowerShell 5.1 передаёт аргументы программам, не экранируя
# кавычки внутри (и \ перед закрывающей кавычкой) — делаем это сами,
# иначе пароль с " дошёл бы до gh обрезанным. PowerShell 7.3+ экранирует сам.
function NativeArg([string]$v) {
    if ($PSVersionTable.PSVersion -ge [version]"7.3") { return $v }
    $a = $v -replace '(\\*)"', '$1$1\"'
    if ($a -match '\s') { $a = $a -replace '(\\+)$', '$1$1' }
    $a
}
$pass = NativeArg $pass
$alias = NativeArg $alias
& gh secret set ANDROID_KEYSTORE_B64 @repoArgs --body $b64
if ($LASTEXITCODE -ne 0) { throw "gh secret set ANDROID_KEYSTORE_B64 не удался" }
& gh secret set ANDROID_KEYSTORE_PASSWORD @repoArgs --body $pass
if ($LASTEXITCODE -ne 0) { throw "gh secret set ANDROID_KEYSTORE_PASSWORD не удался" }
& gh secret set ANDROID_KEY_ALIAS @repoArgs --body $alias
if ($LASTEXITCODE -ne 0) { throw "gh secret set ANDROID_KEY_ALIAS не удался" }
Remove-Variable pass, b64

Write-Host ""
Write-Host "готово: три секрета записаны. Пересобрать релиз:"
Write-Host "  git tag -f v1.0.0; git push origin v1.0.0 --force"
