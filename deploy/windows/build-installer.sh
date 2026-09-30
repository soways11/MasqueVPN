#!/bin/sh
# Сборка установщика masquevpn для Windows.
#
#   sh deploy/windows/build-installer.sh 1.0.0 [каталог-для-установщика]
#
# Работает и в Linux, и в macOS: makensis кроссплатформенный
# (apt install nsis / brew install makensis), программы собирает Go.
set -eu

version=${1:?версия, например 1.0.0}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
out=${2:-$root/dist}
# makensis пишет относительно каталога .nsi, а не текущего: относительный
# путь дал бы «Can't open output file». Поэтому — абсолютный.
mkdir -p "$out"
out=$(cd "$out" && pwd)

# Версия файла в Windows — четыре числа: 1.0.0 → 1.0.0.0. Её видит
# установщик; сам masquevpn.exe берёт сведения о версии из
# cmd/masquevpn-win/rsrc_windows_amd64.syso — перед релизом новой версии
# пересобрать его (cmd/masquevpn-win/winres/README.md).
version4=$(echo "$version" | awk -F. '{printf "%d.%d.%d.%d", $1, $2, $3, ($4==""?0:$4)}')

command -v makensis >/dev/null 2>&1 || { echo "нужен makensis (пакет nsis)" >&2; exit 1; }
[ -f "$here/wintun/amd64/wintun.dll" ] || { echo "нет $here/wintun/amd64/wintun.dll — см. wintun/README.md" >&2; exit 1; }

echo "==> сборка программ (windows/amd64)"
rm -rf "$here/build"
mkdir -p "$here/build" "$out"
# -H=windowsgui: у окна нет консоли. Иконку и версию exe берёт из
# cmd/masquevpn-win/rsrc_windows_amd64.syso (см. cmd/masquevpn-win/winres).
(cd "$root" && GOOS=windows GOARCH=amd64 go build -tags utls -trimpath \
    -ldflags="-s -w -H=windowsgui -X github.com/soways11/masquevpn/internal/version.Version=$version" -o "$here/build/masquevpn.exe" ./cmd/masquevpn-win)
(cd "$root" && GOOS=windows GOARCH=amd64 go build -tags utls -trimpath \
    -ldflags="-s -w -X github.com/soways11/masquevpn/internal/version.Version=$version" -o "$here/build/masquevpn-cli.exe" ./cmd/vpnclient)

echo "==> установщик"
makensis -V2 -DVERSION="$version" -DVERSION4="$version4" -DSRC="$here" -DOUT="$out" "$here/masquevpn.nsi"
rm -rf "$here/build"
echo "готово: $out/masquevpn-setup-$version.exe"
