#!/bin/sh
# Тексты лицензий всего чужого кода, что попадает в программы masquevpn.
#
#   sh deploy/third-party-notices.sh      → THIRD_PARTY_NOTICES.txt в корне
#
# MIT, BSD и Apache требуют прикладывать свои тексты ко ВСЕМ копиям — в том
# числе к бинарникам в установщиках. Файл кладётся в .deb, установщик
# Windows и пакет VPS. Список модулей берётся из самой сборки (go list -deps
# по всем программам, Linux и Windows, с тегом utls и без), поэтому новая
# зависимость без обновлённого файла роняет тест internal/legal.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
out=${1:-$root/THIRD_PARTY_NOTICES.txt}

mods=$(for os in linux windows; do
    for tags in "" utls; do
        GOOS=$os go list -tags "$tags" -deps -f '{{with .Module}}{{.Path}}{{end}}' ./cmd/... ./mobile/core
    done
done | sort -u | grep -v '^github.com/soways11/masquevpn$' || true)

section() { # заголовок и тексты лицензий из каталога $2
    printf '\n================================================================================\n%s\n================================================================================\n' "$1"
    found=0
    for f in "$2"/LICENSE* "$2"/LICENCE* "$2"/COPYING* "$2"/NOTICE*; do
        [ -f "$f" ] || continue
        printf '\n--- %s ---\n\n' "$(basename "$f")"
        tr -d '\r' < "$f"
        found=1
    done
    [ "$found" = 1 ] || { echo "нет файла лицензии: $1 ($2)" >&2; exit 1; }
}

{
    echo "masquevpn — лицензии стороннего кода"
    echo
    echo "Сам masquevpn распространяется по лицензии MIT (файл LICENSE)."
    echo "Ниже — тексты лицензий кода, который входит в программы masquevpn."
    echo "Файл собирается скриптом deploy/third-party-notices.sh."
    section "Go (стандартная библиотека и среда выполнения)" "$(go env GOROOT)"
    for m in $mods; do
        dir=$(go list -m -f '{{.Dir}}' "$m")
        ver=$(go list -m -f '{{if .Replace}}{{if .Replace.Version}}{{.Replace.Version}}{{else}}в репозитории: third_party{{end}}{{else}}{{.Version}}{{end}}' "$m")
        section "$m ($ver)" "$dir"
    done
    section "Wintun (только установщик Windows: wintun.dll)" "$root/deploy/windows/wintun"
} > "$out"
echo "готово: $out"
