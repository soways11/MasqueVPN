#!/bin/sh
# Пакет для установки сервера на VPS: бинарники под amd64 и arm64 и скрипты.
#
#   VERSION=1.0.0 sh deploy/vps/build.sh [каталог-для-пакета]   → masquevpn-vps.tar.gz
#
# VERSION попадает в бинарник (vpnserver version, журнал при запуске); без
# неё — «dev».
#
# Дальше:  scp masquevpn-vps.tar.gz root@СЕРВЕР:/tmp/
#          ssh root@СЕРВЕР 'cd /tmp && tar xzf masquevpn-vps.tar.gz && cd masquevpn-vps && sh install.sh ДОМЕН почта'
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
out=${1:-$root/dist}
version=${VERSION:-dev}

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
pkg="$stage/masquevpn-vps"
mkdir -p "$pkg"

for arch in amd64 arm64; do
    echo "==> vpnserver ($arch)"
    (cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath \
        -ldflags="-s -w -X github.com/soways11/masquevpn/internal/version.Version=$version" -o "$pkg/vpnserver-$arch" ./cmd/vpnserver)
done
for f in install.sh uninstall.sh diag.sh README.txt; do
    install -m 0644 "$here/$f" "$pkg/$f"
done
# Лицензия и тексты лицензий чужого кода — к каждой копии бинарников.
install -m 0644 "$root/LICENSE" "$pkg/LICENSE"
install -m 0644 "$root/THIRD_PARTY_NOTICES.txt" "$pkg/THIRD_PARTY_NOTICES.txt"
chmod 0755 "$pkg"/*.sh

mkdir -p "$out"
tar -C "$stage" -czf "$out/masquevpn-vps.tar.gz" masquevpn-vps
echo "готово: $out/masquevpn-vps.tar.gz"
