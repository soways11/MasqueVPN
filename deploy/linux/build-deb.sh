#!/bin/sh
# Сборка пакета masquevpn для Debian и Ubuntu.
#
#   sh deploy/linux/build-deb.sh amd64 0.2.0 [каталог-для-пакета]
#   sh deploy/linux/build-deb.sh arm64 0.2.0
#
# Нужны Go и dpkg-deb (есть на любом Debian/Ubuntu). Программы собираются из
# исходников здесь же — пакет не зависит от того, что лежит в папках рядом.
#
# Что ставит пакет:
#   /usr/lib/masquevpn/masquevpn-gui     окно
#   /usr/lib/masquevpn/masquevpn-cli     клиент без окна
#   /usr/bin/masquevpn                   запуск окна (через pkexec)
#   /usr/bin/masquevpn-cli               ссылка на клиент без окна
#   /usr/share/applications/…            ярлык в меню приложений
#   /usr/share/icons/hicolor/…           значок
#   /usr/share/polkit-1/actions/…        разрешение pkexec на запуск окна
#   /lib/systemd/system/…client.service  постоянный VPN без окна (выключен)
#   /var/lib/masquevpn                   профили и псевдоним устройства (0700)
set -eu

arch=${1:?архитектура: amd64 или arm64}
version=${2:?версия, например 0.2.0}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
out=${3:-$root/dist}
# Кто собрал пакет — видно в «dpkg -s masquevpn» у каждого, кто его поставил.
# Поэтому по умолчанию не чей-то адрес, а заглушка (.invalid — домен, который
# заведомо никому не принадлежит); свой — через переменную:
#   MAINTAINER="Имя <почта>" sh deploy/linux/build-deb.sh amd64 0.2.0
maintainer=${MAINTAINER:-masquevpn <packages@masquevpn.invalid>}

case "$arch" in
    amd64|arm64) ;;
    *) echo "архитектура $arch не поддерживается: amd64 или arm64" >&2; exit 1 ;;
esac

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
pkg="$stage/masquevpn_${version}_${arch}"

echo "==> сборка программ ($arch)"
mkdir -p "$pkg/usr/lib/masquevpn"
# Тег utls — отпечаток ClientHello браузера; без cgo, чтобы пакет не зависел
# от версии glibc на машине пользователя.
(cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -tags utls -trimpath \
    -ldflags="-s -w" -o "$pkg/usr/lib/masquevpn/masquevpn-gui" ./cmd/masquevpn-gui)
(cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -tags utls -trimpath \
    -ldflags="-s -w" -o "$pkg/usr/lib/masquevpn/masquevpn-cli" ./cmd/vpnclient)

echo "==> раскладка файлов"
install -D -m 0755 "$here/masquevpn" "$pkg/usr/bin/masquevpn"
mkdir -p "$pkg/usr/bin"
ln -s ../lib/masquevpn/masquevpn-cli "$pkg/usr/bin/masquevpn-cli"
install -D -m 0644 "$here/masquevpn.desktop" "$pkg/usr/share/applications/masquevpn.desktop"
install -D -m 0644 "$here/io.masquevpn.gui.policy" "$pkg/usr/share/polkit-1/actions/io.masquevpn.gui.policy"
install -D -m 0644 "$here/masquevpn-client.service" "$pkg/lib/systemd/system/masquevpn-client.service"
for s in 48 64 128 256; do
    install -D -m 0644 "$here/icons/masquevpn-$s.png" "$pkg/usr/share/icons/hicolor/${s}x${s}/apps/masquevpn.png"
done

size=$(du -sk "$pkg" | cut -f1)
mkdir -p "$pkg/DEBIAN"
cat > "$pkg/DEBIAN/control" <<EOF
Package: masquevpn
Version: $version
Architecture: $arch
Maintainer: $maintainer
Installed-Size: $size
Section: net
Priority: optional
Depends: pkexec | policykit-1
Recommends: fonts-liberation | fonts-dejavu-core | fonts-noto-core
Homepage: https://github.com/soways11/masquevpn
Description: VPN на MASQUE (CONNECT-IP поверх HTTP/3)
 Клиент masquevpn: окно для рабочего стола и клиент без окна.
 Туннель идёт внутри QUIC и снаружи выглядит как обычный HTTP/3.
EOF

cat > "$pkg/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
# Каталог данных: профили с ключами и псевдоним устройства. Только root —
# окно работает от root (pkexec), а другим пользователям машины ключи видеть
# незачем.
mkdir -p /var/lib/masquevpn
chmod 0700 /var/lib/masquevpn
# Значок и ярлык появляются в меню сразу, а не после перезахода.
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -q -t /usr/share/icons/hicolor || true
fi
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications || true
fi
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
exit 0
EOF

cat > "$pkg/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
# Туннель без окна останавливаем до удаления программы — иначе он остался
# бы работать от уже удалённого файла.
if [ -d /run/systemd/system ] && systemctl is-active --quiet masquevpn-client 2>/dev/null; then
    systemctl stop masquevpn-client || true
fi
if [ "$1" = remove ] && [ -d /run/systemd/system ]; then
    systemctl disable masquevpn-client >/dev/null 2>&1 || true
fi
exit 0
EOF

cat > "$pkg/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
# «Удалить» оставляет профили: переустановка не должна стоить доступов.
# «Удалить полностью» (purge) — убирает и их: там ключи.
if [ "$1" = purge ]; then
    rm -rf /var/lib/masquevpn
fi
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
exit 0
EOF
chmod 0755 "$pkg/DEBIAN/postinst" "$pkg/DEBIAN/prerm" "$pkg/DEBIAN/postrm"

mkdir -p "$out"
dpkg-deb --build --root-owner-group "$pkg" "$out/masquevpn_${version}_${arch}.deb" >/dev/null
echo "готово: $out/masquevpn_${version}_${arch}.deb"
