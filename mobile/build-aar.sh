#!/bin/sh
# Сборка ядра masquevpn в библиотеку для Android (core.aar).
#
# Запускать на машине, где есть Android SDK и NDK: gomobile связывает Go с
# Java через cgo, а для этого нужен компилятор из NDK. В контейнере
# разработки его нет, поэтому шаг вынесен сюда и делается один раз перед
# сборкой приложения.
#
#   export ANDROID_HOME=$HOME/Android/Sdk
#   export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/<версия>
#   ./mobile/build-aar.sh
#
# Результат: mobile/android/app/libs/core.aar
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
out="$root/mobile/android/app/libs"

if [ -z "${ANDROID_NDK_HOME:-}" ] && [ -z "${ANDROID_HOME:-}" ]; then
    echo "нужен ANDROID_HOME (и NDK внутри него) либо ANDROID_NDK_HOME" >&2
    exit 1
fi

# gomobile ставится в GOBIN; init достаточно выполнить один раз.
#
# Версия закреплена, а не @latest: свежий gomobile требует Go 1.26, и на
# машине с Go из go.mod проекта (1.24) установка падала бы на ровном месте.
# Это та же версия, которой сверены привязки (core/BINDINGS.md).
GOMOBILE_VERSION=v0.0.0-20260209203831-923679eb55af
if ! command -v gomobile >/dev/null 2>&1; then
    echo "ставлю gomobile $GOMOBILE_VERSION…"
    go install golang.org/x/mobile/cmd/gomobile@$GOMOBILE_VERSION
    go install golang.org/x/mobile/cmd/gobind@$GOMOBILE_VERSION
fi
gomobile init

mkdir -p "$out"
cd "$root"

# gomobile bind собирает обвязку, которая импортирует golang.org/x/mobile/bind,
# и ищет этот пакет в зависимостях НАШЕГО модуля. В go.mod его нет (серверу
# и окнам он не нужен), поэтому без этой строки bind падает с «no Go package
# in golang.org/x/mobile/bind». Правит go.mod и go.sum — это ожидаемо.
go get golang.org/x/mobile/bind@$GOMOBILE_VERSION

# Имя пакета Java оставляем по умолчанию (core): именно так его импортирует
# приложение (import core.Core). Менять — только вместе с импортами в Kotlin.
#
# Тег utls даёт клиенту отпечаток ClientHello браузера. Без него сборка тоже
# работает, но транспорт будет узнаваем как Go.
gomobile bind \
    -target=android/arm64,android/arm,android/amd64 \
    -androidapi 24 \
    -tags utls \
    -o "$out/core.aar" \
    ./mobile/core

echo "готово: $out/core.aar"
