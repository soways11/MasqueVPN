#!/bin/sh
# Полная сборка Android-клиента: ядро (core.aar) и приложение (APK) одной
# командой. Запускать на машине с Android SDK и NDK — в контейнере разработки
# их нет (dl.google.com и Maven Central закрыты политикой сети), поэтому шаг
# делается снаружи.
#
# Что нужно поставить один раз:
#   - Go (тот же, что собирает сервер)
#   - Android Studio  →  внутри неё SDK Manager ставит:
#       • Android SDK Platform 35
#       • NDK (Side by side)  — любой из последних
#       • Android SDK Build-Tools
#
# Переменные окружения (Android Studio обычно ставит SDK сюда):
#   export ANDROID_HOME=$HOME/Android/Sdk               # Linux
#   export ANDROID_HOME=$HOME/Library/Android/sdk       # macOS
#   export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/<версия>
#
# Затем просто:
#   ./mobile/build-apk.sh
#
# Готовый APK окажется в:
#   mobile/android/app/build/outputs/apk/debug/app-debug.apk
# Его и переносить на телефон (включив «установку из неизвестных источников»).
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)

# Релиз, подписанный своим ключом: ./mobile/build-apk.sh --release
# Ключ — mobile/android/keystore.properties (make-keystore.ps1 на Windows
# или вручную, см. docs/android-apk.md; в CI его пишет workflow из секретов).
task=assembleDebug
apk="$root/mobile/android/app/build/outputs/apk/debug/app-debug.apk"
if [ "${1:-}" = "--release" ]; then
    if [ ! -f "$root/mobile/android/keystore.properties" ]; then
        echo "нет mobile/android/keystore.properties — неподписанный APK телефон не поставит" >&2
        exit 1
    fi
    task=assembleRelease
    apk="$root/mobile/android/app/build/outputs/apk/release/app-release.apk"
fi
rm -f "$apk"

echo "==> шаг 1/2: собираю ядро (gomobile bind → core.aar)"
sh "$root/mobile/build-aar.sh"

echo "==> шаг 2/2: собираю приложение (gradlew $task)"
cd "$root/mobile/android"
# Первый запуск скачает дистрибутив Gradle по версии из
# gradle/wrapper/gradle-wrapper.properties — это нормально и делается один раз.
# Через sh, а не ./gradlew: из Windows файл попадает в git без права на
# запуск, и раннер GitHub отвечал «Permission denied» (код 126).
sh ./gradlew "$task" ${GRADLE_ARGS:-}

echo
if [ -f "$apk" ]; then
    echo "готово: $apk"
    echo "Перенесите его на телефон и установите (нужно разрешить установку"
    echo "из неизвестных источников для того приложения, через которое ставите)."
else
    echo "APK не найден там, где ожидался: $apk" >&2
    echo "Смотрите вывод Gradle выше." >&2
    exit 1
fi
