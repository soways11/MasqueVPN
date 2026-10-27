import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Ключ подписи релиза — из mobile/android/keystore.properties (его пишет
// mobile/make-keystore.ps1). Файла в репозитории нет и быть не должно: в нём
// пароль. Нет файла — релиз собирается неподписанным, а build-apk.ps1
// -Release откажется его выдавать.
val releaseSigning = Properties().apply {
    val f = rootProject.file("keystore.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}

// Версия приложения. В релизе (GitHub Actions) приходит из тега:
//   ./gradlew assembleRelease -PversionName=1.0.0
// Локально — значение ниже; build-apk.ps1/.sh его не меняют.
val appVersion = (project.findProperty("versionName") as String?) ?: "1.1.0"

// versionCode выводится из версии: 1.2.3 → 1020300. Android не ставит APK с
// МЕНЬШИМ versionCode поверх большего, поэтому номер обязан расти вместе с
// версией — и совпадать у релизной и локальной сборки одной версии, иначе
// собранный у себя APK не встанет поверх скачанного с GitHub (так и было:
// локально 4, в релизе 1000+номер запуска). Две последние цифры — запас на
// пересборку той же версии (-PversionCode).
fun versionCodeOf(v: String): Int {
    val m = Regex("^(\\d+)\\.(\\d+)\\.(\\d+)").find(v)
        ?: throw GradleException("версия «$v»: ожидалось X.Y.Z")
    val (major, minor, patch) = m.destructured
    return major.toInt() * 1_000_000 + minor.toInt() * 10_000 + patch.toInt() * 100
}

// Тексты лицензий внутрь APK. На desktop LICENSE и THIRD_PARTY_NOTICES.txt
// кладутся рядом с программой установщиком (.deb, NSIS, пакет VPS), а APK их
// до сих пор не несёт вовсе — то есть пользователь Android получает код
// сторонних библиотек без текстов их лицензий, чего MIT и BSD прямо требуют.
// Файлы копируются в assets на сборке, а не лежат в репозитории копией:
// копия разъехалась бы с корневой (её пересобирает
// deploy/third-party-notices.sh), и именно устаревшую увёз бы APK.
val legalAssets = layout.buildDirectory.dir("generated/legal")

val copyLegal by tasks.registering(Copy::class) {
    from(rootProject.file("../../LICENSE"))
    from(rootProject.file("../../THIRD_PARTY_NOTICES.txt"))
    into(legalAssets)
}

android {
    namespace = "io.masquevpn.android"
    compileSdk = 35

    sourceSets["main"].assets.srcDir(legalAssets)

    defaultConfig {
        applicationId = "io.masquevpn.android"
        // 24 — VpnService.Builder в нужном нам виде и стабильный protect().
        minSdk = 24
        targetSdk = 35
        versionCode = (project.findProperty("versionCode") as String?)?.toInt() ?: versionCodeOf(appVersion)
        versionName = appVersion
    }

    signingConfigs {
        if (releaseSigning.getProperty("storeFile") != null) {
            create("release") {
                storeFile = file(releaseSigning.getProperty("storeFile"))
                storePassword = releaseSigning.getProperty("storePassword")
                keyAlias = releaseSigning.getProperty("keyAlias")
                keyPassword = releaseSigning.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.findByName("release")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

// Копирование лицензий должно случиться до всех задач, читающих каталог
// assets, — иначе задача просто не выполнится (APK уедет без текстов), а на
// release-сборке Gradle 8.11 вовсе падает: lint-задача
// generateReleaseLintVitalReportModel читает build/generated/legal, не объявив
// зависимости от copyLegal. Покрываем и сборку assets (merge*Assets), и все
// задачи lint — copyLegal дёшев, лишняя зависимость безвредна.
tasks.configureEach {
    if ((name.startsWith("merge") && name.endsWith("Assets")) || name.contains("Lint")) {
        dependsOn(copyLegal)
    }
}

dependencies {
    // core.aar — ядро, собранное gomobile bind (см. mobile/build-aar.sh).
    // Больше зависимостей нет: экраны на View и теме Material из самой
    // системы. AppCompat убран сознательно — трём экранам он ничего не даёт,
    // а первой сборке — лишнюю библиотеку, которую надо скачать.
    implementation(files("libs/core.aar"))
}
