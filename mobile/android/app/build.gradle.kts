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

android {
    namespace = "io.masquevpn.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "io.masquevpn.android"
        // 24 — VpnService.Builder в нужном нам виде и стабильный protect().
        minSdk = 24
        targetSdk = 35
        // В релизе (GitHub Actions) версия приходит из тега:
        //   ./gradlew assembleRelease -PversionName=0.3.0 -PversionCode=5
        // Локально — эти значения. versionCode только растёт: Android не
        // ставит поверх APK с тем же или меньшим.
        versionCode = (project.findProperty("versionCode") as String?)?.toInt() ?: 4
        versionName = (project.findProperty("versionName") as String?) ?: "0.2.2"
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

dependencies {
    // core.aar — ядро, собранное gomobile bind (см. mobile/build-aar.sh).
    // Больше зависимостей нет: экраны на View и теме Material из самой
    // системы. AppCompat убран сознательно — трём экранам он ничего не даёт,
    // а первой сборке — лишнюю библиотеку, которую надо скачать.
    implementation(files("libs/core.aar"))
}
