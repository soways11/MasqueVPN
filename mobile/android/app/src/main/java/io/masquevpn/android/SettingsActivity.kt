package io.masquevpn.android

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.widget.TextView

/**
 * Настройки. Короче, чем в окне, — почему, объяснено в разметке
 * (activity_settings.xml): то, что на desktop делает приложение, на Android
 * делает система, и честнее вести туда, чем рисовать переключатель, который
 * ничего не гарантирует.
 */
class SettingsActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)

        findViewById<View>(R.id.back).setOnClickListener { finish() }
        findViewById<View>(R.id.add).setOnClickListener {
            startActivity(Intent(this, AddActivity::class.java))
        }
        findViewById<View>(R.id.always_on).setOnClickListener { openVpnSettings() }

        findViewById<TextView>(R.id.device_id).text = Store.deviceId(this)
        findViewById<TextView>(R.id.version).text = try {
            packageManager.getPackageInfo(packageName, 0).versionName ?: "—"
        } catch (e: Exception) {
            "—"
        }
    }

    /**
     * «Постоянный VPN» и «Блокировать соединения без VPN» — в системных
     * настройках VPN. На некоторых прошивках такого экрана нет по прямому
     * адресу; тогда — общие настройки сети.
     */
    private fun openVpnSettings() {
        try {
            startActivity(Intent(Settings.ACTION_VPN_SETTINGS))
        } catch (e: ActivityNotFoundException) {
            startActivity(Intent(Settings.ACTION_WIRELESS_SETTINGS))
        }
    }
}
