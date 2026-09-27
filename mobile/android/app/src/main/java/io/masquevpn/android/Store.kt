package io.masquevpn.android

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import core.Core
import core.Profiles
import org.json.JSONArray
import org.json.JSONObject
import java.security.SecureRandom

/**
 * Хранилище приложения: профили, псевдоним устройства, резолверы системы.
 *
 * Профили лежат строкой в SharedPreferences, а работает с ними ядро
 * (core.Profiles) — те же правила, что в окнах Windows и Linux: что считать
 * ошибкой формы, к какому полю её приписать, как переименовать выбранный
 * профиль, не сбив выбор. Здесь только чтение и запись строки.
 *
 * Служба читает отсюда же, а не из Intent: при «постоянном VPN» система
 * поднимает её без участия экрана, и в Intent тогда пусто.
 */
object Store {

    private const val PREFS = "masquevpn"
    private const val KEY_PROFILES = "profiles"
    private const val KEY_DEVICE = "device_id"

    private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** Профили. Испорченная строка не роняет приложение — начинаем с пустого. */
    fun profiles(ctx: Context): Profiles {
        val raw = prefs(ctx).getString(KEY_PROFILES, "") ?: ""
        return try {
            Core.loadProfiles(raw)
        } catch (e: Exception) {
            Core.loadProfiles("")
        }
    }

    fun save(ctx: Context, p: Profiles) {
        prefs(ctx).edit().putString(KEY_PROFILES, p.json()).apply()
    }

    /**
     * Псевдоним этого телефона — постоянный, создаётся один раз.
     *
     * Ключ у человека один, а устройств несколько. Сервер закрепляет адрес
     * за парой «клиент + устройство»; без постоянного псевдонима телефон
     * получал бы новый адрес при каждом запуске, и соединения внутри туннеля
     * рвались бы на ровном месте.
     *
     * В резервную копию не попадает (allowBackup=false в манифесте): копия,
     * восстановленная на другом телефоне, дала бы двум устройствам один
     * псевдоним — и они снова делили бы один адрес.
     */
    fun deviceId(ctx: Context): String {
        val sp = prefs(ctx)
        val existing = sp.getString(KEY_DEVICE, null)
        if (!existing.isNullOrBlank()) return existing
        val b = ByteArray(8)
        SecureRandom().nextBytes(b)
        val id = b.joinToString("") { "%02x".format(it) }
        sp.edit().putString(KEY_DEVICE, id).apply()
        return id
    }

    /**
     * Дополняет конфигурацию резолверами системы для прикрытия DNS.
     *
     * Прикрытие шлёт настоящие запросы МИМО туннеля, чтобы телефон не
     * выглядел машиной, которая часами льёт объём на один адрес и при этом
     * не спрашивает имён. На desktop ядро берёт резолверы из resolv.conf, а
     * на Android читать их неоткуда — без этого прикрытие молча не включится.
     * Брать их надо ДО подключения: после него активной сетью станет туннель.
     * Заданные вручную (dns_cover.servers) не трогаем.
     *
     * Кладём их и при выключенном прикрытии: ядро ищет по ним ещё и адрес
     * самого сервера (bootstrapResolvers). Своего списка DNS у Go на
     * Android нет, и без этого подключение по имени шло в [::1]:53 —
     * «connection refused». Выключенное прикрытие от этого не включится:
     * его решает флаг disabled, а не список.
     */
    fun withSystemResolvers(ctx: Context, configJson: String): String {
        val cfg = JSONObject(configJson)
        val cover = cfg.optJSONObject("dns_cover") ?: JSONObject()
        if ((cover.optJSONArray("servers")?.length() ?: 0) > 0) return configJson

        val servers = systemResolvers(ctx)
        if (servers.isEmpty()) return configJson

        val arr = JSONArray()
        for (s in servers) arr.put(s)
        cover.put("servers", arr)
        cfg.put("dns_cover", cover)
        return cfg.toString()
    }

    /** Резолверы активной сети; IPv6 — в скобках, ядру нужен вид «хост:порт». */
    //
    // Прикрытие DNS — дополнительная маскировка, а не условие подключения:
    // если система не отдала резолверы (нет разрешения ACCESS_NETWORK_STATE,
    // сети нет, прошивка чудит), подключаемся без них, а не падаем.
    private fun systemResolvers(ctx: Context): List<String> = try {
        resolversOf(ctx)
    } catch (e: SecurityException) {
        emptyList()
    }

    private fun resolversOf(ctx: Context): List<String> {
        val cm = ctx.getSystemService(ConnectivityManager::class.java) ?: return emptyList()
        val net = cm.activeNetwork ?: return emptyList()
        val lp: LinkProperties = cm.getLinkProperties(net) ?: return emptyList()
        return lp.dnsServers.mapNotNull { addr ->
            val host = addr.hostAddress ?: return@mapNotNull null
            when {
                // Ссылочно-локальные (fe80::%wlan0) не годятся: зона теряется.
                host.contains('%') -> null
                host.contains(':') -> "[$host]:53"
                else -> "$host:53"
            }
        }
    }
}
