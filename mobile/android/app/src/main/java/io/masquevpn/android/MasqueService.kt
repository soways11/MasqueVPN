package io.masquevpn.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.util.Log
import core.Core
import core.Events
import core.Protector
import core.Tunnel
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.concurrent.thread

/**
 * Служба туннеля.
 *
 * Три обязанности, и ни одной больше: создать интерфейс по описанию, которое
 * дало ядро, защитить сокет и отдать ядру дескриптор. Протокол, маскировка,
 * ротация и переподключение — всё в Go, том же коде, что работает на Linux и
 * Windows.
 *
 * Порядок именно такой, а не «создать интерфейс и подключиться»: адрес
 * выдаёт сервер уже внутри установленной сессии, а VpnService.Builder
 * требует адрес ДО создания интерфейса. Поэтому сперва Connect (сессия без
 * интерфейса), потом Builder по её ответу, потом Attach.
 */
class MasqueService : VpnService() {

    companion object {
        const val ACTION_START = "io.masquevpn.START"
        const val ACTION_STOP = "io.masquevpn.STOP"

        private const val TAG = "masquevpn"
        private const val CHANNEL = "tunnel"
        private const val NOTIFICATION_ID = 1
        private const val LOG_LIMIT = 200

        /** Паузы между попытками при постоянном VPN: 2, 4, 8 … 60 секунд. */
        private const val RETRY_FIRST_MS = 2_000L
        private const val RETRY_MAX_MS = 60_000L

        /** Состояние ядра (Core.State*). Служба живёт дольше экрана. */
        @Volatile
        var state: String = Core.StateStopped
            private set

        /** Пользователь нажал «Отключить», а ядро ещё не остановилось. */
        @Volatile
        var stopping: Boolean = false
            private set

        /** Причина последней неудачи — экран показывает её под кнопкой. */
        @Volatile
        var lastError: String = ""
            private set

        /** Строки журнала вида «12:04:31 текст» — как в окнах. */
        val log = ArrayDeque<String>()

        /** Экран подписывается, пока открыт. Вызывается из чужих потоков. */
        @Volatile
        var onUpdate: (() -> Unit)? = null

        @Volatile
        private var running: Tunnel? = null

        /** Счётчики работающего туннеля (см. Tunnel.statsJSON) или пусто. */
        fun statsJSON(): String = running?.statsJSON() ?: Core.newTunnel().statsJSON()

        private val clock = SimpleDateFormat("HH:mm:ss", Locale.ROOT)

        fun note(line: String) {
            synchronized(log) {
                log.addLast(clock.format(Date()) + " " + line)
                while (log.size > LOG_LIMIT) log.removeFirst()
            }
            onUpdate?.invoke()
        }
    }

    private val tunnel: Tunnel = Core.newTunnel()
    private var iface: ParcelFileDescriptor? = null
    private var worker: Thread? = null

    // Постоянный VPN (его включают в настройках Android) система поднимает
    // сама и сама же перезапускает, как только служба остановилась. Если
    // подключение не удаётся, «остановиться с ошибкой» превращается в
    // петлю: остановились — система тут же запустила — снова ошибка, по
    // нескольку раз в секунду. Поэтому в этом режиме служба не
    // останавливается, а повторяет попытку с растущей паузой. Весь трафик
    // тем временем заблокирован системой («Блокировать без VPN») — ровно
    // то, чего человек от постоянного VPN и хочет.
    private val main = Handler(Looper.getMainLooper())
    private var persistent = false
    private var retryDelay = 0L
    private val retry = Runnable { retryNow() }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopTunnel()
            return START_NOT_STICKY
        }

        // Служба запускается не только нашей кнопкой. При «постоянном VPN»
        // её поднимает система, и Intent тогда пуст или несёт
        // SERVICE_INTERFACE. Конфигурацию в таком случае взять неоткуда,
        // кроме собственного хранилища, — поэтому читаем её оттуда всегда.
        startForeground(NOTIFICATION_ID, notification(getString(R.string.notify_connecting)))
        // Нашей кнопкой — ACTION_START; всё остальное (пустой Intent,
        // SERVICE_INTERFACE) — запуск системой, то есть постоянный VPN.
        persistent = intent?.action != ACTION_START
        main.removeCallbacks(retry)
        retryDelay = 0L
        val profiles = Store.profiles(this)
        val cfg = profiles.currentConfig()
        if (cfg.isBlank()) {
            fail(getString(R.string.no_profiles))
            stopTunnel()
            return START_NOT_STICKY
        }
        note("подключение: профиль " + profiles.current())
        startTunnel(cfg)

        // START_NOT_STICKY: перезапускать туннель без ведома пользователя
        // нельзя — он мог остановить его сознательно. Постоянный VPN система
        // поднимает сама, и этот флаг ей не мешает.
        return START_NOT_STICKY
    }

    private fun startTunnel(configJson: String) {
        if (worker != null) return
        lastError = ""
        stopping = false
        worker = thread(name = "masquevpn") {
            try {
                // Резолверы системы нужны прикрытию DNS, и взять их надо
                // ДО подключения: после него активной сетью станет туннель.
                val cfg = Store.withSystemResolvers(this, configJson)

                // Псевдоним телефона: по одному ключу работают несколько
                // устройств, и у каждого должен быть свой адрес.
                tunnel.setDeviceID(Store.deviceId(this))
                // Где ядру помнить удачный порт сервера между запусками.
                tunnel.setStateDir(filesDir.absolutePath)

                // 1. Сессия без интерфейса. Ядро вернёт JSON с тем, что
                //    нужно настроить.
                val networkJson = tunnel.connect(cfg, protector(), events())
                val pfd = buildInterface(networkJson).establish()
                    ?: throw IllegalStateException(
                        "система не дала интерфейс: разрешение на VPN отозвано?"
                    )
                iface = pfd
                // detachFd, а не getFd: дескриптор переходит во владение
                // ядра, и закрывать его теперь будет оно.
                tunnel.attach(pfd.detachFd().toLong())
                running = tunnel
                retryDelay = 0L
                note("туннель работает")
            } catch (e: Throwable) {
                Log.e(TAG, "запуск не удался", e)
                fail(e.message ?: e.toString())
                if (persistent && !stopping) scheduleRetry() else stopTunnel()
            }
        }
    }

    /** Постоянный VPN: прибраться после неудачи и попробовать позже. */
    private fun scheduleRetry() {
        try {
            tunnel.stop()
        } catch (e: Throwable) {
            Log.e(TAG, "уборка перед повтором", e)
        }
        try {
            iface?.close()
        } catch (e: Throwable) {
            Log.e(TAG, "закрытие интерфейса", e)
        }
        iface = null
        running = null
        worker = null
        retryDelay = if (retryDelay == 0L) RETRY_FIRST_MS else minOf(retryDelay * 2, RETRY_MAX_MS)
        note("повтор через ${retryDelay / 1000} с")
        main.postDelayed(retry, retryDelay)
    }

    private fun retryNow() {
        if (stopping || worker != null) return
        val cfg = Store.profiles(this).currentConfig()
        if (cfg.isBlank()) {
            fail(getString(R.string.no_profiles))
            stopTunnel()
            return
        }
        note("подключение: повтор")
        startTunnel(cfg)
    }

    /** Строит интерфейс по описанию от ядра — то, что на Linux делает netsetup. */
    private fun buildInterface(networkJson: String): Builder {
        val nw = JSONObject(networkJson)
        val b = Builder()
        b.setSession(getString(R.string.app_name))
        b.setMtu(nw.optInt("mtu", 1280))

        for (a in nw.strings("addresses")) {
            val (ip, prefix) = splitPrefix(a)
            b.addAddress(ip, prefix)
        }
        for (r in nw.strings("routes")) {
            val (ip, prefix) = splitPrefix(r)
            b.addRoute(ip, prefix)
        }
        for (d in nw.strings("dns")) {
            b.addDnsServer(d)
        }
        // Себя в туннель не заворачиваем. Основная защита — protect() на
        // сокете, это вторая линия: если система почему-то не применит её,
        // приложение не окажется отрезано от своего же сервера.
        b.addDisallowedApplication(packageName)

        b.setConfigureIntent(
            PendingIntent.getActivity(
                this, 0, Intent(this, MainActivity::class.java),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
        )
        return b
    }

    /**
     * VpnService.protect: трафик самого туннеля идёт мимо туннеля.
     *
     * Получатель указан явно (this@MasqueService): внутри объекта есть своя
     * protect, и полагаться на разрешение перегрузки по типу аргумента —
     * верный способ однажды получить бесконечную рекурсию. gomobile
     * отображает Go-шный int в long, отсюда toInt().
     */
    private fun protector() = object : Protector {
        override fun protect(fd: Long): Boolean = this@MasqueService.protect(fd.toInt())
    }

    private fun events() = object : Events {
        override fun onState(s: String) {
            state = s
            updateNotification()
            onUpdate?.invoke()
        }

        override fun onLog(level: String, message: String) {
            Log.println(priority(level), TAG, message)
            // Отладочное — только в logcat: на экране его десятки строк в
            // секунду, и важное тонет.
            if (level != "debug") note(message)
            if (level == "error") lastError = message
        }

        override fun onRebind(networkJson: String) {
            // Сервер выдал другой адрес — интерфейс надо построить заново.
            // Сессия при этом жива: соединения внутри туннеля переживают
            // перестройку.
            try {
                val pfd = buildInterface(networkJson).establish() ?: return
                val old = iface
                iface = pfd
                tunnel.rebind(pfd.detachFd().toLong())
                old?.close()
                note("интерфейс перестроен")
            } catch (e: Throwable) {
                Log.e(TAG, "перестроение интерфейса", e)
                note("ошибка перестроения: ${e.message}")
            }
        }
    }

    private fun fail(message: String) {
        lastError = message
        note("ошибка: $message")
    }

    private fun stopTunnel() {
        main.removeCallbacks(retry)
        persistent = false
        stopping = true
        onUpdate?.invoke()
        thread {
            try {
                tunnel.stop()
            } catch (e: Throwable) {
                Log.e(TAG, "остановка", e)
            }
            running = null
            iface = null
            worker = null
            state = Core.StateStopped
            stopping = false
            note("остановлено")
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    /** Пользователь отозвал разрешение или включил другой VPN. */
    override fun onRevoke() {
        note("разрешение на VPN отозвано")
        stopTunnel()
    }

    override fun onDestroy() {
        main.removeCallbacks(retry)
        running = null
        tunnel.stop()
        super.onDestroy()
    }

    // ---------- уведомление ----------

    private fun updateNotification() {
        val text = when (state) {
            Core.StateRunning ->
                getString(R.string.notify_on, Store.profiles(this).current())
            Core.StateConnecting, Core.StateReady -> getString(R.string.notify_connecting)
            else -> getString(R.string.notify_off)
        }
        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, notification(text))
    }

    private fun notification(text: String): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(CHANNEL) == null) {
            nm.createNotificationChannel(
                NotificationChannel(
                    CHANNEL, getString(R.string.notify_channel),
                    NotificationManager.IMPORTANCE_LOW
                )
            )
        }
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val stop = PendingIntent.getService(
            this, 1, Intent(this, MasqueService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return Notification.Builder(this, CHANNEL)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_stat_masque)
            .setColor(getColor(R.color.accent))
            .setContentIntent(open)
            .addAction(Notification.Action.Builder(null, getString(R.string.disconnect), stop).build())
            .setOngoing(true)
            .build()
    }

    private fun priority(level: String) = when (level) {
        "debug" -> Log.DEBUG
        "warn" -> Log.WARN
        "error" -> Log.ERROR
        else -> Log.INFO
    }
}

/** Достаёт массив строк, которого может не быть. */
private fun JSONObject.strings(key: String): List<String> {
    val arr: JSONArray = optJSONArray(key) ?: return emptyList()
    return (0 until arr.length()).map { arr.getString(it) }
}

/**
 * Разбирает «10.66.0.2/32» и «::/0» — срезом по последнему слэшу, а не
 * разбиением строки: так однозначно для обоих семейств адресов.
 */
private fun splitPrefix(s: String): Pair<String, Int> {
    val i = s.lastIndexOf('/')
    require(i > 0) { "не похоже на префикс: $s" }
    return s.substring(0, i) to s.substring(i + 1).toInt()
}
