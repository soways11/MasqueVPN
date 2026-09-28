package io.masquevpn.android

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.text.SpannableString
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.view.LayoutInflater
import android.view.View
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.PopupMenu
import android.widget.TextView
import android.widget.Toast
import core.Core
import org.json.JSONArray
import org.json.JSONObject

/**
 * Главный экран — тот же, что в окнах Windows и Linux: состояние, кнопка,
 * скорости, счётчики, профили, журнал.
 *
 * Ничего не решает сам: состояние берёт у службы, числа — готовыми строками
 * из ядра (тем же кодом, что форматирует их в окнах), профили — из ядра
 * через Store. Здесь только показать и передать нажатие.
 */
class MainActivity : Activity() {

    private lateinit var statusDot: View
    private lateinit var status: TextView
    private lateinit var session: TextView
    private lateinit var connect: FrameLayout
    private lateinit var connectLabel: TextView
    private lateinit var connectArrow: ImageView
    private lateinit var rateIn: TextView
    private lateinit var rateOut: TextView
    private lateinit var error: TextView
    private lateinit var stats: View
    private lateinit var bytesIn: TextView
    private lateinit var bytesOut: TextView
    private lateinit var sessionTotal: TextView
    private lateinit var profilesBox: LinearLayout
    private lateinit var empty: View
    private lateinit var logSummary: TextView

    private var shownProfiles = ""

    private val ui = Handler(Looper.getMainLooper())
    private val tick = object : Runnable {
        override fun run() {
            render()
            ui.postDelayed(this, TICK_MS)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        statusDot = findViewById(R.id.status_dot)
        status = findViewById(R.id.status)
        session = findViewById(R.id.session)
        connect = findViewById(R.id.connect)
        connectLabel = findViewById(R.id.connect_label)
        connectArrow = findViewById(R.id.connect_arrow)
        rateIn = findViewById(R.id.rate_in)
        rateOut = findViewById(R.id.rate_out)
        error = findViewById(R.id.error)
        stats = findViewById(R.id.stats)
        bytesIn = findViewById(R.id.bytes_in)
        bytesOut = findViewById(R.id.bytes_out)
        sessionTotal = findViewById(R.id.session_total)
        profilesBox = findViewById(R.id.profiles)
        empty = findViewById(R.id.empty)
        logSummary = findViewById(R.id.log_summary)

        findViewById<View>(R.id.add).setOnClickListener { openAdd(null) }
        findViewById<View>(R.id.settings).setOnClickListener {
            startActivity(Intent(this, SettingsActivity::class.java))
        }
        empty.setOnClickListener { openAdd(null) }
        connect.setOnClickListener { onConnectClicked() }
        findViewById<View>(R.id.log_row).setOnClickListener {
            startActivity(Intent(this, LogActivity::class.java))
        }

        askNotificationPermission()
    }

    override fun onResume() {
        super.onResume()
        MasqueService.onUpdate = { ui.post { render() } }
        shownProfiles = "" // профили могли поменяться на экране добавления
        ui.post(tick)
    }

    override fun onPause() {
        ui.removeCallbacks(tick)
        MasqueService.onUpdate = null
        super.onPause()
    }

    // ---------- состояние ----------

    /** Состояние экрана — те же четыре, что gui.State в окнах. */
    private enum class UiState { Off, Connecting, On, Stopping }

    private fun uiState(): UiState = when {
        MasqueService.stopping -> UiState.Stopping
        MasqueService.state == Core.StateRunning -> UiState.On
        MasqueService.state == Core.StateConnecting ||
            MasqueService.state == Core.StateReady -> UiState.Connecting
        else -> UiState.Off
    }

    private fun render() {
        val st = uiState()
        val failed = st == UiState.Off && MasqueService.lastError.isNotBlank()

        status.setText(
            when {
                failed -> R.string.state_failed
                st == UiState.Connecting -> R.string.state_connecting
                st == UiState.On -> R.string.state_on
                st == UiState.Stopping -> R.string.state_stopping
                else -> R.string.state_off
            }
        )
        status.setTextColor(
            getColor(
                when {
                    failed -> R.color.danger
                    st == UiState.On -> R.color.accent
                    else -> R.color.dim
                }
            )
        )
        statusDot.backgroundTintList = ColorStateList.valueOf(
            getColor(
                when (st) {
                    UiState.On -> R.color.accent
                    UiState.Connecting, UiState.Stopping -> R.color.dot_busy
                    UiState.Off -> if (failed) R.color.danger else R.color.idle_dot
                }
            )
        )

        // Кнопка: залитая только там, где нажатие — обычное дело. Отключение
        // и отмена — обведённые: их не нажимают походя.
        val accent = st == UiState.Off
        connect.setBackgroundResource(if (accent) R.drawable.bg_button_accent else R.drawable.bg_button_outline)
        connectArrow.visibility = if (accent) View.VISIBLE else View.GONE
        connectLabel.setText(
            when (st) {
                UiState.Off -> R.string.connect
                UiState.Connecting -> R.string.cancel
                UiState.On -> R.string.disconnect
                UiState.Stopping -> R.string.stopping
            }
        )
        connectLabel.setTextColor(
            getColor(
                when (st) {
                    UiState.Off -> R.color.accent_ink
                    UiState.Stopping -> R.color.dim
                    else -> R.color.text
                }
            )
        )
        connect.isEnabled = st != UiState.Stopping
        connect.contentDescription = connectLabel.text

        val s = JSONObject(MasqueService.statsJSON())
        rateIn.text = s.optString("rate_in_text", getString(R.string.zero_rate))
        rateOut.text = s.optString("rate_out_text", getString(R.string.zero_rate))
        bytesIn.text = s.optString("bytes_in_text", getString(R.string.zero_bytes))
        bytesOut.text = s.optString("bytes_out_text", getString(R.string.zero_bytes))
        val sessionText = s.optString("session_text", getString(R.string.zero_time))
        sessionTotal.text = sessionText
        session.text = if (st == UiState.On) sessionText else ""

        // Причина неудачи — на месте счётчиков: они в этот момент пусты.
        if (failed) {
            error.text = MasqueService.lastError
            error.visibility = View.VISIBLE
            stats.visibility = View.GONE
        } else {
            error.visibility = View.GONE
            stats.visibility = View.VISIBLE
        }

        renderProfiles()
        renderLog()
    }

    // ---------- профили ----------

    private fun renderProfiles() {
        val list = Store.profiles(this).listJSON()
        if (list == shownProfiles) return // перестраивать строки каждую секунду незачем
        shownProfiles = list

        profilesBox.removeAllViews()
        val rows = JSONArray(list)
        empty.visibility = if (rows.length() == 0) View.VISIBLE else View.GONE
        val inflater = LayoutInflater.from(this)
        for (i in 0 until rows.length()) {
            val r = rows.getJSONObject(i)
            val name = r.getString("name")
            val current = r.optBoolean("current")
            val row = inflater.inflate(R.layout.item_profile, profilesBox, false)
            row.findViewById<TextView>(R.id.name).apply {
                text = name
                setTextColor(getColor(if (current) R.color.accent else R.color.text))
            }
            row.findViewById<TextView>(R.id.server).text = r.optString("host")
            row.findViewById<View>(R.id.selected).visibility =
                if (current) View.VISIBLE else View.INVISIBLE
            row.setOnClickListener { select(name) }
            val menu = row.findViewById<View>(R.id.menu)
            menu.setOnClickListener { showProfileMenu(menu, name, current) }
            profilesBox.addView(row)
        }
    }

    private fun select(name: String) {
        val p = Store.profiles(this)
        if (p.current().equals(name, ignoreCase = true)) return
        // На ходу профиль не меняем — как в окне: переключение означало бы
        // разрыв туннеля в ответ на касание, которым, возможно, просто
        // листали список.
        if (uiState() != UiState.Off) {
            toast(R.string.switch_while_on)
            return
        }
        p.select(name)
        Store.save(this, p)
        MasqueService.note("выбран профиль: $name")
        shownProfiles = ""
        render()
    }

    /** Меню профиля — те же пункты, что в окне. */
    private fun showProfileMenu(anchor: View, name: String, current: Boolean) {
        val menu = PopupMenu(this, anchor)
        val m = menu.menu
        if (!current) m.add(GROUP_USE, MENU_USE, 0, R.string.menu_use)
        m.add(GROUP_EDIT, MENU_RENAME, 1, R.string.menu_rename)
        m.add(GROUP_EDIT, MENU_EDIT, 2, R.string.menu_edit)
        m.add(GROUP_EDIT, MENU_LINK, 3, R.string.menu_copy_link)
        // Удаление — красным, как в окне: единственный необратимый пункт.
        val remove = SpannableString(getString(R.string.menu_remove))
        remove.setSpan(
            ForegroundColorSpan(getColor(R.color.danger)), 0, remove.length,
            Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
        )
        m.add(GROUP_REMOVE, MENU_REMOVE, 4, remove)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            m.setGroupDividerEnabled(true)
        }
        menu.setOnMenuItemClickListener { item ->
            when (item.itemId) {
                MENU_USE -> select(name)
                MENU_RENAME -> rename(name)
                MENU_EDIT -> openAdd(name)
                MENU_LINK -> copyLink(name)
                MENU_REMOVE -> confirmRemove(name)
            }
            true
        }
        menu.show()
    }

    private fun rename(name: String) {
        val input = EditText(this).apply {
            setText(name)
            setSelection(name.length)
            setSingleLine()
            setTextAppearance(R.style.TextAppearance_Masque_Row)
            setBackgroundResource(R.drawable.bg_field)
            val pad = (14 * resources.displayMetrics.density).toInt()
            setPadding(pad, pad, pad, pad)
        }
        val box = FrameLayout(this).apply {
            val pad = (20 * resources.displayMetrics.density).toInt()
            setPadding(pad, pad / 2, pad, 0)
            addView(input)
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.rename_title)
            .setView(box)
            .setPositiveButton(R.string.save) { _, _ ->
                val p = Store.profiles(this)
                try {
                    p.rename(name, input.text.toString())
                    Store.save(this, p)
                    shownProfiles = ""
                    render()
                } catch (e: Exception) {
                    toast(e.message ?: e.toString())
                }
            }
            .setNegativeButton(R.string.dismiss, null)
            .show()
    }

    private fun confirmRemove(name: String) {
        val p = Store.profiles(this)
        if (uiState() != UiState.Off && p.current().equals(name, ignoreCase = true)) {
            toast(R.string.remove_while_on)
            return
        }
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.remove_title, name))
            .setMessage(R.string.remove_message)
            .setPositiveButton(R.string.remove) { _, _ ->
                val fresh = Store.profiles(this)
                try {
                    fresh.remove(name)
                    Store.save(this, fresh)
                    MasqueService.note("профиль удалён: $name")
                    shownProfiles = ""
                    render()
                } catch (e: Exception) {
                    toast(e.message ?: e.toString())
                }
            }
            .setNegativeButton(R.string.dismiss, null)
            .show()
    }

    /**
     * Ссылка в буфер обмена — чтобы перенести доступ на другое устройство.
     * В ней ключ, поэтому буфер помечается как чувствительный (Android 13+
     * тогда не показывает его содержимое во всплывающем превью), а человеку
     * прямо говорится, что пересылать её можно только себе.
     */
    private fun copyLink(name: String) {
        val link = try {
            Store.profiles(this).linkFor(name)
        } catch (e: Exception) {
            toast(e.message ?: e.toString())
            return
        }
        val clip = ClipData.newPlainText(getString(R.string.app_name), link)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            clip.description.extras = PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            }
        }
        getSystemService(ClipboardManager::class.java).setPrimaryClip(clip)
        Toast.makeText(this, R.string.link_copied, Toast.LENGTH_LONG).show()
    }

    private fun openAdd(editName: String?) {
        val i = Intent(this, AddActivity::class.java)
        if (editName != null) i.putExtra(AddActivity.EXTRA_EDIT, editName)
        startActivity(i)
    }

    // ---------- журнал ----------

    private fun renderLog() {
        val lines = synchronized(MasqueService.log) { MasqueService.log.toList() }
        logSummary.text = if (lines.isEmpty()) {
            getString(R.string.log_empty)
        } else {
            val count = resources.getQuantityString(R.plurals.log_records, lines.size, lines.size)
            val last = lines.last()
            if (last.length >= 5) getString(R.string.log_last, count, last.substring(0, 5)) else count
        }
    }

    // ---------- подключение ----------

    private fun onConnectClicked() {
        if (uiState() != UiState.Off) {
            startService(Intent(this, MasqueService::class.java).setAction(MasqueService.ACTION_STOP))
            return
        }
        if (Store.profiles(this).count() == 0L) {
            toast(R.string.no_profiles)
            return
        }
        // Система обязана спросить человека, прежде чем приложение получит
        // право заворачивать весь трафик. prepare возвращает намерение, если
        // согласия ещё нет.
        val consent = VpnService.prepare(this)
        if (consent != null) {
            @Suppress("DEPRECATION")
            startActivityForResult(consent, REQUEST_VPN)
            return
        }
        startTunnel()
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        @Suppress("DEPRECATION")
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_VPN) {
            if (resultCode == RESULT_OK) startTunnel() else toast(R.string.vpn_denied)
        }
    }

    private fun startTunnel() {
        startForegroundService(
            Intent(this, MasqueService::class.java).setAction(MasqueService.ACTION_START)
        )
    }

    /**
     * На Android 13+ уведомление не покажется без разрешения, а для VPN оно
     * не украшение: это видимый признак работы и кнопка «Отключить». Служба
     * работает и без него, поэтому просим один раз, без принуждения.
     */
    private fun askNotificationPermission() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQUEST_NOTIFY)
        }
    }

    private fun toast(res: Int) = Toast.makeText(this, res, Toast.LENGTH_SHORT).show()
    private fun toast(text: String) = Toast.makeText(this, text, Toast.LENGTH_LONG).show()

    companion object {
        private const val REQUEST_VPN = 1
        private const val REQUEST_NOTIFY = 3
        private const val TICK_MS = 1000L

        private const val GROUP_USE = 1
        private const val GROUP_EDIT = 2
        private const val GROUP_REMOVE = 3
        private const val MENU_USE = 1
        private const val MENU_RENAME = 2
        private const val MENU_EDIT = 3
        private const val MENU_LINK = 4
        private const val MENU_REMOVE = 5
    }
}
