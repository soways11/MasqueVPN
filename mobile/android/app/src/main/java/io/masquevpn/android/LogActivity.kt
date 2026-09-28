package io.masquevpn.android

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast

/**
 * Журнал целиком: отдельный экран с кнопкой «назад», как в окнах.
 *
 * Строки берутся из MasqueService.log (не больше LOG_LIMIT) и обновляются раз
 * в секунду. Если журнал прокручен до конца, новые записи видны сразу; если
 * человек читает середину — экран не дёргается под ним.
 */
class LogActivity : Activity() {

    private val ui = Handler(Looper.getMainLooper())
    private lateinit var scroll: ScrollView
    private lateinit var text: TextView
    private var shown = -1 // сколько строк показано; -1 — ещё ничего

    private val tick = object : Runnable {
        override fun run() {
            render()
            ui.postDelayed(this, TICK_MS)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_log)
        scroll = findViewById(R.id.log_scroll)
        text = findViewById(R.id.log_text)

        findViewById<View>(R.id.back).setOnClickListener { finish() }
        findViewById<View>(R.id.copy).setOnClickListener { copy() }
    }

    override fun onResume() {
        super.onResume()
        shown = -1
        ui.post(tick)
    }

    override fun onPause() {
        super.onPause()
        ui.removeCallbacks(tick)
    }

    private fun lines(): List<String> = synchronized(MasqueService.log) { MasqueService.log.toList() }

    private fun render() {
        val lines = lines()
        // Строк столько же и последняя та же — перерисовывать незачем: иначе
        // выделение текста сбрасывалось бы каждую секунду.
        val key = lines.size * 31 + (lines.lastOrNull()?.hashCode() ?: 0)
        if (key == shown) return
        val first = shown == -1
        shown = key

        // Был ли журнал прокручен до конца — до того, как текст сменится.
        val atBottom = first || !scroll.canScrollVertically(1)
        text.text = if (lines.isEmpty()) getString(R.string.log_none) else lines.joinToString("\n")
        if (atBottom) {
            scroll.post { scroll.fullScroll(View.FOCUS_DOWN) }
        }
    }

    private fun copy() {
        val lines = lines()
        if (lines.isEmpty()) return
        val clip = ClipData.newPlainText(getString(R.string.log), lines.joinToString("\n"))
        getSystemService(ClipboardManager::class.java).setPrimaryClip(clip)
        Toast.makeText(this, R.string.log_copied, Toast.LENGTH_SHORT).show()
    }

    companion object {
        private const val TICK_MS = 1000L
    }
}
