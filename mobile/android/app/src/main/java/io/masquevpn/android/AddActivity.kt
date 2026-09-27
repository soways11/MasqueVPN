package io.masquevpn.android

import android.app.Activity
import android.app.AlertDialog
import android.content.ClipboardManager
import android.content.Intent
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.view.inputmethod.EditorInfo
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import core.Core
import org.json.JSONObject

/**
 * Добавление и правка сервера — форма из окон Windows и Linux.
 *
 * Правила формы живут в ядре (config.BuildForm): что считать ошибкой, к
 * какому полю её приписать, что человеку сказать. Здесь — показать ответ и
 * подсветить поле.
 *
 * Открывается и по ссылке masquevpn:// — например, из мессенджера, если он
 * делает такие ссылки нажимаемыми: поля сразу заполнены, остаётся нажать
 * «Добавить». Сам профиль при этом не добавляется молча: человек должен
 * видеть, к какому серверу подключится.
 */
class AddActivity : Activity() {

    private lateinit var fields: Array<EditText>
    private lateinit var title: TextView
    private lateinit var confirmLabel: TextView
    private lateinit var notice: TextView
    private lateinit var delete: View

    /** Имя профиля, который правим; null — добавляем новый. */
    private var editing: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_add)

        // Порядок совпадает с номерами полей ядра: 1 — адрес, 2 — ключ,
        // 3 — идентификатор (Core.Field*), имя — четвёртое, без номера.
        fields = arrayOf(
            findViewById(R.id.server),
            findViewById(R.id.key),
            findViewById(R.id.client_id),
            findViewById(R.id.name),
        )
        title = findViewById(R.id.title)
        confirmLabel = findViewById(R.id.confirm_label)
        notice = findViewById(R.id.notice)
        delete = findViewById(R.id.delete)

        findViewById<View>(R.id.back).setOnClickListener { finish() }
        findViewById<View>(R.id.paste).setOnClickListener { paste() }
        findViewById<View>(R.id.confirm).setOnClickListener { confirm() }
        delete.setOnClickListener { confirmDelete() }

        // Правка поля снимает с него красную рамку: ошибка была про прежнее
        // значение.
        for (f in fields) {
            f.addTextChangedListener(object : TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
                override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
                override fun afterTextChanged(s: Editable?) {
                    f.setBackgroundResource(R.drawable.bg_field)
                }
            })
        }
        fields[3].setOnEditorActionListener { _, action, _ ->
            if (action == EditorInfo.IME_ACTION_DONE) {
                confirm()
                true
            } else {
                false
            }
        }

        editing = intent.getStringExtra(EXTRA_EDIT)
        if (editing != null && savedInstanceState == null) {
            loadForEdit(editing!!)
        }
        if (editing != null) {
            title.setText(R.string.edit_server)
            confirmLabel.setText(R.string.save)
            delete.visibility = View.VISIBLE
            showNotice(getString(R.string.edit_notice), false)
        }

        // Открыли ссылкой masquevpn://… — раскладываем её по полям.
        val link = intent.data?.toString()
        if (link != null && savedInstanceState == null && Core.isLink(link)) {
            fill(link)
        }
    }

    private fun loadForEdit(name: String) {
        val json = Store.profiles(this).fieldsJSON(name)
        if (json.isBlank()) {
            finish() // профиль удалили, пока открывали форму
            return
        }
        val f = JSONObject(json)
        fields[0].setText(f.optString("server"))
        fields[1].setText(f.optString("auth_key"))
        fields[2].setText(f.optString("client_id"))
        fields[3].setText(f.optString("name"))
    }

    /** «Вставить из буфера» — ссылка или client.json раскладываются по полям. */
    private fun paste() {
        val clip = getSystemService(ClipboardManager::class.java).primaryClip
        val text = if (clip != null && clip.itemCount > 0) {
            clip.getItemAt(0).coerceToText(this)?.toString() ?: ""
        } else {
            ""
        }
        if (text.isBlank()) {
            showNotice(getString(R.string.clipboard_empty), true)
            return
        }
        fill(text)
    }

    private fun fill(text: String) {
        val r = JSONObject(Core.parseShared(text))
        if (!r.optBoolean("ok")) {
            showNotice(r.optString("error"), true)
            return
        }
        fields[0].setText(r.optString("server"))
        fields[1].setText(r.optString("auth_key"))
        fields[2].setText(r.optString("client_id"))
        // Имя из ссылки — лучше домена: «дача» говорит больше. Своё, уже
        // вписанное человеком, не затираем.
        val name = r.optString("name")
        if (name.isNotBlank() && fields[3].text.isBlank()) fields[3].setText(name)
        showNotice(getString(R.string.pasted_notice), false)
        fields[0].requestFocus()
    }

    private fun confirm() {
        val p = Store.profiles(this)
        val server = fields[0].text.toString()
        val key = fields[1].text.toString()
        val id = fields[2].text.toString()
        val name = fields[3].text.toString()
        val answer = editing?.let { p.update(it, server, key, id, name) }
            ?: p.add(server, key, id, name)
        val r = JSONObject(answer)
        if (!r.optBoolean("ok")) {
            // Подсвечиваем именно то поле, где ошибка: «неверный ключ» без
            // подсветки заставляет перечитывать всю форму.
            val field = r.optInt("field")
            if (field in 1..3) {
                fields[field - 1].setBackgroundResource(R.drawable.bg_field_error)
                fields[field - 1].requestFocus()
            }
            showNotice(r.optString("error"), true)
            return
        }
        Store.save(this, p)
        val added = r.optString("name")
        MasqueService.note(if (editing != null) "профиль изменён: $added" else "добавлен профиль: $added")
        finish()
    }

    private fun confirmDelete() {
        val name = editing ?: return
        val p = Store.profiles(this)
        val connected = MasqueService.state != Core.StateStopped &&
            MasqueService.state != Core.StateError
        if (connected && p.current().equals(name, ignoreCase = true)) {
            showNotice(getString(R.string.remove_while_on), true)
            return
        }
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.remove_title, name))
            .setMessage(R.string.remove_message)
            .setPositiveButton(R.string.remove) { _, _ ->
                try {
                    p.remove(name)
                    Store.save(this, p)
                    MasqueService.note("профиль удалён: $name")
                    finish()
                } catch (e: Exception) {
                    Toast.makeText(this, e.message ?: e.toString(), Toast.LENGTH_LONG).show()
                }
            }
            .setNegativeButton(R.string.dismiss, null)
            .show()
    }

    private fun showNotice(text: String, failed: Boolean) {
        notice.text = text
        notice.setTextColor(getColor(if (failed) R.color.danger else R.color.dim))
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        val link = intent.data?.toString() ?: return
        if (Core.isLink(link)) fill(link)
    }

    companion object {
        const val EXTRA_EDIT = "edit"
    }
}
