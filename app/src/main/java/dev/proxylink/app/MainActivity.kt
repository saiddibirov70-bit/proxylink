package dev.proxylink.app

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.Gravity
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat

class MainActivity : ComponentActivity() {

    private lateinit var host: EditText
    private lateinit var port: EditText
    private lateinit var type: Spinner
    private lateinit var user: EditText
    private lateinit var pass: EditText
    private lateinit var status: TextView
    private lateinit var toggle: Button

    private val handler = Handler(Looper.getMainLooper())
    private val ticker = object : Runnable {
        override fun run() {
            refresh()
            handler.postDelayed(this, 1000)
        }
    }

    private val consent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK) startVpn()
        else VpnState.message = "Разрешение VPN не получено"
    }

    private val notifications = registerForActivityResult(ActivityResultContracts.RequestPermission()) {}

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val saved = Prefs.load(this)
        host = field("Хост прокси", saved.host)
        port = field("Порт", saved.port.toString()).apply {
            inputType = InputType.TYPE_CLASS_NUMBER
        }
        type = Spinner(this).apply {
            adapter = ArrayAdapter(
                this@MainActivity,
                android.R.layout.simple_spinner_item,
                arrayOf("SOCKS5", "HTTP")
            ).apply { setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item) }
            setSelection(if (saved.type == "HTTP") 1 else 0)
        }
        user = field("Логин (необязательно)", saved.user)
        pass = field("Пароль (необязательно)", saved.pass).apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }

        status = TextView(this).apply {
            textSize = 15f
            setPadding(0, 24, 0, 12)
        }
        toggle = Button(this).apply {
            text = "Подключить"
            setOnClickListener { onToggle() }
        }
        val note = TextView(this).apply {
            text = "TCP идёт через SOCKS5/HTTP, DNS — через DoT, остальной UDP блокируется, " +
                "поэтому QUIC отключён и трафик уходит на TCP."
            textSize = 12f
            alpha = 0.7f
            setPadding(0, 28, 0, 0)
        }

        val form = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 48, 48, 48)
            addView(title("ProxyLink"))
            addView(host)
            addView(port)
            addView(label("Тип прокси"))
            addView(type)
            addView(user)
            addView(pass)
            addView(status)
            addView(toggle)
            addView(note)
        }
        setContentView(ScrollView(this).apply {
            addView(form, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        })

        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            notifications.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    private fun title(text: String) = TextView(this).apply {
        this.text = text
        textSize = 26f
        gravity = Gravity.CENTER
        setPadding(0, 0, 0, 24)
    }

    private fun label(text: String) = TextView(this).apply {
        this.text = text
        textSize = 13f
        alpha = 0.7f
        setPadding(0, 16, 0, 4)
    }

    private fun field(hint: String, value: String) = EditText(this).apply {
        this.hint = hint
        setText(value)
        setPadding(12, 12, 12, 12)
    }

    private fun onToggle() {
        if (VpnState.running) {
            startService(Intent(this, ProxyVpnService::class.java).setAction(ProxyVpnService.ACTION_STOP))
            return
        }

        val h = host.text.toString().trim()
        val p = port.text.toString().trim().toIntOrNull()
        if (h.isEmpty() || p == null || p !in 1..65535) {
            VpnState.message = "Проверь хост и порт"
            refresh()
            return
        }

        Prefs.save(
            this,
            ProxyConfig(
                host = h,
                port = p,
                type = if (type.selectedItemPosition == 1) "HTTP" else "SOCKS5",
                user = user.text.toString(),
                pass = pass.text.toString()
            )
        )

        val prepare = VpnService.prepare(this)
        if (prepare != null) consent.launch(prepare) else startVpn()
    }

    private fun startVpn() {
        val intent = Intent(this, ProxyVpnService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) startForegroundService(intent)
        else startService(intent)
    }

    private fun refresh() {
        status.text = VpnState.message
        toggle.text = if (VpnState.running) "Отключить" else "Подключить"
    }

    override fun onResume() {
        super.onResume()
        refresh()
        handler.post(ticker)
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(ticker)
    }
}
