package dev.proxylink.app

import android.content.Context

data class ProxyConfig(
    val host: String,
    val port: Int,
    val type: String,
    val user: String,
    val pass: String
)

object Prefs {
    private const val NAME = "proxylink"

    fun load(ctx: Context): ProxyConfig {
        val p = ctx.getSharedPreferences(NAME, Context.MODE_PRIVATE)
        return ProxyConfig(
            host = p.getString("host", "") ?: "",
            port = p.getInt("port", 1080),
            type = p.getString("type", "SOCKS5") ?: "SOCKS5",
            user = p.getString("user", "") ?: "",
            pass = p.getString("pass", "") ?: ""
        )
    }

    fun save(ctx: Context, c: ProxyConfig) {
        ctx.getSharedPreferences(NAME, Context.MODE_PRIVATE).edit()
            .putString("host", c.host)
            .putInt("port", c.port)
            .putString("type", c.type)
            .putString("user", c.user)
            .putString("pass", c.pass)
            .apply()
    }
}

object VpnState {
    @Volatile var running = false
    @Volatile var message = "Отключён"
}
