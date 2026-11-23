package dev.proxylink.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import dev.proxylink.app.net.Tunnel
import java.net.InetAddress

class ProxyVpnService : VpnService() {

    private var tunnel: Tunnel? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopSelf()
            return START_NOT_STICKY
        }
        if (tunnel != null) return START_STICKY

        startForeground(NOTIF_ID, notification())

        val cfg = Prefs.load(this)
        // Resolve before the VPN is up, otherwise the DNS query would be swallowed by the TUN.
        val hostIp = try {
            InetAddress.getByName(cfg.host).hostAddress ?: cfg.host
        } catch (e: Exception) {
            cfg.host
        }
        val fixed = cfg.copy(host = hostIp)

        try {
            val builder = Builder()
                .setSession("ProxyLink")
                .setMtu(1400)
                .addAddress("10.0.0.2", 24)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("1.1.1.1")

            val fd: ParcelFileDescriptor = builder.establish()
                ?: throw IllegalStateException("VpnService.establish() returned null")
            tunnel = Tunnel(this, fd, fixed).also { it.start() }
            VpnState.running = true
            VpnState.message = "Подключён: ${fixed.host}:${fixed.port} (${fixed.type})"
        } catch (e: Exception) {
            VpnState.message = "Ошибка: ${e.message}"
            stopSelf()
            return START_NOT_STICKY
        }
        return START_STICKY
    }

    override fun onDestroy() {
        tunnel?.stop()
        tunnel = null
        VpnState.running = false
        VpnState.message = "Отключён"
        super.onDestroy()
    }

    override fun onBind(intent: Intent?) =
        if (intent?.action == VpnService.SERVICE_INTERFACE) super.onBind(intent) else null

    private fun notification(): Notification {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(CHANNEL, "ProxyLink", NotificationManager.IMPORTANCE_LOW)
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }

        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val stop = PendingIntent.getService(
            this, 1, Intent(this, ProxyVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL)
        } else {
            Notification.Builder(this)
        }
        return builder
            .setSmallIcon(android.R.drawable.stat_sys_upload)
            .setContentTitle("ProxyLink")
            .setContentText("Туннель активен")
            .setContentIntent(open)
            .addAction(android.R.drawable.ic_delete, "Отключить", stop)
            .setOngoing(true)
            .build()
    }

    companion object {
        const val ACTION_STOP = "dev.proxylink.app.STOP"
        private const val CHANNEL = "proxylink"
        private const val NOTIF_ID = 1
    }
}
