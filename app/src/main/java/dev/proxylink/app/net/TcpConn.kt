package dev.proxylink.app.net

import android.net.VpnService
import dev.proxylink.app.ProxyConfig
import java.io.OutputStream
import java.net.Socket
import java.util.ArrayDeque
import java.util.concurrent.atomic.AtomicBoolean

class TcpConn(
    private val vpn: VpnService,
    private val tunnel: Tunnel,
    clientIp: ByteArray,
    clientPort: Int,
    private val serverIp: ByteArray,
    private val serverPort: Int,
    cliIsn: Long,
    private val cfg: ProxyConfig
) {
    companion object {
        private const val MSS = 1360
        private const val MAX_INFLIGHT = MSS * 8
        private const val RETX_MS = 700L
    }

    private val clientIp = clientIp
    private val clientPort = clientPort
    private val clientIsn = cliIsn

    private val ourIsn = (Math.random() * 4294967296.0).toLong() and 0xffffffffL
    private var rcvNxt = (clientIsn + 1) and 0xffffffffL
    private var sndNxt = (ourIsn + 1) and 0xffffffffL
    private var window = 65535

    private val lock = Any()
    private val pending = ArrayDeque<ByteArray>()
    private val queue = ArrayDeque<Segment>()
    private var socket: Socket? = null
    private var out: OutputStream? = null
    @Volatile private var established = false
    private val closed = AtomicBoolean(false)

    private class Segment(val seq: Long, val data: ByteArray) {
        var sent: Long = 0L
        var tries: Int = 0
    }

    fun begin() {
        Thread {
            try {
                val s = ProxyConnector.connect(vpn, cfg, Ip4.ipStr(serverIp), serverPort)
                if (closed.get()) {
                    s.close()
                    return@Thread
                }
                socket = s
                out = s.getOutputStream()

                tunnel.send(
                    serverIp, clientIp, serverPort, clientPort,
                    ourIsn, (clientIsn + 1) and 0xffffffffL,
                    Ip4.SYN or Ip4.ACK, ByteArray(0)
                )

                synchronized(lock) {
                    while (!pending.isEmpty()) {
                        out!!.write(pending.removeFirst())
                    }
                    out!!.flush()
                }
                established = true

                val input = s.getInputStream()
                val buf = ByteArray(MSS)
                while (!closed.get()) {
                    val n = input.read(buf)
                    if (n < 0) break
                    enqueue(buf.copyOf(n))
                }
                if (!closed.get()) {
                    tunnel.send(
                        serverIp, clientIp, serverPort, clientPort,
                        sndNxt, rcvNxt, Ip4.FIN or Ip4.ACK, ByteArray(0)
                    )
                    sndNxt = (sndNxt + 1) and 0xffffffffL
                }
            } catch (e: Exception) {
                if (!closed.get()) {
                    tunnel.send(
                        serverIp, clientIp, serverPort, clientPort,
                        0L, 0L, Ip4.RST or Ip4.ACK, ByteArray(0)
                    )
                }
            } finally {
                close()
            }
        }.apply { isDaemon = true }.start()
    }

    fun onClientAck(ack: Long, win: Int) {
        window = if (win <= 0) 1 else win
        synchronized(lock) {
            while (!queue.isEmpty()) {
                val first = queue.first()
                if (Ip4.seqBefore((first.seq + first.data.size) and 0xffffffffL, ack)) {
                    queue.removeFirst()
                } else break
            }
        }
        if (ack == ((ourIsn + 1) and 0xffffffffL)) established = true
        flush()
    }

    fun onClientData(payload: ByteArray) {
        rcvNxt = (rcvNxt + payload.size) and 0xffffffffL
        synchronized(lock) {
            if (out != null && established) {
                try {
                    out!!.write(payload)
                    out!!.flush()
                } catch (e: Exception) {
                    close()
                }
            } else {
                pending.addLast(payload)
            }
        }
        tunnel.send(
            serverIp, clientIp, serverPort, clientPort,
            sndNxt, rcvNxt, Ip4.ACK, ByteArray(0)
        )
    }

    private fun enqueue(data: ByteArray) {
        var off = 0
        while (off < data.size) {
            val len = minOf(MSS, data.size - off)
            val chunk = data.copyOfRange(off, off + len)
            synchronized(lock) {
                queue.addLast(Segment(sndNxt, chunk))
                sndNxt = (sndNxt + len) and 0xffffffffL
            }
            off += len
        }
        flush()
    }

    private fun flush() {
        synchronized(lock) {
            var inFlight = 0
            for (s in queue) if (s.sent != 0L) inFlight += s.data.size
            val cap = minOf(window, MAX_INFLIGHT)
            for (s in queue) {
                if (s.sent != 0L) continue
                if (inFlight + s.data.size > cap) break
                tunnel.send(
                    serverIp, clientIp, serverPort, clientPort,
                    s.seq, rcvNxt, Ip4.PSH or Ip4.ACK, s.data
                )
                s.sent = System.currentTimeMillis()
                s.tries++
                inFlight += s.data.size
                if (inFlight >= cap) break
            }
        }
    }

    fun onTimeout() {
        val now = System.currentTimeMillis()
        synchronized(lock) {
            for (s in queue) {
                if (s.sent != 0L && now - s.sent > RETX_MS && s.tries < 8) {
                    tunnel.send(
                        serverIp, clientIp, serverPort, clientPort,
                        s.seq, rcvNxt, Ip4.PSH or Ip4.ACK, s.data
                    )
                    s.sent = now
                    s.tries++
                }
            }
        }
    }

    fun close() {
        if (closed.getAndSet(true)) return
        try { socket?.close() } catch (_: Exception) {}
        tunnel.remove(this)
    }
}
