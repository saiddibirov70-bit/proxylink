package dev.proxylink.app.net

import android.net.VpnService
import android.os.ParcelFileDescriptor
import dev.proxylink.app.ProxyConfig
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

class Tunnel(
    private val vpn: VpnService,
    private val pfd: ParcelFileDescriptor,
    private val cfg: ProxyConfig
) {
    private val inFd = ParcelFileDescriptor.dup(pfd.fileDescriptor)
    private val outFd = ParcelFileDescriptor.dup(pfd.fileDescriptor)
    private val input = FileInputStream(inFd.fileDescriptor)
    private val output = FileOutputStream(outFd.fileDescriptor)

    private val conns = ConcurrentHashMap<String, TcpConn>()
    private val pool = Executors.newCachedThreadPool { r -> Thread(r).apply { isDaemon = true } }
    private val timer = ScheduledThreadPoolExecutor(1) { r -> Thread(r).apply { isDaemon = true } }
    private val writeLock = Any()
    private val buf = ByteArray(4096)
    @Volatile private var running = true

    fun start() {
        pool.execute { readLoop() }
        timer.scheduleAtFixedRate({ conns.values.forEach { it.onTimeout() } }, 300, 300, TimeUnit.MILLISECONDS)
    }

    fun stop() {
        running = false
        conns.values.forEach { it.close() }
        conns.clear()
        pool.shutdownNow()
        timer.shutdownNow()
        safely { input.close() }
        safely { output.close() }
        safely { inFd.close() }
        safely { outFd.close() }
        safely { pfd.close() }
    }

    private fun safely(block: () -> Unit) {
        try { block() } catch (_: Exception) {}
    }

    private fun readLoop() {
        while (running) {
            val n = try { input.read(buf) } catch (e: Exception) { break }
            if (n < 0) break
            if (n >= 20) handle(buf, n)
        }
    }

    private fun handle(b: ByteArray, n: Int) {
        if ((b[0].toInt() and 0xf0) != 0x40) return
        val ihl = (b[0].toInt() and 0x0f) * 4
        if (ihl < 20 || n < ihl + 8) return
        val total = Ip4.u16(b, 2)
        if (total < ihl + 8 || total > n) return

        val srcIp = b.copyOfRange(12, 16)
        val dstIp = b.copyOfRange(16, 20)
        when (b[9].toInt() and 0xff) {
            6 -> handleTcp(b, n, ihl, total, srcIp, dstIp)
            17 -> handleUdp(b, n, ihl, total, srcIp, dstIp)
            else -> Unit
        }
    }

    private fun handleTcp(
        b: ByteArray, n: Int, ihl: Int, total: Int,
        srcIp: ByteArray, dstIp: ByteArray
    ) {
        if (total < ihl + 20) return
        val t = ihl
        val sp = Ip4.u16(b, t)
        val dp = Ip4.u16(b, t + 2)
        val seq = Ip4.u32(b, t + 4)
        val ack = Ip4.u32(b, t + 8)
        val flags = b[t + 13].toInt() and 0xff
        val win = Ip4.u16(b, t + 14)
        val doff = ((b[t + 12].toInt() and 0xff) shr 4) * 4
        if (doff < 20 || t + doff > total) return

        val pOff = t + doff
        val pLen = total - ihl - doff
        val payload = if (pLen > 0 && pOff + pLen <= n) {
            b.copyOfRange(pOff, pOff + pLen)
        } else ByteArray(0)

        val key = "$sp-$dp-${Ip4.ipStr(dstIp)}"
        val syn = flags and Ip4.SYN != 0
        val ackF = flags and Ip4.ACK != 0
        val rst = flags and Ip4.RST != 0
        val fin = flags and Ip4.FIN != 0

        if (syn && !ackF) {
            if (conns.containsKey(key)) return
            val c = TcpConn(vpn, this, srcIp, sp, dstIp, dp, seq, cfg)
            conns[key] = c
            c.begin()
            return
        }

        val c = conns[key]
        if (c == null) {
            if (!rst) send(dstIp, srcIp, dp, sp, 0L, 0L, Ip4.RST or Ip4.ACK, ByteArray(0))
            return
        }
        if (rst || fin) {
            c.close()
            conns.remove(key)
            return
        }
        if (ackF) c.onClientAck(ack, win)
        if (payload.isNotEmpty()) c.onClientData(payload)
    }

    /** Only DNS/53 is translated to DoT. Everything else UDP is dropped on purpose:
     *  this prevents QUIC from leaking outside the proxy and forces a TCP fallback. */
    private fun handleUdp(
        b: ByteArray, n: Int, ihl: Int, total: Int,
        srcIp: ByteArray, dstIp: ByteArray
    ) {
        if (total < ihl + 8) return
        val u = ihl
        val sp = Ip4.u16(b, u)
        val dp = Ip4.u16(b, u + 2)
        if (dp != 53) return

        val pOff = u + 8
        val pLen = total - ihl - 8
        if (pLen <= 0 || pOff + pLen > n) return
        val query = b.copyOfRange(pOff, pOff + pLen)

        val client = srcIp
        val dnsServer = dstIp
        pool.execute {
            try {
                val answer = dnsOverTls(query)
                val outBuf = ByteArray(20 + 8 + answer.size + 4)
                val len = Ip4.buildUdp(dnsServer, client, 53, sp, answer, outBuf)
                synchronized(writeLock) {
                    output.write(outBuf, 0, len)
                    output.flush()
                }
            } catch (_: Exception) {}
        }
    }

    private fun dnsOverTls(query: ByteArray): ByteArray {
        val plain = ProxyConnector.connect(vpn, cfg, "1.1.1.1", 853)
        val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
        val tls = factory.createSocket(plain, "cloudflare-dns.com", 853, true) as SSLSocket
        tls.soTimeout = 10000
        tls.startHandshake()

        val os = tls.getOutputStream()
        os.write(query.size ushr 8)
        os.write(query.size)
        os.write(query)
        os.flush()

        val ins = tls.getInputStream()
        val hi = ins.read()
        val lo = ins.read()
        if (hi < 0 || lo < 0) throw IOException("DoT: unexpected EOF")
        val len = ((hi shl 8) or lo) and 0xffff
        val response = ByteArray(len)
        var off = 0
        while (off < len) {
            val r = ins.read(response, off, len - off)
            if (r < 0) throw IOException("DoT: truncated response")
            off += r
        }
        safely { tls.close() }
        return response
    }

    fun send(
        srcIp: ByteArray,
        dstIp: ByteArray,
        sp: Int,
        dp: Int,
        seq: Long,
        ack: Long,
        flags: Int,
        payload: ByteArray
    ) {
        val outBuf = ByteArray(20 + 20 + payload.size + 4)
        val len = Ip4.buildTcp(srcIp, dstIp, sp, dp, seq, ack, flags, 65535, payload, outBuf)
        synchronized(writeLock) {
            output.write(outBuf, 0, len)
            output.flush()
        }
    }

    fun remove(conn: TcpConn) {
        conns.values.remove(conn)
    }
}
