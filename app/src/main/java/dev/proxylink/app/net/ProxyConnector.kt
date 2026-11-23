package dev.proxylink.app.net

import android.net.VpnService
import android.util.Base64
import dev.proxylink.app.ProxyConfig
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket

object ProxyConnector {

    /** Connects a socket to [target]:[port] through the configured proxy.
     *  vpn.protect() is essential: otherwise the proxy connection itself loops back into the TUN. */
    fun connect(vpn: VpnService, cfg: ProxyConfig, target: String, port: Int): Socket {
        val s = Socket()
        vpn.protect(s)
        s.connect(InetSocketAddress(cfg.host, cfg.port), 8000)
        s.tcpNoDelay = true
        s.soTimeout = 12000
        if (cfg.type == "HTTP") httpConnect(s, cfg, target, port) else socks5(s, cfg, target, port)
        s.soTimeout = 0
        return s
    }

    private fun ipv4(target: String): ByteArray {
        val parts = target.split(".")
        require(parts.size == 4) { "Target is not an IPv4 address: $target" }
        return ByteArray(4) { parts[it].toInt().toByte() }
    }

    private fun socks5(s: Socket, cfg: ProxyConfig, target: String, port: Int) {
        val out = DataOutputStream(s.getOutputStream())
        val inp = DataInputStream(s.getInputStream())

        if (cfg.user.isNotEmpty()) out.write(byteArrayOf(5, 2, 0, 2))
        else out.write(byteArrayOf(5, 1, 0))
        out.flush()

        val ver = inp.readUnsignedByte()
        val method = inp.readUnsignedByte()
        if (ver != 5) throw IOException("Bad SOCKS version: $ver")
        if (method == 2) {
            val u = cfg.user.toByteArray(Charsets.UTF_8)
            val p = cfg.pass.toByteArray(Charsets.UTF_8)
            out.writeByte(1)
            out.writeByte(u.size)
            out.write(u)
            out.writeByte(p.size)
            out.write(p)
            out.flush()
            if (inp.readUnsignedByte() != 1 || inp.readUnsignedByte() != 0) {
                throw IOException("SOCKS authentication failed")
            }
        } else if (method != 0) {
            throw IOException("No acceptable SOCKS auth method: $method")
        }

        out.writeByte(5)
        out.writeByte(1)
        out.writeByte(0)
        out.writeByte(1)
        out.write(ipv4(target))
        out.writeShort(port)
        out.flush()

        val rver = inp.readUnsignedByte()
        val rep = inp.readUnsignedByte()
        inp.readUnsignedByte()
        val atyp = inp.readUnsignedByte()
        when (atyp) {
            1 -> skip(inp, 4)
            3 -> skip(inp, inp.readUnsignedByte())
            4 -> skip(inp, 16)
            else -> throw IOException("Bad SOCKS address type: $atyp")
        }
        skip(inp, 2)
        if (rver != 5 || rep != 0) throw IOException("SOCKS connect rejected: $rep")
    }

    private fun skip(inp: DataInputStream, count: Int) {
        var left = count
        val buf = ByteArray(256)
        while (left > 0) {
            val r = inp.read(buf, 0, minOf(left, buf.size))
            if (r < 0) throw IOException("Unexpected EOF from proxy")
            left -= r
        }
    }

    private fun httpConnect(s: Socket, cfg: ProxyConfig, target: String, port: Int) {
        val auth = if (cfg.user.isNotEmpty()) {
            val token = Base64.encodeToString(
                "${cfg.user}:${cfg.pass}".toByteArray(Charsets.UTF_8),
                Base64.NO_WRAP
            )
            "Proxy-Authorization: Basic $token\r\n"
        } else ""
        val request = "CONNECT $target:$port HTTP/1.1\r\n" +
            "Host: $target:$port\r\n" +
            auth +
            "\r\n"
        val os = s.getOutputStream()
        os.write(request.toByteArray(Charsets.ISO_8859_1))
        os.flush()

        val raw = s.getInputStream()
        val accumulated = ByteArrayOutputStream()
        while (true) {
            val b = raw.read()
            if (b < 0) throw IOException("Proxy closed connection during CONNECT")
            accumulated.write(b)
            val a = accumulated.toByteArray()
            val n = a.size
            if (n >= 4 && a[n - 4] == 13.toByte() && a[n - 3] == 10.toByte() &&
                a[n - 2] == 13.toByte() && a[n - 1] == 10.toByte()
            ) break
        }
        val head = accumulated.toString("ISO-8859-1")
        if (!head.contains(" 200 ")) {
            throw IOException("HTTP proxy rejected CONNECT: ${head.lineSequence().firstOrNull()}")
        }
    }
}
