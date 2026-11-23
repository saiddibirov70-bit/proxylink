package dev.proxylink.app.net

object Ip4 {
    const val FIN = 1
    const val SYN = 2
    const val RST = 4
    const val PSH = 8
    const val ACK = 16

    fun u16(b: ByteArray, o: Int): Int =
        ((b[o].toInt() and 0xff) shl 8) or (b[o + 1].toInt() and 0xff)

    fun u32(b: ByteArray, o: Int): Long =
        ((b[o].toLong() and 0xff) shl 24) or
            ((b[o + 1].toLong() and 0xff) shl 16) or
            ((b[o + 2].toLong() and 0xff) shl 8) or
            (b[o + 3].toLong() and 0xff)

    fun ipStr(b: ByteArray): String = b.joinToString(".") { (it.toInt() and 0xff).toString() }

    /** True if sequence number a is before b, with 32-bit wraparound taken into account. */
    fun seqBefore(a: Long, b: Long): Boolean = (((a - b) and 0xffffffffL) > 0x7fffffffL)

    private fun put16(b: ByteArray, o: Int, v: Int) {
        b[o] = (v ushr 8).toByte()
        b[o + 1] = v.toByte()
    }

    private fun put32(b: ByteArray, o: Int, v: Long) {
        b[o] = (v ushr 24).toByte()
        b[o + 1] = (v ushr 16).toByte()
        b[o + 2] = (v ushr 8).toByte()
        b[o + 3] = v.toByte()
    }

    fun checksum(b: ByteArray, off: Int, len: Int): Int {
        var sum = 0L
        var i = off
        var left = len
        while (left > 1) {
            val word = ((b[i].toInt() and 0xff) shl 8) or (b[i + 1].toInt() and 0xff)
            sum += word.toLong()
            i += 2
            left -= 2
        }
        if (left == 1) sum += (b[i].toInt() and 0xff).toLong() shl 8
        while ((sum ushr 16) != 0L) sum = (sum and 0xffffL) + (sum ushr 16)
        return (sum.inv() and 0xffffL).toInt()
    }

    private var ipId = 1

    /** Builds a complete IPv4 + TCP packet. [out] must be at least 40 + payload.size + 4. */
    fun buildTcp(
        src: ByteArray,
        dst: ByteArray,
        sp: Int,
        dp: Int,
        seq: Long,
        ack: Long,
        flags: Int,
        win: Int,
        payload: ByteArray,
        out: ByteArray
    ): Int {
        val tcpOff = 20
        val tcpLen = 20 + payload.size

        put16(out, tcpOff, sp and 0xffff)
        put16(out, tcpOff + 2, dp and 0xffff)
        put32(out, tcpOff + 4, seq)
        put32(out, tcpOff + 8, ack)
        out[tcpOff + 12] = (5 shl 4).toByte()
        out[tcpOff + 13] = flags.toByte()
        put16(out, tcpOff + 14, win and 0xffff)
        put16(out, tcpOff + 16, 0)
        put16(out, tcpOff + 18, 0)
        if (payload.isNotEmpty()) {
            System.arraycopy(payload, 0, out, tcpOff + 20, payload.size)
        }

        val pseudo = ByteArray(12 + tcpLen)
        System.arraycopy(src, 0, pseudo, 0, 4)
        System.arraycopy(dst, 0, pseudo, 4, 4)
        pseudo[9] = 6
        put16(pseudo, 10, tcpLen)
        System.arraycopy(out, tcpOff, pseudo, 12, tcpLen)
        put16(out, tcpOff + 16, checksum(pseudo, 0, pseudo.size))

        val total = 20 + tcpLen
        out[0] = 0x45
        out[1] = 0
        put16(out, 2, total)
        put16(out, 4, ipId++ and 0xffff)
        put16(out, 6, 0x4000)
        out[8] = 64
        out[9] = 6
        put16(out, 10, 0)
        System.arraycopy(src, 0, out, 12, 4)
        System.arraycopy(dst, 0, out, 16, 4)
        put16(out, 10, checksum(out, 0, 20))
        return total
    }

    /** Builds an IPv4 + UDP packet. UDP checksum is set to 0 (allowed for IPv4). */
    fun buildUdp(
        src: ByteArray,
        dst: ByteArray,
        sp: Int,
        dp: Int,
        payload: ByteArray,
        out: ByteArray
    ): Int {
        val udpLen = 8 + payload.size
        put16(out, 20, sp and 0xffff)
        put16(out, 22, dp and 0xffff)
        put16(out, 24, udpLen)
        put16(out, 26, 0)
        if (payload.isNotEmpty()) {
            System.arraycopy(payload, 0, out, 28, payload.size)
        }

        val total = 20 + udpLen
        out[0] = 0x45
        out[1] = 0
        put16(out, 2, total)
        put16(out, 4, ipId++ and 0xffff)
        put16(out, 6, 0x4000)
        out[8] = 64
        out[9] = 17
        put16(out, 10, 0)
        System.arraycopy(src, 0, out, 12, 4)
        System.arraycopy(dst, 0, out, 16, 4)
        put16(out, 10, checksum(out, 0, 20))
        return total
    }
}
