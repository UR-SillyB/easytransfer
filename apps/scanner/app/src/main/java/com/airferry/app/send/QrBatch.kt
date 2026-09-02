package com.airferry.app.send

/**
 * One rendered QR tile inside a packed batch. Zero-copy view: `buf` is the
 * whole batch buffer and modules are read at `offset + y * side + x`
 * (1 = dark). Mirrors the web sender's `parseMultiQrBuf` layout
 * (`u32le count`, then per tile `u32le side` + `side²` bytes).
 */
class QrTile(val side: Int, val buf: ByteArray, val offset: Int) {
    fun isDark(x: Int, y: Int): Boolean = buf[offset + y * side + x].toInt() != 0
}

data class QrBatch(val tiles: List<QrTile>)

/** Marker prefix thrown by `senderNextQr` when the playlist hits an unstaged chunk. */
const val NOT_STAGED_PREFIX = "AF2_CHUNK_NOT_STAGED:"

/** Extract the chunk index from an `AF2_CHUNK_NOT_STAGED:<index>` message, or null. */
fun parseNotStagedIndex(message: String?): Int? {
    if (message == null || !message.startsWith(NOT_STAGED_PREFIX)) return null
    return message.substring(NOT_STAGED_PREFIX.length).trim().toIntOrNull()
}

/** Parse a packed QR batch from `NativeBridge.senderNextQr`. */
fun parseQrBatch(buf: ByteArray): QrBatch {
    require(buf.size >= 4) { "batch buffer too small: ${buf.size}" }
    val count = leInt(buf, 0)
    require(count in 1..4) { "bad tile count $count" }
    var pos = 4
    val tiles = ArrayList<QrTile>(count)
    repeat(count) {
        require(pos <= buf.size - 4) { "truncated tile header" }
        val side = leInt(buf, pos)
        pos += 4
        require(side in 21..177 && side % 4 == 1) { "bad QR side $side" }
        require(pos + side * side <= buf.size) { "tile overruns buffer" }
        tiles += QrTile(side, buf, pos)
        pos += side * side
    }
    require(pos == buf.size) { "trailing bytes after $count tiles: ${buf.size - pos}" }
    return QrBatch(tiles)
}

private fun leInt(buf: ByteArray, off: Int): Int =
    (buf[off].toInt() and 0xFF) or
        ((buf[off + 1].toInt() and 0xFF) shl 8) or
        ((buf[off + 2].toInt() and 0xFF) shl 16) or
        ((buf[off + 3].toInt() and 0xFF) shl 24)
