package com.airferry.app.send

import android.content.ContentResolver
import com.airferry.app.nativelib.NativeBridge
import org.json.JSONObject
import java.io.FileInputStream
import java.nio.channels.FileChannel
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * High-level sender session manager (AF2 protocol) — the Android counterpart
 * of the web sender's `compress.worker.ts` (prep) + `chunk-stager.ts`
 * (play-time staging). No wire-format logic lives here (SPEC §9): planning,
 * hashing, encoding and playlist scheduling all run inside the Rust core;
 * this class only streams file bytes across the JNI boundary.
 *
 * ## Threading / locking
 * The native handle is NOT thread-safe; every native call happens under
 * [lock]. The render loop calls [nextQr] on its own coroutine, prefetch runs
 * on an IO coroutine, and [prepare]/[build] run once before playback.
 *
 * ## Memory
 * Bounded by one chunk (8 MiB): prep streams files in 1 MiB slices, and play
 * time materializes one chunk at a time for encode + stage.
 */
class SenderSessionManager(private val resolver: ContentResolver) {

    /** Everything the native build needs, computed by [prepare]. */
    class Prepared(
        val kinds: ByteArray,
        val paths: Array<String>,
        val sizes: LongArray,
        val contentHashes: ByteArray,
        val chunkHashes: ByteArray,
        val plan: ChunkPlan
    )

    private val lock = ReentrantLock()

    @Volatile
    var handle: Long = 0
        private set

    var items: List<SendItem> = emptyList()
        private set

    var plan: ChunkPlan? = null
        private set

    /** fps × symbolSize × qrCount — the encode-time compression budget. */
    private var channelBps: Long = 0

    /** Prep-pass file sources, keyed by item index (segments of one item are
     *  consecutive, so one open per item). Closed at the end of [prepare]. */
    private val prepChannels = HashMap<Int, OpenedItem>()

    /** An open SAF file: random-access channel + the fd wrapper to release. */
    private class OpenedItem(val channel: FileChannel, val pfd: android.os.ParcelFileDescriptor) :
        java.io.Closeable {
        override fun close() {
            runCatching { channel.close() }
            runCatching { pfd.close() }
        }
    }

    /**
     * Plan + hash pass: read every item exactly once in canonical (chunk plan)
     * order, producing per-item content hashes and per-chunk hashes. Never
     * holds more than one 1 MiB slice. `onProgress(doneBytes, totalBytes)` is
     * invoked per slice — throttle in the caller.
     */
    fun prepare(
        items: List<SendItem>,
        onProgress: (done: Long, total: Long) -> Unit = { _, _ -> }
    ): Prepared {
        require(items.isNotEmpty()) { "nothing to send" }
        val kinds = ByteArray(items.size) { items[it].kind.toByte() }
        val paths = Array(items.size) { items[it].displayName }
        val sizes = LongArray(items.size) { items[it].size }
        val planJson = NativeBridge.senderPlanChunks(kinds, paths, sizes, CHUNK_RAW_SIZE)
        val plan = ChunkPlan.parse(planJson)

        val total = items.sumOf { it.size }
        val itemHashers = LongArray(items.size) { NativeBridge.blake3Create() }
        val chunkHashes = ByteArray(plan.chunkCount * HASH_BYTES)
        val slice = ByteArray(SLICE_BYTES)
        var done = 0L
        var liveChunkHasher = 0L
        try {
            plan.chunks.forEachIndexed { ci, segs ->
                val chunkHasher = NativeBridge.blake3Create()
                liveChunkHasher = chunkHasher
                for (seg in segs) {
                    streamSlice(items, seg, slice) { buf, n ->
                        NativeBridge.blake3Update(chunkHasher, view(buf, n))
                        NativeBridge.blake3Update(itemHashers[seg.item], view(buf, n))
                        done += n
                        onProgress(done, total)
                    }
                }
                // digest finalizes AND destroys the native handle
                liveChunkHasher = 0
                val digest = NativeBridge.blake3Digest(chunkHasher)
                System.arraycopy(digest, 0, chunkHashes, ci * HASH_BYTES, HASH_BYTES)
            }
            val contentHashes = ByteArray(items.size * HASH_BYTES)
            for (i in items.indices) {
                val digestHandle = itemHashers[i]
                itemHashers[i] = 0
                val digest = NativeBridge.blake3Digest(digestHandle)
                System.arraycopy(digest, 0, contentHashes, i * HASH_BYTES, HASH_BYTES)
            }
            return Prepared(kinds, paths, sizes, contentHashes, chunkHashes, plan)
        } finally {
            // Hasher handles are only released by digesting them; on abort
            // (IO error / coroutine cancel) drain whichever are still alive.
            if (liveChunkHasher != 0L) runCatching { NativeBridge.blake3Digest(liveChunkHasher) }
            for (h in itemHashers) if (h != 0L) runCatching { NativeBridge.blake3Digest(h) }
            closePrepChannels()
        }
    }

    /** Build the native streamed sender. Call once after [prepare]. */
    fun build(prepared: Prepared, items: List<SendItem>, symbolSize: Int, fps: Int, redundancyPct: Int) {
        val h = NativeBridge.senderBuildStreamed(
            prepared.kinds, prepared.paths, prepared.sizes,
            prepared.contentHashes, prepared.chunkHashes,
            symbolSize, CHUNK_RAW_SIZE, redundancyPct
        )
        check(h != 0L) { "native sender build returned a null handle" }
        lock.withLock {
            if (handle != 0L) NativeBridge.senderDestroy(handle)
            handle = h
            this.items = items
            this.plan = prepared.plan
            this.channelBps = fps.toLong() * symbolSize
        }
    }

    /**
     * Pull the next QR tile batch for rendering. Transparently stages the
     * chunk named by an `AF2_CHUNK_NOT_STAGED:<i>` rejection and retries —
     * the failed native call has no side effects, so at most one retry per
     * chunk boundary is ever needed.
     */
    fun nextQr(count: Int = 1): QrBatch {
        lock.withLock {
            check(handle != 0L) { "sender not built" }
            var stagedRetries = 0
            while (true) {
                try {
                    return parseQrBatch(NativeBridge.senderNextQr(handle, count))
                } catch (e: IllegalStateException) {
                    val idx = parseNotStagedIndex(e.message) ?: throw e
                    check(++stagedRetries <= 2) { "chunk $idx still not staged after retry" }
                    stageChunkLocked(idx)
                }
            }
        }
    }

    /**
     * Prefetch hook (call from an IO coroutine every ~100 ms during play):
     * keep the armed set {current, next} staged so [nextQr] never blocks the
     * render loop on disk + encode. Mirrors the web sender's chunk-stager:
     * staged bytes are consumed as the playlist window moves on, so `current`
     * must be RE-armed for the next epoch, and `next` wraps to chunk 0 after
     * the last chunk.
     */
    fun prefetchNextChunk() {
        lock.withLock {
            val p = plan ?: return
            if (handle == 0L) return
            val current = NativeBridge.senderCurrentChunkIndex(handle)
            if (current < 0) return // bootstrap: manifest symbols still playing
            if (!NativeBridge.senderIsStaged(handle, current)) {
                stageChunkLocked(current) // consumed by the live window; re-arm for next epoch
            }
            val next = (current + 1) % p.chunkCount
            if (!NativeBridge.senderIsStaged(handle, next)) {
                stageChunkLocked(next)
            }
        }
    }

    /** Stage chunk [index]: assemble raw bytes, hash, balanced-encode, hand over. */
    private fun stageChunkLocked(index: Int) {
        val p = checkNotNull(plan) { "sender not built" }
        if (NativeBridge.senderIsStaged(handle, index)) return
        val raw = assembleChunk(p, index)
        var rawHasher = NativeBridge.blake3Create()
        val rawHash = try {
            NativeBridge.blake3Update(rawHasher, raw)
            val digestHandle = rawHasher
            rawHasher = 0
            NativeBridge.blake3Digest(digestHandle)
        } finally {
            if (rawHasher != 0L) runCatching { NativeBridge.blake3Digest(rawHasher) }
        }
        val packed = NativeBridge.encodeChunkBalanced(raw, channelBps, p.chunkCount == 1)
        val codecId = packed[0].toInt() and 0xFF
        val data = packed.copyOfRange(1, packed.size)
        NativeBridge.senderStageChunk(handle, index, codecId, data, rawHash)
    }

    /** Assemble one chunk's raw canonical bytes from its segments. */
    private fun assembleChunk(p: ChunkPlan, index: Int): ByteArray {
        val raw = ByteArray(p.rawSizeOf(index).toInt())
        var off = 0
        for (seg in p.chunks[index]) {
            off += readInto(items[seg.item], seg.start, raw, off, seg.len.toInt())
        }
        return raw
    }

    fun statsJson(): JSONObject? {
        val s = lock.withLock {
            if (handle == 0L) null else NativeBridge.senderStatsJson(handle)
        } ?: return null
        return try { JSONObject(s) } catch (_: Exception) { null }
    }

    fun transferIdHex(): String? = lock.withLock {
        if (handle == 0L) null else NativeBridge.senderTransferIdHex(handle)
    }

    /** 1-based broadcast epoch (1 when idle — display only). */
    fun epoch(): Int = lock.withLock {
        if (handle == 0L) 1 else NativeBridge.senderEpoch(handle)
    }

    fun destroy() {
        lock.withLock {
            if (handle != 0L) {
                NativeBridge.senderDestroy(handle)
                handle = 0
            }
            plan = null
            items = emptyList()
        }
        closePrepChannels()
    }

    // ===== byte streaming =====

    /**
     * Stream `[seg.start, seg.start + seg.len)` of an item through [slice]-sized
     * callbacks. Text items read from memory; file items via a cached
     * random-access channel (prep) or a fresh one (staging).
     */
    private fun streamSlice(
        items: List<SendItem>,
        seg: ChunkSegment,
        slice: ByteArray,
        cb: (buf: ByteArray, n: Int) -> Unit
    ) {
        val item = items[seg.item]
        val text = item.text
        if (text != null) {
            var pos = seg.start.toInt()
            val end = (seg.start + seg.len).toInt()
            while (pos < end) {
                val n = minOf(slice.size, end - pos)
                System.arraycopy(text, pos, slice, 0, n)
                cb(slice, n)
                pos += n
            }
            return
        }
        val opened = prepChannels.getOrPut(seg.item) { openItem(item) }
        val channel = opened.channel
        channel.position(seg.start)
        var remaining = seg.len
        val nioBuf = java.nio.ByteBuffer.wrap(slice)
        while (remaining > 0) {
            nioBuf.clear()
            nioBuf.limit(minOf(slice.size.toLong(), remaining).toInt())
            val n = channel.read(nioBuf)
            if (n < 0) throw java.io.IOException("EOF in ${item.displayName}: ${seg.len - remaining}/${seg.len}")
            cb(slice, n)
            remaining -= n
        }
    }

    /** Copy [len] bytes of [item] starting at [start] into [dst] at [dstOff]. */
    private fun readInto(item: SendItem, start: Long, dst: ByteArray, dstOff: Int, len: Int): Int {
        val text = item.text
        if (text != null) {
            System.arraycopy(text, start.toInt(), dst, dstOff, len)
            return len
        }
        openItem(item).use { opened ->
            val channel = opened.channel
            val nioBuf = java.nio.ByteBuffer.wrap(dst, dstOff, len)
            channel.position(start)
            var read = 0
            while (read < len) {
                val n = channel.read(nioBuf)
                if (n < 0) throw java.io.IOException("EOF in ${item.displayName}: $read/$len")
                read += n
            }
            return read
        }
    }

    private fun openItem(item: SendItem): OpenedItem {
        val uri = item.uri ?: throw java.io.IOException("item ${item.displayName} has no source")
        val pfd = resolver.openFileDescriptor(uri, "r")
            ?: throw java.io.IOException("cannot open ${item.displayName}")
        // The channel closes its FileInputStream; OpenedItem.close adds the pfd.
        return OpenedItem(FileInputStream(pfd.fileDescriptor).channel, pfd)
    }

    private fun closePrepChannels() {
        for ((_, opened) in prepChannels) opened.close()
        prepChannels.clear()
    }

    companion object {
        /** Canonical chunk size — MUST match the receiver-side default (8 MiB). */
        const val CHUNK_RAW_SIZE = 8 * 1024 * 1024
        private const val HASH_BYTES = 32
        private const val SLICE_BYTES = 1024 * 1024

        /** Avoid copying when a callback consumed a full slice. */
        private fun view(buf: ByteArray, n: Int): ByteArray =
            if (n == buf.size) buf else buf.copyOf(n)
    }
}
