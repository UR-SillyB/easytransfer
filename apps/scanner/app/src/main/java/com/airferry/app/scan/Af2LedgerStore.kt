package com.airferry.app.scan

import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.UUID
import org.json.JSONObject

/**
 * Crash-safe §12 resume ledger — the journal twin of [ChunkSpillStore]'s
 * `.partial` file.
 *
 * Format: one JSONL journal per transfer, `af2-<tid>.ledger.jsonl`.
 * - Line 1 (header): `{"v":1,"tid":…,"rid":…,"root":…,"crs":…}` — `rid`
 *   identifies this receive attempt (legacy headers omit it); written once,
 *   atomically (temp file + fsync + rename) before the first chunk commit.
 * - Each later line: `{"c":<index>}` (chunk committed after spill+fsync) or
 *   `{"i":<index>}` (chunk invalidated after a re-verification failure).
 *
 * Per-line append + fsync keeps every interleaving crash-safe: only a torn
 * final line is skipped; corruption before the tail rejects the candidate,
 * so the ledger never reports MORE than what hit the disk. A commit line is only appended after
 * the chunk bytes were pwrite + fsync'd into the spill — the §12 ordering
 * rule "账本完成 ⇒ 数据已落盘" holds by construction.
 *
 * Only touched from the ingest thread (the decode pool serializes ingest)
 * and the recovery path that runs under the same lock.
 */
class Af2LedgerStore private constructor(private val path: File) {

    var transferIdHex: String = ""
        private set
    /** One receive attempt, persisted across process restart. Unlike Transfer
     * ID this changes when the same content is intentionally received again. */
    var recoveryId: String = ""
        private set
    var chunkRawSize: Int = 0
        private set
    /** ROOT frame bytes (hex at rest) for the §12 resume() call. */
    var rootFrameBytes: ByteArray = ByteArray(0)
        private set
    private val completed = sortedSetOf<Int>()
    private var headerDurable = false

    val completedIndices: IntArray get() = completed.toIntArray()

    /** Load an existing ledger for `tid`, or null when none exists. */
    fun reload(): Boolean {
        completed.clear()
        transferIdHex = ""
        recoveryId = ""
        chunkRawSize = 0
        rootFrameBytes = ByteArray(0)
        headerDurable = false
        if (!path.isFile) return false
        if (path.length() > MAX_LEDGER_BYTES) return false
        val text = try {
            path.readText()
        } catch (_: Exception) {
            return false
        }
        val originalByteLength = text.toByteArray(Charsets.UTF_8).size.toLong()
        val tailTerminated = text.endsWith('\n')
        val durableText = if (tailTerminated) {
            text
        } else {
            val lastNewline = text.lastIndexOf('\n')
            if (lastNewline < 0) return false // even the header lacks its commit delimiter
            text.substring(0, lastNewline + 1)
        }
        val splitLines = durableText.split('\n')
        val lines = if (splitLines.lastOrNull()?.isEmpty() == true) {
            splitLines.dropLast(1)
        } else {
            splitLines
        }
        // A blank physical record is corruption; filtering it out could hide
        // a lost invalidation. Only an unterminated final JSON fragment can be
        // the product of a crash-torn append and may be skipped.
        if (lines.isEmpty() || lines.any { it.isBlank() }) return false
        val header = try {
            JSONObject(lines.first())
        } catch (_: Exception) {
            return false
        }
        val fileTid = transferIdFromLedgerName(path.name) ?: return false
        val parsedTid = header.optString("tid", "")
        val hasRecoveryId = header.has("rid")
        val parsedRecoveryId = if (hasRecoveryId) header.optString("rid", "") else parsedTid
        val parsedVersion = strictInt(header, "v")
        val parsedChunkRawSize = strictInt(header, "crs") ?: 0
        val rootHex = header.optString("root", "")
        val parsedRoot = if (rootHex.length <= MAX_ROOT_FRAME_HEX_CHARS) {
            hexToBytes(rootHex)
        } else {
            ByteArray(0)
        }
        if (
            header.length() != (if (hasRecoveryId) 5 else 4) ||
            header.opt("tid") !is String ||
            header.opt("root") !is String ||
            (hasRecoveryId && header.opt("rid") !is String) ||
            parsedVersion != 1 ||
            parsedTid != fileTid ||
            !parsedRecoveryId.matches(SAFE_RECOVERY_ID) ||
            parsedChunkRawSize !in LEGAL_CHUNK_RAW_SIZES ||
            parsedRoot.isEmpty()
        ) return false

        val parsedCompleted = sortedSetOf<Int>()
        for (position in 1 until lines.size) {
            val o = try {
                JSONObject(lines[position])
            } catch (_: Exception) {
                return false
            }
            val key = when {
                o.length() == 1 && o.has("c") -> "c"
                o.length() == 1 && o.has("i") -> "i"
                else -> return false
            }
            val index = strictInt(o, key) ?: return false
            if (index !in 0 until MAX_CHUNK_COUNT) return false
            if (key == "c") parsedCompleted.add(index) else parsedCompleted.remove(index)
        }
        if (!tailTerminated) {
            // Never append after a crash fragment: `fragment + next JSON`
            // would turn recoverable work into permanent middle corruption.
            // A record is committed only by its trailing newline, so even a
            // syntactically-complete unterminated JSON object is discarded.
            val durableByteLength = durableText.toByteArray(Charsets.UTF_8).size.toLong()
            try {
                RandomAccessFile(path, "rw").use { file ->
                    if (file.length() != originalByteLength) return false
                    file.setLength(durableByteLength)
                    file.fd.sync()
                }
            } catch (_: Exception) {
                return false
            }
        }
        transferIdHex = parsedTid
        recoveryId = parsedRecoveryId
        chunkRawSize = parsedChunkRawSize
        rootFrameBytes = parsedRoot
        completed.addAll(parsedCompleted)
        headerDurable = true
        return true
    }

    /** Append one commit event (after the chunk was spilled + fsync'd). */
    @Throws(IOException::class)
    fun commit(index: Int) {
        require(index in 0 until MAX_CHUNK_COUNT) { "invalid AF2 chunk index: $index" }
        if (!headerDurable) throw IOException("AF2 ledger header is not durable")
        appendLine(JSONObject().put("c", index))
        completed.add(index)
    }

    /** Append one invalidate event (after a spill re-verification failure). */
    @Throws(IOException::class)
    fun invalidate(index: Int) {
        require(index in 0 until MAX_CHUNK_COUNT) { "invalid AF2 chunk index: $index" }
        if (!headerDurable) throw IOException("AF2 ledger header is not durable")
        appendLine(JSONObject().put("i", index))
        completed.remove(index)
    }

    @Throws(IOException::class)
    private fun appendLine(o: JSONObject) {
        FileOutputStream(path, true).use { fos ->
            fos.write((o.toString() + "\n").toByteArray())
            fos.fd.sync()
        }
    }

    /** Delete the journal (transfer finished / relocked away / abandoned). */
    fun discard() {
        path.delete()
        headerDurable = false
    }

    data class PendingTransfer(
        val transferIdHex: String,
        val chunkRawSize: Int,
        val completedCount: Int,
        val diskBytes: Long,
        val lastModified: Long,
    )

    companion object {
        private const val MAX_CHUNK_COUNT = 131_072
        private const val MAX_LEDGER_BYTES = 32L * 1024 * 1024
        private const val MAX_ROOT_FRAME_BYTES = 26 + 2400 + 4
        private const val MAX_ROOT_FRAME_HEX_CHARS = MAX_ROOT_FRAME_BYTES * 2
        private val LEGAL_CHUNK_RAW_SIZES = setOf(1, 2, 4, 8, 16, 32).mapTo(mutableSetOf()) {
            it * 1024 * 1024
        }
        internal val SAFE_TRANSFER_ID = Regex("^[A-Za-z0-9_-]{1,64}$")
        private val SAFE_RECOVERY_ID = Regex("^[A-Za-z0-9_-]{1,64}$")

        private fun transferIdFromLedgerName(name: String): String? {
            val prefix = "af2-"
            val suffix = ".ledger.jsonl"
            if (!name.startsWith(prefix) || !name.endsWith(suffix)) return null
            return name.removePrefix(prefix).removeSuffix(suffix).takeIf { it.matches(SAFE_TRANSFER_ID) }
        }

        /** List all uncompleted/partial transfer ledgers in `dir`. */
        fun listPendingTransfers(dir: File): List<PendingTransfer> {
            val candidates = dir.listFiles { f -> transferIdFromLedgerName(f.name) != null }
                ?: return emptyList()
            val list = mutableListOf<PendingTransfer>()
            for (f in candidates) {
                val store = Af2LedgerStore(f)
                if (store.reload()) {
                    val tid = store.transferIdHex
                    val spill = File(dir, "af2-$tid.partial")
                    val spillBytes = if (spill.isFile) spill.length() else 0L
                    list.add(
                        PendingTransfer(
                            transferIdHex = tid,
                            chunkRawSize = store.chunkRawSize,
                            completedCount = store.completedIndices.size,
                            diskBytes = f.length() + spillBytes,
                            lastModified = f.lastModified()
                        )
                    )
                }
            }
            return list.sortedByDescending { it.lastModified }
        }

        /** Discard all pending journals and spill files in `dir`. */
        fun discardAllPending(dir: File) {
            dir.listFiles { f ->
                f.name.startsWith("af2-") && (
                    f.name.endsWith(".ledger.jsonl") ||
                    f.name.endsWith(".partial") ||
                    f.name.endsWith(".tmp")
                )
            }?.forEach { it.delete() }
        }

        /** Resume source: newest valid ledger in `dir` (by mtime), or null. */
        fun loadMostRecent(dir: File): Af2LedgerStore? {
            val candidates = dir.listFiles { f -> transferIdFromLedgerName(f.name) != null }
                ?: return null
            for (candidate in candidates.sortedByDescending { it.lastModified() }) {
                try {
                    val store = Af2LedgerStore(candidate)
                    if (store.reload()) return store
                } catch (_: Exception) {
                    // One corrupt candidate must not hide older valid work.
                }
            }
            return null
        }

        /** Remove unrecoverable spill files that have no valid resume journal. */
        fun sweepOrphanPartials(dir: File) {
            val validTids = mutableSetOf<String>()
            dir.listFiles { f -> transferIdFromLedgerName(f.name) != null }?.forEach { file ->
                val store = Af2LedgerStore(file)
                if (store.reload()) {
                    validTids.add(store.transferIdHex)
                } else {
                    file.delete()
                }
            }
            dir.listFiles { f -> f.name.startsWith("af2-") && f.name.endsWith(".partial") }
                ?.forEach { partial ->
                    val tid = partial.name.removePrefix("af2-").removeSuffix(".partial")
                    if (tid !in validTids) partial.delete()
                }
        }

        /** Create + write the header for a fresh transfer's journal. */
        fun create(
            dir: File,
            transferIdHex: String,
            chunkRawSize: Int,
            rootFrameBytes: ByteArray
        ): Af2LedgerStore {
            require(transferIdHex.matches(SAFE_TRANSFER_ID)) { "invalid AF2 transfer id" }
            require(chunkRawSize in LEGAL_CHUNK_RAW_SIZES) { "invalid AF2 chunk size" }
            require(rootFrameBytes.size in 1..MAX_ROOT_FRAME_BYTES) {
                "invalid AF2 ROOT frame"
            }
            if ((!dir.exists() && !dir.mkdirs()) || !dir.isDirectory) {
                throw IOException("AF2 ledger directory is unavailable")
            }
            val path = File(dir, "af2-$transferIdHex.ledger.jsonl")
            val recoveryId = UUID.randomUUID().toString()
            val header = JSONObject()
                .put("v", 1)
                .put("tid", transferIdHex)
                .put("rid", recoveryId)
                .put("crs", chunkRawSize)
                .put("root", bytesToHex(rootFrameBytes))
            // Atomic header: temp + fsync + rename so a crash mid-create
            // never leaves a headerless journal that a later commit would
            // append to. Keep an existing same-transfer ledger intact until
            // the replacement header itself is durable: a disk-full failure
            // during relock must not destroy otherwise resumable work.
            val tmp = File(dir, "${path.name}.${UUID.randomUUID()}.tmp")
            try {
                FileOutputStream(tmp).use { fos ->
                    fos.write((header.toString() + "\n").toByteArray())
                    fos.fd.sync()
                }
                try {
                    Files.move(
                        tmp.toPath(),
                        path.toPath(),
                        StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING,
                    )
                } catch (_: AtomicMoveNotSupportedException) {
                    // Both paths live in the same cache directory. Even when
                    // the provider lacks ATOMIC_MOVE, a replace-rename occurs
                    // only after the new header has been flushed.
                    Files.move(
                        tmp.toPath(),
                        path.toPath(),
                        StandardCopyOption.REPLACE_EXISTING,
                    )
                }
            } catch (e: Exception) {
                throw IOException("AF2 ledger header write failed", e)
            } finally {
                tmp.delete()
            }
            return Af2LedgerStore(path).apply {
                this.transferIdHex = transferIdHex
                this.recoveryId = recoveryId
                this.chunkRawSize = chunkRawSize
                this.rootFrameBytes = rootFrameBytes.copyOf()
                this.headerDurable = true
            }
        }

        /** Drop the journal (and spill) of `tid` — completion cleanup. */
        fun discardFor(dir: File, transferIdHex: String) {
            File(dir, "af2-$transferIdHex.ledger.jsonl").delete()
        }

        private fun bytesToHex(b: ByteArray): String =
            b.joinToString("") { "%02x".format(it) }

        private fun hexToBytes(s: String): ByteArray {
            if (s.length % 2 != 0) return ByteArray(0)
            return ByteArray(s.length / 2) { i ->
                val hi = Character.digit(s[i * 2], 16)
                val lo = Character.digit(s[i * 2 + 1], 16)
                if (hi < 0 || lo < 0) return ByteArray(0)
                ((hi shl 4) + lo).toByte()
            }
        }

        private fun strictInt(o: JSONObject, key: String): Int? = when (val value = o.opt(key)) {
            is Int -> value
            is Long -> value.takeIf {
                it in Int.MIN_VALUE.toLong()..Int.MAX_VALUE.toLong()
            }?.toInt()
            else -> null
        }
    }
}
