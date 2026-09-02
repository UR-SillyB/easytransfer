package com.airferry.app.scan

import android.content.Context
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.UUID

/**
 * Crash-safe retry metadata for fully materialized receive entries whose
 * [ContentStore] index publication has not committed yet.
 *
 * The staged `.partial` files are useless after a restart without their
 * logical names, bundle grouping and deterministic entry IDs. This manifest
 * keeps that ownership next to the bytes and replays [ContentStore.putFileBatch]
 * idempotently on startup. A crash after index commit but before stage cleanup
 * is recognized through the stable IDs and only removes the stale shell.
 */
object PendingRecoveryStore {
    private const val TAG = "PendingRecoveryStore"
    internal const val MANIFEST_NAME = ".airferry-pending.json"
    private const val STAGE_ROOT = "af2-entry-stage"
    private const val MAX_MANIFEST_BYTES = 4L * 1024 * 1024
    private const val MAX_ENTRIES = 4096
    private const val MAX_ATTEMPTS_PER_START = 256

    data class RetrySummary(val imported: Int, val alreadyCommitted: Int, val failed: Int)

    fun createStageDirectory(cacheDir: File): File {
        val root = File(cacheDir, STAGE_ROOT)
        if ((!root.exists() && !root.mkdirs()) || !root.isDirectory) {
            throw java.io.IOException("无法创建接收暂存目录")
        }
        val stage = File(root, UUID.randomUUID().toString())
        if (!stage.mkdir()) throw java.io.IOException("无法创建接收事务目录")
        return stage
    }

    /** Persist the retry plan only after every source file is complete+fsync'd. */
    fun persist(stageDir: File, requests: List<ContentStore.PutFileRequest>) {
        require(requests.isNotEmpty() && requests.size <= MAX_ENTRIES) {
            "invalid pending recovery entry count"
        }
        val stageCanonical = stageDir.canonicalFile
        require(stageCanonical.isDirectory) { "pending recovery stage is unavailable" }
        val entries = JSONArray()
        for (request in requests) {
            val source = request.file.canonicalFile
            require(source.parentFile == stageCanonical && source.isFile) {
                "pending recovery source escaped its stage"
            }
            val expectedSize = request.expectedSize ?: source.length()
            require(expectedSize >= 0 && source.length() == expectedSize) {
                "pending recovery source length mismatch"
            }
            val stableId = request.stableEntryId
            require(!stableId.isNullOrBlank() && stableId.length <= 256) {
                "pending recovery requires a bounded stable entry id"
            }
            entries.put(JSONObject().apply {
                put("file", source.name)
                put("name", request.displayName)
                put("crc", request.crcHex)
                put("crcUnknown", request.crcUnknown)
                put("kind", request.kind)
                if (request.bundleId != null) put("bundleId", request.bundleId)
                if (request.bundleTitle != null) put("bundleTitle", request.bundleTitle)
                put("size", expectedSize)
                put("stableId", stableId)
            })
        }
        val payload = JSONObject().put("v", 1).put("entries", entries)
            .toString().toByteArray(Charsets.UTF_8)
        require(payload.size.toLong() <= MAX_MANIFEST_BYTES) {
            "pending recovery manifest is too large"
        }
        val target = File(stageDir, MANIFEST_NAME)
        val temp = File(stageDir, ".$MANIFEST_NAME.${UUID.randomUUID()}.tmp")
        try {
            FileOutputStream(temp).use { output ->
                output.write(payload)
                output.fd.sync()
            }
            try {
                Files.move(
                    temp.toPath(), target.toPath(),
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING,
                )
            } catch (_: AtomicMoveNotSupportedException) {
                Files.move(temp.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING)
            }
        } finally {
            temp.delete()
        }
    }

    /** Retry bounded pending transactions. Malformed/partial attempts remain
     * untouched for forensic recovery and are handled by cache maintenance. */
    fun retryAll(context: Context): RetrySummary {
        val root = File(context.cacheDir, STAGE_ROOT)
        val attempts = root.listFiles { file -> file.isDirectory }
            ?.sortedBy { it.lastModified() }
            ?.take(MAX_ATTEMPTS_PER_START)
            ?: emptyList()
        var imported = 0
        var committed = 0
        var failed = 0
        for (stage in attempts) {
            val requests = readRequests(stage) ?: continue
            try {
                val existing = ContentStore.listEntries(context).associateBy { it.id }
                val matches = requests.map { request ->
                    existing[request.stableEntryId]?.let { entry ->
                        val expectedName = if (request.bundleId != null) {
                            FileNameUtil.sanitizeRelativePath(request.displayName)
                        } else {
                            FileNameUtil.sanitize(request.displayName).ifBlank { "received_file" }
                        }
                        entry.name == expectedName && entry.size == request.expectedSize &&
                            entry.kind == request.kind && entry.bundleId == request.bundleId
                    } == true
                }
                if (matches.all { it }) {
                    stage.deleteRecursively()
                    committed++
                    continue
                }
                // PutFileBatch is atomic, so a proper prior generation has all
                // stable IDs or none. Never guess through a conflicting prefix.
                if (matches.any { it } || requests.any { !it.file.isFile || it.file.length() != it.expectedSize }) {
                    failed++
                    continue
                }
                ContentStore.putFileBatch(context, requests)
                stage.deleteRecursively()
                imported++
            } catch (e: Exception) {
                failed++
                Log.w(TAG, "pending receive publication retry failed: $stage", e)
            }
        }
        return RetrySummary(imported, committed, failed)
    }

    internal fun readRequests(stageDir: File): List<ContentStore.PutFileRequest>? {
        val manifest = File(stageDir, MANIFEST_NAME)
        if (!manifest.isFile || manifest.length() !in 1..MAX_MANIFEST_BYTES) return null
        return try {
            val root = JSONObject(manifest.readText())
            if (root.length() != 2 || strictLong(root, "v") != 1L || root.opt("entries") !is JSONArray) {
                return null
            }
            val entries = root.getJSONArray("entries")
            if (entries.length() !in 1..MAX_ENTRIES) return null
            val stageCanonical = stageDir.canonicalFile
            val stableIds = HashSet<String>()
            buildList(entries.length()) {
                for (i in 0 until entries.length()) {
                    val item = entries.optJSONObject(i) ?: return null
                    val fileName = strictString(item, "file", 255) ?: return null
                    if (fileName != File(fileName).name || fileName == MANIFEST_NAME) return null
                    val displayName = strictString(item, "name", 4096) ?: return null
                    val crc = strictString(item, "crc", 128) ?: return null
                    val kind = strictString(item, "kind", 16)?.takeIf {
                        it == "file" || it == "text"
                    } ?: return null
                    val stableId = strictString(item, "stableId", 256)
                        ?.takeIf { it.isNotBlank() && stableIds.add(it) } ?: return null
                    val size = strictLong(item, "size")?.takeIf { it >= 0 } ?: return null
                    val crcUnknown = item.opt("crcUnknown") as? Boolean ?: return null
                    val bundleId = optionalString(item, "bundleId", 4096) ?: return null
                    val bundleTitle = optionalString(item, "bundleTitle", 4096) ?: return null
                    val source = File(stageDir, fileName).canonicalFile
                    if (source.parentFile != stageCanonical) return null
                    add(ContentStore.PutFileRequest(
                        displayName, source, crc, crcUnknown, kind,
                        bundleId.value, bundleTitle.value, size, stableId,
                    ))
                }
            }
        } catch (_: Exception) {
            null
        }
    }

    private data class OptionalString(val value: String?)

    private fun optionalString(o: JSONObject, key: String, max: Int): OptionalString? {
        if (!o.has(key) || o.isNull(key)) return OptionalString(null)
        return strictString(o, key, max)?.let(::OptionalString)
    }

    private fun strictString(o: JSONObject, key: String, max: Int): String? =
        (o.opt(key) as? String)?.takeIf { it.length <= max && !it.contains('\u0000') }

    private fun strictLong(o: JSONObject, key: String): Long? = when (val value = o.opt(key)) {
        is Int -> value.toLong()
        is Long -> value
        else -> null
    }
}
