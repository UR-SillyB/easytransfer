package com.airferry.app.send

import android.net.Uri
import java.text.Normalizer

/**
 * One item queued for sending. Two shapes only (no directory support on
 * Android v1): a SAF-picked file (`uri` set) or an in-memory UTF-8 text
 * message (`text` set). `displayName` becomes the wire path exactly as the
 * web sender names items (NFC-normalized, e.g. `文字消息.txt`).
 */
data class SendItem(
    /** 1 = file, 2 = utf8 text (KIND_FILE / KIND_UTF8_TEXT in core/af2). */
    val kind: Int,
    val displayName: String,
    val size: Long,
    val uri: Uri? = null,
    val text: ByteArray? = null
) {
    companion object {
        const val KIND_FILE = 1
        const val KIND_UTF8_TEXT = 2
        const val DEFAULT_TEXT_NAME = "文字消息.txt"
    }
}

/**
 * Fail fast against the smallest bundled receiver budget. AF2 is one-way and
 * cannot negotiate capacity, so an Android sender must not emit a perfectly
 * valid broadcast that the 8 GiB Web/WASM receiver is guaranteed to reject.
 * The subtraction form also prevents a hostile provider size from overflowing
 * a signed Long during aggregation.
 */
internal fun validateSendItems(items: List<SendItem>): Long {
    require(items.isNotEmpty()) { "没有可发送的内容" }
    require(items.size <= MAX_AF2_ENTRIES) {
        "发送条目数 ${items.size} 超过 AF2 上限 $MAX_AF2_ENTRIES"
    }
    var total = 0L
    for ((index, item) in items.withIndex()) {
        require(item.kind == SendItem.KIND_FILE || item.kind == SendItem.KIND_UTF8_TEXT) {
            "发送条目 $index 类型无效"
        }
        require(item.size >= 0) { "发送条目 ${item.displayName} 大小无效" }
        require(item.size <= MAX_INTEROPERABLE_SEND_BYTES - total) {
            "所选内容超过内置接收端通用上限 8 GiB"
        }
        total += item.size
    }
    require(total > 0) { "所选内容全部为 0 字节，没有可传输的数据" }
    return total
}

/**
 * Allocate a unique, NFC-normalized single-component AF2 path. Android's
 * multi-document picker does not retain parent directories, so two files from
 * different folders commonly arrive with the same display name. Resolve that
 * collision before the expensive read/hash pass instead of letting Manifest
 * validation reject it at the end.
 */
internal fun uniqueSendDisplayName(used: MutableSet<String>, requested: String): String {
    val wireSafe = requested.map { c ->
        if (c == '/' || c == '\\' || c.code < 0x20) '_' else c
    }.joinToString("").trim().let { cleaned ->
        if (cleaned.isEmpty() || cleaned == "." || cleaned == "..") "unnamed" else cleaned
    }
    val normalized = Normalizer.normalize(wireSafe, Normalizer.Form.NFC)
    val dot = normalized.lastIndexOf('.')
    val stem = if (dot > 0) normalized.substring(0, dot) else normalized
    val extension = if (dot > 0) normalized.substring(dot) else ""
    val first = fitSendComponent(stem, "", extension)
    if (used.add(first)) return first

    var ordinal = 1
    while (true) {
        val suffix = " ($ordinal)"
        val candidate = fitSendComponent(stem, suffix, extension)
        if (used.add(candidate)) return candidate
        ordinal++
    }
}

private fun fitSendComponent(stem: String, suffix: String, extension: String = ""): String {
    val suffixBytes = suffix.toByteArray(Charsets.UTF_8).size
    val extensionBytes = extension.toByteArray(Charsets.UTF_8).size
    if (suffixBytes + extensionBytes <= MAX_AF2_COMPONENT_BYTES) {
        val stemBudget = MAX_AF2_COMPONENT_BYTES - suffixBytes - extensionBytes
        return takeUtf8Prefix(stem, stemBudget) + suffix + extension
    }
    // An unusually long extension cannot be preserved together with the
    // discriminator. Keep a bounded prefix and the suffix, whose uniqueness
    // is more important than the cosmetic extension in this edge case.
    return takeUtf8Prefix(stem + extension, MAX_AF2_COMPONENT_BYTES - suffixBytes) + suffix
}

private fun takeUtf8Prefix(value: String, maxBytes: Int): String {
    if (maxBytes <= 0) return ""
    var byteCount = 0
    var end = 0
    while (end < value.length) {
        val codePoint = value.codePointAt(end)
        val chars = Character.charCount(codePoint)
        val encodedBytes = String(Character.toChars(codePoint)).toByteArray(Charsets.UTF_8).size
        if (byteCount + encodedBytes > maxBytes) break
        byteCount += encodedBytes
        end += chars
    }
    return value.substring(0, end)
}

private const val MAX_AF2_COMPONENT_BYTES = 255
private const val MAX_AF2_ENTRIES = 4096
internal const val MAX_INTEROPERABLE_SEND_BYTES = 8L * 1024 * 1024 * 1024
