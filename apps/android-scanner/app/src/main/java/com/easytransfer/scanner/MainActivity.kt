package com.easytransfer.scanner

import android.Manifest
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.google.zxing.BinaryBitmap
import com.google.zxing.MultiFormatReader
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.nio.ByteBuffer
import java.util.concurrent.Executors

class MainActivity : ComponentActivity() {

    private lateinit var windowsAddrInput: EditText
    private lateinit var previewView: PreviewView
    private lateinit var statusText: TextView
    private lateinit var controlInfoText: TextView
    private lateinit var frameInfoText: TextView
    private lateinit var missingHint: TextView
    private lateinit var startScanButton: Button
    private lateinit var stopScanButton: Button
    private lateinit var finalizeButton: Button
    private lateinit var exportButton: Button

    private val cameraExecutor = Executors.newSingleThreadExecutor()
    private val ioExecutor = Executors.newSingleThreadExecutor()
    private var isScanning = false
    private lateinit var prefs: SharedPreferences

    private var transferId: String? = null
    private val symbolMap = linkedMapOf<String, JSONObject>()
    private val expectedByBlock = linkedMapOf<String, Int>()
    private val allSeenByBlock = linkedMapOf<String, MutableSet<Int>>()
    private val missingSymbolIds = linkedSetOf<String>()
    private var uploadedCount = 0
    private val uploadedSymbolIds = linkedSetOf<String>()
    private val uploadConflictIds = linkedSetOf<String>()
    private var controlMetaReady = false
    private var controlFileName: String = ""
    private var controlFileSize: Long = 0L
    private var controlSymbolCount: Int = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        windowsAddrInput = findViewById(R.id.windowsAddrInput)
        previewView = findViewById(R.id.previewView)
        statusText = findViewById(R.id.statusText)
        controlInfoText = findViewById(R.id.controlInfoText)
        frameInfoText = findViewById(R.id.frameInfoText)
        missingHint = findViewById(R.id.missingHint)
        startScanButton = findViewById(R.id.startScanButton)
        stopScanButton = findViewById(R.id.stopScanButton)
        finalizeButton = findViewById(R.id.finalizeButton)
        exportButton = findViewById(R.id.exportButton)

        prefs = getSharedPreferences("easytransfer_pref", MODE_PRIVATE)
        val savedAddr = prefs.getString("windows_addr", "") ?: ""
        if (savedAddr.isNotBlank()) {
            windowsAddrInput.setText(savedAddr)
        }

        startScanButton.setOnClickListener { startScan() }
        stopScanButton.setOnClickListener { stopScan() }
        finalizeButton.setOnClickListener { finalizeAndUpload() }
        exportButton.setOnClickListener { exportLogs() }
    }

    override fun onDestroy() {
        super.onDestroy()
        cameraExecutor.shutdownNow()
        ioExecutor.shutdownNow()
    }

    private fun startScan() {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.CAMERA), 1001)
            return
        }
        if (isScanning) {
            statusText.text = "阶段：扫码中"
            return
        }
        isScanning = true
        val providerFuture = ProcessCameraProvider.getInstance(this)
        providerFuture.addListener({
            val provider = providerFuture.get()
            val preview = Preview.Builder().build().also { it.setSurfaceProvider(previewView.surfaceProvider) }
            val analyzer = ImageAnalysis.Builder()
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()
                .also {
                    it.setAnalyzer(cameraExecutor, FrameAnalyzer { payload -> onPayloadDecoded(payload) })
                }
            provider.unbindAll()
            provider.bindToLifecycle(this, CameraSelector.DEFAULT_BACK_CAMERA, preview, analyzer)
            statusText.text = "阶段：扫码采集中"
        }, ContextCompat.getMainExecutor(this))
    }

    private fun stopScan() {
        isScanning = false
        val providerFuture = ProcessCameraProvider.getInstance(this)
        providerFuture.addListener({
            providerFuture.get().unbindAll()
            statusText.text = "阶段：扫码停止，等待校验"
        }, ContextCompat.getMainExecutor(this))
    }

    @Synchronized
    private fun onPayloadDecoded(payload: String) {
        if (!isScanning) return
        try {
            val obj = JSONObject(payload)
            val kind = obj.optString("kind")

            if (kind == "control") {
                processControlFrame(obj)
                return
            }

            if (kind != "symbol") return
            runOnUiThread {
                frameInfoText.text =
                    "当前帧：#${readInt(obj, "frame_seq", "frame", -1)} 文件${readInt(obj, "file_id", null, -1)} 块${readInt(obj, "block", "block_id", -1)} 分片${readInt(obj, "symbol", "symbol_index", -1)}"
            }

            val sid = obj.optString("symbol_id")
            if (sid.isBlank()) return

            val tid = obj.optString("transfer_id")
            if (transferId == null && tid.isNotBlank()) transferId = tid
            if (transferId != null && tid.isNotBlank() && tid != transferId) {
                runOnUiThread { statusText.text = "错误：扫描到不同传输ID，请重新开始" }
                return
            }

            if (symbolMap.containsKey(sid)) {
                val oldPayload = symbolMap[sid]?.let { sym ->
                    val p = sym.optString("payload_b64")
                    if (p.isNotBlank()) p else sym.optString("data_b64")
                }
                val newPayload = obj.optString("payload_b64").ifBlank { obj.optString("data_b64") }
                if (!oldPayload.isNullOrBlank() && oldPayload != newPayload) {
                    uploadConflictIds.add(sid)
                }
                return
            }
            symbolMap[sid] = obj

            val fileId = readInt(obj, "file_id", null, -1)
            val blockId = readInt(obj, "block", "block_id", -1)
            val symbolId = readInt(obj, "symbol", "symbol_index", -1)
            val expected = readInt(obj, "source_symbol_total", "k", -1)
            val isRepair = readBool(obj, "is_repair", "redundant", false)
            val blockKey = "f${fileId}:b${blockId}"
            if (expected > 0) expectedByBlock[blockKey] = maxOf(expectedByBlock[blockKey] ?: 0, expected)
            if (symbolId >= 0 && !isRepair) {
                allSeenByBlock.getOrPut(blockKey) { linkedSetOf() }.add(symbolId)
            }

            runOnUiThread {
                statusText.text = "阶段：扫码采集中，已收 ${symbolMap.size} 分片"
            }
        } catch (_: Exception) {
        }
    }

    private fun processControlFrame(obj: JSONObject) {
        transferId = obj.optString("transfer_id")
        val existingUploaded = prefs.getStringSet("uploaded_${transferId}", emptySet()) ?: emptySet()
        uploadedSymbolIds.clear()
        uploadedSymbolIds.addAll(existingUploaded)
        val b64 = obj.optString("payload_data_b64")
        val crc = obj.optInt("payload_data_crc32", -1)
        if (b64.isNotBlank()) {
            try {
                val bytes = android.util.Base64.decode(b64, android.util.Base64.DEFAULT)
                if (crc >= 0 && crc32(bytes) != crc) {
                    runOnUiThread { statusText.text = "控制帧校验失败" }
                    return
                }
                val dataObj = JSONObject(String(bytes, Charsets.UTF_8))
                controlFileName = dataObj.optString("payload_name")
                controlFileSize = dataObj.optLong("payload_size", 0L)
                controlSymbolCount = dataObj.optInt("payload_symbol_count", 0)
            } catch (_: Exception) {
                controlFileName = obj.optString("payload_name")
                controlFileSize = obj.optLong("payload_size", 0L)
                controlSymbolCount = obj.optInt("payload_symbol_count", 0)
            }
        } else {
            controlFileName = obj.optString("payload_name")
            controlFileSize = obj.optLong("payload_size", 0L)
            controlSymbolCount = obj.optInt("payload_symbol_count", 0)
        }
        controlMetaReady = controlFileName.isNotBlank() && controlFileSize > 0 && controlSymbolCount > 0
        runOnUiThread {
            statusText.text = "阶段：控制帧已接收，可开始数据扫码"
            controlInfoText.text = "控制帧信息：${controlFileName} | ${controlFileSize} 字节 | ${controlSymbolCount} 分片"
            finalizeButton.isEnabled = controlMetaReady
        }
    }

    private fun rebuildMissing() {
        missingSymbolIds.clear()
        for ((blockKey, expected) in expectedByBlock) {
            if (expected <= 0) continue
            val seen = allSeenByBlock[blockKey] ?: emptySet<Int>()
            val prefix = transferId ?: "unknown"
            for (i in 0 until expected) {
                if (!seen.contains(i)) {
                    missingSymbolIds.add("$prefix:${blockKey}:s$i")
                }
            }
        }
    }

    private fun finalizeAndUpload() {
        stopScan()
        if (!controlMetaReady) {
            statusText.text = "控制帧未完成，请先扫控制帧"
            return
        }
        rebuildMissing()
        missingHint.text = "缺失分片：${missingSymbolIds.size}"
        if (missingSymbolIds.isNotEmpty()) {
            statusText.text = "阶段：校验未通过，请补扫缺失分片"
            return
        }

        val windowsAddr = windowsAddrInput.text?.toString()?.trim().orEmpty()
        if (windowsAddr.isBlank()) {
            statusText.text = "请填写 Windows 地址"
            return
        }
        prefs.edit().putString("windows_addr", windowsAddr).apply()

        statusText.text = "阶段：校验通过，开始上传"
        uploadedCount = 0
        uploadConflictIds.clear()
        val transferKey = "uploaded_${transferId ?: ""}"
        val existingUploaded = prefs.getStringSet(transferKey, emptySet()) ?: emptySet()
        uploadedSymbolIds.clear()
        uploadedSymbolIds.addAll(existingUploaded)

        ioExecutor.execute {
            val manifestPayload = buildManifestFromSymbols()
            if (!uploadManifestToWindows(windowsAddr, manifestPayload)) {
                runOnUiThread {
                    statusText.text = "上传失败：manifest 上传失败"
                }
                return@execute
            }

            val values = synchronized(this) { symbolMap.values.toList() }
            for (obj in values) {
                val sid = obj.optString("symbol_id")
                if (sid.isBlank()) continue
                if (uploadedSymbolIds.contains(sid)) continue

                val payloadB64 = obj.optString("payload_b64").ifBlank { obj.optString("data_b64") }
                val payloadCrcCheck = obj.optInt("payload_crc32", obj.optInt("crc32", -1))
                if (payloadB64.isNotBlank() && payloadCrcCheck >= 0) {
                    try {
                        val bytes = android.util.Base64.decode(payloadB64, android.util.Base64.DEFAULT)
                        if (crc32(bytes) != payloadCrcCheck) {
                            uploadConflictIds.add(sid)
                            continue
                        }
                    } catch (_: Exception) {
                        uploadConflictIds.add(sid)
                        continue
                    }
                }

                val rec = JSONObject()
                rec.put("symbol_id", sid)
                val payloadText = obj.optString("payload_b64").ifBlank { obj.optString("data_b64") }
                val payloadCrcOut = obj.optInt("payload_crc32", obj.optInt("crc32", -1))
                val blockId = readInt(obj, "block", "block_id", -1)
                val symbolId = readInt(obj, "symbol", "symbol_index", -1)
                val isRepair = readBool(obj, "is_repair", "redundant", false)
                rec.put("payload_b64", payloadText)
                rec.put("data_b64", payloadText)
                if (payloadCrcOut >= 0) {
                    rec.put("payload_crc32", payloadCrcOut)
                    rec.put("crc32", payloadCrcOut)
                }
                rec.put("file_id", readInt(obj, "file_id", null, -1))
                rec.put("block", blockId)
                rec.put("block_id", blockId)
                rec.put("symbol", symbolId)
                rec.put("symbol_index", symbolId)
                rec.put("redundant", isRepair)
                rec.put("is_repair", isRepair)
                rec.put("transfer_id", obj.optString("transfer_id"))
                rec.put("frame", readInt(obj, "frame", "frame_seq", -1))
                rec.put("frame_seq", readInt(obj, "frame_seq", "frame", -1))

                var ok = false
                var retry = 0
                while (!ok && retry < 3) {
                    ok = uploadToWindows(windowsAddr, rec.toString())
                    retry += 1
                }
                if (ok) {
                    uploadedCount += 1
                    uploadedSymbolIds.add(sid)
                    prefs.edit().putStringSet(transferKey, uploadedSymbolIds).apply()
                }
            }

            runOnUiThread {
                statusText.text = "阶段：上传完成，成功 $uploadedCount / ${symbolMap.size}，冲突 ${uploadConflictIds.size}"
            }
        }
    }

    private fun buildManifestFromSymbols(): String {
        val values = synchronized(this) { symbolMap.values.toList() }
        val grouped = values.groupBy { it.optInt("file_id", -1) }
        val filesArr = JSONArray()
        val sourcesArr = JSONArray()
        val repairsArr = JSONArray()
        for ((fileId, list) in grouped) {
            if (fileId < 0) continue
            val source = list.filter { !readBool(it, "is_repair", "redundant", false) }
                .sortedWith(compareBy<JSONObject> { readInt(it, "block", "block_id", -1) }.thenBy { readInt(it, "symbol", "symbol_index", -1) })
            if (source.isEmpty()) continue
            val first = source.first()
            val obj = JSONObject()
            val path = first.optString("payload_file_name").ifBlank {
                first.optString("file_name").ifBlank { first.optString("path", "file_${fileId}.bin") }
            }
            val size = when {
                first.has("payload_file_size") -> first.optLong("payload_file_size", 0L)
                first.has("file_size") -> first.optLong("file_size", 0L)
                else -> first.optLong("size", 0L)
            }
            val sha = first.optString("payload_file_sha256").ifBlank { first.optString("file_sha256", "") }
            val compression = first.optString("payload_compression").ifBlank { first.optString("compression", "none") }
            obj.put("path", path)
            obj.put("size", size)
            obj.put("sha256", sha)
            obj.put("compression", compression)
            val sidArr = JSONArray()
            source.forEachIndexed { idx, sym ->
                val sid = sym.optString("symbol_id")
                sidArr.put(sid)
                val srcSpec = JSONObject()
                srcSpec.put("symbol_id", sid)
                srcSpec.put("file", path)
                srcSpec.put("index", idx)
                srcSpec.put("size", decodeB64Len(sym.optString("payload_b64").ifBlank { sym.optString("data_b64") }))
                srcSpec.put("sha256", sym.optString("payload_sha256"))
                sourcesArr.put(srcSpec)
            }
            obj.put("source_symbol_ids", sidArr)
            filesArr.put(obj)

            list.filter { readBool(it, "is_repair", "redundant", false) }.forEach { rep ->
                val repSpec = JSONObject()
                repSpec.put("symbol_id", rep.optString("symbol_id"))
                repSpec.put("file", path)
                repSpec.put("size", decodeB64Len(rep.optString("payload_b64").ifBlank { rep.optString("data_b64") }))
                repSpec.put("sha256", rep.optString("payload_sha256"))
                val xorArr = when {
                    rep.has("xor_of") -> rep.optJSONArray("xor_of")
                    rep.has("repair_of") -> rep.optJSONArray("repair_of")
                    else -> JSONArray()
                } ?: JSONArray()
                repSpec.put("xor_of", xorArr)
                repairsArr.put(repSpec)
            }
        }
        val manifest = JSONObject()
        manifest.put("version", 1)
        manifest.put("protocol", "easytransfer/1")
        manifest.put("stream_id", transferId ?: "")
        manifest.put("transfer_id", transferId ?: "")
        manifest.put("files", filesArr)
        manifest.put("sources", sourcesArr)
        manifest.put("repairs", repairsArr)
        return manifest.toString()
    }

    private fun uploadManifestToWindows(addr: String, payload: String): Boolean {
        return try {
            val endpoint = if (addr.startsWith("http://") || addr.startsWith("https://")) {
                "$addr/upload-manifest"
            } else {
                "http://$addr/upload-manifest"
            }
            val conn = (URL(endpoint).openConnection() as HttpURLConnection)
            conn.requestMethod = "POST"
            conn.connectTimeout = 10000
            conn.readTimeout = 30000
            conn.doOutput = true
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8")
            val bytes = payload.toByteArray(Charsets.UTF_8)
            conn.setRequestProperty("Content-Length", bytes.size.toString())
            conn.outputStream.use { out: OutputStream -> out.write(bytes) }
            conn.responseCode in 200..299
        } catch (_: Exception) {
            false
        }
    }

    private fun uploadToWindows(addr: String, payload: String): Boolean {
        return try {
            val endpoint = if (addr.startsWith("http://") || addr.startsWith("https://")) {
                "$addr/upload-symbol"
            } else {
                "http://$addr/upload-symbol"
            }
            val conn = (URL(endpoint).openConnection() as HttpURLConnection)
            conn.requestMethod = "POST"
            conn.connectTimeout = 10000
            conn.readTimeout = 30000
            conn.doOutput = true
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8")
            val bytes = payload.toByteArray(Charsets.UTF_8)
            conn.setRequestProperty("Content-Length", bytes.size.toString())
            conn.outputStream.use { out: OutputStream -> out.write(bytes) }
            conn.responseCode in 200..299
        } catch (_: Exception) {
            false
        }
    }

    private fun exportLogs() {
        try {
            val outDir = File(getExternalFilesDir(null), "scan-validate-upload")
            outDir.mkdirs()

            val uploaded = File(outDir, "validated_symbols.jsonl")
            val lines = symbolMap.values.map {
                JSONObject().apply {
                    put("symbol_id", it.optString("symbol_id"))
                    val payloadText = it.optString("payload_b64").ifBlank { it.optString("data_b64") }
                    put("payload_b64", payloadText)
                    put("data_b64", payloadText)
                    put("file_id", readInt(it, "file_id", null, -1))
                    put("block", readInt(it, "block", "block_id", -1))
                    put("symbol", readInt(it, "symbol", "symbol_index", -1))
                    put("redundant", readBool(it, "is_repair", "redundant", false))
                }.toString()
            }
            uploaded.writeText(lines.joinToString("\n", postfix = if (lines.isEmpty()) "" else "\n"))

            val missing = JSONObject()
            missing.put("transfer_id", transferId ?: "")
            val arr = JSONArray()
            missingSymbolIds.forEach { arr.put(it) }
            missing.put("missing_symbol_ids", arr)
            File(outDir, "missing_symbols.json").writeText(missing.toString(2))

            val report = JSONObject()
            report.put("scanned_symbols", symbolMap.size)
            report.put("missing_symbols", missingSymbolIds.size)
            report.put("uploaded_symbols", uploadedCount)
            report.put("manifest_ready", controlMetaReady)
            report.put("control_file_name", controlFileName)
            report.put("control_file_size", controlFileSize)
            report.put("control_symbol_count", controlSymbolCount)
            report.put("upload_conflict_count", uploadConflictIds.size)
            report.put("resume_uploaded_symbols", uploadedSymbolIds.size)
            File(outDir, "upload_report.json").writeText(report.toString(2))

            statusText.text = "已导出：${outDir.absolutePath}"
        } catch (e: Exception) {
            statusText.text = "导出失败：${e.message}"
        }
    }
}

private fun readInt(obj: JSONObject, primary: String, fallback: String?, defaultValue: Int): Int {
    if (obj.has(primary)) return obj.optInt(primary, defaultValue)
    if (fallback != null && obj.has(fallback)) return obj.optInt(fallback, defaultValue)
    return defaultValue
}

private fun readBool(obj: JSONObject, primary: String, fallback: String?, defaultValue: Boolean): Boolean {
    if (obj.has(primary)) return obj.optBoolean(primary, defaultValue)
    if (fallback != null && obj.has(fallback)) return obj.optBoolean(fallback, defaultValue)
    return defaultValue
}

private fun decodeB64Len(data: String): Int {
    if (data.isBlank()) return 0
    return try {
        android.util.Base64.decode(data, android.util.Base64.DEFAULT).size
    } catch (_: Exception) {
        0
    }
}

private fun crc32(bytes: ByteArray): Int {
    val crc = java.util.zip.CRC32()
    crc.update(bytes)
    return crc.value.toInt()
}

private class FrameAnalyzer(
    private val onPayload: (String) -> Unit,
) : ImageAnalysis.Analyzer {
    private val reader = MultiFormatReader()

    override fun analyze(image: ImageProxy) {
        val mediaImage = image.image
        if (mediaImage != null) {
            try {
                val plane = image.planes[0]
                val data = plane.buffer.toByteArray()
                val source = PlanarYUVLuminanceSource(
                    data,
                    image.width,
                    image.height,
                    0,
                    0,
                    image.width,
                    image.height,
                    false,
                )
                val bitmap = BinaryBitmap(HybridBinarizer(source))
                val result = reader.decodeWithState(bitmap)
                onPayload(result.text)
            } catch (_: Exception) {
            } finally {
                reader.reset()
            }
        }
        image.close()
    }
}

private fun ByteBuffer.toByteArray(): ByteArray {
    rewind()
    val data = ByteArray(remaining())
    get(data)
    return data
}
