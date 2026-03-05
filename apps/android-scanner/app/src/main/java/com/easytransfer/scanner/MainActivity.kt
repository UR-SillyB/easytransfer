package com.easytransfer.scanner

import android.Manifest
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
    private lateinit var missingHint: TextView
    private lateinit var startScanButton: Button
    private lateinit var stopScanButton: Button
    private lateinit var finalizeButton: Button
    private lateinit var exportButton: Button

    private val cameraExecutor = Executors.newSingleThreadExecutor()
    private val ioExecutor = Executors.newSingleThreadExecutor()
    private var isScanning = false

    private var transferId: String? = null
    private val symbolMap = linkedMapOf<String, JSONObject>()
    private val expectedByBlock = linkedMapOf<String, Int>()
    private val allSeenByBlock = linkedMapOf<String, MutableSet<Int>>()
    private val missingSymbolIds = linkedSetOf<String>()
    private var uploadedCount = 0
    private var manifestText: String? = null
    private val manifestChunks = linkedMapOf<Int, ByteArray>()
    private var manifestChunkTotal = 0
    private var manifestSha256: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        windowsAddrInput = findViewById(R.id.windowsAddrInput)
        previewView = findViewById(R.id.previewView)
        statusText = findViewById(R.id.statusText)
        missingHint = findViewById(R.id.missingHint)
        startScanButton = findViewById(R.id.startScanButton)
        stopScanButton = findViewById(R.id.stopScanButton)
        finalizeButton = findViewById(R.id.finalizeButton)
        exportButton = findViewById(R.id.exportButton)

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

    private fun onPayloadDecoded(payload: String) {
        if (!isScanning) return
        try {
            val obj = JSONObject(payload)
            val kind = obj.optString("kind")

            if (kind.startsWith("manifest_")) {
                processManifestFrame(obj)
                return
            }

            if (kind != "symbol") return

            val sid = obj.optString("stable_symbol_id")
            if (sid.isBlank()) return

            val tid = obj.optString("transfer_id")
            if (transferId == null && tid.isNotBlank()) transferId = tid
            if (transferId != null && tid.isNotBlank() && tid != transferId) return

            if (symbolMap.containsKey(sid)) return
            symbolMap[sid] = obj

            val blockKey = "f${obj.optInt("file_id", -1)}:b${obj.optInt("block_id", -1)}"
            val symbolId = obj.optInt("symbol_id", -1)
            val expected = obj.optInt("symbol_total", -1)
            if (expected > 0) expectedByBlock[blockKey] = maxOf(expectedByBlock[blockKey] ?: 0, expected)
            if (symbolId >= 0) {
                allSeenByBlock.getOrPut(blockKey) { linkedSetOf() }.add(symbolId)
            }

            runOnUiThread {
                statusText.text = "阶段：扫码采集中，已收 ${symbolMap.size} 分片"
            }
        } catch (_: Exception) {
        }
    }

    private fun processManifestFrame(obj: JSONObject) {
        val kind = obj.optString("kind")
        when (kind) {
            "manifest_start" -> {
                manifestChunks.clear()
                manifestChunkTotal = obj.optInt("chunk_total", 0)
                manifestSha256 = obj.optString("manifest_sha256")
                runOnUiThread {
                    statusText.text = "阶段：接收 manifest 控制帧"
                }
            }
            "manifest_chunk" -> {
                val idx = obj.optInt("chunk_index", -1)
                val b64 = obj.optString("payload_b64")
                if (idx >= 0 && b64.isNotBlank()) {
                    try {
                        val bytes = android.util.Base64.decode(b64, android.util.Base64.DEFAULT)
                        val crc = obj.optLong("payload_crc32", -1).toInt()
                        if (crc32(bytes) == crc) {
                            manifestChunks[idx] = bytes
                        }
                    } catch (_: Exception) {
                    }
                }
            }
            "manifest_end" -> {
                if (manifestChunkTotal > 0 && manifestChunks.size == manifestChunkTotal) {
                    val all = ByteArray(manifestChunks.values.sumOf { it.size })
                    var off = 0
                    for (i in 0 until manifestChunkTotal) {
                        val part = manifestChunks[i] ?: return
                        System.arraycopy(part, 0, all, off, part.size)
                        off += part.size
                    }
                    val text = String(all, Charsets.UTF_8)
                    val sha = sha256Hex(all)
                    if (manifestSha256.isNullOrBlank() || manifestSha256 == sha) {
                        manifestText = text
                        runOnUiThread {
                            statusText.text = "阶段：manifest 已就绪，继续扫码数据分片"
                        }
                    }
                }
            }
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

        statusText.text = "阶段：校验通过，开始上传"
        uploadedCount = 0
        ioExecutor.execute {
            val m = manifestText
            if (!m.isNullOrBlank()) {
                uploadManifestToWindows(windowsAddr, m)
            }
            val values = symbolMap.values.toList()
            for (obj in values) {
                val rec = JSONObject()
                rec.put("symbol_id", obj.optString("stable_symbol_id"))
                rec.put("data_b64", obj.optString("payload_b64"))
                rec.put("file_id", obj.optInt("file_id", -1))
                rec.put("block", obj.optInt("block_id", -1))
                rec.put("symbol", obj.optInt("symbol_id", -1))
                rec.put("redundant", obj.optBoolean("is_repair", false))

                val ok = uploadToWindows(windowsAddr, rec.toString())
                if (ok) uploadedCount += 1
            }
            runOnUiThread {
                statusText.text = "阶段：上传完成，成功 $uploadedCount / ${symbolMap.size}"
            }
        }
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
            conn.connectTimeout = 3000
            conn.readTimeout = 5000
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
            conn.connectTimeout = 3000
            conn.readTimeout = 5000
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
                    put("symbol_id", it.optString("stable_symbol_id"))
                    put("data_b64", it.optString("payload_b64"))
                    put("file_id", it.optInt("file_id", -1))
                    put("block", it.optInt("block_id", -1))
                    put("symbol", it.optInt("symbol_id", -1))
                    put("redundant", it.optBoolean("is_repair", false))
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
            report.put("manifest_ready", !manifestText.isNullOrBlank())
            File(outDir, "upload_report.json").writeText(report.toString(2))

            statusText.text = "已导出：${outDir.absolutePath}"
        } catch (e: Exception) {
            statusText.text = "导出失败：${e.message}"
        }
    }
}

private fun sha256Hex(bytes: ByteArray): String {
    val md = java.security.MessageDigest.getInstance("SHA-256")
    val out = md.digest(bytes)
    val sb = StringBuilder(out.size * 2)
    for (b in out) sb.append(String.format("%02x", b))
    return sb.toString()
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
