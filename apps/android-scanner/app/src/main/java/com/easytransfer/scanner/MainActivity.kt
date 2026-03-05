package com.easytransfer.scanner

import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.activity.ComponentActivity
import org.json.JSONObject
import java.io.File
import java.io.OutputStream
import java.net.Inet4Address
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Executors

class MainActivity : ComponentActivity() {

    private lateinit var addressHint: TextView
    private lateinit var statusText: TextView
    private lateinit var startServiceButton: Button
    private lateinit var stopServiceButton: Button
    private lateinit var exportButton: Button

    private val ioExecutor = Executors.newSingleThreadExecutor()
    private var serverSocket: ServerSocket? = null
    private val session = mutableListOf<String>()
    private val outputBuffer = StringBuilder()
    private var receivedBytes: Long = 0L
    private val port = 18777

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        addressHint = findViewById(R.id.addressHint)
        statusText = findViewById(R.id.statusText)
        startServiceButton = findViewById(R.id.startServiceButton)
        stopServiceButton = findViewById(R.id.stopServiceButton)
        exportButton = findViewById(R.id.exportButton)

        startServiceButton.setOnClickListener { startService() }
        stopServiceButton.setOnClickListener { stopService() }
        exportButton.setOnClickListener { exportSession() }

        updateAddressHint()
    }

    override fun onDestroy() {
        super.onDestroy()
        stopService()
        ioExecutor.shutdownNow()
    }

    private fun updateAddressHint() {
        val ip = getLocalIpv4Address() ?: "未知"
        addressHint.text = "服务地址：http://$ip:$port/upload"
    }

    private fun startService() {
        if (serverSocket != null) {
            statusText.text = "服务已在运行"
            return
        }
        ioExecutor.execute {
            try {
                val ss = ServerSocket(port)
                serverSocket = ss
                runOnUiThread { statusText.text = "服务已启动，等待 Windows 连接..." }
                while (!ss.isClosed) {
                    val client = ss.accept()
                    handleClient(client)
                }
            } catch (e: Exception) {
                runOnUiThread { statusText.text = "服务异常：${e.message}" }
            } finally {
                serverSocket = null
            }
        }
    }

    private fun stopService() {
        try {
            serverSocket?.close()
            serverSocket = null
            statusText.text = "服务已停止"
        } catch (e: Exception) {
            statusText.text = "停止失败：${e.message}"
        }
    }

    private fun handleClient(socket: Socket) {
        socket.use { s ->
            val request = s.getInputStream().bufferedReader(Charsets.UTF_8)
            val firstLine = request.readLine() ?: return
            val headers = mutableMapOf<String, String>()
            while (true) {
                val line = request.readLine() ?: break
                if (line.isBlank()) break
                val idx = line.indexOf(':')
                if (idx > 0) {
                    headers[line.substring(0, idx).trim().lowercase()] = line.substring(idx + 1).trim()
                }
            }

            if (!firstLine.startsWith("POST /upload")) {
                writeHttp(s.getOutputStream(), 404, "Not Found", "仅支持 POST /upload")
                return
            }

            val contentLength = headers["content-length"]?.toIntOrNull() ?: 0
            if (contentLength <= 0) {
                writeHttp(s.getOutputStream(), 400, "Bad Request", "缺少内容")
                return
            }

            val bodyBytes = CharArray(contentLength)
            var totalRead = 0
            while (totalRead < contentLength) {
                val n = request.read(bodyBytes, totalRead, contentLength - totalRead)
                if (n <= 0) break
                totalRead += n
            }

            val payload = String(bodyBytes, 0, totalRead)
            receivedBytes += totalRead
            session.add(payload)
            outputBuffer.append(payload).append("\n")

            runOnUiThread {
                statusText.text = "已接收 ${session.size} 段，累计 ${receivedBytes} 字节"
            }

            val response = JSONObject()
            response.put("ok", true)
            response.put("received_segments", session.size)
            response.put("received_bytes", receivedBytes)
            writeHttp(s.getOutputStream(), 200, "OK", response.toString())
        }
    }

    private fun writeHttp(out: OutputStream, code: Int, reason: String, body: String) {
        val bytes = body.toByteArray(Charsets.UTF_8)
        val header = "HTTP/1.1 $code $reason\r\n" +
            "Content-Type: application/json; charset=utf-8\r\n" +
            "Content-Length: ${bytes.size}\r\n" +
            "Connection: close\r\n\r\n"
        out.write(header.toByteArray(Charsets.UTF_8))
        out.write(bytes)
        out.flush()
    }

    private fun exportSession() {
        try {
            val outDir = File(getExternalFilesDir(null), "service-session")
            outDir.mkdirs()
            val received = File(outDir, "received_payloads.txt")
            received.writeText(outputBuffer.toString())

            val report = JSONObject()
            report.put("segments", session.size)
            report.put("received_bytes", receivedBytes)
            report.put("note", "Windows 端已通过地址上传成功")

            val feedback = File(outDir, "service_report.json")
            feedback.writeText(report.toString(2))

            statusText.text = "已导出：${outDir.absolutePath}"
        } catch (e: Exception) {
            statusText.text = "导出失败：${e.message}"
        }
    }

    private fun getLocalIpv4Address(): String? {
        return try {
            val interfaces = NetworkInterface.getNetworkInterfaces() ?: return null
            while (interfaces.hasMoreElements()) {
                val nif = interfaces.nextElement()
                val addresses = nif.inetAddresses
                while (addresses.hasMoreElements()) {
                    val addr = addresses.nextElement()
                    if (!addr.isLoopbackAddress && addr is Inet4Address) {
                        return addr.hostAddress
                    }
                }
            }
            null
        } catch (_: Exception) {
            null
        }
    }
}
