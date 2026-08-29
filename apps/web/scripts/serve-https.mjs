// Minimal HTTPS static file server for LAN receiver testing.
// Usage: node serve-https.mjs <dir> <crt> <key> [port]
import https from "node:https"
import fs from "node:fs"
import path from "node:path"

const [,, dir, crt, key, portArg] = process.argv
const requestedPort = portArg === undefined ? 8765 : Number(portArg)
const port = Number.isInteger(requestedPort) && requestedPort >= 1 && requestedPort <= 65535
  ? requestedPort
  : NaN
if (!dir || !crt || !key) {
  console.error("usage: node serve-https.mjs <serveDir> <crt> <key> [port]")
  process.exit(1)
}
if (!Number.isInteger(port)) {
  console.error(`invalid port: ${portArg}`)
  process.exit(1)
}

const types = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript",
  ".wasm": "application/wasm",
  ".css": "text/css",
  ".png": "image/png",
}
const root = fs.realpathSync(dir)

const server = https.createServer(
  { cert: fs.readFileSync(crt), key: fs.readFileSync(key) },
  (req, res) => {
    let urlPath
    try {
      urlPath = decodeURIComponent((req.url || "/").split("?")[0])
    } catch {
      res.writeHead(400); res.end("bad request"); return
    }
    // Request targets begin with '/'. Passing that directly to path.resolve
    // discards `root`, so normalize it to a relative path first.
    const relativePath = urlPath === "/"
      ? "receiver.html"
      : urlPath.replace(/^[/\\]+/, "")
    const candidatePath = path.resolve(root, relativePath)
    // Boundary-aware containment: a plain startsWith(dir) also admits sibling
    // directories that share the prefix (e.g. dist vs dist-standalone).
    let filePath = candidatePath
    let isFile = false
    try {
      filePath = fs.realpathSync(candidatePath)
      isFile = fs.statSync(filePath).isFile()
    } catch { /* missing/raced */ }
    // Recheck after resolving symlinks so a link within the served tree cannot
    // expose an arbitrary file elsewhere on the machine.
    const contained = filePath === root || filePath.startsWith(root + path.sep)
    if (!contained || !isFile) {
      res.writeHead(404); res.end("not found"); return
    }
    res.writeHead(200, { "content-type": types[path.extname(filePath)] || "application/octet-stream" })
    const stream = fs.createReadStream(filePath)
    stream.on("error", () => {
      if (!res.headersSent) res.writeHead(500)
      res.end()
    })
    stream.pipe(res)
  }
)

server.listen(port, "0.0.0.0", () => {
  console.log(`HTTPS server serving ${dir} on 0.0.0.0:${port}`)
  console.log(`  本机:   https://localhost:${port}/receiver.html`)
  console.log(`  局域网: https://192.168.242.149:${port}/receiver.html`)
  console.log(`  (自签证书 — 浏览器会警告，点「高级」→「继续」即可)`)
})
