/** Sender-side AF2 entry path helpers. */

/**
 * Canonicalize a browser-provided file/relative path before it enters the AF2
 * manifest. AF2 uses forward slashes and NFC Unicode paths; parent traversal is
 * never a valid sender path.
 */
export function normalizeSenderPath(raw: string, fallback = "unnamed"): string {
  const normalized = (raw || fallback).replace(/\\/g, "/").normalize("NFC")
  const parts = normalized.split("/").filter((part) => part.length > 0 && part !== ".")
  if (parts.some((part) => part === "..")) {
    throw new Error(`非法相对路径（包含 ..）: ${raw}`)
  }
  const path = parts.join("/") || fallback
  if ([...path].some((c) => c.codePointAt(0)! < 0x20)) {
    throw new Error(`非法相对路径（包含控制字符）: ${raw}`)
  }
  if (parts.some((part) => utf8Length(part) > MAX_COMPONENT_BYTES)) {
    throw new Error(`相对路径单段超过 ${MAX_COMPONENT_BYTES} 字节: ${raw}`)
  }
  if (utf8Length(path) > MAX_PATH_BYTES) {
    throw new Error(`相对路径超过 ${MAX_PATH_BYTES} 字节: ${raw}`)
  }
  return path
}

/**
 * One file travelling from the main thread into the compress worker.
 *
 * `path` is REQUIRED in practice for anything picked via directory picker /
 * drag-and-drop walk: a JS-level `webkitRelativePath` own-property override
 * does NOT survive postMessage — the structured clone of a File serializes
 * the browser-native internal relative-path field (empty for those files),
 * so the hierarchy must travel as a sibling string field.
 */
export interface SenderFileItem {
  file: File
  /** Main-thread-resolved sender path (directory picks / drop walks). */
  path?: string
}

/**
 * Prefer the explicitly carried path, then the browser-native relative path,
 * then the bare file name. Plain files fall back to `file.name`.
 */
export function senderPathForFile(
  file: Pick<File, "name"> & { webkitRelativePath?: string },
  overridePath?: string
): string {
  const rel = (overridePath ?? file.webkitRelativePath)?.trim()
  return normalizeSenderPath(rel || file.name || "unnamed")
}

/** Add a numeric suffix to the basename while preserving its parent directory. */
export function uniqueSenderPath(used: Set<string>, requestedPath: string): string {
  const path = normalizeSenderPath(requestedPath)
  if (!used.has(path)) return path

  const slash = path.lastIndexOf("/")
  const dir = slash >= 0 ? path.slice(0, slash + 1) : ""
  const name = slash >= 0 ? path.slice(slash + 1) : path
  const dot = name.lastIndexOf(".")
  const stem = dot > 0 ? name.slice(0, dot) : name
  const ext = dot > 0 ? name.slice(dot) : ""
  const componentBudget = Math.min(MAX_COMPONENT_BYTES, MAX_PATH_BYTES - utf8Length(dir))
  let i = 1
  let candidate = ""
  do {
    candidate = `${dir}${fitComponent(stem, ` (${i})`, ext, componentBudget)}`
    i++
  } while (used.has(candidate))
  return candidate
}

const MAX_COMPONENT_BYTES = 255
const MAX_PATH_BYTES = 1024

function fitComponent(
  stem: string,
  suffix: string,
  extension: string,
  maxBytes: number
): string {
  const suffixBytes = utf8Length(suffix)
  const extensionBytes = utf8Length(extension)
  if (suffixBytes > maxBytes) {
    throw new Error("相对路径已达 1024 字节，无法为重名文件添加唯一后缀")
  }
  if (suffixBytes + extensionBytes <= maxBytes) {
    return `${utf8Prefix(stem, maxBytes - suffixBytes - extensionBytes)}${suffix}${extension}`
  }
  return `${utf8Prefix(stem + extension, maxBytes - suffixBytes)}${suffix}`
}

function utf8Length(value: string): number {
  return new TextEncoder().encode(value).byteLength
}

function utf8Prefix(value: string, maxBytes: number): string {
  if (maxBytes <= 0) return ""
  let usedBytes = 0
  let out = ""
  for (const codePoint of value) {
    const bytes = utf8Length(codePoint)
    if (usedBytes + bytes > maxBytes) break
    usedBytes += bytes
    out += codePoint
  }
  return out
}
