/**
 * Web Receiver History & Pending Transfer storage.
 *
 * Persists completed reception history and tracks in-flight/interrupted
 * AF2 transfers for resume visibility and OPFS cleanup.
 */

export interface ReceiveHistoryItem {
  id: string // transferIdHex
  title: string
  kind: "file" | "bundle" | "text"
  totalRawSize: number
  entryCount: number
  completedChunks: number
  totalChunks: number
  status: "completed" | "partial"
  timestamp: number
  textContent?: string
  /** The full received text remains on the result screen; history keeps only a
   * bounded preview so 100 records cannot exhaust localStorage. */
  textContentTruncated?: boolean
}

const STORAGE_KEY = "airferry_receive_history_v2"
const TRANSFER_ID_RE = /^[0-9a-f]{32}$/
const MAX_HISTORY_ITEMS = 100
const MAX_TITLE_CHARS = 4096
const MAX_PERSISTED_TEXT_CHARS = 16 * 1024

function boundedInteger(value: unknown, fallback: number, min: number, max: number): number {
  return typeof value === "number" && Number.isSafeInteger(value)
    ? Math.min(max, Math.max(min, value))
    : fallback
}

function normalizeHistoryItem(value: unknown): ReceiveHistoryItem | null {
  if (!value || typeof value !== "object") return null
  const item = value as Record<string, unknown>
  if (typeof item.id !== "string" || !TRANSFER_ID_RE.test(item.id)) return null
  if (item.kind !== "file" && item.kind !== "bundle" && item.kind !== "text") return null
  if (item.status !== "completed" && item.status !== "partial") return null
  const timestamp = boundedInteger(item.timestamp, 0, 0, Number.MAX_SAFE_INTEGER)
  if (timestamp <= 0) return null
  const title = typeof item.title === "string"
    ? item.title.slice(0, MAX_TITLE_CHARS)
    : ""
  const rawText = typeof item.textContent === "string" ? item.textContent : undefined
  const textContent = rawText?.slice(0, MAX_PERSISTED_TEXT_CHARS)
  return {
    id: item.id,
    title: title || `传输 ${item.id.slice(0, 8)}`,
    kind: item.kind,
    totalRawSize: boundedInteger(item.totalRawSize, 0, 0, Number.MAX_SAFE_INTEGER),
    entryCount: boundedInteger(item.entryCount, 1, 1, 1_000_000),
    completedChunks: boundedInteger(item.completedChunks, 0, 0, 131_072),
    totalChunks: boundedInteger(item.totalChunks, 1, 1, 131_072),
    status: item.status,
    timestamp,
    textContent,
    textContentTruncated:
      item.textContentTruncated === true ||
      (rawText !== undefined && rawText.length > MAX_PERSISTED_TEXT_CHARS),
  }
}

export function getReceiveHistory(): ReceiveHistoryItem[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return []
    const parsed = JSON.parse(raw)
    if (!Array.isArray(parsed)) return []
    const seen = new Set<string>()
    return parsed
      .map(normalizeHistoryItem)
      .filter((item): item is ReceiveHistoryItem => item !== null)
      .sort((a, b) => b.timestamp - a.timestamp)
      .filter((item) => !seen.has(item.id) && !!seen.add(item.id))
      .slice(0, MAX_HISTORY_ITEMS)
  } catch {
    return []
  }
}

function saveHistory(items: ReceiveHistoryItem[]): boolean {
  const capped = items.slice(0, MAX_HISTORY_ITEMS)
  // Quotas differ by browser. Prefer dropping the oldest metadata records to
  // silently leaving a completed transfer recorded as an in-flight partial.
  for (let count = capped.length; count >= 0; count--) {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(capped.slice(0, count)))
      return true
    } catch {
      // Retry with one fewer oldest record.
    }
  }
  return false
}

export function recordPartialTransfer(
  transferIdHex: string,
  title: string,
  totalRawSize: number,
  entryCount: number,
  completedChunks: number,
  totalChunks: number,
  kind: "file" | "bundle" | "text" = "file"
): void {
  if (!TRANSFER_ID_RE.test(transferIdHex)) return
  const list = getReceiveHistory().filter((it) => it.id !== transferIdHex)
  list.unshift({
    id: transferIdHex,
    title: (title || `传输 ${transferIdHex.slice(0, 8)}`).slice(0, MAX_TITLE_CHARS),
    kind,
    totalRawSize: boundedInteger(totalRawSize, 0, 0, Number.MAX_SAFE_INTEGER),
    entryCount: boundedInteger(entryCount, 1, 1, 1_000_000),
    completedChunks: boundedInteger(completedChunks, 0, 0, 131_072),
    totalChunks: boundedInteger(totalChunks, 1, 1, 131_072),
    status: "partial",
    timestamp: Date.now(),
  })
  saveHistory(list)
}

export function recordCompletedTransfer(
  transferIdHex: string,
  title: string,
  totalRawSize: number,
  entryCount: number,
  kind: "file" | "bundle" | "text",
  textContent?: string
): void {
  if (!TRANSFER_ID_RE.test(transferIdHex)) return
  const list = getReceiveHistory().filter((it) => it.id !== transferIdHex)
  const persistedText = typeof textContent === "string"
    ? textContent.slice(0, MAX_PERSISTED_TEXT_CHARS)
    : undefined
  list.unshift({
    id: transferIdHex,
    title: (title || (kind === "text" ? "文字消息" : `文件传输 ${transferIdHex.slice(0, 8)}`))
      .slice(0, MAX_TITLE_CHARS),
    kind,
    totalRawSize: boundedInteger(totalRawSize, 0, 0, Number.MAX_SAFE_INTEGER),
    entryCount: boundedInteger(entryCount, 1, 1, 1_000_000),
    completedChunks: 1,
    totalChunks: 1,
    status: "completed",
    timestamp: Date.now(),
    textContent: persistedText,
    textContentTruncated:
      typeof textContent === "string" && textContent.length > MAX_PERSISTED_TEXT_CHARS,
  })
  saveHistory(list)
}

function protectedIdSet(ids: readonly string[]): Set<string> {
  return new Set(ids.filter((id) => TRANSFER_ID_RE.test(id)))
}

async function cleanupTransferFiles(id: string): Promise<boolean> {
  if (typeof navigator === "undefined" || !navigator.storage?.getDirectory) return true
  try {
    const root = await navigator.storage.getDirectory()
    let success = true
    // Remove the ownership ledger first. A crash/failure after this point
    // leaves at worst an orphan partial that the bounded sweep can reclaim;
    // the opposite order leaves a valid journal pointing at vanished data.
    for (const name of [
      `af2-${id}.ledger.jsonl`,
      `af2-${id}.partial`,
      `af2-${id}.released`,
    ]) {
      try {
        await root.removeEntry(name)
      } catch (err) {
        if (!(err instanceof DOMException && err.name === "NotFoundError")) success = false
      }
    }
    return success
  } catch {
    return false
  }
}

export async function deleteHistoryItem(
  id: string,
  protectedIds: readonly string[] = [],
): Promise<boolean> {
  if (!TRANSFER_ID_RE.test(id) || protectedIdSet(protectedIds).has(id)) return false
  if (!(await cleanupTransferFiles(id))) return false
  const list = getReceiveHistory().filter((it) => it.id !== id)
  return saveHistory(list)
}

export async function clearAllReceiveHistory(
  protectedIds: readonly string[] = [],
): Promise<{ removed: number; failed: number }> {
  const items = getReceiveHistory()
  const protectedSet = protectedIdSet(protectedIds)
  const keep: ReceiveHistoryItem[] = []
  let removed = 0
  let failed = 0
  for (const item of items) {
    if (protectedSet.has(item.id)) {
      keep.push(item)
      continue
    }
    if (await cleanupTransferFiles(item.id)) {
      removed++
    } else {
      failed++
      keep.push(item)
    }
  }
  saveHistory(keep)
  return { removed, failed }
}
