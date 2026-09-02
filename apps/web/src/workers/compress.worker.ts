/**
 * AF2 streaming preparation worker.
 *
 * Single bounded-memory pass over the user's selection (§9.3): every chunk is
 * assembled once from `File.slice()` reads, hashed incrementally (per-entry +
 * per-chunk BLAKE3) and balanced-encoded in the same pass. Only metadata and
 * 32-byte digests leave this worker — the content bytes NEVER materialize on
 * the main thread. The retained item sources + chunk plan then serve
 * play-time `stage` requests: a chunk's raw bytes are re-assembled and
 * deterministically re-encoded on demand, keeping the WASM sender's content
 * memory at one chunk at a time.
 *
 * Memory profile (bounded-memory by design constants, NOT by transfer size):
 *   - one chunk's raw bytes + one encode in flight during the pass/stage;
 *   - ≤ ENCODING_CACHE_CAP compressed/mixed cache, with RAW retention capped
 *     separately at RAW_ENCODING_CACHE_CAP; a RAW hit skips the per-epoch disk
 *     read + BLAKE3 + codec probe without imposing a 256 MiB media-cache floor;
 *   - BLAKE3 hashers only for entries STRADDLING the current chunk boundary
 *     (each is digested + freed the moment its entry's last byte is fed);
 *   - per-transfer metadata (paths/sizes/32-byte digests, ≤ 4096 entries).
 *
 * Prepare jobs are serialized through `prepareChain`, and only the LATEST
 * received jobId may commit its staging state or post `done`/`error`: a
 * stale job finishing late (slow reads) must never overwrite the newer
 * job's `active` — that race used to brick staging with
 * "staging state unavailable" after rapid re-sends.
 */

/// <reference lib="webworker" />

import {
  normalizeSenderPath,
  senderPathForFile,
  uniqueSenderPath,
  type SenderFileItem,
} from "@/lib/sender-path"
import {
  consumeEncodedChunk,
  retainBytes,
  uniqueTransferBuffers,
} from "@/lib/transfer-ownership"
import { ensureWasm, Blake3Wasm, encode_chunk_balanced, plan_chunks } from "@/wasm/loader"
import { MAX_ORIGINAL_BYTES, MAX_ORIGINAL_MIB } from "@/types"

export const KIND_FILE = 1
export const KIND_UTF8_TEXT = 2
export const KIND_DIRECTORY = 3

/** Hard cap on cached chunk encodings. RAW chunks share the same budget:
 * media payloads are (almost) always RAW and used to be re-read + re-hashed +
 * re-probed from disk on EVERY epoch — the dominant stall of the streamed
 * pipeline. Bounded by the cap, NOT by transfer size. */
const ENCODING_CACHE_CAP = 256 * 1024 * 1024
/** Incompressible media used to retain no encoding cache at all. Keep the new
 * RAW fast path useful without adding a 256 MiB floor on low-memory browsers. */
const RAW_ENCODING_CACHE_CAP = 64 * 1024 * 1024

/** AF2 wire format: the Manifest carries at most 4096 entries. */
const MAX_ENTRIES = 4096

/** Max wait for the main thread's prepareContinue after the probe phase. */
const PROBE_TIMEOUT_MS = 5_000

export interface PreparedEntry {
  kind: number
  path: string
  size: number
  /** BLAKE3-256 of the entry content (32 bytes). */
  hash: Uint8Array
  /**
   * §9.3 resend-cache stamp for this item — the sender's local cache
   * invalidation key (SPEC §10.2: `(path, size, mtime)`; mtime is a LOCAL
   * cache key, never protocol identity). Files: `size:lastModified`.
   * Text items have no mtime, so their stamp is `t:size:fnv1a(content)`.
   */
  fingerprint: string
}

export interface EncodeParams {
  /** Playout payload rate in bytes/sec — feeds the balanced codec policy. */
  channelBps: number
  /** Single-chunk transfers always escalate to the high-ratio preset. */
  forceFull: boolean
}

/** One planned chunk: which item ranges assemble its raw bytes. */
interface PlannedChunk {
  segments: { item: number; start: number; len: number }[]
}

/** Byte source for one item: a lazily-sliced File or an in-memory text. */
type ItemSource = { file: File } | { bytes: Uint8Array }

/**
 * FNV-1a 32-bit — cheap content stamp for text items (the only input that can
 * change without changing size). Not a security primitive.
 */
function fnv1a32(bytes: Uint8Array): number {
  let h = 0x811c9dc5
  for (let i = 0; i < bytes.length; i++) {
    h ^= bytes[i]
    h = Math.imul(h, 0x01000193)
  }
  return h >>> 0
}

function post(msg: unknown, transfer: Transferable[] = []): void {
  ;(postMessage as (m: unknown, transfer?: Transferable[]) => void)(msg, transfer)
}

/** Retained state of the last COMMITTED prepare — serves stage requests. */
let active: {
  jobId: number
  sources: ItemSource[]
  chunks: PlannedChunk[]
  params: EncodeParams
  /** codec != RAW encodings, capped at ENCODING_CACHE_CAP (FIFO eviction). */
  encodings: Map<number, { codec: number; data: Uint8Array; rawHash: Uint8Array }>
  encodingsBytes: number
  rawEncodingsBytes: number
} | null = null

/** Latest prepare jobId RECEIVED (set synchronously, in receipt order). */
let latestPrepareJob: number | null = null

/**
 * Pending probe continuation: the cheap metadata-only probe phase handed
 * control to the main thread (§9.3 resend-cache lookup) and is waiting for
 * `prepareContinue` — `true` skips the whole read/hash/encode pass.
 */
let pendingContinue: { jobId: number; resolve: (useCache: boolean) => void } | null = null

/** Serializes prepare passes: one disk-hashing walk at a time. */
let prepareChain: Promise<void> = Promise.resolve()

async function readSourceRange(src: ItemSource, start: number, len: number): Promise<Uint8Array> {
  if ("file" in src) {
    const buf = await src.file.slice(start, start + len).arrayBuffer()
    if (buf.byteLength !== len) {
      throw new Error(
        `文件读取截断: 期望 ${len} 字节，实际读取 ${buf.byteLength} 字节（文件可能已被修改）`
      )
    }
    return new Uint8Array(buf)
  }
  return src.bytes.subarray(start, start + len)
}

/**
 * Assemble one chunk's raw bytes from its planned item ranges. `hashInto`
 * (stage path) is fed the same bytes incrementally — the RAW staging digest
 * comes out nearly free, keeping the BLAKE3 of an 8 MiB chunk on THIS thread
 * instead of the render thread.
 */
async function assembleChunk(
  a: NonNullable<typeof active>,
  index: number,
  hashInto?: Blake3Wasm
): Promise<Uint8Array> {
  const planned = a.chunks[index]
  const total = planned.segments.reduce((s, g) => s + g.len, 0)
  const out = new Uint8Array(total)
  let pos = 0
  for (const seg of planned.segments) {
    const part = await readSourceRange(a.sources[seg.item], seg.start, seg.len)
    out.set(part, pos)
    hashInto?.update(part)
    pos += seg.len
  }
  return out
}

/** Deterministic balanced encode (same inputs ⇒ same bytes, both at prepare
 * and at every later re-stage — the chunk's encoded_hash depends on it). */
function encodeChunk(
  a: NonNullable<typeof active>,
  raw: Uint8Array
): { codec: number; data: Uint8Array } {
  const enc = encode_chunk_balanced(
    raw,
    BigInt(Math.max(0, Math.round(a.params.channelBps))),
    a.params.forceFull
  )
  // into_data() consumes and destroys the wasm-bindgen handle. Never call
  // free() afterwards: the generated wrapper has already zeroed its pointer.
  const { codec, data } = consumeEncodedChunk(enc)
  if (codec !== 0 && data.length > 0 && data.length < raw.length) {
    return { codec, data }
  }
  // RAW marker (compression cannot win): stage as RAW with the raw bytes.
  return { codec: 0, data: new Uint8Array(0) }
}

function cacheEncoding(
  a: NonNullable<typeof active>,
  index: number,
  codec: number,
  data: Uint8Array,
  rawHash: Uint8Array
): void {
  // A duplicate/concurrent stage for the same index replaces the entry. Take
  // the old accounting out first; otherwise repeated overwrites inflate the
  // byte counters and evict unrelated hot chunks prematurely.
  const previous = a.encodings.get(index)
  if (previous) {
    a.encodings.delete(index)
    a.encodingsBytes -= previous.data.byteLength
    if (previous.codec === 0) a.rawEncodingsBytes -= previous.data.byteLength
  }
  while (
    (a.encodingsBytes + data.byteLength > ENCODING_CACHE_CAP ||
      (codec === 0 && a.rawEncodingsBytes + data.byteLength > RAW_ENCODING_CACHE_CAP)) &&
    a.encodings.size > 0
  ) {
    const oldest = a.encodings.keys().next().value as number
    const evict = a.encodings.get(oldest)
    a.encodings.delete(oldest)
    if (evict) {
      a.encodingsBytes -= evict.data.byteLength
      if (evict.codec === 0) a.rawEncodingsBytes -= evict.data.byteLength
    }
  }
  // `chunkHashes` are transferred to the main thread when prepare completes.
  // Retain an independent 32-byte buffer for later stage requests.
  a.encodings.set(index, { codec, data, rawHash: retainBytes(rawHash) })
  a.encodingsBytes += data.byteLength
  if (codec === 0) a.rawEncodingsBytes += data.byteLength
}

/**
 * Stage-reply helper: caches the (data, rawHash) pair and posts the `staged`
 * message. The posted buffers are fresh `.slice()` copies TRANSFERRED to the
 * main thread — without the transfer list the structured clone would copy
 * them again on the receiving end, and posting the cached originals would
 * detach the cache's own storage.
 */
function postStaged(
  a: NonNullable<typeof active>,
  jobId: number,
  index: number,
  codec: number,
  data: Uint8Array,
  rawHash: Uint8Array
): void {
  cacheEncoding(a, index, codec, data, rawHash)
  const dataOut = data.slice()
  const hashOut = rawHash.slice()
  post(
    { type: "staged", jobId, index, codec, data: dataOut, rawHash: hashOut },
    [dataOut.buffer as ArrayBuffer, hashOut.buffer as ArrayBuffer]
  )
}

async function runPrepare(
  jobId: number,
  files: SenderFileItem[] | undefined,
  text: string | undefined,
  name: string | undefined,
  params: EncodeParams
): Promise<void> {
  // Everything allocated here dies with this function unless the job is
  // still the latest one at commit time. `entryHashers` holds ONLY the
  // entries whose byte range the canonical walk has entered but not yet
  // completed — a hasher is digested and freed the moment its entry's last
  // byte is fed (see the early-finalize pass in the chunk loop), so peak
  // hasher count tracks entries straddling chunk boundaries, not the total
  // entry count. Directories never appear in segments; the protocol defines
  // their content hash as H(empty), computed once.
  let entryHashers: (Blake3Wasm | null)[] = []
  const freeLiveHashers = (): void => {
    for (let k = 0; k < entryHashers.length; k++) {
      const h = entryHashers[k]
      if (h) {
        try {
          h.free()
        } catch {
          /* already freed */
        }
        entryHashers[k] = null
      }
    }
  }
  try {
    await ensureWasm()
    if (latestPrepareJob !== jobId) return

    const sources: ItemSource[] = []
    const metas: { kind: number; path: string; size: number; fingerprint: string }[] = []
    let displayName = "传输内容"

    if (typeof text === "string") {
      // NFC-normalize: the AF2 manifest validates paths as Unicode NFC and
      // rejects combining marks (macOS delivers NFD filenames by default).
      const cleanName = normalizeSenderPath(name?.trim() || "文字消息.txt")
      displayName = cleanName
      const encoded = new TextEncoder().encode(text)
      if (encoded.byteLength > MAX_ORIGINAL_BYTES) {
        throw new Error(`文字内容超过当前网页发送端 ${MAX_ORIGINAL_MIB} MiB 宿主上限`)
      }
      sources.push({ bytes: encoded })
      metas.push({
        kind: KIND_UTF8_TEXT,
        path: cleanName,
        size: encoded.byteLength,
        fingerprint: `t:${encoded.byteLength}:${fnv1a32(encoded)}`,
      })
    } else if (Array.isArray(files) && files.length > 0) {
      const first = files[0].file
      displayName = first.name
      if (files.length > 1) {
        displayName = `${first.name} 等 ${files.length} 个文件`
      }
      const usedPaths = new Set<string>()
      for (const item of files) {
        const file = item.file
        if (file.size > MAX_ORIGINAL_BYTES) {
          throw new Error(
            `所选内容超过当前网页发送端 ${MAX_ORIGINAL_MIB} MiB 宿主上限: ${file.name}`
          )
        }
        // Directory hierarchy arrives in item.path: a webkitRelativePath
        // own-property override on the File does not survive the structured
        // clone into this worker (the clone re-serializes the browser-native
        // field, which is empty for picked/walked files).
        const filePath = uniqueSenderPath(usedPaths, senderPathForFile(file, item.path))
        usedPaths.add(filePath)
        sources.push({ file })
        metas.push({
          kind: KIND_FILE,
          path: filePath,
          size: file.size,
          fingerprint: `${file.size}:${file.lastModified}`,
        })
      }
    }

    // Structural gates BEFORE building any plan: an over-host-cap or >4096-entry
    // selection must fail here, not after materializing a huge chunk layout
    // (or worse, mid-pass).
    if (metas.length > MAX_ENTRIES) {
      throw new Error(`条目数 ${metas.length} 超过 AF2 协议上限 ${MAX_ENTRIES}（文件/文件夹数过多）`)
    }
    const totalBytes = metas.reduce((s, m) => s + m.size, 0)
    if (totalBytes > MAX_ORIGINAL_BYTES) {
      throw new Error(`所选内容超过当前网页发送端 ${MAX_ORIGINAL_MIB} MiB 宿主上限`)
    }
    if (totalBytes === 0) {
      // AF2 cannot encode a zero-byte canonical stream (receiver OTI gate
      // rejects F=0). Fail with a user-readable message instead of the
      // internal plan_chunks error after this gate.
      throw new Error("所选内容全部为 0 字节（空文件/空文本），没有可传输的数据")
    }

    // Canonical chunk layout (NFC-path sorted inside plan_chunks — the same
    // order the manifest assembles the stream with).
    const plan = JSON.parse(
      plan_chunks(
        new Uint8Array(metas.map((m) => m.kind)),
        metas.map((m) => m.path),
        new Float64Array(metas.map((m) => m.size)),
        8 * 1024 * 1024
      )
    ) as { chunks: number[][] }
    const chunks: PlannedChunk[] = plan.chunks.map((flat) => {
      const segments: { item: number; start: number; len: number }[] = []
      for (let i = 0; i < flat.length; i += 3) {
        segments.push({ item: flat[i], start: flat[i + 1], len: flat[i + 2] })
      }
      return { segments }
    })

    const chunkRawSize = 8 * 1024 * 1024

    // §9.3 resend-cache fast path: hand the metadata-only result to the main
    // thread BEFORE any disk read. On a cache hit the whole read/hash/encode
    // pass is skipped (resending a 100 GB selection costs O(metadata), not
    // O(content)); staging then re-reads chunks on demand exactly like a
    // cache-miss playback. A missing reply falls through to the full pass
    // after PROBE_TIMEOUT_MS.
    const staged: NonNullable<typeof active> = {
      jobId,
      sources,
      chunks,
      params,
      encodings: new Map(),
      encodingsBytes: 0,
      rawEncodingsBytes: 0,
    }
    const probeEntries: PreparedEntry[] = metas.map((m) => ({
      kind: m.kind,
      path: m.path,
      size: m.size,
      // Hashes are unknown at probe time (empty placeholders); the cache-hit
      // payload never uses them.
      hash: new Uint8Array(0),
      fingerprint: m.fingerprint,
    }))
    post({
      phase: "probe",
      jobId,
      entries: probeEntries,
      chunkCount: chunks.length,
      totalBytes,
      displayName,
    })
    const useCache = await new Promise<boolean>((resolve) => {
      let settled = false
      pendingContinue = {
        jobId,
        resolve: (v: boolean) => {
          if (settled) return
          settled = true
          resolve(v)
        },
      }
      setTimeout(() => {
        if (pendingContinue?.jobId === jobId) {
          pendingContinue = null
          settled = true
          resolve(false)
        }
      }, PROBE_TIMEOUT_MS)
    })
    if (latestPrepareJob !== jobId) return
    if (useCache) {
      active = staged
      post({
        phase: "done",
        jobId,
        streamed: true,
        cached: true,
        entries: probeEntries,
        chunkHashes: [],
        chunkCount: chunks.length,
        chunkRawSize,
        totalBytes,
        displayName,
      })
      return
    }

    // §9.3 single pass: per-chunk hashing + balanced encoding, one chunk's
    // bytes live at a time. Entry hashers are finalized (digest + free) as
    // soon as the canonical walk feeds their entry's last byte.
    const emptyHasher = new Blake3Wasm()
    const EMPTY_HASH = new Uint8Array(emptyHasher.digest())
    emptyHasher.free()
    // plan_chunks emits no segment for a zero-byte entry, so its digest can
    // never arrive through the canonical walk below — seed it up front with
    // H(empty) (exactly what the core assigns to a size-0 entry) or the pass
    // would end with "entry hash missing" after reading every other file.
    const entryDigests: (Uint8Array | null)[] = metas.map((m) =>
      // Each transferable empty entry needs its own backing buffer. Reusing
      // EMPTY_HASH would put one ArrayBuffer into the transfer list repeatedly.
      m.kind === KIND_DIRECTORY || m.size === 0 ? retainBytes(EMPTY_HASH) : null
    )
    entryHashers = metas.map((m) =>
      m.kind === KIND_DIRECTORY || m.size === 0 ? null : new Blake3Wasm()
    )
    const hashedLen: number[] = metas.map(() => 0)
    const chunkHashes: Uint8Array[] = []
    for (let i = 0; i < chunks.length; i++) {
      // A newer prepare was received while this pass was reading disk —
      // abort early instead of wasting IO and then racing the commit (the
      // finally clause releases any still-live hashers).
      if (latestPrepareJob !== jobId) {
        return
      }
      const raw = await assembleChunk(staged, i)
      // Feed the entry hashers the same bytes in stream order. A chunk's
      // segments are already stream-ordered (plan_chunks emits them in
      // canonical order), so hashing each segment into its item's hasher
      // reproduces exactly one full pass per entry.
      const chunkHasher = new Blake3Wasm()
      try {
        let pos = 0
        for (const seg of chunks[i].segments) {
          const slice = raw.subarray(pos, pos + seg.len)
          chunkHasher.update(slice)
          entryHashers[seg.item]?.update(slice)
          hashedLen[seg.item] += seg.len
          pos += seg.len
        }
        chunkHashes.push(new Uint8Array(chunkHasher.digest()))
      } finally {
        chunkHasher.free()
      }
      // Early finalize: an entry fully covered by the walk so far is done —
      // digest and free NOW instead of holding one hasher per entry until
      // the end of the pass (matters at the 4096-entry ceiling).
      for (const seg of chunks[i].segments) {
        const it = seg.item
        const h = entryHashers[it]
        if (h && hashedLen[it] === metas[it].size) {
          entryDigests[it] = new Uint8Array(h.digest())
          h.free()
          entryHashers[it] = null
        }
      }
      const { codec, data: encoded } = encodeChunk(staged, raw)
      // Cache every verdict (RAW included): play-time re-stages then hit the
      // cache instead of re-reading + re-hashing + re-probing each epoch.
      cacheEncoding(staged, i, codec, codec !== 0 ? encoded : raw, chunkHashes[i])
      if ((i + 1) % 8 === 0 || i === chunks.length - 1) {
        post({ phase: "progress", jobId, done: i + 1, total: chunks.length })
      }
    }

    // The last chunk completes every remaining entry by construction.
    const entries: PreparedEntry[] = metas.map((m, i) => {
      const dg = entryDigests[i]
      if (!dg) throw new Error(`internal: entry hash missing for ${m.path}`)
      return {
        kind: m.kind,
        path: m.path,
        size: m.size,
        hash: dg,
        fingerprint: m.fingerprint,
      }
    })
    freeLiveHashers()
    entryHashers = []

    // Latest-wins commit: a job superseded while reading must not overwrite
    // the newer job's staging state (rapid re-send race).
    if (latestPrepareJob !== jobId) return
    active = staged
    const hashTransfers = uniqueTransferBuffers([
      ...chunkHashes,
      ...entries.map((en) => en.hash),
    ])
    post(
      {
        phase: "done",
        jobId,
        streamed: true,
        entries,
        chunkHashes,
        chunkCount: chunks.length,
        chunkRawSize,
        totalBytes,
        displayName,
      },
      hashTransfers
    )
  } catch (err: unknown) {
    if (latestPrepareJob === jobId) {
      active = null
      post({
        phase: "error",
        message: err instanceof Error ? err.message : String(err),
        jobId,
      })
    }
  } finally {
    freeLiveHashers()
  }
}

self.addEventListener("message", (e: MessageEvent) => {
  const data = e.data
  if (!data || typeof data !== "object") return

  if (data.type === "wasm-init") {
    post({ phase: "ready" })
    return
  }

  if (data.type === "prepareContinue") {
    const { jobId, useCache } = data as { jobId: number; useCache: boolean }
    if (pendingContinue?.jobId === jobId) {
      const resolve = pendingContinue.resolve
      pendingContinue = null
      resolve(!!useCache)
    }
    return
  }

  if (data.type === "stage") {
    const { jobId, index } = data as { jobId: number; index: number }
    const a = active
    if (!a || a.jobId !== jobId || index < 0 || index >= a.chunks.length) {
      post({ type: "stageError", jobId, index, message: "staging state unavailable" })
      return
    }
    void (async () => {
      try {
        const cached = a.encodings.get(index)
        if (cached) {
          // cacheEncoding replaces + re-inserts at the back (Map insertion
          // order), so this also performs the LRU touch in one place.
          postStaged(a, jobId, index, cached.codec, cached.data, cached.rawHash)
          return
        }
        const hasher = new Blake3Wasm()
        try {
          const raw = await assembleChunk(a, index, hasher)
          const rawDigest = new Uint8Array(hasher.digest())
          const { codec, data: encoded } = encodeChunk(a, raw)
          postStaged(a, jobId, index, codec, codec !== 0 ? encoded : raw, rawDigest)
        } finally {
          hasher.free()
        }
      } catch (err: unknown) {
        post({
          type: "stageError",
          jobId,
          index,
          message: err instanceof Error ? err.message : String(err),
        })
      }
    })()
    return
  }

  const { jobId, files, text, name, encodeParams } = data as {
    jobId: number
    files?: SenderFileItem[]
    text?: string
    name?: string
    encodeParams?: EncodeParams
  }
  const requestedBps = Number(encodeParams?.channelBps ?? 0)
  const params: EncodeParams = {
    channelBps: Number.isFinite(requestedBps)
      ? Math.min(Number.MAX_SAFE_INTEGER, Math.max(0, Math.round(requestedBps)))
      : 0,
    forceFull: encodeParams?.forceFull === true,
  }

  // Respond immediately so the UI flips to "reading" without waiting behind
  // a still-running older pass; the pass itself is serialized.
  post({ phase: "reading", jobId })
  latestPrepareJob = jobId
  if (pendingContinue && pendingContinue.jobId !== jobId) {
    const resolve = pendingContinue.resolve
    pendingContinue = null
    resolve(false)
  }
  prepareChain = prepareChain.then(() =>
    runPrepare(jobId, files, text, name, params)
  )
})
