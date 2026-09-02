/**
 * QR decode worker — decodes QR codes from a captured video frame.
 *
 * Single backend: FAST — the self-compiled ZXing-C++ → WASM module
 * (`fastzxing/airferry_zxing.js`, built by scripts/build-fastzxing.sh with
 * Emscripten 3.1.64, -O3 + SIMD). It reads a raw Y (luminance) plane — no
 * RGBA conversion, ~4× less data across the postMessage boundary. The former
 * `zxing-wasm` compat fallback was removed (FAST-only policy): the build now
 * FAILS when the fast artifacts are missing instead of silently shipping a
 * slow path (see apps/web/scripts/prepare-wasm.cjs).
 *
 * ## Decode strategy (mirrors Android/Windows QrDecodePool)
 * - Hot path: per-code bbox tracking. After a full-frame lock, each frame
 *   decodes only the expanded windows around the last-known code positions
 *   (`airferry_wasm_decode_regions_y`) — O(Σ code pixels) instead of the
 *   full-frame finder scan.
 * - Cold path: full-frame multi decode on the first frame, every
 *   MULTI_FULL_DECODE_EVERY consecutive tracked misses, and periodically even
 *   while regions succeed so an initially partial lock can grow.
 * - A region miss falls through to a full-frame scan in the same frame, so a
 *   moved/blurred code re-locks immediately.
 *
 * Scratch buffers (Y-plane input copy, out-len word, hint array) are
 * persistent and grow-only — the previous malloc/copy/free per frame churned
 * ~2 MB blocks through the WASM allocator at camera rate.
 *
 * ## Protocol
 * - main → `{type:"init"}`: load the FAST module
 * - main → `{type:"decode", width, height, yPlane, format:"Y", jobId}`
 * - worker → `{type:"ready"}` / `{type:"decoded", payloads, jobId}` /
 *   `{type:"error", message}`
 *
 * One frame in flight per worker (the pool keeps N frames across cores).
 */

/// <reference lib="webworker" />

// @ts-expect-error generated emscripten ES6 module has no static d.ts
import loadAirferryZxing from "@/fastzxing/airferry_zxing.js"
import zxingWasmUrl from "@/fastzxing/airferry_zxing.wasm?url"
import { shrinkStreakAfterTrackedResult } from "@/lib/qr-tracking-policy"

interface FastZxingModule {
  _airferry_wasm_decode_multi_y(
    p: number,
    len: number,
    w: number,
    h: number,
    stride: number,
    outLen: number
  ): number
  // Additive export (feature-detected — absent in older cached builds).
  _airferry_wasm_decode_regions_y?(
    p: number,
    len: number,
    w: number,
    h: number,
    stride: number,
    hints: number,
    hintCount: number,
    margin: number,
    outLen: number
  ): number
  _airferry_wasm_free(p: number): void
  _airferry_wasm_abi_version(): number
  _malloc(n: number): number
  _free(p: number): void
  HEAPU8: Uint8Array
  HEAPU32: Uint32Array
  HEAP32: Int32Array
}

let fastMod: FastZxingModule | null = null

// ---------------------------------------------------------------------------
// Persistent WASM-heap scratch (init on first use, never freed)
// ---------------------------------------------------------------------------
/** Y-plane input buffer: grows to the largest frame seen, reused per frame. */
let srcPtr = 0
let srcCap = 0
/** `size_t out_len` write-back word. */
let lenPtr = 0
/** Packed s32×4×4 hint array for the tracked-region decode. */
let hintsPtr = 0
const MAX_TRACKED_CODES = 4

function ensureScratch(planeLen: number): boolean {
  if (!fastMod) return false
  if (lenPtr === 0) {
    lenPtr = fastMod._malloc(8)
    if (lenPtr === 0) return false
  }
  if (hintsPtr === 0) {
    hintsPtr = fastMod._malloc(MAX_TRACKED_CODES * 16)
    if (hintsPtr === 0) return false
  }
  if (planeLen > srcCap) {
    if (srcPtr !== 0) fastMod._free(srcPtr)
    srcPtr = fastMod._malloc(planeLen)
    if (srcPtr === 0) {
      srcCap = 0
      return false
    }
    srcCap = planeLen
  }
  return true
}

/** Load the self-compiled ZXing-C++ WASM (the only backend). */
async function loadFastBackend(): Promise<void> {
  if (fastMod) return
  const initFn = (loadAirferryZxing as unknown as { default?: (opts?: unknown) => Promise<unknown> })
    .default || (loadAirferryZxing as unknown as (opts?: unknown) => Promise<unknown>)
  const inst = await initFn({
    locateFile: (path: string) => (path.endsWith(".wasm") ? zxingWasmUrl : path),
  })
  const m = inst as FastZxingModule | null | undefined
  if (!m || m._airferry_wasm_abi_version() !== 1) {
    throw new Error("FAST ZXing ABI 版本不匹配（期望 1）")
  }
  fastMod = m
}

// ---------------------------------------------------------------------------
// Tracked-region state (per worker; screen codes barely move between frames,
// so each worker's own lock stays valid across the frames routed to it)
// ---------------------------------------------------------------------------
/** Packed 4×N bboxes {minX,minY,maxX,maxY} of the tracked codes. */
let trackedBboxes: Int32Array | null = null
/** Maximum slot count discovered by full-frame scans; grows, never shrinks. */
let lockedCount = 0
/** Consecutive tracked-region misses → periodic full-frame re-lock. */
let multiMiss = 0
const MULTI_FULL_DECODE_EVERY = 3
/** Successful region decodes must not suppress discovery forever when the
 * first full scan saw only a subset of the on-screen codes. */
const MULTI_PERIODIC_FULL_EVERY = 30
let multiFrames = 0
/** Consecutive PARTIAL hits (some tracked slots decoded, others missed) →
 * full-frame re-lock. Without this, a code that moved out of its tracking
 * window while the others keep decoding starves until the 30-frame periodic
 * scan — its symbol throughput collapses ~30×. The shrink logic retires
 * slots that stay gone, so the extra scans stop once the lock matches
 * reality. */
let partialMiss = 0
const PARTIAL_FULL_DECODE_EVERY = 5
const TRACK_MARGIN = 0.35
const TRACK_SHRINK_AFTER_FULL_SCANS = 3
let lowerFullCountStreak = 0

interface DecodedCode {
  payload: Uint8Array
  bbox: Int32Array
}

/**
 * Parse the packed multi-result wire layout:
 * [u32 count LE][u32 payload_len LE][payload][4×s32 bbox LE]...
 */
function parsePacked(packed: Uint8Array): DecodedCode[] {
  const out: DecodedCode[] = []
  if (packed.length < 4) return out
  const count =
    (packed[0] | (packed[1] << 8) | (packed[2] << 16) | (packed[3] << 24)) >>> 0
  // The native contract emits at most four records. Reject an impossible
  // count up front so a corrupted result cannot turn this into a very long
  // parser loop (or rely on signed u32 coercion to skip validation).
  if (count > MAX_TRACKED_CODES) return out
  let off = 4
  for (let i = 0; i < count; i++) {
    // A truncated record (length header or payload running past the packed
    // buffer) means a corrupt write from the native side — stop parsing
    // instead of emitting silently truncated payloads.
    if (off + 4 > packed.length) break
    const len =
      (packed[off] |
        (packed[1 + off] << 8) |
        (packed[2 + off] << 16) |
        (packed[3 + off] << 24)) >>>
      0
    off += 4
    // Subtraction avoids an overflowing/addition-wrapping style check if this
    // parser is ever ported to a fixed-width JS host or the ABI changes.
    if (len > packed.length - off - 16) break
    // AF2 wire frame minimum size is 30 B (Header 26 B + Frame CRC 4 B)
    if (
      len >= 30 &&
      packed[off] === 0x41 &&
      packed[off + 1] === 0x46 &&
      packed[off + 2] === 2 &&
      packed[off + 3] >= 1 &&
      packed[off + 3] <= 3 &&
      out.length < MAX_TRACKED_CODES
    ) {
      const bbox = new Int32Array(4)
      for (let k = 0; k < 4; k++) {
        const o = off + len + k * 4
        bbox[k] = packed[o] | (packed[o + 1] << 8) | (packed[o + 2] << 16) | (packed[o + 3] << 24)
      }
      out.push({ payload: packed.slice(off, off + len), bbox })
    }
    off += len + 16
  }
  return out
}

/** Read the malloc'd packed result at `outPtr` (freeing it), or []. */
function takePacked(outPtr: number): DecodedCode[] {
  if (!fastMod || outPtr === 0) return []
  try {
    const outLen = fastMod.HEAPU32[lenPtr >> 2]
    if (outLen <= 0 || outPtr + outLen > fastMod.HEAPU8.byteLength) {
      return []
    }
    const packed = fastMod.HEAPU8.subarray(outPtr, outPtr + outLen)
    return parsePacked(packed)
  } finally {
    // The native ABI currently never returns a non-null pointer with length
    // zero, but free defensively on every path so a future ABI regression
    // cannot leak one result allocation per camera frame.
    fastMod._airferry_wasm_free(outPtr)
  }
}

function seedTrackedSlots(results: DecodedCode[]): void {
  if (results.length === 0) return
  const packed = new Int32Array(results.length * 4)
  for (let i = 0; i < results.length; i++) results[i].bbox.forEach((v, k) => (packed[i * 4 + k] = v))
  trackedBboxes = packed
  lockedCount = results.length
  lowerFullCountStreak = 0
}

/** A full scan may itself be partial. Grow the lock when it discovers more
 * codes, but never shrink a previously-known slot set on a transient miss. */
function mergeFullTrackedSlots(results: DecodedCode[]): void {
  if (trackedBboxes === null || lockedCount === 0 || results.length > lockedCount) {
    seedTrackedSlots(results)
  } else {
    if (results.length < lockedCount) {
      lowerFullCountStreak++
      if (lowerFullCountStreak >= TRACK_SHRINK_AFTER_FULL_SCANS) {
        seedTrackedSlots(results)
        return
      }
    } else {
      lowerFullCountStreak = 0
    }
    updateTrackedSlots(results)
  }
}

/** Nearest-center slot update; unmatched slots keep their last bbox (a
 *  transient miss must not drop a code from the tracking list). */
function updateTrackedSlots(results: DecodedCode[]): void {
  const old = trackedBboxes
  if (!old || lockedCount === 0) return seedTrackedSlots(results)
  // A complete ROI hit proves all tracked codes are still present. Do not let
  // partial periodic full scans, separated by complete ROI hits, age a healthy
  // four-code lock down to fewer lanes.
  lowerFullCountStreak = shrinkStreakAfterTrackedResult(
    lowerFullCountStreak,
    results.length,
    lockedCount
  )
  const updated = old.slice()
  const claimed = new Array<boolean>(lockedCount).fill(false)
  for (const r of results) {
    const cx = (r.bbox[0] + r.bbox[2]) / 2
    const cy = (r.bbox[1] + r.bbox[3]) / 2
    let bestSlot = -1
    let bestDist = Number.MAX_SAFE_INTEGER
    for (let i = 0; i < lockedCount; i++) {
      if (claimed[i]) continue
      const dx = cx - (old[i * 4] + old[i * 4 + 2]) / 2
      const dy = cy - (old[i * 4 + 1] + old[i * 4 + 3]) / 2
      const d = dx * dx + dy * dy
      if (d < bestDist) {
        bestDist = d
        bestSlot = i
      }
    }
    if (bestSlot >= 0) {
      claimed[bestSlot] = true
      for (let k = 0; k < 4; k++) updated[bestSlot * 4 + k] = r.bbox[k]
    }
  }
  trackedBboxes = updated
}

/** Decode all QR codes in a Y (luminance) plane, tracked-regions first. */
function decodeFastY(
  yPlane: Uint8Array,
  w: number,
  h: number,
  rowStride: number
): Uint8Array[] {
  if (!fastMod || !ensureScratch(yPlane.length)) return []
  // Wrap the decode calls in try/finally only for the input copy state: the
  // scratch buffers are persistent, so a trap leaves them allocated and
  // reusable — nothing to release.
  fastMod.HEAPU8.set(yPlane, srcPtr)
  fastMod.HEAPU32[lenPtr >> 2] = 0
  fastMod.HEAPU32[(lenPtr >> 2) + 1] = 0

  const tracked = trackedBboxes
  multiFrames++
  const dueFullLock =
    tracked === null ||
    lockedCount === 0 ||
    multiFrames % MULTI_PERIODIC_FULL_EVERY === 0 ||
    (multiMiss > 0 && multiMiss % MULTI_FULL_DECODE_EVERY === 0) ||
    (partialMiss > 0 && partialMiss % PARTIAL_FULL_DECODE_EVERY === 0)
  const decodeRegions = fastMod._airferry_wasm_decode_regions_y

  if (!dueFullLock && tracked && lockedCount > 0 && decodeRegions) {
    const n = Math.min(lockedCount, MAX_TRACKED_CODES)
    fastMod.HEAP32.set(tracked.subarray(0, n * 4), hintsPtr >> 2)
    const outPtr = decodeRegions(
      srcPtr,
      yPlane.length,
      w,
      h,
      rowStride,
      hintsPtr,
      n,
      TRACK_MARGIN,
      lenPtr
    )
    const results = takePacked(outPtr)
    if (results.length > 0) {
      updateTrackedSlots(results)
      if (results.length < n) {
        partialMiss++
      } else {
        partialMiss = 0
      }
      multiMiss = 0
      return results.map((r) => r.payload)
    }
    multiMiss++
    // All-region miss → full-frame re-lock THIS frame (below).
  }

  const outPtr = fastMod._airferry_wasm_decode_multi_y(
    srcPtr,
    yPlane.length,
    w,
    h,
    rowStride,
    lenPtr
  )
  const results = takePacked(outPtr)
  if (results.length > 0) {
    mergeFullTrackedSlots(results)
    multiMiss = 0
  } else {
    multiMiss++
  }
  partialMiss = 0
  return results.map((r) => r.payload)
}

function resetTracker(): void {
  trackedBboxes = null
  lockedCount = 0
  multiMiss = 0
  multiFrames = 0
  partialMiss = 0
  lowerFullCountStreak = 0
}

function post(msg: unknown): void {
  ;(postMessage as (m: unknown) => void)(msg)
}

self.addEventListener("message", async (e: MessageEvent) => {
  const data = e.data
  if (!data || typeof data !== "object") return

  if (data.type === "init") {
    try {
      await loadFastBackend()
      resetTracker()
      post({ type: "ready" })
    } catch (err) {
      post({ type: "error", message: `解码器加载失败: ${String(err)}` })
    }
    return
  }

  if (data.type === "decode") {
    const { width, height, yPlane, jobId } = data as {
      width: number
      height: number
      yPlane?: Uint8Array
      jobId: number
    }
    // Always answer: the main thread marks this pool slot busy on dispatch,
    // and a silent return would leave it busy forever (pool shrinks to 0
    // with no error surfaced).
    if (!fastMod || !yPlane) {
      post({ type: "decoded", payloads: [], jobId })
      return
    }
    try {
      // Feed the raw Y (luminance) plane — no RGBA conversion.
      const payloads = decodeFastY(yPlane, width, height, width)
      post({ type: "decoded", payloads, jobId })
    } catch (err) {
      post({
        type: "error",
        message: `解码失败: ${String(err)}`,
        jobId,
      })
    }
    return
  }
})
