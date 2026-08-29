/**
 * AirFerry options / sender page (AF2 protocol).
 *
 * Route: select (with settings modal/page) → play → stats.
 */
import { useCallback, useEffect, useRef, useState } from "react"
import {
  type CompressPhase,
  type Page,
  type PendingItem,
  type TransferConfig,
  loadConfig,
  saveConfig,
} from "@/types"
import { FileSelectPage } from "@/pages/FileSelectPage"
import { SettingsPage } from "@/pages/SettingsPage"
import { PlayPage } from "@/pages/PlayPage"
import { StatsPage } from "@/pages/StatsPage"
import {
  ensureWasm,
  SenderBuilderWasm,
  type SenderSessionWasm,
} from "@/wasm/loader"
import {
  deleteCachedManifest,
  getCachedManifest,
  putCachedManifest,
} from "@/lib/sender-cache"
import { createChunkStager, type ChunkStager } from "@/lib/chunk-stager"
import { SettingsIcon } from "@/components/icons"
import type { PreparedEntry } from "@/workers/compress.worker"
import { senderPathForFile, type SenderFileItem } from "@/lib/sender-path"
import "@/assets/app.css"

const iconUrl = new URL("../assets/icon.png", import.meta.url).href

function createCompressWorker(): Worker {
  if (typeof globalThis !== "undefined" && (globalThis as any).__WORKER_CODE__) {
    const blob = new Blob([(globalThis as any).__WORKER_CODE__], { type: "application/javascript" })
    const url = URL.createObjectURL(blob)
    return new Worker(url)
  }
  return new Worker(new URL("./workers/compress.worker.ts", import.meta.url), {
    type: "module",
  })
}

async function initializeCompressWorker(worker: Worker): Promise<void> {
  worker.postMessage({ type: "wasm-init" })
}

function itemsToFiles(items: PendingItem[]): SenderFileItem[] {
  return items.map((it): SenderFileItem => {
    if (it.kind === "file") {
      return { file: it.file, path: it.path ?? senderPathForFile(it.file) }
    }
    const name = it.name?.trim() ? it.name.trim() : "文字消息.txt"
    const finalName = name.toLowerCase().endsWith(".txt") ? name : `${name}.txt`
    return {
      file: new File([it.content], finalName, {
        type: "text/plain;charset=utf-8",
        lastModified: Date.now(),
      }),
      path: finalName,
    }
  })
}

/**
 * Streamed preparation payload: hash-only entry metadata + the chunk hash
 * table. Content bytes never cross this boundary — they stream into the WASM
 * sender chunk-by-chunk at play time via `stage_chunk` (bounded memory for
 * arbitrarily large transfers).
 */
interface PreparedPayload {
  entries: PreparedEntry[]
  chunkHashes: Uint8Array[]
  chunkCount: number
  totalBytes: number
  displayName: string
  /** §9.3 cache hit: the worker skipped the whole read/hash/encode pass. */
  cachedManifestHex?: string
}

export interface AppState {
  page: Page
  /** Page the settings screen was opened from; closing settings returns here. */
  settingsFrom: Page | null
  items: PendingItem[]
  prepared: PreparedPayload | null
  session: SenderSessionWasm | null
  stager: ChunkStager | null
  config: TransferConfig
  initializing: boolean
  compressPhase: CompressPhase | null
  error: string | null
}

const freedSessions = new WeakSet<SenderSessionWasm>()
function freeSenderSession(session: SenderSessionWasm | null | undefined): void {
  if (!session || freedSessions.has(session)) return
  freedSessions.add(session)
  try {
    session.free()
  } catch (_) {
    // Ignore double-free errors
  }
}

export default function App() {
  useEffect(() => {
    document.title = "AirFerry · 无网文件传输"
  }, [])

  const [state, setState] = useState<AppState>({
    page: "select",
    settingsFrom: null,
    items: [],
    prepared: null,
    session: null,
    stager: null,
    config: loadConfig(),
    initializing: false,
    compressPhase: null,
    error: null,
  })

  const epoch = useRef(0)
  const issuedEpoch = useRef(-1)
  const workerRef = useRef<Worker | null>(null)
  const restartWorkerRef = useRef<() => void>(() => undefined)
  const mountedRef = useRef(true)
  const ownedSessionRef = useRef<SenderSessionWasm | null>(null)
  const ownedStagerRef = useRef<ChunkStager | null>(null)
  /** Latest probe-phase cache lookup, keyed by prepare jobId. */
  const cachedManifestRef = useRef<{ jobId: number; hex: string } | null>(null)
  /** One-shot cache bypass used when a cached manifest fails to build. */
  const forceCacheMissJobRef = useRef<number | null>(null)
  // Latest session builder. The worker "done" handler lives in a mount-time
  // effect closure, so it must call through this ref to see fresh config.
  const startPlaybackRef = useRef<(p: PreparedPayload, startEpoch: number) => Promise<void>>(
    async () => undefined
  )

  const releaseOwnedSession = useCallback(() => {
    const s = ownedSessionRef.current
    if (s) {
      ownedSessionRef.current = null
      freeSenderSession(s)
    }
    const st = ownedStagerRef.current
    if (st) {
      ownedStagerRef.current = null
      st.dispose()
    }
  }, [])

  // The worker-error handler lives in a mount-time effect closure (empty
  // deps), so it must call through this ref to release a live playback
  // session instead of capturing the callback.
  const releaseOwnedSessionRef = useRef(releaseOwnedSession)
  releaseOwnedSessionRef.current = releaseOwnedSession

  useEffect(() => {
    mountedRef.current = true
    return () => {
      mountedRef.current = false
      releaseOwnedSession()
    }
  }, [releaseOwnedSession])

  useEffect(() => {
    if (typeof window === "undefined") return
    let worker: Worker | null = null
    let disposed = false
    const handler = (e: MessageEvent) => {
      const msg = e.data
      if (!msg || typeof msg.phase !== "string") return
      if (typeof msg.jobId === "number") {
        if (msg.jobId !== epoch.current || issuedEpoch.current !== epoch.current) return
      } else if (issuedEpoch.current !== epoch.current) {
        return
      }

      if (msg.phase === "error") {
        issuedEpoch.current = -1
        setState((s) => ({
          ...s,
          compressPhase: null,
          error: msg.message || "文件准备失败",
        }))
        return
      }

      if (msg.phase === "reading") {
        setState((s) => ({
          ...s,
          compressPhase: "reading",
          error: null,
        }))
        return
      }

      if (msg.phase === "probe") {
        // Metadata-only probe finished (no disk reads yet): decide whether
        // the §9.3 resend cache can skip the whole content pass.
        const worker = workerRef.current
        if (!worker) return
        const jobId = msg.jobId as number
        const probeEntries = msg.entries as PreparedEntry[]
        if (forceCacheMissJobRef.current === jobId) {
          forceCacheMissJobRef.current = null
          cachedManifestRef.current = null
          worker.postMessage({ type: "prepareContinue", jobId, useCache: false })
          return
        }
        void (async () => {
          let useCache = false
          let hit: { jobId: number; hex: string } | null = null
          try {
            const cached = await getCachedManifest(probeEntries, 8 * 1024 * 1024)
            if (cached && cached.chunkRawSize === 8 * 1024 * 1024) {
              hit = { jobId, hex: cached.manifestHex }
              useCache = true
            }
          } catch {
            /* cache is advisory */
          }
          cachedManifestRef.current = hit
          worker.postMessage({ type: "prepareContinue", jobId, useCache })
        })()
        return
      }

      if (msg.phase === "progress") {
        // Streaming prepare pass: per-chunk progress (large transfers can take
        // a while at disk-read speed); reuse the "reading" phase for the UI.
        return
      }

      if (msg.phase === "done") {
        issuedEpoch.current = -1
        const cacheRef = cachedManifestRef.current
        const cacheHit =
          msg.cached === true && cacheRef != null && cacheRef.jobId === msg.jobId
            ? cacheRef.hex
            : undefined
        const payload: PreparedPayload = {
          entries: msg.entries as PreparedEntry[],
          chunkHashes: msg.chunkHashes as Uint8Array[],
          chunkCount: Number(msg.chunkCount) || 0,
          totalBytes: msg.totalBytes as number,
          displayName: msg.displayName as string,
          cachedManifestHex: cacheHit,
        }
        setState((s) => ({
          ...s,
          prepared: payload,
          compressPhase: null,
          error: null,
        }))
        // Files are ready — build the encoder session and jump straight to the
        // QR play page (no intermediate params step in the main flow).
        void startPlaybackRef.current(payload, epoch.current)
      }
    }

    const failWorker = (message: string) => {
      if (disposed) return
      // A crashed worker orphans any LIVE streamed playback: the stager keeps
      // posting stage requests into a terminated worker and the render loop
      // spins on AF2_CHUNK_NOT_STAGED forever — a frozen QR stream the
      // receiver can never complete, with no send-side error surfaced. Tear
      // the session down with an actionable message; the restart below
      // re-arms the worker for the next prepare pass.
      if (ownedSessionRef.current != null) {
        releaseOwnedSessionRef.current()
        setState((s) => ({
          ...s,
          session: null,
          stager: null,
          page: "select",
          compressPhase: null,
          error: `文件处理线程崩溃，播放已停止: ${message}。请重新发送。`,
        }))
      } else {
        setState((s) => ({
          ...s,
          compressPhase: null,
          error: `文件处理线程错误: ${message}，正在重启…`,
        }))
      }
      startWorker()
    }

    const errorHandler = (e: ErrorEvent) => {
      e.preventDefault()
      failWorker(e.message || "worker crashed")
    }
    const messageErrorHandler = () => failWorker("无法解析 worker 消息")
    const startWorker = () => {
      worker?.removeEventListener("message", handler)
      worker?.removeEventListener("error", errorHandler)
      worker?.removeEventListener("messageerror", messageErrorHandler)
      worker?.terminate()
      try {
        worker = createCompressWorker()
        workerRef.current = worker
        worker.addEventListener("message", handler)
        worker.addEventListener("error", errorHandler)
        worker.addEventListener("messageerror", messageErrorHandler)
        void initializeCompressWorker(worker).catch((e) =>
          failWorker(e instanceof Error ? e.message : String(e))
        )
      } catch (e) {
        worker = null
        workerRef.current = null
        setState((s) => ({
          ...s,
          compressPhase: null,
          error: `无法启动文件处理线程: ${e instanceof Error ? e.message : String(e)}`,
        }))
      }
    }
    restartWorkerRef.current = startWorker
    startWorker()
    return () => {
      disposed = true
      restartWorkerRef.current = () => undefined
      worker?.terminate()
      workerRef.current = null
    }
  }, [])

  const onItemsChange = useCallback((items: PendingItem[]) => {
    releaseOwnedSession()
    epoch.current += 1
    forceCacheMissJobRef.current = null
    cachedManifestRef.current = null
    if (issuedEpoch.current >= 0) restartWorkerRef.current()
    issuedEpoch.current = -1
    setState((s) => ({
      ...s,
      items,
      prepared: null,
      session: null,
      stager: null,
      compressPhase: null,
      error: null,
    }))
  }, [releaseOwnedSession])

  const startPlaybackWithPayload = useCallback(async (p: PreparedPayload, startEpoch: number) => {
    const cfg = state.config
    const chunkRawSize = 8 * 1024 * 1024
    const retryPrepareWithoutCache = (): boolean => {
      const worker = workerRef.current
      const items = state.items
      if (!worker || items.length === 0) return false
      epoch.current += 1
      const retryEpoch = epoch.current
      issuedEpoch.current = retryEpoch
      forceCacheMissJobRef.current = retryEpoch
      cachedManifestRef.current = null
      releaseOwnedSession()
      setState((s) => ({
        ...s,
        prepared: null,
        session: null,
        stager: null,
        page: "select",
        initializing: false,
        compressPhase: "reading",
        error: null,
      }))
      const channelBps = Math.round(
        cfg.symbolSize * (cfg.fps || 60) * Math.max(1, cfg.multiQr || 1)
      )
      const forceFull = items.reduce(
        (sum, it) =>
          sum +
          (it.kind === "file"
            ? it.file.size
            : new TextEncoder().encode(it.content).length),
        0
      ) <= chunkRawSize
      const encodeParams = { channelBps, forceFull }
      if (items.length === 1 && items[0].kind === "text") {
        worker.postMessage({
          jobId: retryEpoch,
          text: items[0].content,
          name: items[0].name,
          encodeParams,
        })
      } else {
        worker.postMessage({
          jobId: retryEpoch,
          files: itemsToFiles(items),
          encodeParams,
        })
      }
      return true
    }
    setState((s) => ({ ...s, initializing: true, error: null }))
    try {
      await ensureWasm()
      if (!mountedRef.current || epoch.current !== startEpoch) {
        if (mountedRef.current) {
          setState((s) => ({ ...s, initializing: false }))
        }
        return
      }
      // Streamed build: only kind/path/size + BLAKE3 digests cross into the
      // core — the canonical stream never materializes (bounded memory).
      // Content reaches the sender per chunk at play time via stage_chunk.
      const buildFromMeta = () => {
        const builder = new SenderBuilderWasm()
        for (const en of p.entries) {
          builder.add_meta(en.kind, en.path, en.size, en.hash)
        }
        for (const h of p.chunkHashes) {
          builder.add_chunk_hash(h)
        }
        return builder
      }
      const buildFromCachedMeta = () => {
        const builder = new SenderBuilderWasm()
        for (const en of p.entries) {
          builder.add_cached_meta(en.kind, en.path, en.size)
        }
        return builder
      }
      let session: SenderSessionWasm | null = null
      if (p.cachedManifestHex) {
        // Probe-phase cache hit: the worker already skipped the content
        // pass. If the cached manifest itself is unusable, retry the prepare
        // once with cache bypass rather than attempting to build from the
        // probe's intentionally-empty hash placeholders.
        try {
          session = buildFromCachedMeta().build_streamed_cached(
            p.cachedManifestHex,
            cfg.symbolSize,
            chunkRawSize,
            cfg.redundancyPct
          )
        } catch (e) {
          console.warn("cached manifest unusable, retrying full prepare:", e)
          // A cache-hit worker intentionally skipped the content pass, so
          // p.entries/p.chunkHashes contain probe placeholders and CANNOT be
          // used for a metadata rebuild here. Start one fresh prepare job and
          // bypass the cache exactly once; that job will read/hash/encode the
          // sources and overwrite the bad cache entry with a valid manifest.
          if (!retryPrepareWithoutCache()) throw e
          return
        }
      }
      if (!session) {
        session = buildFromMeta().build_streamed(
          cfg.symbolSize,
          chunkRawSize,
          cfg.redundancyPct
        )
        try {
          await putCachedManifest(p.entries, session.manifest_json(), chunkRawSize)
        } catch {
          // advisory
        }
      }
      if (!mountedRef.current || epoch.current !== startEpoch) {
        freeSenderSession(session)
        releaseOwnedSession()
        if (mountedRef.current) {
          setState((s) => ({ ...s, session: null, initializing: false }))
        }
        return
      }
      releaseOwnedSession()
      ownedSessionRef.current = session
      // Play-time chunk staging: the prepare worker still holds the item
      // sources + chunk plan; startEpoch doubles as the stage request's
      // currency guard (it equals the prepare jobId).
      const worker = workerRef.current
      const stager =
        worker && p.chunkCount > 0
          ? createChunkStager({
              worker,
              session,
              jobId: startEpoch,
              chunkCount: p.chunkCount,
              isLive: () =>
                mountedRef.current &&
                epoch.current === startEpoch &&
                ownedSessionRef.current === session &&
                workerRef.current === worker,
              onFatal: (message) => {
                if (epoch.current !== startEpoch) return
                // A stage can only fail terminally when the source bytes
                // disagree with the prepare-time manifest hashes (file
                // modified/moved between prepare and playback) or its slice
                // read failed — either way continuing is pointless: every
                // later stage of this session would fail the same gate.
                // Tear the session down with an actionable message instead
                // of an endless stage-retry loop.
                const changed =
                  /hash mismatch|disagree with the manifest/i.test(message)
                if (changed && p.cachedManifestHex) {
                  // Metadata cache fingerprints can be stale when content was
                  // rewritten without changing size/mtime. Evict the poisoned
                  // entry and transparently perform one real read/hash pass.
                  releaseOwnedSession()
                  setState((s) => ({
                    ...s,
                    session: null,
                    stager: null,
                    page: "select",
                    initializing: true,
                    error: null,
                  }))
                  void (async () => {
                    await deleteCachedManifest(p.entries, chunkRawSize)
                    if (epoch.current !== startEpoch) return
                    if (!retryPrepareWithoutCache()) {
                      setState((s) => ({
                        ...s,
                        initializing: false,
                        error: "缓存校验失败，且文件处理线程不可用，请重新发送",
                      }))
                    }
                  })()
                  return
                }
                const userMessage = changed
                  ? "源文件内容与准备传输时不一致（可能已被修改），请重新选择并发送"
                  : `分块读取失败（源文件可能已被移动或修改），请重新发送。${message}`
                releaseOwnedSession()
                setState((s) => ({
                  ...s,
                  session: null,
                  stager: null,
                  page: "select",
                  error: userMessage,
                  initializing: false,
                }))
              },
            })
          : null
      if (stager) {
        ownedStagerRef.current = stager
      }
      setState((s) => ({ ...s, session, stager, page: "play", initializing: false }))
    } catch (e: any) {
      console.error("WASM session creation failed:", e)
      setState((s) => ({
        ...s,
        initializing: false,
        error: `编码器初始化失败: ${e?.message || e}`,
      }))
    }
  }, [state.config, state.items, releaseOwnedSession])

  startPlaybackRef.current = startPlaybackWithPayload

  const onPlay = useCallback(() => {
    const items = state.items
    if (items.length === 0) return
    if (state.compressPhase != null || state.initializing) return
    const worker = workerRef.current
    if (!worker) {
      setState((s) => ({ ...s, error: "文件处理线程尚未就绪，请重试" }))
      return
    }
    epoch.current += 1
    const e = epoch.current
    issuedEpoch.current = e
    releaseOwnedSession()
    setState((s) => ({
      ...s,
      session: null,
      stager: null,
      compressPhase: "reading",
      error: null,
    }))
    // Balanced-encode params captured NOW (from the live config): the worker
    // reuses them verbatim for every play-time re-stage — determinism keeps
    // the staged encoded_hash (and thus the chunk object_id) stable.
    const channelBps = Math.round(
      state.config.symbolSize * (state.config.fps || 60) * Math.max(1, state.config.multiQr || 1)
    )
    const forceFull = items.reduce(
      (s, it) => s + (it.kind === "file" ? it.file.size : new TextEncoder().encode(it.content).length),
      0
    ) <= 8 * 1024 * 1024
    const encodeParams = { channelBps, forceFull }
    if (items.length === 1 && items[0].kind === "text") {
      worker.postMessage({
        jobId: e,
        text: items[0].content,
        name: items[0].name,
        encodeParams,
      })
    } else {
      worker.postMessage({ jobId: e, files: itemsToFiles(items), encodeParams })
    }
  }, [state.items, state.compressPhase, state.initializing, state.config, releaseOwnedSession])

  const updateConfig = useCallback(
    (patch: Partial<TransferConfig>) =>
      setState((s) => {
        const next = { ...s.config, ...patch }
        saveConfig(next)
        return { ...s, config: next }
      }),
    []
  )

  const stopPlayback = useCallback(() => {
    setState((s) => ({
      ...s,
      page: "stats",
      initializing: false,
      error: null,
    }))
  }, [])

  const openSettings = useCallback(() => {
    setState((s) => ({ ...s, settingsFrom: s.page, page: "settings" }))
  }, [])

  const closeSettings = useCallback(() => {
    setState((s) => ({ ...s, page: s.settingsFrom ?? "select", settingsFrom: null }))
  }, [])

  const closeStats = useCallback(() => {
    releaseOwnedSession()
    setState((s) => ({
      ...s,
      session: null,
      stager: null,
      page: "select",
      prepared: null,
      initializing: false,
      error: null,
    }))
  }, [releaseOwnedSession])

  const busyLabel =
    state.compressPhase === "reading"
      ? "正在读取文件…"
      : state.initializing
      ? "正在准备编码…"
      : null

  // Step-bar navigation: every finished step is clickable to go back /
  // forward between the pages of the CURRENT transfer session. Guarded while
  // a preparation pass runs (reading / encoder init) so the clicks cannot
  // race startPlaybackWithPayload's epoch checks.
  const stepsBusy = state.compressPhase != null || state.initializing
  const canPlay = state.session != null && state.prepared != null
  const gotoSelect = () => {
    if (stepsBusy || state.page === "select") return
    setState((s) => ({ ...s, page: "select" }))
  }
  const gotoPlay = () => {
    if (stepsBusy || !canPlay || state.page === "play") return
    setState((s) => ({ ...s, page: "play" }))
  }
  const gotoStats = () => {
    if (stepsBusy || state.session == null || state.page === "stats") return
    setState((s) => ({ ...s, page: "stats" }))
  }

  return (
    <div className="app">
      <header className="app-header">
        <div className="app-logo">
          <img src={iconUrl} alt="AirFerry" />
        </div>
        <div className="app-title">
          <h1>AirFerry</h1>
        </div>
        {state.page !== "settings" && (
          <button
            type="button"
            className="btn secondary btn-sm settings-btn"
            onClick={openSettings}
            title="传输设置"
          >
            <SettingsIcon size={16} />
            <span>设置</span>
          </button>
        )}
      </header>
      {state.page !== "settings" && (
        <div className="steps">
          <div
            className={`step ${state.page === "select" ? "active" : state.session ? "done" : ""} ${
              stepsBusy || state.page === "select" ? "disabled" : ""
            }`}
            onClick={gotoSelect}
            role="button"
            aria-disabled={stepsBusy || state.page === "select"}
            title="返回选择文件"
          >
            <span className="step-dot">1</span>
            <span className="step-label">选择文件</span>
          </div>
          <div className="step-line" />
          <div
            className={`step ${state.page === "play" ? "active" : state.page === "stats" ? "done" : ""} ${
              stepsBusy || !canPlay || state.page === "play" ? "disabled" : ""
            }`}
            onClick={gotoPlay}
            role="button"
            aria-disabled={stepsBusy || !canPlay || state.page === "play"}
            title={canPlay ? "返回播放传输" : "尚未准备传输"}
          >
            <span className="step-dot">2</span>
            <span className="step-label">播放传输</span>
          </div>
          <div className="step-line" />
          <div
            className={`step ${state.page === "stats" ? "active" : ""} ${
              stepsBusy || state.session == null || state.page === "stats" ? "disabled" : ""
            }`}
            onClick={gotoStats}
            role="button"
            aria-disabled={stepsBusy || state.session == null || state.page === "stats"}
            title={state.session ? "查看传输统计" : "尚未开始传输"}
          >
            <span className="step-dot">3</span>
            <span className="step-label">传输统计</span>
          </div>
        </div>
      )}
      <main className="app-main">
        {state.error && (
          <div className="error-banner" role="alert">
            {state.error}
          </div>
        )}
        {state.page === "select" && (
          <FileSelectPage
            items={state.items}
            onItemsChange={onItemsChange}
            onPlay={onPlay}
            busyLabel={busyLabel}
          />
        )}
        {state.page === "settings" && (
          <SettingsPage
            config={state.config}
            onChange={updateConfig}
            onBack={closeSettings}
          />
        )}
        {state.page === "play" && state.session && state.prepared && (
          <PlayPage
            session={state.session}
            stager={state.stager}
            config={state.config}
            totalBytes={state.prepared.totalBytes}
            onStop={stopPlayback}
          />
        )}
        {state.page === "stats" && state.session && (
          <StatsPage
            session={state.session}
            fileSize={state.prepared?.totalBytes ?? 0}
            onClose={closeStats}
          />
        )}
      </main>
    </div>
  )
}
