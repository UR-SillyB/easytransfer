import assert from "node:assert/strict"
import test from "node:test"

import { ChunkStore, OpfsJournal, sweepOrphanPartials } from "../src/workers/receive-storage.ts"

const encoder = new TextEncoder()
const decoder = new TextDecoder()
const TID_JOURNALED = "11111111111111111111111111111111"
const TID_OLDER = "22222222222222222222222222222222"
const TID_CAFE = "33333333333333333333333333333333"
const TID_WRITE_FAIL = "44444444444444444444444444444444"
const TID_REMOVE_FAIL = "55555555555555555555555555555555"
const TID_BEEF = "66666666666666666666666666666666"
const TID_KEEPALIVE = "77777777777777777777777777777777"
const TID_OLD_RESUME = "88888888888888888888888888888888"
const TID_MARKER_FAIL = "99999999999999999999999999999999"
const TID_ORPHAN = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const TID_BAD = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const TID_FRESH = "cccccccccccccccccccccccccccccccc"
const TID_OLDEST = "dddddddddddddddddddddddddddddddd"
const TID_MIDDLE = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
const TID_NEWEST = "ffffffffffffffffffffffffffffffff"
const TID_OLDER_SMALL = "01010101010101010101010101010101"
const TID_NEWEST_LARGE = "02020202020202020202020202020202"
const LEGAL_CHUNK_SIZE = 1024 * 1024

class FakeFileHandle {
  constructor(name) {
    this.kind = "file"
    this.name = name
    this.bytes = new Uint8Array(0)
    this.lastModified = Date.now()
    this.syncOpen = false
    this.syncOpenCount = 0
    this.failWriteAt = null
    this.shortWriteAt = null
    /** Simulates a stale/short getFile() snapshot (size guard must trip). */
    this.getFileSize = null
    this.getFileFailsWhileSyncOpen = false
    this.failGetFile = false
    this.failWritableWrite = false
    this.abortCount = 0
  }

  async getFile() {
    if (this.failGetFile) throw new Error("simulated getFile failure")
    if (this.getFileFailsWhileSyncOpen && this.syncOpen) {
      throw new Error("getFile unavailable while sync handle is open")
    }
    const snapshot = this.bytes.slice()
    const size = this.getFileSize ?? snapshot.byteLength
    return {
      size,
      lastModified: this.lastModified,
      text: async () => decoder.decode(snapshot),
      slice: (start, end) =>
        new Blob([snapshot.subarray(Math.max(0, start), Math.min(snapshot.byteLength, end))]),
    }
  }

  async createSyncAccessHandle() {
    this.syncOpenCount++
    if (this.syncOpen) throw new Error("SyncAccessHandle already locked")
    this.syncOpen = true
    const file = this
    return {
      read(buf, options = {}) {
        const at = options.at ?? 0
        const target = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
        const available = Math.max(0, Math.min(target.byteLength, file.bytes.byteLength - at))
        if (available > 0) target.set(file.bytes.subarray(at, at + available))
        return available
      },
      write(buf, options = {}) {
        const at = options.at ?? 0
        if (file.failWriteAt === at) throw new Error("simulated write failure")
        const source = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
        const requested = source.byteLength
        const actual = file.shortWriteAt === at ? Math.max(0, requested - 1) : requested
        const required = at + actual
        if (required > file.bytes.byteLength) {
          const grown = new Uint8Array(required)
          grown.set(file.bytes)
          file.bytes = grown
        }
        file.bytes.set(source.subarray(0, actual), at)
        file.lastModified++
        return actual
      },
      flush() {},
      close() {
        file.syncOpen = false
      },
      getSize() {
        return file.bytes.byteLength
      },
    }
  }

  async createWritable({ keepExistingData = false } = {}) {
    let working = keepExistingData ? this.bytes.slice() : new Uint8Array(0)
    let position = 0
    const file = this
    return {
      async seek(next) {
        position = next
      },
      async truncate(size) {
        const resized = new Uint8Array(size)
        resized.set(working.subarray(0, size))
        working = resized
        position = Math.min(position, size)
      },
      async write(value) {
        if (file.failWritableWrite) throw new Error("simulated journal write failure")
        const source = typeof value === "string" ? encoder.encode(value) : new Uint8Array(value)
        const required = position + source.byteLength
        if (required > working.byteLength) {
          const grown = new Uint8Array(required)
          grown.set(working)
          working = grown
        }
        working.set(source, position)
        position += source.byteLength
      },
      async close() {
        file.bytes = working
        file.lastModified++
      },
      async abort() {
        file.abortCount++
      },
    }
  }
}

class FakeDirectoryHandle {
  constructor() {
    this.files = new Map()
    this.failRemoveNames = new Set()
    this.failCreateNames = new Set()
  }

  async getFileHandle(name, options = {}) {
    const existing = this.files.get(name)
    if (existing) return existing
    if (!options.create) throw new Error("not found")
    if (this.failCreateNames.has(name)) throw new Error("simulated create failure")
    const file = new FakeFileHandle(name)
    this.files.set(name, file)
    return file
  }

  async removeEntry(name) {
    if (this.failRemoveNames.has(name)) throw new Error("simulated remove failure")
    if (!this.files.delete(name)) throw new Error("not found")
  }

  async *entries() {
    yield* this.files.entries()
  }
}

async function appendText(handle, text) {
  const writer = await handle.createWritable({ keepExistingData: true })
  await writer.seek((await handle.getFile()).size)
  await writer.write(text)
  await writer.close()
}

test("ChunkStore acquires one exclusive OPFS handle per transfer", async () => {
  const dir = new FakeDirectoryHandle()
  const store = new ChunkStore()

  await store.init(dir, "abcd")
  assert.equal(store.writeChunk(0, 4, Uint8Array.from([1, 2, 3, 4])), "disk")
  await store.init(dir, "abcd")
  assert.equal(store.writeChunk(1, 4, Uint8Array.from([5, 6, 7, 8])), "disk")

  const partial = dir.files.get("af2-abcd.partial")
  assert.equal(partial.syncOpenCount, 1)
  assert.deepEqual(Array.from(store.readRange(0, 8, 8, 4)), [1, 2, 3, 4, 5, 6, 7, 8])
})

test("ChunkStore reads a mixed disk + memory fallback transfer", async () => {
  const dir = new FakeDirectoryHandle()
  const store = new ChunkStore()
  await store.init(dir, "mixed")
  const partial = dir.files.get("af2-mixed.partial")

  assert.equal(store.writeChunk(0, 4, Uint8Array.from([1, 2, 3, 4])), "disk")
  partial.failWriteAt = 4
  assert.equal(store.writeChunk(1, 4, Uint8Array.from([5, 6, 7, 8])), "memory")
  assert.deepEqual(Array.from(store.readRange(0, 8, 8, 4)), [1, 2, 3, 4, 5, 6, 7, 8])
})

test("ChunkStore treats a short OPFS write as non-durable", async () => {
  const dir = new FakeDirectoryHandle()
  const store = new ChunkStore()
  await store.init(dir, "short")
  const partial = dir.files.get("af2-short.partial")
  partial.shortWriteAt = 0

  assert.equal(store.writeChunk(0, 4, Uint8Array.from([9, 8, 7, 6])), "memory")
  assert.deepEqual(Array.from(store.readRange(0, 4, 4, 4)), [9, 8, 7, 6])
})

test("ChunkStore rejects an out-of-range index before growing the sparse backing", async () => {
  const dir = new FakeDirectoryHandle()
  const store = new ChunkStore()
  await store.init(dir, "index-cap")
  const partial = dir.files.get("af2-index-cap.partial")

  assert.throws(
    () => store.writeChunk(131_072, 4, Uint8Array.from([1, 2, 3, 4])),
    /AF2_STORAGE_FATAL/
  )
  assert.equal(partial.bytes.byteLength, 0)
})

test("ChunkStore rejects a chunk outside the declared transfer geometry", async () => {
  const dir = new FakeDirectoryHandle()
  const store = new ChunkStore()
  await store.init(dir, "geometry")
  const partial = dir.files.get("af2-geometry.partial")

  assert.throws(
    () => store.writeChunk(1, 4, Uint8Array.from([1, 2, 3, 4]), 4),
    /AF2_STORAGE_FATAL/
  )
  assert.equal(partial.bytes.byteLength, 0)
})

test("ChunkStore fails closed when memory fallback exceeds 64 MiB", async () => {
  const store = new ChunkStore()
  await store.init(null, "memory-cap")
  assert.equal(store.writeChunk(0, 64 * 1024 * 1024, new Uint8Array(64 * 1024 * 1024)), "memory")
  assert.throws(
    () => store.writeChunk(1, 64 * 1024 * 1024, new Uint8Array(1)),
    /AF2_STORAGE_FATAL/
  )
})

test("ChunkStore resume does not create a missing partial file", async () => {
  const dir = new FakeDirectoryHandle()
  const store = new ChunkStore()
  await store.init(dir, "missing", { create: false })
  store.markResumed([0])

  assert.equal(dir.files.has("af2-missing.partial"), false)
  assert.equal(store.readChunk(0, 4, 4), null)
})

test("readRangeBlob assembles disk spans and memory fallback spans", async () => {
  const dir = new FakeDirectoryHandle()
  const store = new ChunkStore()
  await store.init(dir, "blobmix")
  const partial = dir.files.get("af2-blobmix.partial")

  assert.equal(store.writeChunk(0, 4, Uint8Array.from([1, 2, 3, 4])), "disk")
  partial.failWriteAt = 4
  assert.equal(store.writeChunk(1, 4, Uint8Array.from([5, 6, 7, 8])), "memory")

  const blob = await store.readRangeBlob(0, 8, 8, 4)
  assert.equal(blob.size, 8)
  assert.deepEqual(Array.from(new Uint8Array(await blob.arrayBuffer())), [1, 2, 3, 4, 5, 6, 7, 8])

  // Sub-range that starts inside the memory chunk.
  const tail = await store.readRangeBlob(5, 3, 8, 4)
  assert.deepEqual(Array.from(new Uint8Array(await tail.arrayBuffer())), [6, 7, 8])

  // Out-of-bounds requests reject instead of returning a short blob; an
  // empty range yields an empty blob.
  assert.equal(await store.readRangeBlob(4, 5, 8, 4), null)
  assert.equal((await store.readRangeBlob(0, 0, 8, 4)).size, 0)
})

test("readRangeBlob ignores a stale getFile snapshot and reads via the sync handle", async () => {
  const dir = new FakeDirectoryHandle()
  const store = new ChunkStore()
  await store.init(dir, "stale")
  const partial = dir.files.get("af2-stale.partial")
  assert.equal(store.writeChunk(0, 4, Uint8Array.from([9, 9, 9, 9])), "disk")

  // getFile() reports a shorter file than the range needs: the size guard
  // must refuse the lazy-slice path and fall back to syncHandle reads.
  partial.getFileSize = 2
  const blob = await store.readRangeBlob(0, 4, 4, 4)
  assert.deepEqual(Array.from(new Uint8Array(await blob.arrayBuffer())), [9, 9, 9, 9])
})

test("prepareBlobReads closes exclusive sync handle before lazy File slicing", async () => {
  const dir = new FakeDirectoryHandle()
  const store = new ChunkStore()
  await store.init(dir, "blob-close")
  const partial = dir.files.get("af2-blob-close.partial")
  partial.getFileFailsWhileSyncOpen = true
  assert.equal(store.writeChunk(0, 4, Uint8Array.from([4, 3, 2, 1])), "disk")

  store.prepareBlobReads()
  assert.equal(partial.syncOpen, false)
  const blob = await store.readRangeBlob(0, 4, 4, 4)
  assert.deepEqual(Array.from(new Uint8Array(await blob.arrayBuffer())), [4, 3, 2, 1])
})

test("reopenAfterBlobReadFailure restores durable chunk reads for assemble retry", async () => {
  const dir = new FakeDirectoryHandle()
  const store = new ChunkStore()
  await store.init(dir, "blob-retry")
  store.writeChunk(0, 4, Uint8Array.from([5, 6, 7, 8]))

  store.prepareBlobReads()
  assert.equal(store.readChunk(0, 4, 4), null, "closed sync handle cannot serve verifier reads")

  await store.reopenAfterBlobReadFailure()
  assert.deepEqual(Array.from(store.readChunk(0, 4, 4) ?? []), [5, 6, 7, 8])
})

test("readRangeBlob refuses multi-chunk sync fallback instead of allocating O(entry)", async () => {
  const dir = new FakeDirectoryHandle()
  const store = new ChunkStore()
  await store.init(dir, "bounded-fallback")
  const partial = dir.files.get("af2-bounded-fallback.partial")
  partial.getFileFailsWhileSyncOpen = true
  assert.equal(store.writeChunk(0, 4, Uint8Array.from([1, 2, 3, 4])), "disk")
  assert.equal(store.writeChunk(1, 4, Uint8Array.from([5, 6, 7, 8])), "disk")

  // While the exclusive handle is open there is no lazy File view. A large
  // request must fail boundedly rather than retain one copy per chunk.
  assert.equal(await store.readRangeBlob(0, 8, 8, 4), null)

  // The real assembly path closes the handle first; the same range then uses
  // lazy File slices and succeeds without whole-entry copies.
  store.prepareBlobReads()
  const blob = await store.readRangeBlob(0, 8, 8, 4)
  assert.deepEqual(Array.from(new Uint8Array(await blob.arrayBuffer())), [1, 2, 3, 4, 5, 6, 7, 8])
})

test("release + discard keep a delivered lazy Blob backing until orphan sweep grace expires", async () => {
  const dir = new FakeDirectoryHandle()
  const store = new ChunkStore()
  await store.init(dir, TID_KEEPALIVE)
  assert.equal(store.writeChunk(0, 4, Uint8Array.from([1, 2, 3, 4])), "disk")

  const blob = await store.readRangeBlob(0, 4, 4, 4)
  assert.equal(await store.release(), true)
  assert.ok(dir.files.has(`af2-${TID_KEEPALIVE}.released`))

  // The delivered Blob is a lazy OPFS reference — the file must survive the
  // assemble step so the user's later download still reads valid bytes.
  assert.ok(dir.files.has(`af2-${TID_KEEPALIVE}.partial`))
  assert.equal(blob.size, 4)
  assert.deepEqual(Array.from(new Uint8Array(await blob.arrayBuffer())), [1, 2, 3, 4])

  // Session reset must not unlink a backing file that a browser download may
  // still be consuming lazily.
  await store.discard()
  assert.equal(dir.files.has(`af2-${TID_KEEPALIVE}.partial`), true)
  await sweepOrphanPartials(dir, 0)
  assert.equal(dir.files.has(`af2-${TID_KEEPALIVE}.partial`), false)
  assert.equal(dir.files.has(`af2-${TID_KEEPALIVE}.released`), false)
})

test("released backing grace starts at release, not an old chunk-write mtime", async () => {
  const dir = new FakeDirectoryHandle()
  const store = new ChunkStore()
  await store.init(dir, TID_OLD_RESUME)
  assert.equal(store.writeChunk(0, 4, Uint8Array.from([1, 2, 3, 4])), "disk")
  dir.files.get(`af2-${TID_OLD_RESUME}.partial`).lastModified = Date.now() - 24 * 60 * 60 * 1000

  assert.equal(await store.release(), true)
  assert.ok(dir.files.has(`af2-${TID_OLD_RESUME}.released`))
  await store.discard()
  await sweepOrphanPartials(dir, 60_000)
  assert.equal(dir.files.has(`af2-${TID_OLD_RESUME}.partial`), true)
})

test("an unreadable release marker fails closed instead of expiring an active Blob", async () => {
  const dir = new FakeDirectoryHandle()
  const store = new ChunkStore()
  await store.init(dir, TID_OLD_RESUME)
  store.writeChunk(0, 4, Uint8Array.from([1, 2, 3, 4]))
  dir.files.get(`af2-${TID_OLD_RESUME}.partial`).lastModified =
    Date.now() - 24 * 60 * 60 * 1000

  assert.equal(await store.release(), true)
  dir.files.get(`af2-${TID_OLD_RESUME}.released`).failGetFile = true
  await store.discard()
  await sweepOrphanPartials(dir, 60_000)

  assert.equal(dir.files.has(`af2-${TID_OLD_RESUME}.partial`), true)
  assert.equal(dir.files.has(`af2-${TID_OLD_RESUME}.released`), true)
})

test("release reports a missing durable marker without unlinking the Blob backing", async () => {
  const dir = new FakeDirectoryHandle()
  const store = new ChunkStore()
  await store.init(dir, TID_MARKER_FAIL)
  assert.equal(store.writeChunk(0, 4, Uint8Array.from([9, 8, 7, 6])), "disk")
  dir.failCreateNames.add(`af2-${TID_MARKER_FAIL}.released`)

  assert.equal(await store.release(), false)
  await store.discard()

  assert.equal(dir.files.has(`af2-${TID_MARKER_FAIL}.partial`), true)
  assert.equal(dir.files.has(`af2-${TID_MARKER_FAIL}.released`), false)
})

test("sweepOrphanPartials removes ledger-less partials and keeps journaled ones", async () => {
  const dir = new FakeDirectoryHandle()
  // A journaled (in-progress-or-resumable) transfer: partial + ledger.
  const journaled = new OpfsJournal()
  await journaled.init(dir, TID_JOURNALED, LEGAL_CHUNK_SIZE, "0102")
  const live = new ChunkStore()
  await live.init(dir, TID_JOURNALED)
  assert.equal(live.writeChunk(0, 4, Uint8Array.from([2, 2, 2, 2])), "disk")
  // An orphan partial: released after a delivered transfer (ledger discarded).
  const owned = new ChunkStore()
  await owned.init(dir, TID_ORPHAN)
  assert.equal(owned.writeChunk(0, 4, Uint8Array.from([1, 1, 1, 1])), "disk")

  await sweepOrphanPartials(dir, 0)

  assert.ok(dir.files.has(`af2-${TID_JOURNALED}.partial`))
  assert.ok(dir.files.has(`af2-${TID_JOURNALED}.ledger.jsonl`))
  assert.equal(dir.files.has(`af2-${TID_ORPHAN}.partial`), false)
})

test("sweepOrphanPartials removes partials whose matching ledger is corrupt", async () => {
  const dir = new FakeDirectoryHandle()
  const badLedger = await dir.getFileHandle(`af2-${TID_BAD}.ledger.jsonl`, { create: true })
  const writer = await badLedger.createWritable()
  await writer.write("not-json\n")
  await writer.close()
  const partial = await dir.getFileHandle(`af2-${TID_BAD}.partial`, { create: true })
  const sync = await partial.createSyncAccessHandle()
  sync.write(Uint8Array.from([1, 2, 3, 4]), { at: 0 })
  sync.close()

  await sweepOrphanPartials(dir, 0)

  assert.equal(dir.files.has(`af2-${TID_BAD}.ledger.jsonl`), false)
  assert.equal(dir.files.has(`af2-${TID_BAD}.partial`), false)
})

test("sweepOrphanPartials preserves a fresh delivered partial during the grace period", async () => {
  const dir = new FakeDirectoryHandle()
  const orphan = await dir.getFileHandle(`af2-${TID_FRESH}.partial`, { create: true })
  const sync = await orphan.createSyncAccessHandle()
  sync.write(Uint8Array.from([7, 7, 7, 7]), { at: 0 })
  sync.close()
  orphan.lastModified = Date.now()

  await sweepOrphanPartials(dir, 60_000)
  assert.equal(dir.files.has(`af2-${TID_FRESH}.partial`), true)

  orphan.lastModified = Date.now() - 120_000
  await sweepOrphanPartials(dir, 60_000)
  assert.equal(dir.files.has(`af2-${TID_FRESH}.partial`), false)
})

test("sweepOrphanPartials bounds retained backings, evicting the oldest first", async () => {
  const dir = new FakeDirectoryHandle()
  const now = Date.now()
  // Three in-grace delivered backings of 100 bytes each; cap allows only 250.
  for (const [name, ageMs] of [
    [`af2-${TID_OLDEST}.partial`, 3_000],
    [`af2-${TID_MIDDLE}.partial`, 2_000],
    [`af2-${TID_NEWEST}.partial`, 1_000],
  ]) {
    const handle = await dir.getFileHandle(name, { create: true })
    const sync = await handle.createSyncAccessHandle()
    sync.write(new Uint8Array(100), { at: 0 })
    sync.close()
    handle.lastModified = now - ageMs
  }

  // Without a cap the grace keeps all three.
  await sweepOrphanPartials(dir, 60_000, 10_000)
  assert.equal(dir.files.size, 3, "grace alone must retain every fresh backing")

  // With a 250-byte cap, the oldest is dropped until the set fits.
  await sweepOrphanPartials(dir, 60_000, 250)
  assert.equal(dir.files.has(`af2-${TID_OLDEST}.partial`), false, "oldest is evicted first")
  assert.equal(dir.files.has(`af2-${TID_MIDDLE}.partial`), true)
  assert.equal(dir.files.has(`af2-${TID_NEWEST}.partial`), true, "newest keeps its grace")
})

test("sweepOrphanPartials keeps one oversize newest backing until grace expires", async () => {
  const dir = new FakeDirectoryHandle()
  const now = Date.now()
  for (const [name, size, ageMs] of [
    [`af2-${TID_OLDER_SMALL}.partial`, 100, 2_000],
    [`af2-${TID_NEWEST_LARGE}.partial`, 300, 1_000],
  ]) {
    const handle = await dir.getFileHandle(name, { create: true })
    const sync = await handle.createSyncAccessHandle()
    sync.write(new Uint8Array(size), { at: 0 })
    sync.close()
    handle.lastModified = now - ageMs
  }

  await sweepOrphanPartials(dir, 60_000, 250)
  assert.equal(dir.files.has(`af2-${TID_OLDER_SMALL}.partial`), false)
  assert.equal(
    dir.files.has(`af2-${TID_NEWEST_LARGE}.partial`),
    true,
    "a single legal download larger than the retained-set cap must keep its grace"
  )
})

test("sweepOrphanPartials leaves files outside the canonical AF2 namespace untouched", async () => {
  const dir = new FakeDirectoryHandle()
  for (const name of [
    "notes.ledger.jsonl",
    "af2-short.ledger.jsonl",
    "af2-short.partial",
    "af2-short.released",
  ]) {
    await dir.getFileHandle(name, { create: true })
  }

  await sweepOrphanPartials(dir, 0)

  assert.deepEqual(Array.from(dir.files.keys()).sort(), [
    "af2-short.ledger.jsonl",
    "af2-short.partial",
    "af2-short.released",
    "notes.ledger.jsonl",
  ])
})

test("OpfsJournal loadMostRecent skips a corrupt newer journal", async () => {
  const dir = new FakeDirectoryHandle()
  const valid = new OpfsJournal()
  await valid.init(dir, TID_OLDER, LEGAL_CHUNK_SIZE, "01020304")
  await valid.commit(2)
  dir.files.get(`af2-${TID_OLDER}.ledger.jsonl`).lastModified = 100

  const bad = await dir.getFileHandle(`af2-${TID_BAD}.ledger.jsonl`, { create: true })
  const w = await bad.createWritable()
  await w.write("bad")
  await w.close()
  bad.lastModified = 200

  const loaded = await OpfsJournal.loadMostRecent(dir)
  assert.equal(loaded.transferIdHex, TID_OLDER)
  assert.deepEqual(loaded.completed, [2])
})

test("OpfsJournal loadMostRecent skips an inaccessible candidate", async () => {
  const dir = new FakeDirectoryHandle()
  const valid = new OpfsJournal()
  await valid.init(dir, TID_OLDER, LEGAL_CHUNK_SIZE, "01020304")
  await valid.commit(2)

  const inaccessible = await dir.getFileHandle(
    `af2-${TID_NEWEST}.ledger.jsonl`, { create: true }
  )
  inaccessible.failGetFile = true

  const loaded = await OpfsJournal.loadMostRecent(dir)
  assert.equal(loaded.transferIdHex, TID_OLDER)
  assert.deepEqual(loaded.completed, [2])
})

test("OpfsJournal binds the header transfer id to its canonical filename", async () => {
  const dir = new FakeDirectoryHandle()
  const handle = await dir.getFileHandle(`af2-${TID_CAFE}.ledger.jsonl`, { create: true })
  const writer = await handle.createWritable()
  await writer.write(JSON.stringify({
    v: 1,
    tid: TID_BEEF,
    crs: LEGAL_CHUNK_SIZE,
    root: "01020304",
  }) + "\n")
  await writer.close()

  assert.equal(await OpfsJournal.loadMostRecent(dir), null)
})

test("OpfsJournal rejects out-of-protocol records and non-trailing corruption", async () => {
  const dir = new FakeDirectoryHandle()
  const journal = new OpfsJournal()
  await journal.init(dir, TID_CAFE, LEGAL_CHUNK_SIZE, "01020304")
  const handle = dir.files.get(`af2-${TID_CAFE}.ledger.jsonl`)
  await appendText(handle, `${JSON.stringify({ c: 131_072 })}\n`)
  assert.equal(await OpfsJournal.loadMostRecent(dir), null)

  await journal.init(dir, TID_BEEF, LEGAL_CHUNK_SIZE, "01020304")
  await journal.commit(1)
  const second = dir.files.get(`af2-${TID_BEEF}.ledger.jsonl`)
  await appendText(second, "{torn\n" + JSON.stringify({ c: 2 }) + "\n")
  assert.equal(await OpfsJournal.loadMostRecent(dir), null)
})

test("OpfsJournal keeps valid commits before a torn final append", async () => {
  const dir = new FakeDirectoryHandle()
  const journal = new OpfsJournal()
  await journal.init(dir, TID_BEEF, LEGAL_CHUNK_SIZE, "01020304")
  await journal.commit(3)
  const handle = dir.files.get(`af2-${TID_BEEF}.ledger.jsonl`)
  await appendText(handle, "{torn")

  const loaded = await OpfsJournal.loadMostRecent(dir)
  assert.deepEqual(loaded.completed, [3])
  assert.equal(decoder.decode(handle.bytes).endsWith("\n"), true)
})

test("OpfsJournal truncates a complete unterminated record before later appends", async () => {
  const dir = new FakeDirectoryHandle()
  const first = new OpfsJournal()
  await first.init(dir, TID_CAFE, LEGAL_CHUNK_SIZE, "01020304")
  await first.commit(1)
  const handle = dir.files.get(`af2-${TID_CAFE}.ledger.jsonl`)
  await appendText(handle, JSON.stringify({ c: 2 }))

  const loaded = await OpfsJournal.loadMostRecent(dir)
  assert.deepEqual(loaded.completed, [1])

  const resumed = new OpfsJournal()
  await resumed.openExisting(dir, TID_CAFE)
  await resumed.commit(3)
  const reloaded = await OpfsJournal.loadMostRecent(dir)
  assert.deepEqual(reloaded.completed, [1, 3])
})

test("OpfsJournal rejects a malformed final record that reached its newline", async () => {
  const dir = new FakeDirectoryHandle()
  const journal = new OpfsJournal()
  await journal.init(dir, TID_CAFE, LEGAL_CHUNK_SIZE, "01020304")
  await journal.commit(3)
  const handle = dir.files.get(`af2-${TID_CAFE}.ledger.jsonl`)
  await appendText(handle, "{malformed\n")

  assert.equal(await OpfsJournal.loadMostRecent(dir), null)
})

test("OpfsJournal init is idempotent and keeps all committed chunk bits", async () => {
  const dir = new FakeDirectoryHandle()
  const journal = new OpfsJournal()

  await journal.init(dir, TID_CAFE, LEGAL_CHUNK_SIZE, "01020304")
  await journal.commit(0)
  await journal.init(dir, TID_CAFE, LEGAL_CHUNK_SIZE, "01020304")
  await journal.commit(1)

  const loaded = await OpfsJournal.loadMostRecent(dir)
  assert.equal(loaded.transferIdHex, TID_CAFE)
  assert.deepEqual(loaded.completed, [0, 1])
  assert.deepEqual(Array.from(loaded.rootFrameBytes), [1, 2, 3, 4])
})

test("OpfsJournal aborts a failed header writer so initialization can retry", async () => {
  const dir = new FakeDirectoryHandle()
  const name = `af2-${TID_WRITE_FAIL}.ledger.jsonl`
  const handle = await dir.getFileHandle(name, { create: true })
  handle.failWritableWrite = true
  const journal = new OpfsJournal()

  await assert.rejects(
    () => journal.init(dir, TID_WRITE_FAIL, LEGAL_CHUNK_SIZE, "01020304"),
    /AF2_STORAGE_FATAL/
  )
  assert.equal(handle.abortCount, 1)

  handle.failWritableWrite = false
  await journal.init(dir, TID_WRITE_FAIL, LEGAL_CHUNK_SIZE, "01020304")
  const loaded = await OpfsJournal.loadMostRecent(dir)
  assert.equal(loaded.transferIdHex, TID_WRITE_FAIL)
})

test("OpfsJournal commit propagates failure without recording the bit", async () => {
  const dir = new FakeDirectoryHandle()
  const journal = new OpfsJournal()
  await journal.init(dir, TID_WRITE_FAIL, LEGAL_CHUNK_SIZE, "01020304")
  dir.files.get(`af2-${TID_WRITE_FAIL}.ledger.jsonl`).failWritableWrite = true

  await assert.rejects(() => journal.commit(7), /AF2_STORAGE_FATAL/)
  dir.files.get(`af2-${TID_WRITE_FAIL}.ledger.jsonl`).failWritableWrite = false
  const loaded = await OpfsJournal.loadMostRecent(dir)
  assert.deepEqual(loaded.completed, [])
})

test("OpfsJournal retains ownership and retries a failed discard", async () => {
  const dir = new FakeDirectoryHandle()
  const journal = new OpfsJournal()
  const name = `af2-${TID_REMOVE_FAIL}.ledger.jsonl`
  await journal.init(dir, TID_REMOVE_FAIL, LEGAL_CHUNK_SIZE, "01020304")
  dir.failRemoveNames.add(name)

  await assert.rejects(() => journal.discard(), /AF2_STORAGE_FATAL/)
  assert.equal(dir.files.has(name), true)
  dir.failRemoveNames.delete(name)
  await journal.discard()
  assert.equal(dir.files.has(name), false)
})

test("OpfsJournal openExisting preserves root and prior commits across a second crash", async () => {
  const dir = new FakeDirectoryHandle()
  const first = new OpfsJournal()
  await first.init(dir, TID_BEEF, LEGAL_CHUNK_SIZE, "aabbccdd")
  await first.commit(0)

  const resumed = new OpfsJournal()
  await resumed.openExisting(dir, TID_BEEF)
  await resumed.commit(1)

  const loaded = await OpfsJournal.loadMostRecent(dir)
  assert.equal(loaded.transferIdHex, TID_BEEF)
  assert.deepEqual(loaded.completed, [0, 1])
  assert.deepEqual(Array.from(loaded.rootFrameBytes), [0xaa, 0xbb, 0xcc, 0xdd])
})
