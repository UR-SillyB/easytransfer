import assert from "node:assert/strict"
import { afterEach, beforeEach, test } from "node:test"

import {
  clearAllReceiveHistory,
  deleteHistoryItem,
  getReceiveHistory,
  recordCompletedTransfer,
  recordPartialTransfer,
} from "../src/storage/receiveHistory.ts"

const STORAGE_KEY = "airferry_receive_history_v2"
const TID_ACTIVE = "11111111111111111111111111111111"
const TID_OTHER = "22222222222222222222222222222222"

class FakeLocalStorage {
  constructor(limit = Number.MAX_SAFE_INTEGER) {
    this.values = new Map()
    this.limit = limit
  }

  getItem(key) {
    return this.values.get(key) ?? null
  }

  setItem(key, value) {
    if (value.length > this.limit) throw new Error("quota exceeded")
    this.values.set(key, value)
  }
}

class FakeOpfsRoot {
  constructor(names = []) {
    this.files = new Set(names)
    this.removed = []
    this.failName = ""
  }

  async removeEntry(name) {
    this.removed.push(name)
    if (name === this.failName) throw new Error("busy")
    if (!this.files.delete(name)) throw new DOMException("missing", "NotFoundError")
  }
}

let originalLocalStorage
let originalNavigator

beforeEach(() => {
  originalLocalStorage = Object.getOwnPropertyDescriptor(globalThis, "localStorage")
  originalNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator")
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    value: new FakeLocalStorage(),
  })
  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: {},
  })
})

afterEach(() => {
  if (originalLocalStorage) Object.defineProperty(globalThis, "localStorage", originalLocalStorage)
  else delete globalThis.localStorage
  if (originalNavigator) Object.defineProperty(globalThis, "navigator", originalNavigator)
  else delete globalThis.navigator
})

test("history parsing rejects foreign IDs and bounds persisted text", () => {
  localStorage.setItem(STORAGE_KEY, JSON.stringify([
    {
      id: "../../foreign",
      title: "bad",
      kind: "file",
      totalRawSize: 1,
      entryCount: 1,
      completedChunks: 1,
      totalChunks: 1,
      status: "completed",
      timestamp: Date.now(),
    },
  ]))
  assert.deepEqual(getReceiveHistory(), [])

  recordCompletedTransfer(
    TID_ACTIVE, "large text", 100_000, 1, "text", "x".repeat(100_000)
  )
  const [item] = getReceiveHistory()
  assert.equal(item.status, "completed")
  assert.equal(item.textContent.length, 16 * 1024)
  assert.equal(item.textContentTruncated, true)
})

test("completed status replaces a partial even under a bounded storage quota", () => {
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    value: new FakeLocalStorage(30_000),
  })
  recordPartialTransfer(TID_ACTIVE, "partial", 10, 1, 1, 2)
  recordCompletedTransfer(
    TID_ACTIVE, "done", 10, 1, "text", "文".repeat(100_000)
  )

  const history = getReceiveHistory()
  assert.equal(history.length, 1)
  assert.equal(history[0].status, "completed")
  assert.equal(history[0].textContentTruncated, true)
})

test("protected active transfer cannot be deleted", async () => {
  const root = new FakeOpfsRoot([
    `af2-${TID_ACTIVE}.ledger.jsonl`,
    `af2-${TID_ACTIVE}.partial`,
  ])
  navigator.storage = { getDirectory: async () => root }
  recordPartialTransfer(TID_ACTIVE, "active", 10, 1, 1, 2)

  assert.equal(await deleteHistoryItem(TID_ACTIVE, [TID_ACTIVE]), false)
  assert.equal(getReceiveHistory().length, 1)
  assert.deepEqual(root.removed, [])
})

test("cleanup removes ledger before partial and retains the record on failure", async () => {
  const root = new FakeOpfsRoot([
    `af2-${TID_ACTIVE}.ledger.jsonl`,
    `af2-${TID_ACTIVE}.partial`,
    `af2-${TID_ACTIVE}.released`,
  ])
  root.failName = `af2-${TID_ACTIVE}.partial`
  navigator.storage = { getDirectory: async () => root }
  recordPartialTransfer(TID_ACTIVE, "active", 10, 1, 1, 2)

  assert.equal(await deleteHistoryItem(TID_ACTIVE), false)
  assert.deepEqual(root.removed.slice(0, 2), [
    `af2-${TID_ACTIVE}.ledger.jsonl`,
    `af2-${TID_ACTIVE}.partial`,
  ])
  assert.equal(getReceiveHistory().length, 1)
})

test("clear-all preserves an active transaction while removing inactive entries", async () => {
  const root = new FakeOpfsRoot([
    `af2-${TID_OTHER}.ledger.jsonl`,
    `af2-${TID_OTHER}.partial`,
  ])
  navigator.storage = { getDirectory: async () => root }
  recordPartialTransfer(TID_ACTIVE, "active", 10, 1, 1, 2)
  recordPartialTransfer(TID_OTHER, "other", 10, 1, 1, 2)

  const summary = await clearAllReceiveHistory([TID_ACTIVE])

  assert.deepEqual(summary, { removed: 1, failed: 0 })
  assert.deepEqual(getReceiveHistory().map((item) => item.id), [TID_ACTIVE])
  assert.equal(root.removed.includes(`af2-${TID_ACTIVE}.ledger.jsonl`), false)
})
