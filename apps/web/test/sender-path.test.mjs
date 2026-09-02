import assert from "node:assert/strict"
import test from "node:test"

import { normalizeSenderPath, senderPathForFile, uniqueSenderPath } from "../src/lib/sender-path.ts"
import { AF2_MAX_ORIGINAL_BYTES, MAX_ORIGINAL_BYTES, MAX_ORIGINAL_MIB, LARGE_TRANSFER_BYTES } from "../src/types.ts"

test("Web sender host limit matches the smallest bundled receiver budget", () => {
  assert.equal(MAX_ORIGINAL_BYTES, 8 * 1024 * 1024 * 1024)
  assert.equal(MAX_ORIGINAL_MIB, 8 * 1024)
  assert.ok(MAX_ORIGINAL_BYTES < AF2_MAX_ORIGINAL_BYTES)
  // The large-transfer confirmation sits strictly between normal and cap.
  assert.ok(LARGE_TRANSFER_BYTES < MAX_ORIGINAL_BYTES)
})

test("senderPathForFile preserves directory picker hierarchy", () => {
  assert.equal(
    senderPathForFile({ name: "foo.txt", webkitRelativePath: "Root/A/foo.txt" }),
    "Root/A/foo.txt"
  )
  assert.equal(
    senderPathForFile({ name: "foo.txt", webkitRelativePath: "Root/B/foo.txt" }),
    "Root/B/foo.txt"
  )
})

test("senderPathForFile prefers the explicit sibling path over the File property", () => {
  // Structured clone of a File re-serializes the browser-native
  // webkitRelativePath field (empty for picked/walked files); the JS-level
  // override is invisible across postMessage. The hierarchy therefore travels
  // as an explicit sibling path and must win — including over a blank native
  // field and over a stale native one.
  assert.equal(
    senderPathForFile({ name: "foo.txt", webkitRelativePath: "" }, "Root/A/foo.txt"),
    "Root/A/foo.txt"
  )
  assert.equal(
    senderPathForFile({ name: "foo.txt", webkitRelativePath: "stale/foo.txt" }, "Root/B/foo.txt"),
    "Root/B/foo.txt"
  )
  // Without an override the old behavior stands (native rel path, then name).
  assert.equal(
    senderPathForFile({ name: "plain.txt", webkitRelativePath: "" }),
    "plain.txt"
  )
})

test("uniqueSenderPath only renames a true full-path collision", () => {
  const used = new Set(["Root/A/foo.txt", "Root/B/foo.txt"])
  assert.equal(uniqueSenderPath(used, "Root/C/foo.txt"), "Root/C/foo.txt")
  assert.equal(uniqueSenderPath(used, "Root/A/foo.txt"), "Root/A/foo (1).txt")
})

test("uniqueSenderPath keeps a suffixed max-length component wire-legal", () => {
  const name = `${"a".repeat(251)}.txt`
  const used = new Set([name])
  const duplicate = uniqueSenderPath(used, name)
  assert.equal(duplicate, `${"a".repeat(247)} (1).txt`)
  assert.ok(new TextEncoder().encode(duplicate).byteLength <= 255)
})

test("normalizeSenderPath canonicalizes separators and rejects traversal", () => {
  assert.equal(normalizeSenderPath("Root\\A\\e\u0301.txt"), "Root/A/é.txt")
  assert.throws(() => normalizeSenderPath("Root/../secret.txt"), /包含 \.\./)
  assert.throws(() => normalizeSenderPath("Root/bad\nname.txt"), /控制字符/)
  assert.throws(() => normalizeSenderPath(`${"界".repeat(86)}.txt`), /单段超过 255 字节/)
})

test("uniqueSenderPath fails early when a 1024-byte path has no suffix room", () => {
  const path = [
    "a".repeat(255),
    "b".repeat(255),
    "c".repeat(255),
    "d".repeat(254),
    "x",
  ].join("/")
  assert.equal(new TextEncoder().encode(path).byteLength, 1024)
  assert.throws(() => uniqueSenderPath(new Set([path]), path), /无法为重名文件添加唯一后缀/)
})
