package com.airferry.app.scan

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * §12 crash-gap tests for the `.partial` spill store (plan E2):
 * pwrite ordering, torn-write detectability, and re-open across a restart.
 * A crash can leave the spill SHORTER than the ledger claims — the store
 * must never serve partial ranges, so the recovery path treats the bit as
 * unverified and re-requests the chunk.
 */
class ChunkSpillStoreTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private fun spillPath(tid: String) = File(tmp.root, "af2-$tid.partial")

    @Test
    fun pwriteThenReopenReadsBack() {
        val store = ChunkSpillStore(tmp.root, "tid1")
        val bytes = ByteArray(4096) { (it % 251).toByte() }
        store.write(3, 8192, bytes) // chunk 3 lives at offset 3 * 8192
        assertEquals(3L * 8192 + 4096, store.length())
        assertArrayEquals(bytes, store.readRange(3L * 8192, 4096)!!)
    }

    @Test
    fun restartReopensExistingSpill() {
        ChunkSpillStore(tmp.root, "tid2").write(0, 8192, ByteArray(8192) { 7 })
        // New process / new store over the same directory.
        val reopened = ChunkSpillStore(tmp.root, "tid2")
        assertArrayEquals(ByteArray(8192) { 7 }, reopened.readRange(0, 8192)!!)
    }

    @Test
    fun truncatedSpillRangeIsRefused() {
        // Crash mid-pwrite: chunk 1's bytes were only partially written, so
        // the file ends inside chunk 1's range. readRange must refuse the
        // WHOLE chunk (never a partial slice) — the recovery path then skips
        // re-verification until a later epoch re-supplies it.
        val store = ChunkSpillStore(tmp.root, "tid3")
        store.write(0, 8192, ByteArray(8192) { 1 })
        store.write(1, 8192, ByteArray(100) { 2 }) // torn chunk 1
        assertNull(store.readRange(8192, 8192))
        assertArrayEquals(ByteArray(8192) { 1 }, store.readRange(0, 8192)!!)
    }

    @Test
    fun overwriteSameIndexRepairs() {
        // After invalidation the sender re-supplies the chunk; the repair
        // write lands on the same canonical offset and wins.
        val store = ChunkSpillStore(tmp.root, "tid4")
        store.write(0, 8192, ByteArray(8192) { 0x11 })
        store.write(0, 8192, ByteArray(8192) { 0x22 })
        assertArrayEquals(ByteArray(8192) { 0x22 }, store.readRange(0, 8192)!!)
    }

    @Test
    fun durableBitmapDistinguishesSparseHolesAndResumeBits() {
        val store = ChunkSpillStore(tmp.root, "tid-known")
        store.write(2, 8192, ByteArray(8192) { 3 })
        assertFalse(store.hasChunk(0))
        assertTrue(store.hasChunk(2))

        val reopened = ChunkSpillStore(tmp.root, "tid-known")
        assertFalse(reopened.hasChunk(2)) // file length alone proves nothing
        reopened.markResumed(intArrayOf(2))
        assertTrue(reopened.hasChunk(2))
    }

    @Test
    fun invalidationWithdrawsTrustUntilReplacementIsDurable() {
        val store = ChunkSpillStore(tmp.root, "tid-repair")
        store.write(0, 4, byteArrayOf(1, 2, 3, 4))
        assertTrue(store.hasChunk(0))

        store.invalidate(0)
        assertFalse(store.hasChunk(0))
        // Bytes remain readable only as the caller's hash-gated last resort.
        assertArrayEquals(byteArrayOf(1, 2, 3, 4), store.readRange(0, 4))

        store.write(0, 4, byteArrayOf(5, 6, 7, 8))
        assertTrue(store.hasChunk(0))
        assertArrayEquals(byteArrayOf(5, 6, 7, 8), store.readRange(0, 4))
    }

    @Test
    fun discardRemovesSpill() {
        val store = ChunkSpillStore(tmp.root, "tid5")
        store.write(0, 8192, ByteArray(8192) { 1 })
        store.discard()
        assertFalse(spillPath("tid5").exists())
    }

    @Test
    fun copyRangeRefusesToOverwriteExistingDestination() {
        val store = ChunkSpillStore(tmp.root, "tid-existing-output")
        store.write(0, 4, byteArrayOf(1, 2, 3, 4))
        val destination = File(tmp.root, "valuable.bin")
        destination.writeBytes(byteArrayOf(9, 9, 9))

        assertFalse(store.copyRangeToFile(0, 4, destination))
        assertArrayEquals(byteArrayOf(9, 9, 9), destination.readBytes())
    }

    @Test
    fun readRangeRejectsOverflowingEndOffset() {
        val store = ChunkSpillStore(tmp.root, "tid-overflow")
        store.write(0, 4, byteArrayOf(1, 2, 3, 4))
        assertNull(store.readRange(Long.MAX_VALUE, 2))
    }

    @Test
    fun rejectsATransferIdThatCouldEscapeTheSpillDirectory() {
        // The id is written to before Af2LedgerStore.create validates it, so
        // the spill store must reject a traversing id itself.
        for (hostile in listOf("../../evil", "a/b", "a\\b", "tid x", "tid\u0000x", "x".repeat(65))) {
            try {
                ChunkSpillStore(tmp.root, hostile)
                throw AssertionError("expected rejection of transfer id: $hostile")
            } catch (_: IllegalArgumentException) {
                // expected
            }
        }
        // The documented empty-id fallback and ordinary hex ids still work.
        ChunkSpillStore(tmp.root, "")
        ChunkSpillStore(tmp.root, "a1b2c3")
    }

    @Test
    fun rejectsChunkIndexOutsideProtocolBudgetBeforeCreatingSparseFile() {
        val store = ChunkSpillStore(tmp.root, "tid-index-cap")

        try {
            store.write(131_072, 32 * 1024 * 1024, byteArrayOf(1))
            throw AssertionError("expected out-of-protocol index rejection")
        } catch (_: IllegalArgumentException) {
            // expected
        }

        assertFalse(spillPath("tid-index-cap").exists())
    }
}
