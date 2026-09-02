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
 * §12 crash-gap tests for the JSONL resume journal (plan E2): atomic header,
 * commit/invalidate ordering, torn-tail tolerance, and headerless rejection.
 * Invariant under test: the journal never reports MORE completed chunks than
 * reached the disk ("账本完成 ⇒ 数据已落盘" is the caller's ordering rule).
 */
class Af2LedgerStoreTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val root = ByteArray(26) { 0xAF.toByte() } // stand-in ROOT frame bytes
    private val chunkRawSize = 8 * 1024 * 1024

    @Test
    fun createWritesHeaderAtomically() {
        val store = Af2LedgerStore.create(tmp.root, "tid-a", chunkRawSize, root)
        assertEquals("tid-a", store.transferIdHex)
        assertTrue(store.recoveryId.isNotBlank())
        assertEquals(chunkRawSize, store.chunkRawSize)
        assertArrayEquals(root, store.rootFrameBytes)
        // Reload from disk as a fresh process would.
        val reloaded = Af2LedgerStore.loadMostRecent(tmp.root)!!
        assertEquals("tid-a", reloaded.transferIdHex)
        assertEquals(store.recoveryId, reloaded.recoveryId)
        assertEquals(chunkRawSize, reloaded.chunkRawSize)
        assertArrayEquals(root, reloaded.rootFrameBytes)
    }

    @Test
    fun sameTransferCreateReplacesDurableLedgerOnlyAfterNewHeaderIsReady() {
        val old = Af2LedgerStore.create(tmp.root, "tid-relock", chunkRawSize, root)
        val oldRecoveryId = old.recoveryId
        old.commit(4)
        val replacementRoot = ByteArray(30) { 0x42 }

        Af2LedgerStore.create(tmp.root, "tid-relock", chunkRawSize, replacementRoot)

        val reloaded = Af2LedgerStore.loadMostRecent(tmp.root)!!
        assertArrayEquals(replacementRoot, reloaded.rootFrameBytes)
        assertTrue(reloaded.recoveryId != oldRecoveryId)
        assertArrayEquals(intArrayOf(), reloaded.completedIndices)
        assertTrue(
            tmp.root.listFiles()?.none {
                it.name.startsWith("af2-tid-relock.ledger.jsonl.") && it.name.endsWith(".tmp")
            } == true
        )
    }

    @Test
    fun commitInvalidateRoundTrip() {
        val store = Af2LedgerStore.create(tmp.root, "tid-b", chunkRawSize, root)
        store.commit(2)
        store.commit(5)
        store.commit(9)
        store.invalidate(5)
        val reloaded = Af2LedgerStore.loadMostRecent(tmp.root)!!
        assertArrayEquals(intArrayOf(2, 9), reloaded.completedIndices)
    }

    @Test
    fun tornTailLineIsSkipped() {
        // Crash mid-append: the last line is a partial JSON fragment. It must
        // be skipped so the journal never reports more than reached the disk.
        val store = Af2LedgerStore.create(tmp.root, "tid-c", chunkRawSize, root)
        store.commit(1)
        store.commit(3)
        File(tmp.root, "af2-tid-c.ledger.jsonl").appendText("{\"c\":")
        val reloaded = Af2LedgerStore.loadMostRecent(tmp.root)!!
        assertArrayEquals(intArrayOf(1, 3), reloaded.completedIndices)
        assertTrue(File(tmp.root, "af2-tid-c.ledger.jsonl").readText().endsWith("\n"))
    }

    @Test
    fun completeUnterminatedRecordIsTruncatedBeforeLaterAppends() {
        val store = Af2LedgerStore.create(tmp.root, "tid-unsealed", chunkRawSize, root)
        store.commit(1)
        val journal = File(tmp.root, "af2-tid-unsealed.ledger.jsonl")
        journal.appendText("{\"c\":2}")

        val resumed = Af2LedgerStore.loadMostRecent(tmp.root)!!
        assertArrayEquals(intArrayOf(1), resumed.completedIndices)
        resumed.commit(3)

        val reloaded = Af2LedgerStore.loadMostRecent(tmp.root)!!
        assertArrayEquals(intArrayOf(1, 3), reloaded.completedIndices)
    }

    @Test
    fun malformedFinalRecordWithNewlineIsRejected() {
        val store = Af2LedgerStore.create(tmp.root, "tid-tail", chunkRawSize, root)
        store.commit(1)
        File(tmp.root, "af2-tid-tail.ledger.jsonl").appendText("{bad\n")

        assertNull(Af2LedgerStore.loadMostRecent(tmp.root))
    }

    @Test
    fun corruptionBeforeTailRejectsCandidate() {
        val store = Af2LedgerStore.create(tmp.root, "tid-mid", chunkRawSize, root)
        store.commit(1)
        File(tmp.root, "af2-tid-mid.ledger.jsonl").appendText("{bad\n{\"c\":2}\n")
        assertNull(Af2LedgerStore.loadMostRecent(tmp.root))
    }

    @Test
    fun headerTransferIdMustMatchLedgerFileName() {
        val rootHex = root.joinToString("") { "%02x".format(it) }
        File(tmp.root, "af2-tid-file.ledger.jsonl").writeText(
            "{\"v\":1,\"tid\":\"tid-other\",\"crs\":$chunkRawSize,\"root\":\"$rootHex\"}\n"
        )
        assertNull(Af2LedgerStore.loadMostRecent(tmp.root))
    }

    @Test
    fun orphanSweepDoesNotDeleteNonAf2LedgerFiles() {
        val unrelated = File(tmp.root, "notes.ledger.jsonl").apply { writeText("private data") }
        val malformedNamespace = File(tmp.root, "af2-bad id.ledger.jsonl").apply {
            writeText("private data")
        }

        Af2LedgerStore.sweepOrphanPartials(tmp.root)

        assertTrue(unrelated.isFile)
        assertTrue(malformedNamespace.isFile)
    }

    @Test
    fun legacyHeaderUsesTransferIdAsRecoveryFallback() {
        val rootHex = root.joinToString("") { "%02x".format(it) }
        File(tmp.root, "af2-tid-legacy.ledger.jsonl").writeText(
            "{\"v\":1,\"tid\":\"tid-legacy\",\"crs\":$chunkRawSize,\"root\":\"$rootHex\"}\n"
        )

        val reloaded = Af2LedgerStore.loadMostRecent(tmp.root)!!
        assertEquals("tid-legacy", reloaded.recoveryId)
    }

    @Test
    fun commitRejectsOutOfProtocolIndex() {
        val store = Af2LedgerStore.create(tmp.root, "tid-index", chunkRawSize, root)
        var failed = false
        try {
            store.commit(131_072)
        } catch (_: IllegalArgumentException) {
            failed = true
        }
        assertTrue(failed)
        assertArrayEquals(intArrayOf(), store.completedIndices)
    }

    @Test
    fun headerlessJournalIsRejected() {
        // Crash before the atomic header rename: a journal with commit lines
        // but no header must not be accepted as a resume source.
        File(tmp.root, "af2-tid-d.ledger.jsonl").writeText("{\"c\":0}\n")
        assertNull(Af2LedgerStore.loadMostRecent(tmp.root))
    }

    @Test
    fun tmpHeaderLeftoverIsIgnored() {
        // Crash between temp write and rename leaves `<name>.ledger.jsonl.tmp`;
        // loadMostRecent only considers the real `.ledger.jsonl` suffix.
        File(tmp.root, "af2-tid-e.ledger.jsonl.tmp").writeText("{\"v\":1}\n")
        assertNull(Af2LedgerStore.loadMostRecent(tmp.root))
    }

    @Test
    fun corruptNewestJournalFallsBackToOlderValidOne() {
        val old = Af2LedgerStore.create(tmp.root, "tid-old", chunkRawSize, root)
        old.commit(1)
        File(tmp.root, "af2-tid-old.ledger.jsonl").setLastModified(1_000L)
        val corrupt = File(tmp.root, "af2-tid-new.ledger.jsonl")
        corrupt.writeText("not-json\n")
        corrupt.setLastModified(2_000L)

        val loaded = Af2LedgerStore.loadMostRecent(tmp.root)!!
        assertEquals("tid-old", loaded.transferIdHex)
        assertArrayEquals(intArrayOf(1), loaded.completedIndices)
    }

    @Test
    fun invalidHexNewestJournalFallsBackToOlderValidOne() {
        val old = Af2LedgerStore.create(tmp.root, "tid-old", chunkRawSize, root)
        old.commit(1)
        File(tmp.root, "af2-tid-old.ledger.jsonl").setLastModified(1_000L)
        File(tmp.root, "af2-tid-new.ledger.jsonl").apply {
            writeText("{\"v\":1,\"tid\":\"tid-new\",\"crs\":$chunkRawSize,\"root\":\"zz\"}\n")
            setLastModified(2_000L)
        }

        val loaded = Af2LedgerStore.loadMostRecent(tmp.root)!!
        assertEquals("tid-old", loaded.transferIdHex)
    }

    @Test
    fun fractionalNumbersAreRejectedWithoutTruncation() {
        val rootHex = root.joinToString("") { "%02x".format(it) }
        File(tmp.root, "af2-tid-fraction.ledger.jsonl").writeText(
            "{\"v\":1,\"tid\":\"tid-fraction\",\"crs\":${chunkRawSize}.5,\"root\":\"$rootHex\"}\n"
        )
        assertNull(Af2LedgerStore.loadMostRecent(tmp.root))
    }

    @Test
    fun failedReloadClearsStateAndPreventsFurtherAppends() {
        val store = Af2LedgerStore.create(tmp.root, "tid-reload", chunkRawSize, root)
        File(tmp.root, "af2-tid-reload.ledger.jsonl").writeText("bad\n")

        assertFalse(store.reload())
        assertEquals("", store.transferIdHex)
        assertArrayEquals(ByteArray(0), store.rootFrameBytes)
        var failed = false
        try {
            store.commit(1)
        } catch (_: java.io.IOException) {
            failed = true
        }
        assertTrue(failed)
    }

    @Test
    fun failedCommitDoesNotAdvanceInMemoryLedger() {
        val store = Af2LedgerStore.create(tmp.root, "tid-fail", chunkRawSize, root)
        val journal = File(tmp.root, "af2-tid-fail.ledger.jsonl")
        assertTrue(journal.delete())
        assertTrue(journal.mkdir()) // Appending a FileOutputStream to a directory must fail.

        var failed = false
        try {
            store.commit(7)
        } catch (_: Exception) {
            failed = true
        }
        assertTrue("commit must propagate durable-write failure", failed)
        assertArrayEquals(intArrayOf(), store.completedIndices)
    }

    @Test
    fun orphanSweepKeepsOnlyPartialsReferencedByValidLedgers() {
        Af2LedgerStore.create(tmp.root, "tid-live", chunkRawSize, root)
        val live = File(tmp.root, "af2-tid-live.partial").apply { writeBytes(byteArrayOf(1)) }
        val orphan = File(tmp.root, "af2-tid-orphan.partial").apply { writeBytes(byteArrayOf(2)) }
        val badJournal = File(tmp.root, "af2-tid-bad.ledger.jsonl").apply { writeText("bad") }
        val badPartial = File(tmp.root, "af2-tid-bad.partial").apply { writeBytes(byteArrayOf(3)) }

        Af2LedgerStore.sweepOrphanPartials(tmp.root)

        assertTrue(live.exists())
        assertFalse(orphan.exists())
        assertFalse(badJournal.exists())
        assertFalse(badPartial.exists())
    }
}
