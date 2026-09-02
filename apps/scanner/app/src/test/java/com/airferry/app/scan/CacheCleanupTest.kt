package com.airferry.app.scan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class CacheCleanupTest {
    @get:Rule
    val tmp = TemporaryFolder()

    @Test
    fun startupPurgeKeepsCommitFailureCopiesAndDeletesInterruptedAttempts() {
        val root = tmp.newFolder("af2-entry-stage")
        val interrupted = java.io.File(root, "interrupted").apply { mkdirs() }
        java.io.File(interrupted, "member.partial").writeBytes(byteArrayOf(1))
        val preserved = java.io.File(root, "preserved").apply { mkdirs() }
        val recovered = java.io.File(preserved, "member.partial").apply {
            writeBytes(byteArrayOf(2, 3))
        }
        PendingRecoveryStore.persist(
            preserved,
            listOf(ContentStore.PutFileRequest(
                "member.bin", recovered, expectedSize = 2, stableEntryId = "retry-0",
            )),
        )
        val legacyFlatTemp = java.io.File(root, "legacy.partial").apply {
            writeBytes(byteArrayOf(4))
        }
        val committedShell = java.io.File(root, "committed-shell").apply { mkdirs() }
        val consumed = java.io.File(committedShell, "member.partial").apply {
            writeBytes(byteArrayOf(5))
        }
        PendingRecoveryStore.persist(
            committedShell,
            listOf(ContentStore.PutFileRequest(
                "done.bin", consumed, expectedSize = 1, stableEntryId = "done-0",
            )),
        )
        consumed.delete()

        assertEquals(3, CacheCleanup.purgeInterruptedEntryStages(root))
        assertFalse(interrupted.exists())
        assertFalse(legacyFlatTemp.exists())
        assertFalse(committedShell.exists())
        assertTrue(recovered.isFile)
        assertTrue(root.isDirectory)
    }

    @Test
    fun pendingManifestRoundTripsLogicalPublicationMetadata() {
        val stage = tmp.newFolder("stage")
        val first = java.io.File(stage, "000000.partial").apply { writeBytes(byteArrayOf(1, 2)) }
        val second = java.io.File(stage, "000001.partial").apply { writeBytes(byteArrayOf(3)) }
        PendingRecoveryStore.persist(stage, listOf(
            ContentStore.PutFileRequest(
                "dir/a.bin", first, kind = "file", bundleId = "bundle-a",
                bundleTitle = "Bundle A", expectedSize = 2, stableEntryId = "attempt-0",
            ),
            ContentStore.PutFileRequest(
                "dir/b.txt", second, kind = "text", bundleId = "bundle-a",
                bundleTitle = "Bundle A", expectedSize = 1, stableEntryId = "attempt-1",
            ),
        ))

        val restored = PendingRecoveryStore.readRequests(stage)!!

        assertEquals(listOf("attempt-0", "attempt-1"), restored.map { it.stableEntryId })
        assertEquals(listOf("dir/a.bin", "dir/b.txt"), restored.map { it.displayName })
        assertEquals(listOf(2L, 1L), restored.map { it.expectedSize })
        assertTrue(restored.all { it.bundleId == "bundle-a" })
    }
}
