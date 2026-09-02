package com.airferry.app.scan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class IngestStatusTest {
    @Test
    fun unpacksNativeStatusBits() {
        val word = (1234L shl 32) or (17L shl 8) or 0b11L
        val status = requireNotNull(ReceiverSessionManager.IngestStatus.unpack(word))

        assertTrue(status.complete)
        assertTrue(status.accepted)
        assertEquals(17, status.mismatchStreak)
        assertEquals(1234, status.receivedSymbols)
    }

    @Test
    fun rejectsNativeErrorSentinel() {
        assertNull(ReceiverSessionManager.IngestStatus.unpack(-1L shl 32))
        val status = requireNotNull(ReceiverSessionManager.IngestStatus.unpack(0L))
        assertFalse(status.complete)
        assertFalse(status.accepted)
    }

    @Test
    fun destroyedManagerCannotBeResumed() {
        val manager = ReceiverSessionManager()
        manager.destroy()

        // This must return before touching NativeBridge: the unit-test process
        // deliberately has no Android JNI library loaded.
        assertFalse(manager.resume(byteArrayOf(1), intArrayOf()))
        assertFalse(manager.isInitialized)
    }
}
