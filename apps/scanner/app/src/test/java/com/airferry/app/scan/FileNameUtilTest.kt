package com.airferry.app.scan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FileNameUtilTest {
    @Test
    fun removesTraversalAndIllegalCharactersButKeepsUnicode() {
        assertEquals("报告 2026（终稿）.txt", FileNameUtil.sanitize("../../报告 2026（终稿）.txt"))
        assertEquals("a_b_c_.txt", FileNameUtil.sanitize("a:b?c*.txt"))
        assertEquals("received_file", FileNameUtil.sanitize("../.."))
    }

    @Test
    fun truncationNeverSplitsSurrogatePairs() {
        // 199 'A' + one emoji (surrogate pair): the cut at 200 chars lands
        // between the pair. Match Windows by retaining the filename prefix
        // and backing up one code unit so the pair is dropped whole.
        val name = "A".repeat(199) + "😀" + "tail"
        val sanitized = FileNameUtil.sanitize(name)
        assertEquals("A".repeat(199), sanitized)
        assertFalse(Character.isHighSurrogate(sanitized.last()))
    }

    @Test
    fun truncationKeepsStablePrefixInsteadOfAttackerControlledTail() {
        val name = "prefix-" + "A".repeat(193) + "attacker-tail"
        val sanitized = FileNameUtil.sanitize(name)
        assertEquals("prefix-" + "A".repeat(193), sanitized)
        assertTrue(sanitized.startsWith("prefix-"))
        assertFalse(sanitized.endsWith("attacker-tail"))
    }

    @Test
    fun relativePathSanitizationPreservesHierarchyWithoutTraversal() {
        assertEquals(
            "目录/子目录/报告 2026.txt",
            FileNameUtil.sanitizeRelativePath("目录/子目录/报告 2026.txt"),
        )
        assertEquals(
            "escape/a_b.txt",
            FileNameUtil.sanitizeRelativePath("../escape/a:b.txt"),
        )
    }
}
