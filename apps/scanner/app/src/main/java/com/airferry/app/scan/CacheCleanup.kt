package com.airferry.app.scan

import android.content.Context
import android.util.Log
import java.io.File

/**
 * App-cache housekeeping for **legacy** recovery temps and share staging.
 *
 * Modern transfers use [ContentStore] under `files/store/` (not purged here).
 * This cleans leftover `cacheDir/recovered_*`, `cacheDir/share/` from older
 * builds, and `cacheDir/af2-entry-stage/` temps from interrupted stagings.
 */
object CacheCleanup {

    private const val TAG = "CacheCleanup"
    private const val PREFS = "airferry_cache"
    private const val KEY_SHARE_DIRTY = "share_dirty"
    private const val SHARE_DIR = "share"
    private const val RECOVERED_PREFIX = "recovered_"
    private const val ENTRY_STAGE_DIR = "af2-entry-stage"

    /** Optional: mark that a legacy share staging dir was used. */
    fun markShareDirty(context: Context) {
        context.applicationContext
            .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(KEY_SHARE_DIRTY, true)
            .apply()
    }

    fun purgeOnAppStart(context: Context) {
        val app = context.applicationContext
        val cache = app.cacheDir ?: return
        val prefs = app.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val shareDirty = prefs.getBoolean(KEY_SHARE_DIRTY, false)

        var removed = 0
        // Serialize with recovery staging / manual 断点清理 (TransferMaintenance):
        // this runs at app start while a resumed transfer's recovery may
        // already be streaming from the very files being swept.
        synchronized (TransferMaintenance.lock) {
            try {
                cache.listFiles()?.forEach { f ->
                    if (f.name.startsWith(RECOVERED_PREFIX)) {
                        if (f.deleteRecursively()) removed++
                    }
                }
                // Always try to clear share/ if present (legacy staging).
                val share = File(cache, SHARE_DIR)
                if (share.exists() && (shareDirty || (share.list()?.isNotEmpty() == true))) {
                    if (share.deleteRecursively()) removed++
                }
                if (shareDirty) {
                    prefs.edit().putBoolean(KEY_SHARE_DIRTY, false).apply()
                }
                // Complete+fsync'd receive entries carry a retry manifest.
                // Replay those transactions before deciding which staging
                // directories are merely interrupted garbage.
                val retried = PendingRecoveryStore.retryAll(app)
                if (retried.imported + retried.alreadyCommitted > 0) {
                    Log.i(TAG, "recovered ${retried.imported} pending publication(s), " +
                        "cleaned ${retried.alreadyCommitted} committed shell(s)")
                }
                // Interrupted §13 entry staging leaves per-attempt directories
                // behind. Remove incomplete attempts, but retain a `.keep`-marked
                // directory: it contains complete files restored after a failed
                // ContentStore index commit and may be the only recovery copy.
                val entryStage = File(cache, ENTRY_STAGE_DIR)
                removed += purgeInterruptedEntryStages(entryStage)
            } catch (e: Exception) {
                Log.w(TAG, "purgeOnAppStart failed", e)
            }
            Unit // synchronized's block is () -> R — pin R = Unit so the
                 // trailing if-statements above stay statements, not expressions
        } // synchronized (TransferMaintenance.lock)
        if (removed > 0) {
            Log.i(TAG, "purged $removed legacy cache entr(y/ies)")
        }
    }

    /** Delete interrupted/partial staging attempts while retaining complete
     * rollback copies explicitly marked by the recovery publisher. */
    internal fun purgeInterruptedEntryStages(entryStage: File): Int {
        var removed = 0
        entryStage.listFiles()?.forEach { attempt ->
            // A marker-only shell can remain if the process died just after
            // ContentStore committed and consumed every source. Do not retain
            // that empty directory forever.
            val keepMarker = File(attempt, PendingRecoveryStore.MANIFEST_NAME).isFile ||
                File(attempt, ".keep").isFile // legacy builds lacked retry metadata
            val keep = attempt.isDirectory && keepMarker &&
                attempt.walkTopDown().any { it.isFile && it.name.endsWith(".partial") }
            if (!keep && attempt.deleteRecursively()) removed++
        }
        if (entryStage.listFiles()?.isEmpty() == true) entryStage.delete()
        return removed
    }
}
