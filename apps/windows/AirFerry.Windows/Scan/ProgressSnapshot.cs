using System.Text.Json;

namespace AirFerry.Windows.Scan;

/// <summary>
/// Full progress snapshot parsed from the on-demand JSON returned by
/// <c>ReceiverProgressJson</c>. Mirrors <c>ReceiverSessionManager.kt::Progress</c>
/// field-for-field; the JSON keys are emitted by <c>cffi.rs::progress_json</c>
/// (identical to <c>jni.rs::progress_json</c>).
/// </summary>
/// <remarks>
/// Intended to be fetched at the UI refresh cadence (~7 Hz), NOT per-frame —
/// per-frame status uses the cheaper packed <see cref="IngestStatus"/> word.
/// </remarks>
public readonly record struct ProgressSnapshot(
    int DecodedSymbols,
    int TotalSymbols,
    int ReceivedSymbols,
    long FramesSeen,
    long FramesDropped,   // frames_duplicate + frames_corrupt (see Parse).
    long FramesCorrupt,
    int DecodedBlocks,
    int TotalBlocks,
    double DecodedFraction,
    double LossRatio,
    bool Complete,
    bool MetaConfirmed,
    int SessionMismatchStreak)
{
    /// <summary>
    /// Parse the progress JSON. Uses <see cref="JsonDocument"/> (zero shared
    /// state, pooled buffers) rather than a generated context, because the
    /// schema is tiny and stable.
    /// </summary>
    public static ProgressSnapshot Parse(string json)
    {
        using JsonDocument doc = JsonDocument.Parse(json);
        JsonElement root = doc.RootElement;
        long framesDuplicate = root.GetLong("frames_duplicate");
        long framesCorrupt = root.GetLong("frames_corrupt");
        return new ProgressSnapshot(
            DecodedSymbols: root.GetInt("decoded_symbols"),
            TotalSymbols: root.GetInt("total_symbols"),
            ReceivedSymbols: root.GetInt("received_symbols"),
            FramesSeen: root.GetLong("frames_seen"),
            // The Rust JSON emits frames_duplicate + frames_corrupt separately
            // (no frames_dropped key). Treat "dropped" as their union — every
            // seen frame that contributed no new data — which is what the
            // loss_ratio already reflects. Same convention as the Kotlin side.
            FramesDropped: SaturatingAdd(framesDuplicate, framesCorrupt),
            FramesCorrupt: framesCorrupt,
            DecodedBlocks: root.GetInt("decoded_blocks"),
            TotalBlocks: root.GetInt("total_blocks"),
            DecodedFraction: root.GetDouble("decoded_fraction"),
            LossRatio: root.GetDouble("loss_ratio"),
            Complete: root.GetBool("complete"),
            MetaConfirmed: root.GetBool("meta_confirmed", defaultValue: false),
            SessionMismatchStreak: root.GetInt("session_mismatch_streak", defaultValue: 0));
    }

    private static long SaturatingAdd(long left, long right)
    {
        if (right > 0 && left > long.MaxValue - right) return long.MaxValue;
        if (right < 0 && left < long.MinValue - right) return long.MinValue;
        return left + right;
    }
}

internal static class JsonElementExtensions
{
    // The progress JSON carries Rust u32/u64 counters derived from an
    // attacker-declared ROOT frame (total_symbols follows total_raw_size).
    // GetInt32/GetInt64 THROW on a number past their range, and this parse
    // runs inside the DispatcherTimer tick with no dispatcher-level handler —
    // one crafted ROOT frame would kill the process. Saturate instead: a
    // pinned-maximum progress bar is a display artefact, a crash is not.
    public static int GetInt(this JsonElement e, string name, int defaultValue = 0)
    {
        if (!e.TryGetProperty(name, out JsonElement p) || p.ValueKind != JsonValueKind.Number)
        {
            return defaultValue;
        }
        if (p.TryGetInt32(out int value))
        {
            return value;
        }
        // Out of int range: clamp to the nearer bound rather than throwing.
        return p.TryGetInt64(out long wide) && wide < 0 ? int.MinValue : int.MaxValue;
    }

    public static long GetLong(this JsonElement e, string name, long defaultValue = 0)
    {
        if (!e.TryGetProperty(name, out JsonElement p) || p.ValueKind != JsonValueKind.Number)
        {
            return defaultValue;
        }
        if (p.TryGetInt64(out long value))
        {
            return value;
        }
        // A u64 past long.MaxValue (or any other unrepresentable number).
        return p.TryGetDouble(out double approx) && approx < 0 ? long.MinValue : long.MaxValue;
    }

    public static double GetDouble(this JsonElement e, string name, double defaultValue = 0.0) =>
        e.TryGetProperty(name, out JsonElement p) && p.ValueKind == JsonValueKind.Number
            ? (p.TryGetDouble(out double value) ? value : defaultValue) : defaultValue;

    public static bool GetBool(this JsonElement e, string name, bool defaultValue = false) =>
        e.TryGetProperty(name, out JsonElement p) && p.ValueKind is JsonValueKind.True or JsonValueKind.False
            ? p.GetBoolean() : defaultValue;
}
