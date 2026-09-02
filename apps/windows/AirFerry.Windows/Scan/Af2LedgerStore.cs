using System.IO;
using System.Text;
using System.Text.Json;

namespace AirFerry.Windows.Scan;

/// <summary>
/// Crash-safe §12 resume ledger — the journal twin of <see cref="ChunkSpillStore"/>'s
/// <c>.partial</c> file. JSONL, one file per transfer (<c>af2-&lt;tid&gt;.ledger.jsonl</c>):
/// <para>
/// Line 1 (header): <c>{"v":1,"tid":…,"rid":…,"root":…,"crs":…}</c> — <c>rid</c>
/// identifies this receive attempt (legacy headers omit it); written atomically
/// (temp + flush + rename) before the first chunk commit. Each later line is
/// <c>{"c":i}</c> (chunk committed after its bytes were pwrite+fsync'd into the
/// spill) or <c>{"i":i}</c> (chunk invalidated after a re-verification failure).
/// Only a torn final line is skipped; earlier corruption rejects the candidate,
/// so the journal never reports more than what reached the disk.
/// </para>
/// <para>
/// Only touched from the pool's serialized ingest callback (under
/// <c>IngestLock</c>) and the recovery core that runs under the same lock.
/// </para>
/// </summary>
public sealed class Af2LedgerStore
{
    private const int MaxChunkCount = 131_072;
    private const long MaxLedgerBytes = 32L * 1024 * 1024;
    private const int MaxRootFrameBytes = 26 + 2400 + 4;
    private static readonly HashSet<int> LegalChunkRawSizes =
        [1 << 20, 2 << 20, 4 << 20, 8 << 20, 16 << 20, 32 << 20];

    private readonly string _path;
    public string TransferIdHex { get; private set; } = "";
    /// <summary>Identity of one receive attempt; survives restart but changes
    /// when the same Transfer is intentionally received again.</summary>
    public string RecoveryId { get; private set; } = "";
    public int ChunkRawSize { get; private set; }
    public byte[] RootFrameBytes { get; private set; } = Array.Empty<byte>();
    public SortedSet<int> Completed { get; } = new();

    private Af2LedgerStore(string path)
    {
        _path = path;
    }

    /// <summary>True once the header line is durably on disk (set by Create).</summary>
    private bool _headerDurable;

    public int[] CompletedIndices => Completed.ToArray();

    /// <summary>Parse (or re-parse) the journal. True when a valid header exists.</summary>
    public bool Reload()
    {
        Completed.Clear();
        TransferIdHex = "";
        RecoveryId = "";
        ChunkRawSize = 0;
        RootFrameBytes = [];
        _headerDurable = false;
        if (!File.Exists(_path))
        {
            return false;
        }
        long originalByteLength = new FileInfo(_path).Length;
        if (originalByteLength > MaxLedgerBytes) return false;
        string text;
        try
        {
            text = File.ReadAllText(_path);
        }
        catch (IOException)
        {
            return false;
        }
        bool tailTerminated = text.EndsWith('\n');
        string durableText;
        if (tailTerminated)
        {
            durableText = text;
        }
        else
        {
            int lastNewline = text.LastIndexOf('\n');
            if (lastNewline < 0) return false;
            durableText = text[..(lastNewline + 1)];
        }
        var records = durableText.Split('\n').ToList();
        if (records.Count > 0 && records[^1].Length == 0)
            records.RemoveAt(records.Count - 1);
        // Blank physical records are corruption, not ignorable whitespace.
        // Only a malformed final fragment without its newline can be a torn
        // append; accepting a newline-terminated bad record can hide an
        // invalidation and resurrect corrupt spill bytes.
        if (records.Count == 0 || records.Any(string.IsNullOrWhiteSpace)) return false;

        JsonElement header;
        try
        {
            using JsonDocument doc = JsonDocument.Parse(records[0]);
            header = doc.RootElement.Clone();
        }
        catch (JsonException)
        {
            return false;
        }
        if (header.ValueKind != JsonValueKind.Object) return false;
        string? fileTid = TransferIdFromLedgerName(Path.GetFileName(_path));
        JsonProperty[] headerProperties = header.EnumerateObject().ToArray();
        string parsedTid = header.TryGetProperty("tid", out JsonElement tid) &&
            tid.ValueKind == JsonValueKind.String
            ? tid.GetString() ?? "" : "";
        bool hasRecoveryId = header.TryGetProperty("rid", out JsonElement rid);
        string parsedRecoveryId = hasRecoveryId && rid.ValueKind == JsonValueKind.String
            ? rid.GetString() ?? ""
            : hasRecoveryId ? "" : parsedTid;
        int parsedChunkRawSize = header.TryGetProperty("crs", out JsonElement crs) &&
            crs.TryGetInt32(out int crsValue) ? crsValue : 0;
        string rootHex = header.TryGetProperty("root", out JsonElement root) &&
            root.ValueKind == JsonValueKind.String
            ? root.GetString() ?? "" : "";
        byte[] parsedRoot = rootHex.Length <= MaxRootFrameBytes * 2
            ? HexToBytes(rootHex) : [];
        if (headerProperties.Length != (hasRecoveryId ? 5 : 4) ||
            !header.TryGetProperty("v", out JsonElement version) ||
            !version.TryGetInt32(out int versionValue) || versionValue != 1 ||
            fileTid is null || !string.Equals(parsedTid, fileTid, StringComparison.Ordinal) ||
            !IsSafeRecoveryId(parsedRecoveryId) ||
            !LegalChunkRawSizes.Contains(parsedChunkRawSize) ||
            parsedRoot.Length == 0)
        {
            return false;
        }

        var parsedCompleted = new SortedSet<int>();
        for (int position = 1; position < records.Count; position++)
        {
            JsonElement record;
            try
            {
                using JsonDocument doc = JsonDocument.Parse(records[position]);
                record = doc.RootElement.Clone();
            }
            catch (JsonException)
            {
                return false;
            }
            JsonProperty[] properties = record.ValueKind == JsonValueKind.Object
                ? record.EnumerateObject().ToArray() : [];
            if (properties.Length != 1 ||
                !properties[0].Value.TryGetInt32(out int index) ||
                index < 0 || index >= MaxChunkCount)
            {
                return false;
            }
            if (properties[0].NameEquals("c"))
            {
                parsedCompleted.Add(index);
            }
            else if (properties[0].NameEquals("i"))
            {
                parsedCompleted.Remove(index);
            }
            else return false;
        }
        if (!tailTerminated)
        {
            // A newline is the commit delimiter. Drop even a complete JSON
            // object when that delimiter was torn, then fsync the repaired
            // prefix before this resumed store is allowed to append again.
            try
            {
                long durableByteLength = Encoding.UTF8.GetByteCount(durableText);
                using var stream = new FileStream(
                    _path, FileMode.Open, FileAccess.Write, FileShare.None);
                if (stream.Length != originalByteLength) return false;
                stream.SetLength(durableByteLength);
                stream.Flush(flushToDisk: true);
            }
            catch (Exception)
            {
                return false;
            }
        }
        // A journal that reloads with a valid header is durable by definition —
        // resumed transfers keep appending to it.
        TransferIdHex = parsedTid;
        RecoveryId = parsedRecoveryId;
        ChunkRawSize = parsedChunkRawSize;
        RootFrameBytes = parsedRoot;
        Completed.UnionWith(parsedCompleted);
        _headerDurable = true;
        return true;
    }

    /// <summary>Append one commit event (after the chunk was spilled + flushed).</summary>
    public void Commit(int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        if (index >= MaxChunkCount) throw new ArgumentOutOfRangeException(nameof(index));
        if (!_headerDurable)
            throw new IOException("AF2 ledger header is not durable");
        AppendLine($"{{\"c\":{index}}}");
        Completed.Add(index);
    }

    /// <summary>Append one invalidate event (after a re-verification failure).</summary>
    public void Invalidate(int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        if (index >= MaxChunkCount) throw new ArgumentOutOfRangeException(nameof(index));
        if (!_headerDurable)
            throw new IOException("AF2 ledger header is not durable");
        AppendLine($"{{\"i\":{index}}}");
        Completed.Remove(index);
    }

    private void AppendLine(string json)
    {
        using var fs = new FileStream(
            _path, FileMode.Append, FileAccess.Write, FileShare.None);
        byte[] bytes = Encoding.UTF8.GetBytes(json + "\n");
        fs.Write(bytes, 0, bytes.Length);
        fs.Flush(flushToDisk: true);
    }

    /// <summary>Delete the journal (transfer finished / relocked away / abandoned).</summary>
    public void Discard()
    {
        try { File.Delete(_path); } catch (IOException) { }
        _headerDurable = false;
    }

    /// <summary>Delete this journal and its same-transfer spill backing.</summary>
    public void DiscardTransferFiles()
    {
        Discard();
        const string suffix = ".ledger.jsonl";
        if (!_path.EndsWith(suffix, StringComparison.Ordinal)) return;
        string spill = _path[..^suffix.Length] + ".partial";
        try { File.Delete(spill); } catch (IOException) { }
    }

    public record PendingTransfer(
        string TransferIdHex,
        int ChunkRawSize,
        int CompletedCount,
        long DiskBytes,
        DateTime LastModified);

    /// <summary>List all pending/uncompleted transfer ledgers in <paramref name="dir"/>.</summary>
    public static IReadOnlyList<PendingTransfer> ListPendingTransfers(string dir)
    {
        if (!Directory.Exists(dir)) return [];
        try
        {
            var list = new List<PendingTransfer>();
            foreach (var file in Directory.EnumerateFiles(dir, "af2-*.ledger.jsonl"))
            {
                if (TransferIdFromLedgerName(Path.GetFileName(file)) is null) continue;
                var store = new Af2LedgerStore(file);
                if (store.Reload())
                {
                    string tid = store.TransferIdHex;
                    string spill = Path.Combine(dir, $"af2-{tid}.partial");
                    long spillBytes = File.Exists(spill) ? new FileInfo(spill).Length : 0L;
                    var fi = new FileInfo(file);
                    list.Add(new PendingTransfer(
                        tid,
                        store.ChunkRawSize,
                        store.CompletedIndices.Length,
                        fi.Length + spillBytes,
                        fi.LastWriteTime));
                }
            }
            return list.OrderByDescending(p => p.LastModified).ToList();
        }
        catch (Exception)
        {
            return [];
        }
    }

    /// <summary>Discard all pending journals, spills, and temp files in <paramref name="dir"/>.</summary>
    public static void DiscardAllPending(string dir)
    {
        if (!Directory.Exists(dir)) return;
        try
        {
            foreach (var f in Directory.EnumerateFiles(dir, "af2-*"))
            {
                if (f.EndsWith(".ledger.jsonl") || f.EndsWith(".partial") || f.EndsWith(".tmp"))
                {
                    try { File.Delete(f); } catch { }
                }
            }
        }
        catch { }
    }

    /// <summary>Resume source: the newest valid journal in <paramref name="dir"/>.</summary>
    public static Af2LedgerStore? LoadMostRecent(string dir)
    {
        try
        {
            if (!Directory.Exists(dir))
            {
                return null;
            }
            foreach (FileInfo candidate in new DirectoryInfo(dir)
                         .EnumerateFiles("af2-*.ledger.jsonl")
                         .Where(f => TransferIdFromLedgerName(f.Name) is not null)
                         .OrderByDescending(f => f.LastWriteTimeUtc))
            {
                try
                {
                    var store = new Af2LedgerStore(candidate.FullName);
                    if (store.Reload()) return store;
                }
                catch
                {
                    // One malformed candidate must not hide older valid work.
                }
            }
            return null;
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>Remove spill files that have no parseable resume journal.</summary>
    public static void SweepOrphanPartials(string dir)
    {
        if (!Directory.Exists(dir)) return;
        try
        {
            var validTids = new HashSet<string>(StringComparer.Ordinal);
            foreach (string journal in Directory.EnumerateFiles(dir, "af2-*.ledger.jsonl"))
            {
                if (TransferIdFromLedgerName(Path.GetFileName(journal)) is null) continue;
                var store = new Af2LedgerStore(journal);
                if (store.Reload())
                {
                    validTids.Add(store.TransferIdHex);
                }
                else
                {
                    try { File.Delete(journal); } catch { }
                }
            }
            foreach (string partial in Directory.EnumerateFiles(dir, "af2-*.partial"))
            {
                string name = Path.GetFileName(partial);
                string tid = name.Substring(4, name.Length - 4 - ".partial".Length);
                if (!validTids.Contains(tid))
                {
                    try { File.Delete(partial); } catch { }
                }
            }
        }
        catch { }
    }

    /// <summary>Create + atomically write the header for a fresh transfer's journal.</summary>
    public static Af2LedgerStore Create(
        string dir, string transferIdHex, int chunkRawSize, byte[] rootFrameBytes)
    {
        if (!IsSafeTransferId(transferIdHex)) throw new ArgumentException("Invalid AF2 transfer id", nameof(transferIdHex));
        if (!LegalChunkRawSizes.Contains(chunkRawSize)) throw new ArgumentOutOfRangeException(nameof(chunkRawSize));
        if (rootFrameBytes.Length == 0 || rootFrameBytes.Length > MaxRootFrameBytes)
            throw new ArgumentException("Invalid AF2 ROOT frame", nameof(rootFrameBytes));
        string path = Path.Combine(dir, $"af2-{transferIdHex}.ledger.jsonl");
        string recoveryId = Guid.NewGuid().ToString("N");
        string header = JsonSerializer.Serialize(new
        {
            v = 1,
            tid = transferIdHex,
            rid = recoveryId,
            crs = chunkRawSize,
            root = BytesToHex(rootFrameBytes),
        });
        // A unique temp avoids stale/concurrent temp collisions. Keep any
        // existing same-transfer ledger until the new header is flushed and
        // ready to replace it, so a failed relock cannot erase resumable work.
        string tmp = $"{path}.{Guid.NewGuid():N}.tmp";
        try
        {
            Directory.CreateDirectory(dir);
            byte[] bytes = Encoding.UTF8.GetBytes(header + "\n");
            using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                fs.Write(bytes, 0, bytes.Length);
                fs.Flush(flushToDisk: true);
            }
            File.Move(tmp, path, overwrite: true);
        }
        catch (Exception ex)
        {
            try { File.Delete(tmp); } catch { }
            throw new IOException("AF2 ledger header write failed", ex);
        }
        return new Af2LedgerStore(path)
        {
            TransferIdHex = transferIdHex,
            RecoveryId = recoveryId,
            ChunkRawSize = chunkRawSize,
            RootFrameBytes = rootFrameBytes.ToArray(),
            _headerDurable = true,
        };
    }

    private static string BytesToHex(byte[] b)
    {
        var sb = new StringBuilder(b.Length * 2);
        foreach (byte x in b)
        {
            sb.Append(x.ToString("x2"));
        }
        return sb.ToString();
    }

    private static byte[] HexToBytes(string s)
    {
        if (s.Length == 0 || s.Length % 2 != 0)
        {
            return Array.Empty<byte>();
        }
        try { return Convert.FromHexString(s); }
        catch (FormatException) { return Array.Empty<byte>(); }
    }

    private static string? TransferIdFromLedgerName(string name)
    {
        const string prefix = "af2-";
        const string suffix = ".ledger.jsonl";
        if (!name.StartsWith(prefix, StringComparison.Ordinal) ||
            !name.EndsWith(suffix, StringComparison.Ordinal)) return null;
        string id = name[prefix.Length..^suffix.Length];
        return IsSafeTransferId(id) ? id : null;
    }

    internal static bool IsSafeTransferId(string id) =>
        id.Length is >= 1 and <= 64 && id.All(c =>
            char.IsAsciiLetterOrDigit(c) || c is '_' or '-');

    private static bool IsSafeRecoveryId(string id) => IsSafeTransferId(id);
}
