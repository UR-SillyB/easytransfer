using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AirFerry.Windows.Bundle;

/// <summary>
/// Content-addressed store + logical entry index (mirrors Android ContentStore).
/// Layout under Documents/AirFerry/store/:
///   blobs/hh/sha256
///   index.json
/// </summary>
public static class ContentStore
{
    private static readonly object Gate = new();
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
    };

    public sealed record Entry(
        string Id,
        string Name,
        string Hash,
        long Size,
        string CrcHex,
        bool CrcUnknown,
        string Kind,
        long CreatedAt,
        string? BundleId,
        string? BundleTitle);

    public sealed record PutResult(Entry Entry, string Path, bool Deduped);

    public sealed record PutBytesRequest(
        string DisplayName,
        byte[] Bytes,
        string CrcHex = "unknown",
        bool CrcUnknown = true,
        string Kind = "file",
        string? BundleId = null,
        string? BundleTitle = null,
        string? StableEntryId = null);

    public sealed record PutFileRequest(
        string DisplayName,
        string FilePath,
        string CrcHex = "unknown",
        bool CrcUnknown = true,
        string Kind = "file",
        string? BundleId = null,
        string? BundleTitle = null,
        long? ExpectedSize = null,
        string? StableEntryId = null);

    private sealed record PendingPublication(
        string BlobPath,
        bool KeepBlob);

    internal static string? RootDirOverride { get; set; }

    public static string RootDir => RootDirOverride ??
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            "AirFerry", "store");

    private static string IndexPath => Path.Combine(RootDir, "index.json");

    public static string BlobPath(string hash)
    {
        string h = hash.ToLowerInvariant();
        if (h.Length != 64 || h.Any(c => !Uri.IsHexDigit(c)))
        {
            throw new ArgumentException("Invalid SHA-256 hash", nameof(hash));
        }
        string dir = Path.Combine(RootDir, "blobs", h[..2]);
        Directory.CreateDirectory(dir);
        return Path.Combine(dir, h);
    }

    public static string Sha256Hex(byte[] bytes)
    {
        byte[] d = SHA256.HashData(bytes);
        return Convert.ToHexString(d).ToLowerInvariant();
    }

    public static PutResult PutBytes(
        string displayName,
        byte[] bytes,
        string crcHex = "unknown",
        bool crcUnknown = true,
        string kind = "file",
        string? bundleId = null,
        string? bundleTitle = null)
    {
        return PutBytesBatch(
        [
            new PutBytesRequest(
                displayName, bytes, crcHex, crcUnknown, kind, bundleId, bundleTitle)
        ]).Single();
    }

    /// <summary>Archive a bundle with one index read/write instead of O(n²) rewrites.</summary>
    public static IReadOnlyList<PutResult> PutBytesBatch(
        IReadOnlyList<PutBytesRequest> requests)
    {
        if (requests.Count == 0) return [];
        foreach (PutBytesRequest request in requests) ValidateKind(request.Kind);
        string[] stableIds = requests
            .Where(request => request.StableEntryId is not null)
            .Select(request => request.StableEntryId!)
            .ToArray();
        if (stableIds.Any(string.IsNullOrWhiteSpace))
            throw new ArgumentException("Stable content entry id must not be blank");
        if (stableIds.Distinct(StringComparer.Ordinal).Count() != stableIds.Length)
            throw new ArgumentException(
                "Stable content entry ids must be unique within a batch");
        lock (Gate)
        {
            // Fail closed before writing a blob. Treating a corrupt index as an
            // empty history would make the next receive overwrite every logical
            // entry and orphan otherwise-valid content-addressed blobs.
            var all = LoadIndex();
            var priorHashes = all.Select(e => e.Hash).ToHashSet(StringComparer.Ordinal);
            Directory.CreateDirectory(RootDir);
            long createdAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var results = new List<PutResult>(requests.Count);
            var createdBlobs = new List<string>();
            bool indexChanged = false;
            try
            {
                foreach (PutBytesRequest request in requests)
                {
                    string hash = Sha256Hex(request.Bytes);
                    string path = BlobPath(hash);
                    string storedName = request.BundleId is not null
                        ? FileNameUtil.SanitizeRelativePath(request.DisplayName)
                        : FileNameUtil.Sanitize(request.DisplayName);
                    Entry? existing = request.StableEntryId is null
                        ? null
                        : all.FirstOrDefault(e => e.Id == request.StableEntryId);
                    if (existing is not null &&
                        (!string.Equals(existing.Hash, hash, StringComparison.Ordinal) ||
                         existing.Size != request.Bytes.LongLength ||
                         !string.Equals(existing.Name, storedName, StringComparison.Ordinal) ||
                         !string.Equals(existing.Kind, request.Kind, StringComparison.Ordinal) ||
                         !string.Equals(existing.BundleId, request.BundleId,
                             StringComparison.Ordinal)))
                    {
                        throw new InvalidDataException(
                            "stable content entry id conflicts with existing history");
                    }
                    bool deduped = FileMatchesHash(path, hash, request.Bytes.LongLength);
                    if (!deduped)
                    {
                        WriteAllBytesAtomic(path, request.Bytes);
                        createdBlobs.Add(path);
                    }
                    if (existing is not null)
                    {
                        results.Add(new PutResult(existing, path, true));
                        continue;
                    }
                    var entry = new Entry(
                        Id: request.StableEntryId ?? Guid.NewGuid().ToString("N"),
                        Name: storedName,
                        Hash: hash,
                        Size: request.Bytes.LongLength,
                        CrcHex: request.CrcHex,
                        CrcUnknown: request.CrcUnknown,
                        Kind: request.Kind,
                        CreatedAt: createdAt,
                        BundleId: request.BundleId,
                        BundleTitle: request.BundleTitle);
                    all.Add(entry);
                    indexChanged = true;
                    results.Add(new PutResult(entry, path, deduped));
                }
                if (indexChanged) SaveIndex(all);
            }
            catch
            {
                foreach (string blob in createdBlobs)
                {
                    if (!priorHashes.Contains(Path.GetFileName(blob)))
                    {
                        try { File.Delete(blob); } catch { }
                    }
                }
                throw;
            }
            return results;
        }
    }

    /// <summary>
    /// Archive a bundle of pre-staged files with ONE index write so a mid-bundle
    /// disk failure cannot leave a truncated bundle committed to history (and to
    /// avoid O(n²) index rewrites). The index is only saved after every member
    /// has been hashed and copied into the blob tree. Caller-owned staging
    /// paths remain intact until index commit, so abrupt process death cannot
    /// consume the only addressable copy. Blobs referenced by the old index
    /// remain in place; otherwise a failed transaction removes them best-effort.
    /// </summary>
    public static IReadOnlyList<PutResult> PutFileBatch(
        IReadOnlyList<PutFileRequest> requests)
    {
        if (requests.Count == 0) return [];
        foreach (PutFileRequest request in requests) ValidateKind(request.Kind);
        string[] stableIds = requests
            .Where(request => request.StableEntryId is not null)
            .Select(request => request.StableEntryId!)
            .ToArray();
        if (stableIds.Any(string.IsNullOrWhiteSpace))
            throw new ArgumentException("Stable content entry id must not be blank");
        if (stableIds.Distinct(StringComparer.Ordinal).Count() != stableIds.Length)
            throw new ArgumentException(
                "Stable content entry ids must be unique within a batch");
        lock (Gate)
        {
            var all = LoadIndex();
            var priorHashes = all.Select(e => e.Hash).ToHashSet(StringComparer.Ordinal);
            Directory.CreateDirectory(RootDir);
            long createdAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var results = new List<PutResult>(requests.Count);
            var published = new List<PendingPublication>();
            bool indexChanged = false;
            try
            {
                foreach (PutFileRequest request in requests)
                {
                    if (!File.Exists(request.FilePath))
                        throw new FileNotFoundException(
                            "Staged bundle member is missing", request.FilePath);
                    long sourceLength = new FileInfo(request.FilePath).Length;
                    if (request.ExpectedSize is not null && sourceLength != request.ExpectedSize.Value)
                        throw new InvalidDataException("staged file length differs from manifest");
                    string hash = Sha256HexFile(request.FilePath);
                    string path = BlobPath(hash);
                    string storedName = request.BundleId is not null
                        ? FileNameUtil.SanitizeRelativePath(request.DisplayName)
                        : FileNameUtil.Sanitize(request.DisplayName);
                    Entry? existing = request.StableEntryId is null
                        ? null
                        : all.FirstOrDefault(e => e.Id == request.StableEntryId);
                    if (existing is not null &&
                        (!string.Equals(existing.Hash, hash, StringComparison.Ordinal) ||
                         existing.Size != sourceLength ||
                         !string.Equals(existing.Name, storedName, StringComparison.Ordinal) ||
                         !string.Equals(existing.Kind, request.Kind, StringComparison.Ordinal) ||
                         !string.Equals(existing.BundleId, request.BundleId,
                             StringComparison.Ordinal)))
                    {
                        throw new InvalidDataException(
                            "stable content entry id conflicts with existing history");
                    }
                    bool deduped = FileMatchesHash(path, hash, sourceLength);
                    if (!deduped)
                    {
                        PublishFileAtomic(request.FilePath, path, hash, sourceLength);
                        published.Add(new PendingPublication(path, priorHashes.Contains(hash)));
                        if (!File.Exists(path) || new FileInfo(path).Length != sourceLength)
                            throw new IOException("content blob changed during publish");
                    }
                    if (existing is not null)
                    {
                        results.Add(new PutResult(existing, path, true));
                        continue;
                    }
                    var entry = new Entry(
                        Id: request.StableEntryId ?? Guid.NewGuid().ToString("N"),
                        Name: storedName,
                        Hash: hash,
                        Size: sourceLength,
                        CrcHex: request.CrcHex,
                        CrcUnknown: request.CrcUnknown,
                        Kind: request.Kind,
                        CreatedAt: createdAt,
                        BundleId: request.BundleId,
                        BundleTitle: request.BundleTitle);
                    all.Add(entry);
                    indexChanged = true;
                    results.Add(new PutResult(entry, path, deduped));
                }
                if (indexChanged) SaveIndex(all);
            }
            catch
            {
                // Sources remain untouched until SaveIndex commits. Roll back
                // only new unreferenced Blobs; an old-index Blob may have been
                // repaired by this publication and must remain available.
                for (int i = published.Count - 1; i >= 0; i--)
                {
                    if (!published[i].KeepBlob)
                    {
                        try { File.Delete(published[i].BlobPath); } catch { }
                    }
                }
                throw;
            }
            // SaveIndex is the commit point. Every staged source is retained
            // until here, then consumed best-effort.
            for (int i = 0; i < results.Count; i++)
            {
                DeleteSourceAfterCommit(requests[i].FilePath, results[i].Path);
            }
            return results;
        }
    }

    /// <summary>
    /// Archive an existing file (e.g. a fully-assembled large-transfer) into the
    /// content-addressed store by streaming its hash and atomically publishing
    /// a copied Blob. The caller-owned source is consumed only after index
    /// commit, closing the move-before-index process-crash gap.
    /// </summary>
    public static PutResult PutFile(
        string displayName,
        string filePath,
        string crcHex = "unknown",
        bool crcUnknown = true,
        string kind = "file",
        string? bundleId = null,
        string? bundleTitle = null,
        string? expectedSha256Hex = null,
        long? expectedSize = null,
        string? stableEntryId = null)
    {
        ValidateKind(kind);
        if (stableEntryId is not null && string.IsNullOrWhiteSpace(stableEntryId))
            throw new ArgumentException(
                "Stable content entry id must not be blank", nameof(stableEntryId));
        lock (Gate)
        {
            var all = LoadIndex();
            Directory.CreateDirectory(RootDir);
            string? expectedHash = expectedSha256Hex?.ToLowerInvariant();
            if (expectedHash is not null &&
                (expectedHash.Length != 64 || expectedHash.Any(c => !Uri.IsHexDigit(c))))
                throw new ArgumentException("Invalid expected SHA-256 hash",
                    nameof(expectedSha256Hex));
            bool sourceExists = File.Exists(filePath);
            if (!sourceExists && expectedHash is null)
                throw new FileNotFoundException(
                    "Assembled task file is missing and no expected hash can identify its blob",
                    filePath);
            long sourceLength = sourceExists
                ? new FileInfo(filePath).Length
                : expectedSize ?? throw new FileNotFoundException(
                    "Assembled task file is missing and expected size is unavailable", filePath);
            if (expectedSize is not null && sourceLength != expectedSize.Value)
                throw new InvalidDataException("assembled file length differs from manifest");
            string hash = sourceExists ? Sha256HexFile(filePath) : expectedHash!;
            if (expectedHash is not null &&
                !string.Equals(hash, expectedHash, StringComparison.Ordinal))
                throw new InvalidDataException("assembled file SHA-256 differs from manifest");
            string storedName = bundleId is not null
                ? FileNameUtil.SanitizeRelativePath(displayName)
                : FileNameUtil.Sanitize(displayName);
            // Reject a stable-id conflict before publishing caller-owned source
            // data into the content-addressed blob tree.
            Entry? existing = stableEntryId is null
                ? null
                : all.FirstOrDefault(e => e.Id == stableEntryId);
            if (existing is not null &&
                (!string.Equals(existing.Hash, hash, StringComparison.Ordinal) ||
                 existing.Size != sourceLength ||
                 !string.Equals(existing.Name, storedName, StringComparison.Ordinal) ||
                 !string.Equals(existing.Kind, kind, StringComparison.Ordinal) ||
                 !string.Equals(existing.BundleId, bundleId, StringComparison.Ordinal)))
                throw new InvalidDataException(
                    "stable content entry id conflicts with existing history");
            string path = BlobPath(hash);
            bool keepBlobOnRollback = all.Any(e =>
                string.Equals(e.Hash, hash, StringComparison.OrdinalIgnoreCase));
            bool publishedBlob = false;
            bool deduped = FileMatchesHash(path, hash, sourceLength);
            if (!deduped)
            {
                if (!sourceExists)
                    throw new FileNotFoundException(
                        "Assembled source and verified content blob are both missing", filePath);
                try
                {
                    PublishFileAtomic(filePath, path, hash, sourceLength);
                    publishedBlob = true;
                    if (!File.Exists(path) || new FileInfo(path).Length != sourceLength)
                        throw new IOException("content blob changed during publish");
                }
                catch
                {
                    if (publishedBlob && !keepBlobOnRollback)
                    {
                        try { File.Delete(path); } catch { }
                    }
                    throw;
                }
            }
            if (existing is not null)
            {
                DeleteSourceAfterCommit(filePath, path);
                return new PutResult(existing, path, true);
            }
            var entry = new Entry(
                Id: stableEntryId ?? Guid.NewGuid().ToString("N"),
                Name: storedName,
                Hash: hash,
                Size: new FileInfo(path).Length,
                CrcHex: crcHex,
                CrcUnknown: crcUnknown,
                Kind: kind,
                CreatedAt: DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                BundleId: bundleId,
                BundleTitle: bundleTitle);
            all.Add(entry);
            try
            {
                SaveIndex(all);
            }
            catch
            {
                if (publishedBlob && !keepBlobOnRollback)
                {
                    try { File.Delete(path); } catch { }
                }
                throw;
            }
            DeleteSourceAfterCommit(filePath, path);
            return new PutResult(entry, path, deduped);
        }
    }

    /// <summary>Streaming SHA-256 of a file (no full-file in-memory buffer).</summary>
    private static string Sha256HexFile(string path)
    {
        using var sha = System.Security.Cryptography.SHA256.Create();
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read);
        return Convert.ToHexString(sha.ComputeHash(fs)).ToLowerInvariant();
    }

    public static IReadOnlyList<Entry> ListEntries()
    {
        lock (Gate) return LoadIndex();
    }

    public static bool DeleteEntry(string id)
    {
        lock (Gate)
        {
            var all = LoadIndex();
            int idx = all.FindIndex(e => e.Id == id);
            if (idx < 0) return false;
            Entry removed = all[idx];
            all.RemoveAt(idx);
            SaveIndex(all);
            if (all.TrueForAll(e => e.Hash != removed.Hash))
            {
                string p = BlobPath(removed.Hash);
                try
                {
                    if (File.Exists(p)) File.Delete(p);
                }
                catch (Exception ex)
                {
                    // SaveIndex above is the logical commit point. Reporting
                    // failure now invites a retry that can no longer find the
                    // entry, while still doing nothing about the orphan Blob.
                    // Match Android's best-effort post-commit cleanup and leave
                    // the inaccessible Blob for maintenance instead.
                    System.Diagnostics.Trace.TraceWarning(
                        "Could not remove unreferenced content Blob {0}: {1}",
                        p, ex.Message);
                }
            }
            return true;
        }
    }

    public static void ClearAll()
    {
        lock (Gate)
        {
            SaveIndex([]);
            DeleteDirectoryAfterCommit(Path.Combine(RootDir, "blobs"));
            DeleteDirectoryAfterCommit(Path.Combine(RootDir, "seg"));
        }
    }

    /// <summary>Legacy archive directory, retained only for one-time migration.</summary>
    private static string LegacyReceivedDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            "AirFerry", "received");

    /// <summary>Import remaining legacy Documents/AirFerry/received files.</summary>
    public static void MigrateLegacyReceivedIfNeeded()
    {
        lock (Gate)
        {
            string legacy = LegacyReceivedDir;
            if (!Directory.Exists(legacy)) return;
            // Materialize the list before PutFile consumes members after index
            // commit. Do not require an empty new index here: a previous launch
            // may have migrated only a prefix before one legacy file failed.
            // Successfully migrated sources are consumed, so later launches
            // can safely retry the files that remain.
            bool migrationFailed = false;
            foreach (string f in Directory.EnumerateFiles(
                legacy, "*", SearchOption.AllDirectories).ToList())
            {
                if (f.EndsWith(".meta", StringComparison.OrdinalIgnoreCase)) continue;
                try
                {
                    string name = Path.GetFileName(f);
                    PutFile(name, f, expectedSize: new FileInfo(f).Length);
                }
                catch
                {
                    migrationFailed = true;
                }
            }
            if (migrationFailed)
            {
                // Never hide a failed legacy member in a backup directory.
                // Leave it at the well-known path so a later launch retries.
                return;
            }
            try
            {
                string bak = legacy + ".bak." + DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                Directory.Move(legacy, bak);
            }
            catch
            {
                // leave legacy in place if rename fails
            }
        }
    }

    private static List<Entry> LoadIndex()
    {
        if (!File.Exists(IndexPath)) return [];
        try
        {
            string json = File.ReadAllText(IndexPath, Encoding.UTF8);
            List<Entry> entries = JsonSerializer.Deserialize<List<Entry>>(json, JsonOpts)
                ?? throw new InvalidDataException("ContentStore index is null");
            if (entries.Any(e => e is null || string.IsNullOrWhiteSpace(e.Id) ||
                                 string.IsNullOrWhiteSpace(e.Name) || e.Kind is not ("file" or "text") ||
                                 e.Size < 0 || e.Hash is null || e.Hash.Length != 64 ||
                                 !e.Hash.All(Uri.IsHexDigit)) ||
                entries.Select(e => e.Id).Distinct(StringComparer.Ordinal).Count() != entries.Count)
            {
                throw new InvalidDataException("ContentStore index contains an invalid entry");
            }
            // Blob filenames and all new entries use lowercase hashes. Accept
            // legacy uppercase JSON only after canonicalizing it, otherwise
            // reference counting and failed-publication rollback can mistake a
            // live Blob for an unreferenced orphan.
            return entries.Select(e => e with { Hash = e.Hash.ToLowerInvariant() }).ToList();
        }
        catch (Exception ex)
        {
            // The backup path itself touches the filesystem — if the index
            // vanished between the read above and here, re-throwing a raw IO
            // exception would escape as a non-InvalidDataException and crash
            // callers that only guard the corruption case.
            string backup = "";
            try
            {
                backup = Path.Combine(
                    RootDir,
                    $"index.corrupt.{File.GetLastWriteTimeUtc(IndexPath).Ticks}.json");
                if (!File.Exists(backup)) File.Copy(IndexPath, backup, overwrite: false);
            }
            catch
            {
                // Preserve the original index in place even if the backup copy
                // cannot be created (disk full/permissions).
            }
            throw new InvalidDataException(
                $"接收历史索引已损坏，已停止写入以保护现有数据。备份: {backup}", ex);
        }
    }

    private static void SaveIndex(List<Entry> entries)
    {
        Directory.CreateDirectory(RootDir);
        string json = JsonSerializer.Serialize(entries, JsonOpts);
        string temp = Path.Combine(RootDir, $"index.{Guid.NewGuid():N}.tmp");
        try
        {
            byte[] encoded = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false)
                .GetBytes(json);
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write,
                       FileShare.None, 64 * 1024, FileOptions.WriteThrough))
            {
                stream.Write(encoded);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temp, IndexPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temp)) File.Delete(temp);
        }
    }

    private static bool FileMatchesHash(string path, string expectedHash, long expectedSize)
    {
        if (!File.Exists(path) || new FileInfo(path).Length != expectedSize) return false;
        try
        {
            using FileStream stream = File.OpenRead(path);
            string actual = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
            return CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(actual), Encoding.ASCII.GetBytes(expectedHash));
        }
        catch
        {
            return false;
        }
    }

    private static void ValidateKind(string kind)
    {
        if (kind is not ("file" or "text"))
            throw new ArgumentException("Invalid content entry kind", nameof(kind));
    }

    /// <summary>
    /// Best-effort post-commit cleanup. A path-normalization or delete failure
    /// must not turn a successfully indexed publication into a reported error.
    /// </summary>
    private static void DeleteSourceAfterCommit(string source, string blob)
    {
        try
        {
            if (File.Exists(source) && !string.Equals(
                    Path.GetFullPath(source), Path.GetFullPath(blob),
                    StringComparison.OrdinalIgnoreCase))
            {
                File.Delete(source);
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Trace.TraceWarning(
                "Could not clean committed staging file {0}: {1}", source, ex.Message);
        }
    }

    /// <summary>
    /// The empty index is already durable when ClearAll reaches this helper.
    /// Failure can leave only unreachable bytes, so log it without reporting
    /// the completed logical operation as failed.
    /// </summary>
    private static void DeleteDirectoryAfterCommit(string path)
    {
        try
        {
            if (Directory.Exists(path)) Directory.Delete(path, recursive: true);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Trace.TraceWarning(
                "Could not remove unreferenced store directory {0}: {1}", path, ex.Message);
        }
    }

    private static void WriteAllBytesAtomic(string path, byte[] bytes)
    {
        string? dir = Path.GetDirectoryName(path);
        if (dir is null) throw new IOException("Blob path has no directory");
        Directory.CreateDirectory(dir);
        string temp = Path.Combine(dir, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write,
                       FileShare.None, 64 * 1024, FileOptions.WriteThrough))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temp, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temp)) File.Delete(temp);
        }
    }

    /// <summary>Publish through a target-directory temp without consuming the
    /// caller's source before index commit.</summary>
    private static void PublishFileAtomic(
        string source, string target, string expectedHash, long expectedSize)
    {
        string? dir = Path.GetDirectoryName(target);
        if (dir is null) throw new IOException("Blob path has no directory");
        Directory.CreateDirectory(dir);
        string temp = Path.Combine(
            dir, $".{Path.GetFileName(target)}.{Guid.NewGuid():N}.publish");
        try
        {
            using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            long copied = 0;
            using (var input = new FileStream(
                       source, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var output = new FileStream(
                       temp, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                       1024 * 1024, FileOptions.WriteThrough))
            {
                byte[] buffer = new byte[1024 * 1024];
                while (true)
                {
                    int count = input.Read(buffer, 0, buffer.Length);
                    if (count == 0) break;
                    output.Write(buffer, 0, count);
                    digest.AppendData(buffer, 0, count);
                    copied += count;
                }
                output.Flush(flushToDisk: true);
            }
            string copiedHash = Convert.ToHexString(digest.GetHashAndReset()).ToLowerInvariant();
            if (copied != expectedSize ||
                !string.Equals(copiedHash, expectedHash, StringComparison.Ordinal))
            {
                throw new IOException("content source changed during publish");
            }
            File.Move(temp, target, overwrite: true);
        }
        finally
        {
            try { File.Delete(temp); } catch { }
        }
    }
}
