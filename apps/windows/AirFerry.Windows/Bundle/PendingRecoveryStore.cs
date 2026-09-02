using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace AirFerry.Windows.Bundle;

/// <summary>
/// Durable retry metadata for complete receive-stage files whose
/// <see cref="ContentStore"/> index publication has not committed yet.
/// </summary>
/// <remarks>
/// A staged <c>.partial</c> file alone cannot be replayed after a process
/// restart: its logical name, bundle membership and deterministic entry ID are
/// all part of the publication. This sidecar retains that information and
/// makes startup replay idempotent across the index-commit/cleanup boundary.
/// </remarks>
public static class PendingRecoveryStore
{
    internal const string ManifestName = ".airferry-pending.json";
    private const long MaxManifestBytes = 4L * 1024 * 1024;
    private const int MaxEntries = 4096;
    private const int MaxAttemptsPerStart = 256;
    private static readonly TimeSpan IncompleteStageGrace = TimeSpan.FromDays(1);
    private static readonly object Gate = new();
    private static readonly UTF8Encoding StrictUtf8 =
        new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
    };

    private sealed record Manifest(int V, IReadOnlyList<ManifestEntry> Entries);

    private sealed record ManifestEntry(
        string File,
        string Name,
        string Crc,
        bool CrcUnknown,
        string Kind,
        string? BundleId,
        string? BundleTitle,
        long Size,
        string StableId);

    public sealed record RetrySummary(int Imported, int AlreadyCommitted, int Failed);

    internal static string? RootDirOverride { get; set; }

    private static string RootDir => RootDirOverride ??
        Path.Combine(Path.GetTempPath(), "AirFerry", "recovery");

    public static string CreateStageDirectory()
    {
        lock (Gate)
        {
            Directory.CreateDirectory(RootDir);
            RejectLink(RootDir, expectDirectory: true);
            string stage = Path.Combine(RootDir, Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(stage);
            return stage;
        }
    }

    /// <summary>Persist the replay plan after every source is complete and flushed.</summary>
    public static void Persist(
        string stageDir,
        IReadOnlyList<ContentStore.PutFileRequest> requests)
    {
        if (requests.Count is < 1 or > MaxEntries)
            throw new ArgumentOutOfRangeException(
                nameof(requests), "Invalid pending recovery entry count");

        lock (Gate)
        {
            string stage = Path.TrimEndingDirectorySeparator(Path.GetFullPath(stageDir));
            if (!Directory.Exists(stage))
                throw new DirectoryNotFoundException("Pending recovery stage is unavailable");
            RejectLink(stage, expectDirectory: true);

            var entries = new List<ManifestEntry>(requests.Count);
            var stableIds = new HashSet<string>(StringComparer.Ordinal);
            foreach (ContentStore.PutFileRequest request in requests)
            {
                string source = Path.GetFullPath(request.FilePath);
                if (!SamePath(Path.GetDirectoryName(source), stage) || !File.Exists(source))
                    throw new InvalidDataException(
                        "Pending recovery source escaped its stage");
                RejectLink(source, expectDirectory: false);
                long actualSize = new FileInfo(source).Length;
                long expectedSize = request.ExpectedSize ?? actualSize;
                if (expectedSize < 0 || actualSize != expectedSize)
                    throw new InvalidDataException(
                        "Pending recovery source length mismatch");
                string stableId = request.StableEntryId ?? "";
                if (string.IsNullOrWhiteSpace(stableId) || stableId.Length > 256 ||
                    !stableIds.Add(stableId))
                    throw new InvalidDataException(
                        "Pending recovery requires unique bounded stable entry IDs");
                ValidateString(request.DisplayName, 4096, "name");
                ValidateString(request.CrcHex, 128, "CRC");
                ValidateKind(request.Kind);
                ValidateOptionalString(request.BundleId, 4096, "bundle ID");
                ValidateOptionalString(request.BundleTitle, 4096, "bundle title");

                entries.Add(new ManifestEntry(
                    Path.GetFileName(source), request.DisplayName, request.CrcHex,
                    request.CrcUnknown, request.Kind, request.BundleId,
                    request.BundleTitle, expectedSize, stableId));
            }

            byte[] payload = JsonSerializer.SerializeToUtf8Bytes(
                new Manifest(1, entries), JsonOptions);
            if (payload.LongLength > MaxManifestBytes)
                throw new InvalidDataException("Pending recovery manifest is too large");

            string target = Path.Combine(stage, ManifestName);
            string temp = Path.Combine(
                stage, $".{ManifestName}.{Guid.NewGuid():N}.tmp");
            try
            {
                using (var stream = new FileStream(
                           temp, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                           64 * 1024, FileOptions.WriteThrough))
                {
                    stream.Write(payload);
                    stream.Flush(flushToDisk: true);
                }
                File.Move(temp, target, overwrite: true);
            }
            finally
            {
                try { if (File.Exists(temp)) File.Delete(temp); } catch { }
            }
        }
    }

    /// <summary>
    /// Replay a bounded number of pending publications. Malformed/conflicting
    /// attempts stay untouched for manual recovery instead of being guessed at.
    /// </summary>
    public static RetrySummary RetryAll()
    {
        lock (Gate)
        {
            if (!Directory.Exists(RootDir)) return new RetrySummary(0, 0, 0);
            RejectLink(RootDir, expectDirectory: true);
            string[] attempts = Directory.EnumerateDirectories(RootDir)
                .Where(IsOwnedStageDirectory)
                .OrderBy(path => Directory.GetLastWriteTimeUtc(path))
                .Take(MaxAttemptsPerStart)
                .ToArray();
            int imported = 0;
            int alreadyCommitted = 0;
            int failed = 0;

            foreach (string stage in attempts)
            {
                IReadOnlyList<ContentStore.PutFileRequest>? requests;
                try
                {
                    requests = ReadRequests(stage);
                }
                catch (Exception ex)
                {
                    Trace.TraceWarning(
                        "Pending receive manifest read failed for {0}: {1}",
                        stage, ex.Message);
                    failed++;
                    continue;
                }
                if (requests is null)
                {
                    // A process kill while copying entries can leave a UUID
                    // stage with no durable manifest. It has no logical names
                    // or stable IDs and cannot be replayed; retain it briefly
                    // for diagnostics, then reclaim it. A malformed manifest
                    // is different and remains untouched for manual recovery.
                    string manifest = Path.Combine(stage, ManifestName);
                    try
                    {
                        if (!File.Exists(manifest) && !IsLink(stage) &&
                            DateTime.UtcNow - Directory.GetLastWriteTimeUtc(stage) >=
                                IncompleteStageGrace)
                        {
                            DeleteStageBestEffort(stage);
                        }
                    }
                    catch { }
                    continue;
                }

                try
                {
                    Dictionary<string, ContentStore.Entry> existing =
                        ContentStore.ListEntries().ToDictionary(
                            entry => entry.Id, StringComparer.Ordinal);
                    bool[] matches = requests.Select(request =>
                    {
                        if (request.StableEntryId is null ||
                            !existing.TryGetValue(request.StableEntryId, out var entry))
                            return false;
                        string expectedName = request.BundleId is not null
                            ? FileNameUtil.SanitizeRelativePath(request.DisplayName)
                            : FileNameUtil.Sanitize(request.DisplayName);
                        return string.Equals(entry.Name, expectedName, StringComparison.Ordinal) &&
                               entry.Size == request.ExpectedSize &&
                               string.Equals(entry.Kind, request.Kind, StringComparison.Ordinal) &&
                               string.Equals(
                                   entry.BundleId, request.BundleId, StringComparison.Ordinal);
                    }).ToArray();

                    if (matches.All(value => value))
                    {
                        DeleteStageBestEffort(stage);
                        alreadyCommitted++;
                        continue;
                    }

                    // PutFileBatch is atomic: a legitimate older generation
                    // has either every stable ID or none. A prefix is a conflict.
                    bool invalidSource = requests.Any(request =>
                        !File.Exists(request.FilePath) || IsLink(request.FilePath) ||
                        new FileInfo(request.FilePath).Length != request.ExpectedSize);
                    if (matches.Any(value => value) || invalidSource)
                    {
                        failed++;
                        continue;
                    }

                    ContentStore.PutFileBatch(requests);
                    DeleteStageBestEffort(stage);
                    imported++;
                }
                catch (Exception ex)
                {
                    failed++;
                    Trace.TraceWarning(
                        "Pending receive publication retry failed for {0}: {1}",
                        stage, ex.Message);
                }
            }
            return new RetrySummary(imported, alreadyCommitted, failed);
        }
    }

    internal static IReadOnlyList<ContentStore.PutFileRequest>? ReadRequests(
        string stageDir)
    {
        string stage = Path.TrimEndingDirectorySeparator(Path.GetFullPath(stageDir));
        if (!Directory.Exists(stage) || IsLink(stage)) return null;
        string manifestPath = Path.Combine(stage, ManifestName);
        if (!File.Exists(manifestPath) || IsLink(manifestPath)) return null;
        long length = new FileInfo(manifestPath).Length;
        if (length is < 1 or > MaxManifestBytes) return null;

        byte[] bytes = File.ReadAllBytes(manifestPath);
        // Force strict UTF-8 validation before JsonDocument's byte parser.
        _ = StrictUtf8.GetString(bytes);
        using JsonDocument document = JsonDocument.Parse(bytes, new JsonDocumentOptions
        {
            CommentHandling = JsonCommentHandling.Disallow,
            AllowTrailingCommas = false,
            MaxDepth = 8,
        });
        JsonElement root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object ||
            root.EnumerateObject().Count() != 2 ||
            !TryStrictInt64(root, "v", out long version) || version != 1 ||
            !root.TryGetProperty("entries", out JsonElement entriesElement) ||
            entriesElement.ValueKind != JsonValueKind.Array)
            return null;

        int count = entriesElement.GetArrayLength();
        if (count is < 1 or > MaxEntries) return null;
        var requests = new List<ContentStore.PutFileRequest>(count);
        var stableIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonElement item in entriesElement.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object || !HasOnlyEntryProperties(item))
                return null;
            if (!TryString(item, "file", 255, out string fileName) ||
                !string.Equals(fileName, Path.GetFileName(fileName), StringComparison.Ordinal) ||
                string.Equals(fileName, ManifestName, StringComparison.OrdinalIgnoreCase) ||
                !TryString(item, "name", 4096, out string displayName) ||
                !TryString(item, "crc", 128, out string crc) ||
                !TryString(item, "kind", 16, out string kind) ||
                kind is not ("file" or "text") ||
                !TryString(item, "stableId", 256, out string stableId) ||
                string.IsNullOrWhiteSpace(stableId) || !stableIds.Add(stableId) ||
                !TryStrictInt64(item, "size", out long size) || size < 0 ||
                !item.TryGetProperty("crcUnknown", out JsonElement crcUnknownElement) ||
                crcUnknownElement.ValueKind is not (JsonValueKind.True or JsonValueKind.False) ||
                !TryOptionalString(item, "bundleId", 4096, out string? bundleId) ||
                !TryOptionalString(item, "bundleTitle", 4096, out string? bundleTitle))
                return null;

            string source = Path.GetFullPath(Path.Combine(stage, fileName));
            if (!SamePath(Path.GetDirectoryName(source), stage)) return null;
            requests.Add(new ContentStore.PutFileRequest(
                displayName, source, crc, crcUnknownElement.GetBoolean(), kind,
                bundleId, bundleTitle, size, stableId));
        }
        return requests;
    }

    private static bool HasOnlyEntryProperties(JsonElement item)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonProperty property in item.EnumerateObject())
        {
            if (!names.Add(property.Name) || property.Name is not (
                    "file" or "name" or "crc" or "crcUnknown" or "kind" or
                    "bundleId" or "bundleTitle" or "size" or "stableId"))
                return false;
        }
        return names.Count is >= 7 and <= 9;
    }

    private static bool TryString(
        JsonElement item, string name, int max, out string value)
    {
        value = "";
        if (!item.TryGetProperty(name, out JsonElement element) ||
            element.ValueKind != JsonValueKind.String)
            return false;
        value = element.GetString() ?? "";
        return value.Length <= max && !value.Contains('\0');
    }

    private static bool TryOptionalString(
        JsonElement item, string name, int max, out string? value)
    {
        value = null;
        if (!item.TryGetProperty(name, out JsonElement element) ||
            element.ValueKind == JsonValueKind.Null)
            return true;
        if (element.ValueKind != JsonValueKind.String) return false;
        value = element.GetString();
        return value is not null && value.Length <= max && !value.Contains('\0');
    }

    private static bool TryStrictInt64(
        JsonElement item, string name, out long value)
    {
        value = 0;
        return item.TryGetProperty(name, out JsonElement element) &&
               element.ValueKind == JsonValueKind.Number &&
               element.TryGetInt64(out value);
    }

    private static void ValidateKind(string kind)
    {
        if (kind is not ("file" or "text"))
            throw new InvalidDataException("Invalid pending recovery entry kind");
    }

    private static void ValidateString(string value, int max, string label)
    {
        if (value.Length > max || value.Contains('\0'))
            throw new InvalidDataException($"Invalid pending recovery {label}");
    }

    private static void ValidateOptionalString(string? value, int max, string label)
    {
        if (value is not null) ValidateString(value, max, label);
    }

    private static bool SamePath(string? left, string right)
    {
        if (left is null) return false;
        StringComparison comparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
        return string.Equals(
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(left)),
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(right)), comparison);
    }

    private static bool IsOwnedStageDirectory(string path) =>
        Guid.TryParseExact(Path.GetFileName(path), "N", out _);

    private static bool IsLink(string path)
    {
        try
        {
            FileAttributes attributes = File.GetAttributes(path);
            return attributes.HasFlag(FileAttributes.ReparsePoint) ||
                   (attributes.HasFlag(FileAttributes.Directory)
                       ? new DirectoryInfo(path).LinkTarget is not null
                       : new FileInfo(path).LinkTarget is not null);
        }
        catch
        {
            return true;
        }
    }

    private static void RejectLink(string path, bool expectDirectory)
    {
        FileAttributes attributes = File.GetAttributes(path);
        if (attributes.HasFlag(FileAttributes.Directory) != expectDirectory || IsLink(path))
            throw new InvalidDataException("Pending recovery path cannot be a link");
    }

    private static void DeleteStageBestEffort(string stage)
    {
        try
        {
            if (Directory.Exists(stage)) Directory.Delete(stage, recursive: true);
        }
        catch (Exception ex)
        {
            // Publication is already committed. Cleanup failure must not turn
            // it into a retry-visible logical failure or duplicate history.
            Trace.TraceWarning(
                "Could not remove committed recovery stage {0}: {1}",
                stage, ex.Message);
        }
    }
}
