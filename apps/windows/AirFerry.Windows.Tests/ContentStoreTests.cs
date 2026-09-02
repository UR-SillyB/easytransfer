using AirFerry.Windows.Bundle;
using Xunit;

namespace AirFerry.Windows.Tests;

public sealed class ContentStoreTests
{
    private static string TempRoot()
    {
        string dir = Path.Combine(Path.GetTempPath(), "AirFerry.ContentStoreTests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    [Fact]
    public void StableBatchRetryReturnsExistingEntriesWithoutDuplicatingHistory()
    {
        string temp = TempRoot();
        string storeRoot = Path.Combine(temp, "store");
        ContentStore.RootDirOverride = storeRoot;
        try
        {
            string first = Path.Combine(temp, "first.partial");
            string second = Path.Combine(temp, "second.partial");
            File.WriteAllBytes(first, [1, 2, 3]);
            File.WriteAllBytes(second, [4, 5]);
            var initial = ContentStore.PutFileBatch([
                new("a.bin", first, BundleId: "attempt-a", BundleTitle: "first",
                    ExpectedSize: 3, StableEntryId: "attempt-a-0"),
                new("b.bin", second, BundleId: "attempt-a", BundleTitle: "first",
                    ExpectedSize: 2, StableEntryId: "attempt-a-1"),
            ]);
            Assert.Equal(2, initial.Count);
            Assert.False(File.Exists(first));
            Assert.False(File.Exists(second));

            // Model a process death after index commit but before the resume
            // ledger was deleted: recovery materializes the same sources again.
            File.WriteAllBytes(first, [1, 2, 3]);
            File.WriteAllBytes(second, [4, 5]);
            var retried = ContentStore.PutFileBatch([
                new("a.bin", first, BundleId: "attempt-a", BundleTitle: "later retry",
                    ExpectedSize: 3, StableEntryId: "attempt-a-0"),
                new("b.bin", second, BundleId: "attempt-a", BundleTitle: "later retry",
                    ExpectedSize: 2, StableEntryId: "attempt-a-1"),
            ]);

            Assert.Equal(initial.Select(result => result.Entry.Id),
                retried.Select(result => result.Entry.Id));
            Assert.Equal(2, ContentStore.ListEntries().Count);
            Assert.False(File.Exists(first));
            Assert.False(File.Exists(second));
        }
        finally
        {
            ContentStore.RootDirOverride = null;
            Directory.Delete(temp, recursive: true);
        }
    }

    [Fact]
    public void StableIdConflictFailsBeforeConsumingRetrySource()
    {
        string temp = TempRoot();
        ContentStore.RootDirOverride = Path.Combine(temp, "store");
        try
        {
            string first = Path.Combine(temp, "first.partial");
            File.WriteAllBytes(first, [1]);
            ContentStore.PutFile(
                "a.bin", first, expectedSize: 1, stableEntryId: "attempt-b-0");

            string conflicting = Path.Combine(temp, "conflict.partial");
            File.WriteAllBytes(conflicting, [2]);
            Assert.Throws<InvalidDataException>(() => ContentStore.PutFile(
                "a.bin", conflicting, expectedSize: 1, stableEntryId: "attempt-b-0"));
            Assert.True(File.Exists(conflicting));
            Assert.Single(ContentStore.ListEntries());
        }
        finally
        {
            ContentStore.RootDirOverride = null;
            Directory.Delete(temp, recursive: true);
        }
    }

    [Fact]
    public void PendingPublicationReplaysCompleteBundleAndRemovesStage()
    {
        string temp = TempRoot();
        ContentStore.RootDirOverride = Path.Combine(temp, "store");
        PendingRecoveryStore.RootDirOverride = Path.Combine(temp, "recovery");
        try
        {
            string stage = PendingRecoveryStore.CreateStageDirectory();
            string first = Path.Combine(stage, "000000.partial");
            string second = Path.Combine(stage, "000001.partial");
            File.WriteAllBytes(first, [1, 2, 3]);
            File.WriteAllBytes(second, [4, 5]);
            List<ContentStore.PutFileRequest> requests =
            [
                new("dir/a.bin", first, BundleId: "bundle-r",
                    BundleTitle: "Bundle R", ExpectedSize: 3,
                    StableEntryId: "retry-r-0"),
                new("dir/b.bin", second, BundleId: "bundle-r",
                    BundleTitle: "Bundle R", ExpectedSize: 2,
                    StableEntryId: "retry-r-1"),
            ];
            PendingRecoveryStore.Persist(stage, requests);

            IReadOnlyList<ContentStore.PutFileRequest> restored =
                PendingRecoveryStore.ReadRequests(stage)!;
            Assert.Equal(["retry-r-0", "retry-r-1"],
                restored.Select(request => request.StableEntryId));

            PendingRecoveryStore.RetrySummary summary =
                PendingRecoveryStore.RetryAll();

            Assert.Equal(1, summary.Imported);
            Assert.Equal(0, summary.AlreadyCommitted);
            Assert.Equal(0, summary.Failed);
            Assert.False(Directory.Exists(stage));
            Assert.Equal(2, ContentStore.ListEntries().Count);
            Assert.All(ContentStore.ListEntries(),
                entry => Assert.Equal("bundle-r", entry.BundleId));
        }
        finally
        {
            PendingRecoveryStore.RootDirOverride = null;
            ContentStore.RootDirOverride = null;
            Directory.Delete(temp, recursive: true);
        }
    }

    [Fact]
    public void PendingPublicationCleansCommittedShellWithoutDuplicatingHistory()
    {
        string temp = TempRoot();
        ContentStore.RootDirOverride = Path.Combine(temp, "store");
        PendingRecoveryStore.RootDirOverride = Path.Combine(temp, "recovery");
        try
        {
            string stage = PendingRecoveryStore.CreateStageDirectory();
            string source = Path.Combine(stage, "000000.partial");
            File.WriteAllBytes(source, [9, 8, 7]);
            List<ContentStore.PutFileRequest> requests =
            [
                new("done.bin", source, ExpectedSize: 3,
                    StableEntryId: "retry-done-0"),
            ];
            PendingRecoveryStore.Persist(stage, requests);
            ContentStore.PutFileBatch(requests);
            Assert.False(File.Exists(source));
            Assert.True(Directory.Exists(stage));

            PendingRecoveryStore.RetrySummary summary =
                PendingRecoveryStore.RetryAll();

            Assert.Equal(0, summary.Imported);
            Assert.Equal(1, summary.AlreadyCommitted);
            Assert.Equal(0, summary.Failed);
            Assert.False(Directory.Exists(stage));
            Assert.Single(ContentStore.ListEntries());
        }
        finally
        {
            PendingRecoveryStore.RootDirOverride = null;
            ContentStore.RootDirOverride = null;
            Directory.Delete(temp, recursive: true);
        }
    }

    [Fact]
    public void PendingManifestRejectsSourceOutsideItsStage()
    {
        string temp = TempRoot();
        PendingRecoveryStore.RootDirOverride = Path.Combine(temp, "recovery");
        try
        {
            string stage = PendingRecoveryStore.CreateStageDirectory();
            File.WriteAllText(
                Path.Combine(stage, PendingRecoveryStore.ManifestName),
                "{\"v\":1,\"entries\":[{" +
                "\"file\":\"../outside.partial\",\"name\":\"x\"," +
                "\"crc\":\"unknown\",\"crcUnknown\":true," +
                "\"kind\":\"file\",\"size\":1,\"stableId\":\"retry-x\"}]}" );

            Assert.Null(PendingRecoveryStore.ReadRequests(stage));
        }
        finally
        {
            PendingRecoveryStore.RootDirOverride = null;
            Directory.Delete(temp, recursive: true);
        }
    }

    [Fact]
    public void PendingRetryReclaimsOnlyStaleOwnedStagesWithoutManifests()
    {
        string temp = TempRoot();
        ContentStore.RootDirOverride = Path.Combine(temp, "store");
        PendingRecoveryStore.RootDirOverride = Path.Combine(temp, "recovery");
        try
        {
            string stale = PendingRecoveryStore.CreateStageDirectory();
            File.WriteAllBytes(Path.Combine(stale, "000000.partial"), [1]);
            Directory.SetLastWriteTimeUtc(stale, DateTime.UtcNow.AddDays(-2));
            string fresh = PendingRecoveryStore.CreateStageDirectory();
            File.WriteAllBytes(Path.Combine(fresh, "000000.partial"), [2]);
            string foreign = Path.Combine(
                PendingRecoveryStore.RootDirOverride, "unrelated");
            Directory.CreateDirectory(foreign);
            Directory.SetLastWriteTimeUtc(foreign, DateTime.UtcNow.AddDays(-2));

            PendingRecoveryStore.RetryAll();

            Assert.False(Directory.Exists(stale));
            Assert.True(Directory.Exists(fresh));
            Assert.True(Directory.Exists(foreign));
        }
        finally
        {
            PendingRecoveryStore.RootDirOverride = null;
            ContentStore.RootDirOverride = null;
            Directory.Delete(temp, recursive: true);
        }
    }
}
