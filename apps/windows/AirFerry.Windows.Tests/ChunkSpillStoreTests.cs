using AirFerry.Windows.Scan;
using Xunit;

namespace AirFerry.Windows.Tests;

public class ChunkSpillStoreTests
{
    [Fact]
    public void ReadAllRewindsTheCachedWriterStream()
    {
        string dir = Path.Combine(Path.GetTempPath(), $"airferry-spill-{Guid.NewGuid():N}");
        byte[] first = [1, 2, 3, 4];
        byte[] second = [5, 6, 7, 8];
        try
        {
            var store = new ChunkSpillStore(dir, "rewind");
            store.Write(0, first.Length, first);
            store.Write(1, first.Length, second);

            Assert.Equal(first.Concat(second).ToArray(), store.ReadAll(8));
            store.Discard();
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void ClosePreservingBackingCanBeReopenedForResume()
    {
        string dir = Path.Combine(Path.GetTempPath(), $"airferry-spill-{Guid.NewGuid():N}");
        byte[] chunk = [1, 2, 3, 4];
        try
        {
            var first = new ChunkSpillStore(dir, "pause");
            first.Write(0, chunk.Length, chunk);
            first.ClosePreservingBacking();

            string path = Path.Combine(dir, "af2-pause.partial");
            Assert.True(File.Exists(path));

            var resumed = new ChunkSpillStore(dir, "pause", deleteExisting: false);
            resumed.MarkResumed([0]);
            Assert.True(resumed.HasChunk(0));
            Assert.Equal(chunk, resumed.ReadRange(0, chunk.Length));
            resumed.Discard();
            Assert.False(File.Exists(path));
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void InvalidationWithdrawsTrustUntilReplacementIsDurable()
    {
        string dir = Path.Combine(Path.GetTempPath(), $"airferry-spill-{Guid.NewGuid():N}");
        try
        {
            var store = new ChunkSpillStore(dir, "repair");
            store.Write(0, 4, [1, 2, 3, 4]);
            Assert.True(store.HasChunk(0));

            store.Invalidate(0);
            Assert.False(store.HasChunk(0));
            // Bytes remain readable only as the caller's hash-gated last resort.
            Assert.Equal(new byte[] { 1, 2, 3, 4 }, store.ReadRange(0, 4));

            store.Write(0, 4, [5, 6, 7, 8]);
            Assert.True(store.HasChunk(0));
            Assert.Equal(new byte[] { 5, 6, 7, 8 }, store.ReadRange(0, 4));
            store.Discard();
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void CopyRangeRefusesToDeleteAnExistingDestination()
    {
        string dir = Path.Combine(Path.GetTempPath(), $"airferry-spill-{Guid.NewGuid():N}");
        string destination = Path.Combine(dir, "valuable.bin");
        try
        {
            var store = new ChunkSpillStore(dir, "existing-output");
            store.Write(0, 4, [1, 2, 3, 4]);
            File.WriteAllBytes(destination, [9, 9, 9]);

            Assert.False(store.CopyRangeToFile(0, 4, destination));
            Assert.Equal(new byte[] { 9, 9, 9 }, File.ReadAllBytes(destination));
            store.Discard();
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true);
        }
    }

    [Theory]
    [InlineData("../../evil")]
    [InlineData(@"..\..\evil")]
    [InlineData("a/b")]
    [InlineData(@"a\b")]
    [InlineData("tid x")]
    [InlineData("c:evil")]
    public void RejectsATransferIdThatCouldEscapeTheSpillDirectory(string hostile)
    {
        // The id is written to before Af2LedgerStore.Create validates it, so
        // the spill store must reject a traversing id itself.
        string dir = Path.Combine(Path.GetTempPath(), $"airferry-spill-{Guid.NewGuid():N}");
        try
        {
            Assert.Throws<ArgumentException>(() => new ChunkSpillStore(dir, hostile));
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void AcceptsAnEmptyIdAndOrdinaryHexIds()
    {
        string dir = Path.Combine(Path.GetTempPath(), $"airferry-spill-{Guid.NewGuid():N}");
        try
        {
            new ChunkSpillStore(dir, "").Discard();
            new ChunkSpillStore(dir, "a1b2c3").Discard();
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void RejectsChunkIndexOutsideProtocolBudgetBeforeCreatingSparseFile()
    {
        string dir = Path.Combine(Path.GetTempPath(), $"airferry-spill-{Guid.NewGuid():N}");
        try
        {
            var store = new ChunkSpillStore(dir, "index-cap");

            Assert.Throws<ArgumentOutOfRangeException>(() =>
                store.Write(131_072, 32 * 1024 * 1024, [1]));
            Assert.False(File.Exists(Path.Combine(dir, "af2-index-cap.partial")));
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true);
        }
    }
}
