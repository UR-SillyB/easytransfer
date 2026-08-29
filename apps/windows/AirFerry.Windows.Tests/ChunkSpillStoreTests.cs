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
}
