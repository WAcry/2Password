using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.IO.Pipes;
using TwoPassword.App;

namespace TwoPassword.Tests;

internal static partial class Program
{
    private static async Task RunExplorerSelectionBrokerTests()
    {
        await Run("Explorer IPC scopes portable copies and elevated windows independently", () =>
        {
            var ordinary = ExplorerSelectionBroker.PipeName(@"C:\Program files\2Password.exe", false);
            Assert(ordinary == ExplorerSelectionBroker.PipeName(@"c:\program files\2password.EXE", false), "Path casing split the same copy.");
            Assert(ordinary != ExplorerSelectionBroker.PipeName(@"C:\Portable\2Password.exe", false), "Distinct copies shared a pipe.");
            Assert(ordinary != ExplorerSelectionBroker.PipeName(@"C:\Program files\2Password.exe", true), "Elevation levels shared a pipe.");
            return Task.CompletedTask;
        });

        await Run("Concurrent Explorer invocations deliver every Unicode path to one receiver", async () =>
        {
            var name = "2Password.Tests." + Guid.NewGuid().ToString("N");
            using var owner = await ExplorerSelectionBroker.ConnectOrCreateAsync(name, [@"C:\initial"]);
            Assert(owner is not null, "The first invocation did not become the owner.");
            var received = new ConcurrentBag<string>();
            owner!.StartReceiving(paths => { foreach (var path in paths) received.Add(path); return Task.CompletedTask; });
            var expected = Enumerable.Range(0, 32).Select(index => @"C:\selected files\中文 🔑 & (" + index + ").txt").ToArray();
            var forwards = expected.Select(async path =>
            {
                using var secondary = await ExplorerSelectionBroker.ConnectOrCreateAsync(name, [path]);
                Assert(secondary is null, "A concurrent selection opened another owner.");
            });
            await Task.WhenAll(forwards).WaitAsync(TimeSpan.FromSeconds(20));
            Assert(received.Count == expected.Length && received.Order().SequenceEqual(expected.Order()), "The receiver lost or duplicated a selection.");
        });

        await Run("Explorer sender waits for initial window readiness and a closed owner can be replaced", async () =>
        {
            var name = "2Password.Tests." + Guid.NewGuid().ToString("N");
            using (var owner = await ExplorerSelectionBroker.ConnectOrCreateAsync(name, [@"C:\initial"]))
            {
                var forward = ExplorerSelectionBroker.ConnectOrCreateAsync(name, [@"C:\pending"]);
                await Task.Delay(100);
                Assert(!forward.IsCompleted, "A sender exited before the initial window accepted its path.");
                string[]? received = null;
                owner!.StartReceiving(paths => { received = paths; return Task.CompletedTask; });
                using var secondary = await forward.WaitAsync(TimeSpan.FromSeconds(5));
                Assert(secondary is null && received!.SequenceEqual(new[] { @"C:\pending" }), "A path was lost during initial window creation.");
            }
            using var replacement = await ExplorerSelectionBroker.ConnectOrCreateAsync(name, [@"C:\next"]);
            Assert(replacement is not null, "A closed owner's pipe could not be reclaimed.");
        });

        await Run("Malformed Explorer messages cannot allocate unbounded memory or block later selections", async () =>
        {
            var name = "2Password.Tests." + Guid.NewGuid().ToString("N");
            using var owner = await ExplorerSelectionBroker.ConnectOrCreateAsync(name, [@"C:\initial"]);
            var received = new ConcurrentBag<string>();
            owner!.StartReceiving(paths => { foreach (var path in paths) received.Add(path); return Task.CompletedTask; });
            using (var malformed = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly))
            {
                await malformed.ConnectAsync(5000);
                var header = new byte[4];
                BinaryPrimitives.WriteInt32LittleEndian(header, int.MaxValue);
                await malformed.WriteAsync(header);
                await malformed.FlushAsync();
            }
            using var secondary = await ExplorerSelectionBroker.ConnectOrCreateAsync(name, [@"C:\after malformed"]);
            Assert(secondary is null && received.Single() == @"C:\after malformed", "A malformed request stopped the broker.");
        });
    }
}
