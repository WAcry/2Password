using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using TwoPassword.Recovery;

namespace TwoPassword.Tests;

internal static partial class Program
{
    private static Task RecoverySampleBoundaries()
    {
        const int blockSize = 4 * 1024 * 1024;
        const int prefix = 73;
        const int finalBytes = 357;
        long length = 2L * blockSize + finalBytes;
        byte[] first = RandomNumberGenerator.GetBytes(blockSize);
        byte[] zero = new byte[blockSize];
        byte[] final = new byte[blockSize];
        RandomNumberGenerator.Fill(final.AsSpan(0, finalBytes));
        byte[][] expected = [MD5.HashData(first), MD5.HashData(zero), MD5.HashData(final)];
        // The reference hashes full, independently padded arrays. Production
        // reads these same slices incrementally, including a short final slice.
        var set = new Par2Set(blockSize, [], expected, 0, [], 0);
        string path = Path.Combine(_root, "bounded-recovery-samples.bin");
        using var file = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None);
        file.Write(new byte[prefix]);
        file.Write(first);
        file.Write(zero);
        file.Write(final, 0, finalBytes);
        file.Flush();

        MethodInfo sample = typeof(RecoveryService).GetMethod("MatchingSamples", BindingFlags.Static | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("Recovery sample method is missing.");
        int Match(long offset, CancellationToken token = default)
        {
            try { return (int)sample.Invoke(null, [file, offset, length, 0, set, token])!; }
            catch (TargetInvocationException error) when (error.InnerException is not null)
            {
                ExceptionDispatchInfo.Capture(error.InnerException).Throw();
                throw;
            }
        }

        Assert(Match(prefix) == 2, "Exact nonzero samples or final zero padding did not match.");
        long before = GC.GetAllocatedBytesForCurrentThread();
        int matches = Match(prefix);
        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert(matches == 2, "All-zero slices should not add ambiguous matches.");
        Assert(allocated < 2L * 1024 * 1024,
            "Recovery sample hashing allocated a block-sized buffer: " + allocated + " bytes.");
        Assert(Match(prefix + 1) == 0, "A shifted payload offset was accepted.");

        // One changed byte in the partial final slice removes exactly one match.
        file.Position = prefix + 2L * blockSize + finalBytes - 1;
        file.WriteByte((byte)(final[finalBytes - 1] ^ 0x40));
        file.Flush();
        Assert(Match(prefix) == 1, "Final-slice damage was hidden by zero padding.");
        file.SetLength(prefix + length - 17);
        Assert(Match(prefix) == 1, "A short file read was treated as a complete zero-padded sample.");

        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        bool observedCancellation = false;
        try { Match(prefix, canceled.Token); }
        catch (OperationCanceledException) { observedCancellation = true; }
        Assert(observedCancellation, "Recovery sample hashing ignored cancellation.");
        return Task.CompletedTask;
    }
}
