using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using TwoPassword.Core;

namespace TwoPassword.Tests;

internal static partial class Program
{
    private static partial async Task RunDetachedCases()
    {
        string directory = Path.Combine(_root, "detached");
        Directory.CreateDirectory(directory);
        string stub = Path.Combine(directory, "template.exe");
        byte[] stubBytes = new byte[512];
        "MZ"u8.CopyTo(stubBytes);
        await File.WriteAllBytesAsync(stub, stubBytes);
        string launcher = Path.Combine(directory, "资料_日本語_🙂.exe");
        string data = Path.ChangeExtension(launcher, ".2pw");

        await Run("Forced detached layout emits paired Unicode launcher and data", async () =>
        {
            var result = await PackageService.CreateAsync(new(_fixture, launcher, Passwords,
                PackageCompression.Zstd, stub, PackageLayout.Detached));
            Assert(result.IsDetached && result.DataPath == data && File.Exists(launcher) && File.Exists(data),
                "Detached pair was not published.");
            Assert(new FileInfo(launcher).Length == stubBytes.Length + HeaderRegion + FooterRegion,
                "Launcher contains unexpected payload data.");
            var info = await PackageService.InspectAsync(launcher);
            Assert(info.IsDetached && info.DataPath == data && info.PasswordSlots == 3, "Detached metadata mismatch.");
            string output = Path.Combine(directory, "roundtrip");
            await PackageService.ExtractAsync(new(launcher, output, PasswordB));
            AssertTreeEqual(_fixture, Path.Combine(output, Path.GetFileName(_fixture)));
        });
        if (!File.Exists(data)) return;
        await Run("Detached sidecar can be opened directly by trusted application", async () =>
        {
            string output = Path.Combine(directory, "direct-data");
            await PackageService.ExtractAsync(new(data, output, PasswordA));
            AssertTreeEqual(_fixture, Path.Combine(output, Path.GetFileName(_fixture)));
        });
        await Run("Missing detached sidecar fails without plaintext output", async () =>
        {
            string held = data + ".held";
            File.Move(data, held);
            try { await ExpectExtractFailure(launcher, PasswordA); }
            finally { File.Move(held, data); }
        });
        await Run("Swapped sidecar with a valid password fails header binding", async () =>
        {
            string held = data + ".original";
            File.Move(data, held);
            File.Copy(_package, data);
            try { await ExpectExtractFailure(launcher, PasswordA); }
            finally
            {
                File.Move(data, data + ".swapped-test-copy");
                File.Move(held, data);
            }
        });
        await Run("Existing detached sidecar is never overwritten", async () =>
        {
            string output = Path.Combine(directory, "existing.exe");
            string sidecar = Path.ChangeExtension(output, ".2pw");
            File.WriteAllText(sidecar, "existing sidecar sentinel");
            await MustFail(() => PackageService.CreateAsync(new(_fixture, output, [PasswordA],
                PackageCompression.Zstd, stub, PackageLayout.Detached)));
            Assert(!File.Exists(output) && File.ReadAllText(sidecar) == "existing sidecar sentinel",
                "Existing sidecar was modified or orphan launcher was created.");
        });
        await Run("Canceled detached creation publishes neither member of pair", async () =>
        {
            string output = Path.Combine(directory, "canceled.exe");
            using var cts = new CancellationTokenSource();
            var progress = new InlineProgress<PackageProgress>(p =>
            {
                if (p.BytesProcessed > 0 && p.BytesProcessed < p.TotalBytes) cts.Cancel();
            });
            await MustCancel(() => PackageService.CreateAsync(new(_fixture, output, [PasswordA],
                PackageCompression.None, stub, PackageLayout.Detached), progress, cts.Token));
            Assert(!File.Exists(output) && !File.Exists(Path.ChangeExtension(output, ".2pw")), "Canceled pair was published.");
            Assert(!Directory.EnumerateFileSystemEntries(directory).Any(p => Path.GetFileName(p).StartsWith(".2password-", StringComparison.Ordinal)),
                "Detached cancellation left a temporary member.");
        });
        await Run("Detached sidecar path cannot overwrite the source file", async () =>
        {
            string source = Path.Combine(directory, "same-name.2pw");
            File.WriteAllText(source, "source sentinel");
            string output = Path.ChangeExtension(source, ".exe");
            await MustFail(() => PackageService.CreateAsync(new(source, output, [PasswordA],
                PackageCompression.Zstd, stub, PackageLayout.Detached)));
            Assert(File.ReadAllText(source) == "source sentinel" && !File.Exists(output), "Sidecar overwrote source.");
        });

        byte[] healthyData = await File.ReadAllBytesAsync(data);
        byte[] expectedHeaderHash = healthyData.AsSpan(16, 32).ToArray();
        foreach (string name in new[] { "../baseline.2pw", @"..\baseline.2pw", @"C:\baseline.2pw",
            "data.2pw:stream", "NUL.2pw", "data.2pw.", "data.2pw ", "data.exe", "" })
        {
            string captured = name;
            await Run("Detached reference rejects unsafe basename: " + name, async () =>
            {
                string hostile = Path.Combine(directory, "unsafe-" + Guid.NewGuid().ToString("N") + ".exe");
                await File.WriteAllBytesAsync(hostile, MakeReferenceLauncher(stubBytes, Encoding.UTF8.GetBytes(captured), expectedHeaderHash));
                await ExpectExtractFailure(hostile, PasswordA);
            });
        }
        await Run("Detached reference rejects invalid UTF-8 bytes", async () =>
        {
            string hostile = Path.Combine(directory, "invalid-utf8.exe");
            await File.WriteAllBytesAsync(hostile, MakeReferenceLauncher(stubBytes, [0xff, .. ".2pw"u8], expectedHeaderHash));
            await ExpectExtractFailure(hostile, PasswordA);
        });
        await Run("Two lost detached descriptors and footers are recoverable", async () =>
        {
            byte[] bytes = await File.ReadAllBytesAsync(launcher);
            int offset = stubBytes.Length;
            bytes.AsSpan(offset, 2048 * 2).Clear();
            bytes.AsSpan(bytes.Length - FooterRegion, 64 * 2).Clear();
            string repairedReference = Path.Combine(directory, "redundant-launcher.exe");
            await File.WriteAllBytesAsync(repairedReference, bytes);
            string output = Path.Combine(directory, "redundant-restored");
            await PackageService.ExtractAsync(new(repairedReference, output, PasswordA));
            AssertTreeEqual(_fixture, Path.Combine(output, Path.GetFileName(_fixture)));
        });
        await Run("Detached launcher accessed through a directory junction is rejected", async () =>
        {
            string link = Path.Combine(_root, "detached-parent-junction");
            CreateJunction(link, directory);
            await ExpectExtractFailure(Path.Combine(link, Path.GetFileName(launcher)), PasswordA);
        });
    }

    private static byte[] MakeReferenceLauncher(byte[] stub, byte[] name, byte[] headerHash)
    {
        byte[] descriptor = new byte[48 + name.Length];
        "2PWREF02"u8.CopyTo(descriptor);
        BinaryPrimitives.WriteInt32LittleEndian(descriptor.AsSpan(8), name.Length);
        headerHash.CopyTo(descriptor, 16);
        name.CopyTo(descriptor, 48);
        using var output = new MemoryStream();
        output.Write(stub);
        WriteReferenceReplicas(output, "2PWLHDR2"u8, descriptor);
        WriteReferenceFooter(output, "2PWLINK2"u8, stub.Length, HeaderRegion);
        return output.ToArray();
    }
}
