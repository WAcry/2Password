using System.Buffers.Binary;
using System.Security.Cryptography;
using TwoPassword.Core;

namespace TwoPassword.Tests;

internal static partial class Program
{
    private const int HeaderRegion = 3 * 2048;
    private const int FooterRegion = 3 * 64;

    private static partial async Task RunFormatAdversarialTests()
    {
        byte[] original = await File.ReadAllBytesAsync(_package);
        int end = original.Length - FooterRegion;
        var frames = FindFrames(original);
        Assert(frames.Count >= 4 && frames[^1].Length == 28, "Fixture needs full frames and terminal.");

        await Run("Unused password slot tampering in all replicas fails with first password", async () =>
        {
            byte[] damaged = RewriteLogicalHeader(original, header => header[48 + 2 * 76 + 60] ^= 1);
            await CheckDamaged(damaged, "unused-slot");
        });
        await Run("Reordered authenticated ciphertext frames are rejected", async () =>
        {
            var first = frames[0]; var second = frames[1];
            Assert(first.Length == second.Length, "Test frames must be equal-sized.");
            byte[] damaged = (byte[])original.Clone();
            original.AsSpan(second.Start, second.Length).CopyTo(damaged.AsSpan(first.Start));
            original.AsSpan(first.Start, first.Length).CopyTo(damaged.AsSpan(second.Start));
            await CheckDamaged(damaged, "reordered-frames");
        });
        await Run("Duplicated authenticated ciphertext frame is rejected", async () =>
        {
            byte[] damaged = (byte[])original.Clone();
            original.AsSpan(frames[0].Start, frames[0].Length).CopyTo(damaged.AsSpan(frames[1].Start));
            await CheckDamaged(damaged, "duplicated-frame");
        });
        await Run("Missing terminal fails despite three structurally valid footers", async () =>
        {
            byte[] damaged = [.. original[..frames[^1].Start], .. original[end..]];
            FixFooterLength(damaged);
            await CheckDamaged(damaged, "missing-terminal");
        });
        await Run("Extra frame after authenticated terminal fails despite valid footers", async () =>
        {
            byte[] damaged = [.. original[..end], .. original[frames[0].Start..(frames[0].Start + frames[0].Length)], .. original[end..]];
            FixFooterLength(damaged);
            await CheckDamaged(damaged, "after-terminal");
        });
        await Run("Forged excessive logical header length is bounded in every replica", async () =>
        {
            byte[] damaged = (byte[])original.Clone();
            for (int i = 0; i < 3; i++) BinaryPrimitives.WriteInt32LittleEndian(damaged.AsSpan(i * 2048 + 8), int.MaxValue);
            await CheckDamaged(damaged, "huge-header");
        });
        await Run("Forged excessive decoded frame length is rejected before allocation", async () =>
        {
            byte[] damaged = (byte[])original.Clone();
            BinaryPrimitives.WriteInt32LittleEndian(damaged.AsSpan(HeaderRegion), int.MaxValue);
            await CheckDamaged(damaged, "huge-raw-frame");
        });
        await Run("Forged excessive encoded frame length is rejected before allocation", async () =>
        {
            byte[] damaged = (byte[])original.Clone();
            BinaryPrimitives.WriteInt32LittleEndian(damaged.AsSpan(HeaderRegion + 4), int.MaxValue);
            await CheckDamaged(damaged, "huge-encoded-frame");
        });
        await Run("Negative frame length is rejected", async () =>
        {
            byte[] damaged = (byte[])original.Clone();
            BinaryPrimitives.WriteInt32LittleEndian(damaged.AsSpan(HeaderRegion), -1);
            await CheckDamaged(damaged, "negative-frame");
        });
        await Run("Frame codec and reserved bits are authenticated", async () =>
        {
            byte[] damaged = (byte[])original.Clone();
            damaged[HeaderRegion + 9] = 1;
            await CheckDamaged(damaged, "frame-reserved");
        });
        await Run("Forged excessive slot count is rejected before KDF work", async () =>
            await CheckDamaged(RewriteLogicalHeader(original, header =>
                BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(40), int.MaxValue)), "huge-slots"));
        await Run("Overflowing footer offset is rejected", async () =>
        {
            byte[] damaged = (byte[])original.Clone();
            RewriteFooters(damaged, record => BinaryPrimitives.WriteInt64LittleEndian(record.AsSpan(8), long.MaxValue));
            await CheckDamaged(damaged, "overflow-footer");
        });
        await Run("Negative footer offset is rejected", async () =>
        {
            byte[] damaged = (byte[])original.Clone();
            RewriteFooters(damaged, record => BinaryPrimitives.WriteInt64LittleEndian(record.AsSpan(8), -1));
            await CheckDamaged(damaged, "negative-footer");
        });
        await Run("Recovery length that does not reach the trailer is rejected", async () =>
        {
            byte[] damaged = (byte[])original.Clone();
            RewriteFooters(damaged, record => BinaryPrimitives.WriteInt64LittleEndian(record.AsSpan(24), 1));
            await CheckDamaged(damaged, "recovery-length");
        });
        await Run("Invalid compression identifier in all replicas is rejected", async () =>
            await CheckDamaged(RewriteLogicalHeader(original, header => header[16] = 0xff), "unknown-compression"));
        await Run("All corrupted header copies fail closed", async () =>
        {
            byte[] damaged = (byte[])original.Clone();
            for (int i = 0; i < 3; i++) damaged[i * 2048 + 55] ^= 1;
            await CheckDamaged(damaged, "all-headers-lost");
        });
        await Run("All corrupted footer copies fail closed", async () =>
        {
            byte[] damaged = (byte[])original.Clone();
            for (int i = 0; i < 3; i++) damaged[end + i * 64 + 63] ^= 1;
            await CheckDamaged(damaged, "all-footers-lost");
        });
        for (int keep = 0; keep < 3; keep++)
        {
            int surviving = keep;
            await Run($"Header/footer replica {surviving + 1} alone restores exact data", async () =>
            {
                byte[] damaged = (byte[])original.Clone();
                for (int i = 0; i < 3; i++)
                    if (i != surviving)
                    {
                        damaged.AsSpan(i * 2048, 2048).Clear();
                        damaged.AsSpan(end + i * 64, 64).Clear();
                    }
                string path = Path.Combine(_root, "redundant-survivor-" + surviving + ".2pw");
                await File.WriteAllBytesAsync(path, damaged);
                string output = Path.Combine(_root, "redundant-output-" + surviving);
                await PackageService.ExtractAsync(new(path, output, PasswordB));
                AssertTreeEqual(_fixture, Path.Combine(output, Path.GetFileName(_fixture)));
            });
        }
        await Run("Checksum-valid conflicting header copies fail closed", async () =>
        {
            byte[] damaged = (byte[])original.Clone();
            int length = BinaryPrimitives.ReadInt32LittleEndian(damaged.AsSpan(8));
            damaged[48 + 36] ^= 1;
            SHA256.HashData(damaged.AsSpan(48, length), damaged.AsSpan(16, 32));
            await CheckDamaged(damaged, "conflicting-header");
        });
        await Run("Checksum-valid conflicting footer copies fail closed", async () =>
        {
            byte[] damaged = (byte[])original.Clone();
            BinaryPrimitives.WriteInt64LittleEndian(damaged.AsSpan(end + 8), 1);
            BinaryPrimitives.WriteInt64LittleEndian(damaged.AsSpan(end + 16), end - 1);
            SHA256.HashData(damaged.AsSpan(end, 32), damaged.AsSpan(end + 32, 32));
            await CheckDamaged(damaged, "conflicting-footer");
        });
        await Run("Damaged footer pretending to be detached does not defeat good replicas", async () =>
        {
            byte[] damaged = (byte[])original.Clone();
            "2PWLINK2"u8.CopyTo(damaged.AsSpan(end));
            string path = Path.Combine(_root, "damaged-routing.2pw");
            await File.WriteAllBytesAsync(path, damaged);
            string output = Path.Combine(_root, "damaged-routing-output");
            await PackageService.ExtractAsync(new(path, output, PasswordA));
            AssertTreeEqual(_fixture, Path.Combine(output, Path.GetFileName(_fixture)));
        });
        await Run("Independent v3 reader authenticates frames and decodes standard PAX", async () =>
        {
            var decoded = await ReferenceDecode(_package);
            AssertReferenceTar(decoded.Tar);
        });
        await Run("Recovery data between payload and trailer is skipped by both readers", async () =>
        {
            byte[] blob = RandomNumberGenerator.GetBytes(4099);
            string package = Path.Combine(_root, "with-recovery.2pw");
            var created = await PackageService.CreateAsync(new(_fixture, package, [PasswordA], PackageCompression.Zstd,
                Recovery: (_, _, output, _) => output.Write(blob)));
            Assert(created.RecoveryBytes == blob.Length && (await PackageService.InspectAsync(package)).RecoveryBytes == blob.Length,
                "Recovery length was not recorded.");
            var regions = PackageService.LocateRegions(package);
            byte[] bytes = await File.ReadAllBytesAsync(package);
            Assert(regions.RecoveryLength == blob.Length && bytes.AsSpan((int)regions.RecoveryOffset, blob.Length).SequenceEqual(blob),
                "Recovery data was not stored in front of the trailer.");
            AssertReferenceTar((await ReferenceDecode(package)).Tar);
            string output = Path.Combine(_root, "with-recovery-output");
            await PackageService.ExtractAsync(new(package, output, PasswordA));
            AssertTreeEqual(_fixture, Path.Combine(output, Path.GetFileName(_fixture)));
        });
        await RunArchiveAttackCases();
        await RunDetachedCases();
    }

    private static List<(int Start, int Length)> FindFrames(byte[] package)
    {
        var result = new List<(int, int)>();
        for (int at = HeaderRegion; at < package.Length - FooterRegion;)
        {
            int encoded = BinaryPrimitives.ReadInt32LittleEndian(package.AsSpan(at + 4, 4));
            int length = checked(12 + encoded + 16);
            Assert(encoded >= 0 && encoded <= 1024 * 1024 && at + length <= package.Length - FooterRegion,
                "Invalid reference fixture frame.");
            result.Add((at, length));
            at += length;
        }
        return result;
    }

    private static async Task CheckDamaged(byte[] damaged, string label)
    {
        string path = Path.Combine(_root, label + ".2pw");
        await File.WriteAllBytesAsync(path, damaged);
        await ExpectExtractFailure(path, PasswordA);
    }

    private static byte[] RewriteLogicalHeader(byte[] original, Action<byte[]> change)
    {
        byte[] output = (byte[])original.Clone();
        int length = BinaryPrimitives.ReadInt32LittleEndian(output.AsSpan(8));
        byte[] header = output.AsSpan(48, length).ToArray();
        change(header);
        byte[] hash = SHA256.HashData(header);
        for (int i = 0; i < 3; i++)
        {
            header.CopyTo(output, i * 2048 + 48);
            hash.CopyTo(output, i * 2048 + 16);
        }
        return output;
    }

    private static void RewriteFooters(byte[] container, Action<byte[]> change)
    {
        for (int i = 0; i < 3; i++)
        {
            int start = container.Length - FooterRegion + i * 64;
            byte[] record = container.AsSpan(start, 64).ToArray();
            change(record);
            SHA256.HashData(record.AsSpan(0, 32), record.AsSpan(32, 32));
            record.CopyTo(container, start);
        }
    }

    private static void FixFooterLength(byte[] container) => RewriteFooters(container, record =>
    {
        long offset = BinaryPrimitives.ReadInt64LittleEndian(record.AsSpan(8));
        BinaryPrimitives.WriteInt64LittleEndian(record.AsSpan(16), container.Length - FooterRegion - offset);
    });

    private static partial Task RunArchiveAttackCases();
    private static partial Task RunDetachedCases();
}
