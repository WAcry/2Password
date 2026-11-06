using System.Buffers.Binary;
using System.Formats.Tar;
using System.Globalization;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using TwoPassword.Core;

namespace TwoPassword.Tests;

internal static partial class Program
{
    private static byte[]? _attackWrappingKey;
    private static readonly byte[] AttackSalt = Enumerable.Repeat((byte)0xa7, 16).ToArray();
    private static readonly long AttackTicks = new DateTime(2020, 1, 2, 3, 4, 5, DateTimeKind.Utc).Ticks;

    private static partial async Task RunArchiveAttackCases()
    {
        // The independent encoder deliberately does not use internal production code.
        // Cache one derived wrapping key for these known synthetic test credentials.
        using (var kdf = new Argon2id([0, .. new UTF8Encoding(false, true).GetBytes(PasswordA)])
        { Salt = AttackSalt, MemorySize = 65536, Iterations = 3, DegreeOfParallelism = 4 })
            _attackWrappingKey = kdf.GetBytes(32);
        try
        {
            await Run("Independent encoder produces a readable valid PAX package", async () =>
            {
                byte[] tar = MakeTar(new AttackEntry("independent.txt", TarEntryType.RegularFile, "independent reference"u8.ToArray()));
                string package = await WriteIndependentPackage(tar, 21, 1, 0);
                string output = Path.Combine(_root, "independent-encoder-output");
                await PackageService.ExtractAsync(new(package, output, PasswordA));
                Assert(File.ReadAllText(Path.Combine(output, "independent.txt")) == "independent reference",
                    "Independent valid-package control failed.");
            });
            foreach (string badPath in new[]
            {
                "../outside.txt", "/absolute.txt", "C:/absolute.txt", @"..\outside.txt",
                "NUL.txt", "COM1.txt", "LPT¹.txt", "root.txt:private", "trailing.", "trailing ",
                "root//child.txt", "root/./child.txt", "root/../child.txt", "root/\u0001control.txt"
            })
            {
                string captured = badPath;
                await Run("Authenticated unsafe TAR path is rejected: " + captured.Replace("\u0001", "<control>", StringComparison.Ordinal), async () =>
                    await RejectArchive(MakeTar(new AttackEntry(captured, TarEntryType.RegularFile, [])), 0, 1, 0));
            }
            await Run("Authenticated duplicate TAR names are rejected", async () =>
                await RejectArchive(MakeTar(new("root.txt", TarEntryType.RegularFile, []),
                    new("root.txt", TarEntryType.RegularFile, [])), 0, 2, 0));
            await Run("Authenticated case-colliding names are rejected", async () =>
                await RejectArchive(MakeTar(new("Root.txt", TarEntryType.RegularFile, []),
                    new("root.txt", TarEntryType.RegularFile, [])), 0, 2, 0));
            await Run("Authenticated file-directory collisions are rejected", async () =>
                await RejectArchive(MakeTar(new("root", TarEntryType.Directory),
                    new("root", TarEntryType.RegularFile, [])), 0, 1, 1));
            await Run("Authenticated missing parent directory is rejected", async () =>
                await RejectArchive(MakeTar(new AttackEntry("root/child.txt", TarEntryType.RegularFile, [])), 0, 1, 0));
            await Run("Authenticated file used as parent directory is rejected", async () =>
                await RejectArchive(MakeTar(new("root", TarEntryType.RegularFile, []),
                    new("root/child", TarEntryType.RegularFile, [])), 0, 2, 0));
            await Run("Authenticated multiple archive roots are rejected", async () =>
                await RejectArchive(MakeTar(new("first", TarEntryType.RegularFile, []),
                    new("second", TarEntryType.RegularFile, [])), 0, 2, 0));
            foreach (var type in new[] { TarEntryType.SymbolicLink, TarEntryType.HardLink, TarEntryType.Fifo })
            {
                var captured = type;
                await Run("Authenticated special TAR type is rejected: " + captured, async () =>
                    await RejectArchive(MakeTar(new AttackEntry("special", captured, Link: "../outside")), 0, 1, 0));
            }
            await Run("Authenticated file length exceeding declared total is rejected", async () =>
                await RejectArchive(MakeTar(new AttackEntry("root.txt", TarEntryType.RegularFile, [1, 2])), 1, 1, 0));
            await Run("Authenticated missing declared entries are rejected", async () =>
                await RejectArchive(MakeTar(new AttackEntry("root.txt", TarEntryType.RegularFile, [])), 0, 2, 0));
            await Run("Authenticated empty TAR cannot satisfy nonempty entry declaration", async () =>
                await RejectArchive(new byte[1024], 0, 1, 0));
            byte[] valid = MakeTar(new AttackEntry("root.txt", TarEntryType.RegularFile, []));
            await Run("Authenticated TAR missing both EOF blocks is rejected", async () =>
                await RejectArchive(valid[..^1024], 0, 1, 0));
            await Run("Authenticated TAR missing one EOF block is rejected", async () =>
                await RejectArchive(valid[..^512], 0, 1, 0));
            await Run("Authenticated TAR with extra EOF block is rejected", async () =>
                await RejectArchive([.. valid, .. new byte[512]], 0, 1, 0));
            await Run("Authenticated TAR with bytes after EOF is rejected", async () =>
                await RejectArchive([.. valid, 1], 0, 1, 0));
            await Run("Authenticated invalid UTF-8 PAX name is rejected without replacement", async () =>
            {
                byte[] metadata = [.. StandardPaxFields(), .. PaxRecord("path", [0xff, 0x2e, 0x74, 0x78, 0x74])];
                await RejectArchive(RawPaxTar(metadata), 0, 1, 0);
            });
            await Run("Authenticated invalid UTF-8 raw TAR header name is rejected", async () =>
            {
                byte[] tar = RawPaxTar(StandardPaxFields());
                int metadataSize = BinaryPaxPayloadLength(StandardPaxFields().Length);
                int regularHeader = 512 + metadataSize;
                tar[regularHeader] = 0xff;
                SetTarChecksum(tar.AsSpan(regularHeader, 512));
                await RejectArchive(tar, 0, 1, 0);
            });
            await Run("Authenticated oversized PAX metadata is rejected before allocation", async () =>
            {
                byte[] tar = (byte[])valid.Clone();
                WriteTarNumber(tar.AsSpan(124, 12), 1024 * 1024 * 1024);
                SetTarChecksum(tar.AsSpan(0, 512));
                await RejectArchive(tar, 0, 1, 0);
            });
            await Run("Authenticated duplicate PAX fields are rejected", async () =>
            {
                byte[] metadata = [.. StandardPaxFields(), .. PaxRecord("path", "root.txt"u8),
                    .. PaxRecord("path", "other.txt"u8)];
                await RejectArchive(RawPaxTar(metadata), 0, 1, 0);
            });
            await Run("Authenticated excessive PAX field count is rejected", async () =>
            {
                using var metadata = new MemoryStream();
                metadata.Write(StandardPaxFields());
                for (int i = 0; i < 65; i++) metadata.Write(PaxRecord("test.field" + i, "x"u8));
                await RejectArchive(RawPaxTar(metadata.ToArray()), 0, 1, 0);
            });
            await Run("Authenticated PAX size larger than total is rejected", async () =>
            {
                byte[] metadata = [.. StandardPaxFields(), .. PaxRecord("size", "9999999999999"u8)];
                await RejectArchive(RawPaxTar(metadata), 0, 1, 0);
            });
            await Run("Authenticated directory with file data is rejected", async () =>
                await RejectArchive(RawPaxTar(StandardPaxFields(), directoryWithData: true), 0, 0, 1));
            byte[] compressed = CompressReference(valid);
            await Run("Independent encoder produces a readable Brotli package", async () =>
            {
                string package = await WriteIndependentPackage(valid, 0, 1, 0, PackageCompression.Brotli);
                string output = Path.Combine(_root, "independent-brotli-output");
                await PackageService.ExtractAsync(new(package, output, PasswordA));
                Assert(File.Exists(Path.Combine(output, "root.txt")), "Independent compressed control failed.");
            });
            await Run("Authenticated truncated Brotli block is rejected", async () =>
                await RejectEncodedFrame(compressed[..(compressed.Length / 2)], valid.Length, PackageCompression.Brotli));
            await Run("Authenticated trailing bytes after Brotli block are rejected", async () =>
                await RejectEncodedFrame([.. compressed, 0xff], valid.Length, PackageCompression.Brotli));
            await Run("Authenticated concatenated Brotli frames are rejected", async () =>
                await RejectEncodedFrame([.. compressed, .. compressed], valid.Length, PackageCompression.Brotli));
            await Run("Authenticated Brotli expansion beyond declared raw length is bounded", async () =>
                await RejectEncodedFrame(compressed, valid.Length - 1, PackageCompression.Brotli));
            byte[] zstd = CompressZstdReference(valid);
            await Run("Independent encoder produces a readable Zstd block package", async () =>
            {
                string package = await WriteIndependentPackage(valid, 0, 1, 0, PackageCompression.Zstd);
                string output = Path.Combine(_root, "independent-zstd-output");
                await PackageService.ExtractAsync(new(package, output, PasswordA));
                Assert(File.Exists(Path.Combine(output, "root.txt")), "Independent Zstd control failed.");
            });
            await Run("Authenticated truncated Zstd block is rejected", async () =>
                await RejectEncodedFrame(zstd[..^1], valid.Length, PackageCompression.Zstd));
            await Run("Authenticated trailing bytes after Zstd frame are rejected", async () =>
                await RejectEncodedFrame([.. zstd, 0], valid.Length, PackageCompression.Zstd));
            await Run("Authenticated concatenated Zstd frames are rejected", async () =>
                await RejectEncodedFrame([.. zstd, .. zstd], valid.Length, PackageCompression.Zstd));
            await Run("Authenticated Zstd declared output length mismatch is rejected", async () =>
                await RejectEncodedFrame(zstd, valid.Length + 1, PackageCompression.Zstd));
            await Run("Authenticated Zstd oversized advertised content is bounded", async () =>
                await RejectEncodedFrame(CompressZstdReference(new byte[2 * 1024 * 1024]), valid.Length, PackageCompression.Zstd));
            await Run("Authenticated Zstd unknown content size is rejected", async () =>
            {
                using var compressor = new ZstdSharp.Compressor(3);
                compressor.SetParameter(ZstdSharp.Unsafe.ZSTD_cParameter.ZSTD_c_contentSizeFlag, 0);
                await RejectEncodedFrame(compressor.Wrap(valid).ToArray(), valid.Length, PackageCompression.Zstd);
            });
            await Run("Authenticated Zstd skippable frame is rejected", async () =>
                await RejectEncodedFrame([0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0], valid.Length, PackageCompression.Zstd));
            await Run("Authenticated per-frame codec cannot override selected algorithm", async () =>
            {
                string package = await WriteReferenceFrames([new ReferenceFrame(zstd, valid.Length, PackageCompression.Zstd)],
                    0, 1, 0, PackageCompression.Brotli);
                await ExpectExtractFailure(package, PasswordA);
            });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(_attackWrappingKey);
            _attackWrappingKey = null;
        }
    }

    private static byte[] MakeTar(params AttackEntry[] entries)
    {
        using var output = new MemoryStream();
        using (var writer = new TarWriter(output, TarEntryFormat.Pax, leaveOpen: true))
        {
            foreach (var item in entries)
            {
                var entry = new PaxTarEntry(item.Type, item.Name, new Dictionary<string, string>
                {
                    ["2Password.creationTicks"] = AttackTicks.ToString(CultureInfo.InvariantCulture),
                    ["2Password.writeTicks"] = AttackTicks.ToString(CultureInfo.InvariantCulture),
                    ["2Password.attributes"] = "0"
                });
                if (item.Type == TarEntryType.RegularFile)
                    entry.DataStream = new MemoryStream(item.Data ?? []);
                if (item.Type is TarEntryType.SymbolicLink or TarEntryType.HardLink)
                    entry.LinkName = item.Link ?? "target";
                writer.WriteEntry(entry);
                entry.DataStream?.Dispose();
            }
        }
        return output.ToArray();
    }

    private static async Task RejectArchive(byte[] archive, long total, int files, int dirs,
        PackageCompression compression = PackageCompression.None)
    {
        string package = await WriteIndependentPackage(archive, total, files, dirs, compression);
        await ExpectExtractFailure(package, PasswordA);
    }

    private static async Task RejectEncodedFrame(byte[] encoded, int rawLength, PackageCompression codec)
    {
        string package = await WriteReferenceFrames([new ReferenceFrame(encoded, rawLength, codec)], 0, 1, 0, codec);
        await ExpectExtractFailure(package, PasswordA);
    }

    private static Task<string> WriteIndependentPackage(byte[] archive, long total, int files, int dirs,
        PackageCompression compression = PackageCompression.None) =>
        WriteReferencePackage(archive, total, files, dirs, compression);

    private static byte[] CompressReference(byte[] input)
    {
        using var output = new MemoryStream();
        using (var stream = new BrotliStream(output, CompressionLevel.Fastest, leaveOpen: true)) stream.Write(input);
        return output.ToArray();
    }

    private static byte[] StandardPaxFields() =>
    [
        .. PaxRecord("2Password.creationTicks", Encoding.ASCII.GetBytes(AttackTicks.ToString(CultureInfo.InvariantCulture))),
        .. PaxRecord("2Password.writeTicks", Encoding.ASCII.GetBytes(AttackTicks.ToString(CultureInfo.InvariantCulture))),
        .. PaxRecord("2Password.attributes", "0"u8)
    ];

    private static byte[] PaxRecord(string key, ReadOnlySpan<byte> value)
    {
        byte[] prefix = Encoding.ASCII.GetBytes(key + "=");
        int contentLength = prefix.Length + value.Length + 1;
        int size = contentLength + 2;
        while (size != contentLength + size.ToString(CultureInfo.InvariantCulture).Length + 1)
            size = contentLength + size.ToString(CultureInfo.InvariantCulture).Length + 1;
        return [.. Encoding.ASCII.GetBytes(size.ToString(CultureInfo.InvariantCulture) + " "), .. prefix, .. value, (byte)'\n'];
    }

    private static int BinaryPaxPayloadLength(int length) => (length + 511) / 512 * 512;

    private static byte[] RawPaxTar(byte[] metadata, bool directoryWithData = false)
    {
        using var output = new MemoryStream();
        output.Write(TarHeader("PaxHeaders/root", (byte)'x', metadata.Length));
        output.Write(metadata);
        output.Write(new byte[BinaryPaxPayloadLength(metadata.Length) - metadata.Length]);
        output.Write(TarHeader("root.txt", directoryWithData ? (byte)'5' : (byte)'0', directoryWithData ? 1 : 0));
        if (directoryWithData) output.Write(new byte[512]);
        output.Write(new byte[1024]);
        return output.ToArray();
    }

    private static byte[] TarHeader(string name, byte type, long size)
    {
        byte[] header = new byte[512];
        Encoding.UTF8.GetBytes(name).CopyTo(header, 0);
        WriteTarNumber(header.AsSpan(100, 8), 384);
        WriteTarNumber(header.AsSpan(108, 8), 0);
        WriteTarNumber(header.AsSpan(116, 8), 0);
        WriteTarNumber(header.AsSpan(124, 12), size);
        WriteTarNumber(header.AsSpan(136, 12), 0);
        header[156] = type;
        "ustar\0"u8.CopyTo(header.AsSpan(257));
        "00"u8.CopyTo(header.AsSpan(263));
        SetTarChecksum(header);
        return header;
    }

    private static void WriteTarNumber(Span<byte> destination, long value)
    {
        destination.Fill((byte)'0');
        destination[^1] = 0;
        byte[] digits = Encoding.ASCII.GetBytes(Convert.ToString(value, 8));
        digits.CopyTo(destination[(destination.Length - digits.Length - 1)..]);
    }

    private static void SetTarChecksum(Span<byte> header)
    {
        header.Slice(148, 8).Fill((byte)' ');
        int sum = 0;
        foreach (byte value in header) sum += value;
        byte[] checksum = Encoding.ASCII.GetBytes(Convert.ToString(sum, 8).PadLeft(6, '0'));
        checksum.CopyTo(header[148..]);
        header[154] = 0;
        header[155] = (byte)' ';
    }

    private sealed record AttackEntry(string Name, TarEntryType Type, byte[]? Data = null, string? Link = null);
}
