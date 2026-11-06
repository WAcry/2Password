using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using TwoPassword.Recovery;

namespace TwoPassword.Tests;

internal static partial class Program
{
    private static async Task RunPar2MetadataTests()
    {
        await Run("PAR2 parser accepts independently encoded Unicode descriptor bytes", async () =>
        {
            string directory = ParityDirectory();
            string basename = "资料_日本語_🙂.exe";
            byte[] content = "synthetic encrypted content"u8.ToArray();
            string index = Path.Combine(directory, basename + ".par2");
            await File.WriteAllBytesAsync(index, BuildParity([(basename, content)]));
            var parsed = await Par2Metadata.LoadAsync(index, CancellationToken.None);
            Assert(parsed.Sources.Count == 1 && parsed.Sources[0].Name == basename &&
                parsed.Sources[0].Length == content.Length &&
                parsed.Sources[0].Md5.SequenceEqual(MD5.HashData(content)), "Unicode PAR2 descriptor changed.");
        });
        await Run("PAR2 parser accepts only the intended launcher and sidecar", async () =>
        {
            string directory = ParityDirectory();
            string index = Path.Combine(directory, "package.exe.par2");
            await File.WriteAllBytesAsync(index, BuildParity([("package.exe", [1]), ("package.2pw", [2])]));
            var set = await Par2Metadata.LoadAsync(index, CancellationToken.None);
            Assert(set.Sources.Count == 2, "Two-file recovery set not recognized.");
        });
        await Run("PAR2 missing index recovers metadata from an intact volume", async () =>
        {
            string directory = ParityDirectory();
            string index = Path.Combine(directory, "package.exe.par2");
            string volume = Path.Combine(directory, "package.exe.vol000+001.par2");
            await File.WriteAllBytesAsync(volume, BuildParity([("package.exe", [1, 2, 3])]));
            var set = await Par2Metadata.LoadAsync(index, CancellationToken.None);
            Assert(set.RecoveryFiles.Length == 1 && set.IndexPath == volume, "Missing-index fallback failed.");
        });
        await Run("PAR2 completely excludes a corrupted index before native discovery", async () =>
        {
            string directory = ParityDirectory();
            string index = Path.Combine(directory, "package.exe.par2");
            string volume = Path.Combine(directory, "package.exe.vol000+001.par2");
            byte[] valid = BuildParity([("package.exe", [1, 2, 3])]);
            await File.WriteAllBytesAsync(volume, valid);
            byte[] broken = (byte[])valid.Clone();
            broken[0] ^= 1;
            await File.WriteAllBytesAsync(index, broken);
            var set = await Par2Metadata.LoadAsync(index, CancellationToken.None);
            Assert(set.IndexPath == volume && set.RecoveryFiles.Length == 1 && !set.RecoveryFiles.Contains(index),
                "Corrupted index leaked into native input set.");
        });
        await Run("PAR2 excludes an entire volume with a late truncated packet", async () =>
        {
            string directory = ParityDirectory();
            string index = Path.Combine(directory, "package.exe.par2");
            string volume = Path.Combine(directory, "package.exe.vol000+001.par2");
            byte[] valid = BuildParity([("package.exe", [1, 2, 3])]);
            await File.WriteAllBytesAsync(index, valid);
            await File.WriteAllBytesAsync(volume, valid[..^1]);
            var set = await Par2Metadata.LoadAsync(index, CancellationToken.None);
            Assert(set.RecoveryFiles.SequenceEqual([index]), "Partially validated volume was retained.");
        });
        await Run("PAR2 differing checksum-valid recovery sets fail closed", async () =>
        {
            string directory = ParityDirectory();
            string index = Path.Combine(directory, "package.exe.par2");
            await File.WriteAllBytesAsync(index, BuildParity([("package.exe", [1])]));
            await File.WriteAllBytesAsync(Path.Combine(directory, "package.exe.vol000+001.par2"),
                BuildParity([("package.exe", [2])]));
            await MustFail(() => Par2Metadata.LoadAsync(index, CancellationToken.None));
        });
        await Run("PAR2 conflicting full hashes for the same FileID fail closed", async () =>
        {
            string directory = ParityDirectory();
            string index = Path.Combine(directory, "package.exe.par2");
            byte[] valid = BuildParity([("package.exe", new byte[20000])]);
            byte[] conflicting = RewriteParityPacket(valid, "PAR 2.0\0FileDesc", body => body[16] ^= 1);
            await File.WriteAllBytesAsync(index, valid);
            await File.WriteAllBytesAsync(Path.Combine(directory, "package.exe.vol000+001.par2"), conflicting);
            await MustFail(() => Par2Metadata.LoadAsync(index, CancellationToken.None));
        });
        foreach (string name in new[] { "../package.exe", @"..\package.exe", "C:/package.exe",
            "package.exe:ads", "NUL.exe", "package.exe.", "unrelated.exe", "package.exe\0hidden" })
        {
            string captured = name;
            await Run("PAR2 rejects checksum-valid unsafe/unrelated filename: " +
                name.Replace("\0", "<NUL>", StringComparison.Ordinal), async () =>
            {
                string directory = ParityDirectory();
                string index = Path.Combine(directory, "package.exe.par2");
                await File.WriteAllBytesAsync(index, BuildParity([(captured, [1])]));
                await MustFail(() => Par2Metadata.LoadAsync(index, CancellationToken.None));
            });
        }
        await Run("PAR2 rejects case-colliding target descriptors", async () =>
        {
            string directory = ParityDirectory();
            string index = Path.Combine(directory, "package.exe.par2");
            await File.WriteAllBytesAsync(index, BuildParity([("package.exe", [1]), ("PACKAGE.EXE", [2])]));
            await MustFail(() => Par2Metadata.LoadAsync(index, CancellationToken.None));
        });
        await Run("PAR2 rejects Unicode filename override packets", async () =>
        {
            string directory = ParityDirectory();
            string index = Path.Combine(directory, "package.exe.par2");
            byte[] valid = BuildParity([("package.exe", [1])]);
            byte[] packet = ParityPacket("PAR 2.0\0UniFileN", new byte[32], valid.AsSpan(32, 16).ToArray());
            await File.WriteAllBytesAsync(index, [.. valid, .. packet]);
            await MustFail(() => Par2Metadata.LoadAsync(index, CancellationToken.None));
        });
        await Run("PAR2 verifies FileID independently of packet checksum", async () =>
        {
            string directory = ParityDirectory();
            string index = Path.Combine(directory, "package.exe.par2");
            byte[] data = RewriteParityPacket(BuildParity([("package.exe", [1])]),
                "PAR 2.0\0FileDesc", body => body[0] ^= 1);
            await File.WriteAllBytesAsync(index, data);
            await MustFail(() => Par2Metadata.LoadAsync(index, CancellationToken.None));
        });
        await Run("PAR2 rejects excessive block allocation metadata", async () =>
        {
            string directory = ParityDirectory();
            string index = Path.Combine(directory, "package.exe.par2");
            byte[] data = RewriteParityPacket(BuildParity([("package.exe", [1])]),
                "PAR 2.0\0Main\0\0\0\0", body => BinaryPrimitives.WriteUInt64LittleEndian(body, ulong.MaxValue));
            await File.WriteAllBytesAsync(index, data);
            await MustFail(() => Par2Metadata.LoadAsync(index, CancellationToken.None));
        });
        await Run("PAR2 rejects inconsistent recovery block lengths", async () =>
        {
            string directory = ParityDirectory();
            string index = Path.Combine(directory, "package.exe.par2");
            byte[] valid = BuildParity([("package.exe", [1])]);
            byte[] recovery = new byte[8];
            BinaryPrimitives.WriteUInt32LittleEndian(recovery, 1);
            await File.WriteAllBytesAsync(index, [.. valid, .. ParityPacket("PAR 2.0\0RecvSlic", recovery, valid.AsSpan(32, 16).ToArray())]);
            await MustFail(() => Par2Metadata.LoadAsync(index, CancellationToken.None));
        });
        await Run("PAR2 parser cancellation stops before work", async () =>
        {
            using var cts = new CancellationTokenSource();
            cts.Cancel();
            await MustCancel(() => Par2Metadata.LoadAsync(Path.Combine(_root, "missing.exe.par2"), cts.Token));
        });
    }

    private static string ParityDirectory()
    {
        string path = Path.Combine(_root, "par2-" + Guid.NewGuid().ToString("N")[..10]);
        Directory.CreateDirectory(path);
        return path;
    }

    private static byte[] BuildParity((string Name, byte[] Data)[] files)
    {
        const int blockSize = 4096;
        var descriptions = new List<(byte[] Body, byte[] Checks)>();
        foreach (var source in files)
        {
            byte[] name = Encoding.UTF8.GetBytes(source.Name);
            byte[] body = new byte[56 + (name.Length + 3) / 4 * 4];
            MD5.HashData(source.Data).CopyTo(body, 16);
            MD5.HashData(source.Data.AsSpan(0, Math.Min(16384, source.Data.Length))).CopyTo(body, 32);
            BinaryPrimitives.WriteUInt64LittleEndian(body.AsSpan(48), (ulong)source.Data.Length);
            name.CopyTo(body, 56);
            MD5.HashData(body.AsSpan(32, 24 + name.Length)).CopyTo(body, 0);
            int count = (source.Data.Length + blockSize - 1) / blockSize;
            byte[] checks = new byte[16 + count * 20];
            body.AsSpan(0, 16).CopyTo(checks);
            for (int i = 0; i < count; i++)
            {
                byte[] padded = new byte[blockSize];
                source.Data.AsSpan(i * blockSize, Math.Min(blockSize, source.Data.Length - i * blockSize)).CopyTo(padded);
                MD5.HashData(padded).CopyTo(checks, 16 + i * 20);
                BinaryPrimitives.WriteUInt32LittleEndian(checks.AsSpan(32 + i * 20), ParityCrc32(padded));
            }
            descriptions.Add((body, checks));
        }
        byte[] main = new byte[12 + files.Length * 16];
        BinaryPrimitives.WriteUInt64LittleEndian(main, blockSize);
        BinaryPrimitives.WriteUInt32LittleEndian(main.AsSpan(8), (uint)files.Length);
        for (int i = 0; i < descriptions.Count; i++) descriptions[i].Body.AsSpan(0, 16).CopyTo(main.AsSpan(12 + i * 16));
        byte[] setId = MD5.HashData(main);
        using var output = new MemoryStream();
        output.Write(ParityPacket("PAR 2.0\0Main\0\0\0\0", main, setId));
        foreach (var description in descriptions)
        {
            output.Write(ParityPacket("PAR 2.0\0FileDesc", description.Body, setId));
            output.Write(ParityPacket("PAR 2.0\0IFSC\0\0\0\0", description.Checks, setId));
        }
        output.Write(ParityPacket("PAR 2.0\0Creator\0", Encoding.ASCII.GetBytes("2Password independent tests"), setId));
        output.Write(ParityPacket("PAR 2.0\0RecvSlic", new byte[4 + blockSize], setId));
        return output.ToArray();
    }

    private static byte[] ParityPacket(string type, byte[] body, byte[] setId)
    {
        byte[] packet = new byte[64 + (body.Length + 3) / 4 * 4];
        "PAR2\0PKT"u8.CopyTo(packet);
        BinaryPrimitives.WriteUInt64LittleEndian(packet.AsSpan(8), (ulong)packet.Length);
        setId.CopyTo(packet, 32);
        Encoding.ASCII.GetBytes(type).CopyTo(packet, 48);
        body.CopyTo(packet, 64);
        MD5.HashData(packet.AsSpan(32)).CopyTo(packet, 16);
        return packet;
    }

    private static byte[] RewriteParityPacket(byte[] original, string type, Action<byte[]> updateBody)
    {
        byte[] output = (byte[])original.Clone();
        for (int at = 0; at < output.Length;)
        {
            int length = (int)BinaryPrimitives.ReadUInt64LittleEndian(output.AsSpan(at + 8, 8));
            if (Encoding.ASCII.GetString(output, at + 48, 16) == type)
            {
                byte[] body = output.AsSpan(at + 64, length - 64).ToArray();
                updateBody(body);
                body.CopyTo(output, at + 64);
                MD5.HashData(output.AsSpan(at + 32, length - 32)).CopyTo(output, at + 16);
                return output;
            }
            at += length;
        }
        throw new InvalidOperationException("Test packet type not found.");
    }

    private static uint ParityCrc32(byte[] data)
    {
        uint crc = uint.MaxValue;
        foreach (byte b in data)
        {
            crc ^= b;
            for (int i = 0; i < 8; i++) crc = (crc >> 1) ^ ((crc & 1) == 0 ? 0U : 0xedb88320U);
        }
        return ~crc;
    }
}
