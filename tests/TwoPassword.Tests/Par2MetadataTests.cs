using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using TwoPassword.Recovery;

namespace TwoPassword.Tests;

internal static partial class Program
{
    private const string MainPacket = "PAR 2.0\0Main\0\0\0\0";
    private const string FileDescPacket = "PAR 2.0\0FileDesc";
    private const string RecoveryPacket = "PAR 2.0\0RecvSlic";

    private static async Task RunPar2MetadataTests()
    {
        byte[] payload = RandomNumberGenerator.GetBytes(20000);
        await Run("PAR2 block size follows par2cmdline defaults", () =>
        {
            Assert(Par2Metadata.BlockSize(1) == 4 && Par2Metadata.BlockSize(8000) == 4 && Par2Metadata.BlockSize(8001) == 8,
                "Small payload block size changed.");
            Assert(Par2Metadata.BlockSize(5 * 1024 * 1024) == 2624, "Block size differs from par2cmdline for 5 MiB.");
            return Task.CompletedTask;
        });
        await Run("PAR2 reader accepts a set stored after the payload", () =>
        {
            var set = ReadParity(BuildParity(payload), payload.Length);
            long blockSize = Par2Metadata.BlockSize(payload.Length);
            byte[] first = new byte[blockSize];
            payload.AsSpan(0, (int)blockSize).CopyTo(first);
            Assert(set.BlockSize == blockSize && set.SourceMd5.SequenceEqual(MD5.HashData(payload)) &&
                set.SliceMd5.Length == (payload.Length + blockSize - 1) / blockSize && set.SliceMd5[0].SequenceEqual(MD5.HashData(first)),
                "Recovery set metadata changed.");
            Assert(set.RecoveryBlocks == 2 && set.Packets.Count == 5, "Creator packet was kept or a packet was lost.");
            return Task.CompletedTask;
        });
        await Run("PAR2 reader resumes at the next packet after damage", () =>
        {
            byte[] critical = BuildParity(payload, recovery: 0);
            byte[] region = [.. critical, .. critical, .. BuildParity(payload, critical: false)];
            region[64 + 3] ^= 1;
            region[critical.Length * 2] ^= 1;
            var set = ReadParity(region, payload.Length);
            Assert(set.RecoveryBlocks == 1, "Damage was not limited to the packets it hit.");
            return Task.CompletedTask;
        });
        await Run("PAR2 reader ignores a truncated final packet", () =>
        {
            Assert(ReadParity(BuildParity(payload)[..^1], payload.Length).RecoveryBlocks == 1, "Truncated packet was used.");
            return Task.CompletedTask;
        });
        await Run("PAR2 differing checksum-valid recovery sets fail closed", () =>
        {
            byte[] other = RandomNumberGenerator.GetBytes(payload.Length);
            return MustFail(() => Task.FromResult(ReadParity([.. BuildParity(payload), .. BuildParity(other)], payload.Length)));
        });
        await Run("PAR2 conflicting descriptions of the same FileID fail closed", () =>
        {
            byte[] valid = BuildParity(payload);
            byte[] conflicting = RewriteParityPacket(valid, FileDescPacket, body => body[16] ^= 1);
            return MustFail(() => Task.FromResult(ReadParity([.. valid, .. conflicting], payload.Length)));
        });
        foreach (string name in new[] { "../payload", "PAYLOAD", "payloa", "payload.exe", "payload\0x", "package.exe" })
        {
            string captured = name;
            await Run("PAR2 rejects a source name other than the payload: " + name.Replace("\0", "<NUL>", StringComparison.Ordinal),
                () => MustFail(() => Task.FromResult(ReadParity(BuildParity(payload, captured), payload.Length))));
        }
        await Run("PAR2 rejects a set describing a different payload length", () =>
            MustFail(() => Task.FromResult(ReadParity(BuildParity(payload), payload.Length + 1))));
        await Run("PAR2 rejects a non-default block size", () =>
            MustFail(() => Task.FromResult(ReadParity(BuildParity(payload, blockSize: 4096), payload.Length))));
        await Run("PAR2 verifies FileID independently of packet checksum", () =>
        {
            byte[] region = RewriteParityPacket(BuildParity(payload), FileDescPacket, body => body[0] ^= 1);
            return MustFail(() => Task.FromResult(ReadParity(region, payload.Length)));
        });
        await Run("PAR2 rejects excessive block allocation metadata", () =>
        {
            byte[] region = RewriteParityPacket(BuildParity(payload), MainPacket, body => BinaryPrimitives.WriteUInt64LittleEndian(body, ulong.MaxValue));
            return MustFail(() => Task.FromResult(ReadParity(region, payload.Length)));
        });
        await Run("PAR2 keeps unknown packet types away from the native tool", () =>
        {
            byte[] valid = BuildParity(payload);
            byte[] setId = valid.AsSpan(32, 16).ToArray();
            byte[] region = [.. valid, .. ParityPacket("PAR 2.0\0UniFileN", new byte[32], setId)];
            using var file = ParityFile(region, out long start);
            var set = Par2Metadata.Read(file, start, region.Length, payload.Length, CancellationToken.None);
            using var output = new MemoryStream();
            Assert(Par2Metadata.Copy(file, start, set, output, CancellationToken.None) == 2, "Recovery packets were lost while copying.");
            string copied = Encoding.ASCII.GetString(output.ToArray());
            Assert(!copied.Contains("UniFileN", StringComparison.Ordinal) && !copied.Contains("Creator", StringComparison.Ordinal),
                "Unused packet types reached the native input.");
            return Task.CompletedTask;
        });
        await Run("PAR2 skips wrong-size and duplicate recovery blocks", () =>
        {
            byte[] valid = BuildParity(payload);
            byte[] setId = valid.AsSpan(32, 16).ToArray();
            byte[] shortBlock = new byte[8];
            BinaryPrimitives.WriteUInt32LittleEndian(shortBlock, 7);
            byte[] region = [.. valid, .. ParityPacket(RecoveryPacket, shortBlock, setId), .. BuildParity(payload, critical: false, recovery: 1)];
            var set = ReadParity(region, payload.Length);
            Assert(set.RecoveryBlocks == 2 && set.Packets.Count == 5, "A malformed or repeated recovery block was counted.");
            return Task.CompletedTask;
        });
        await Run("PAR2 copy checks each packet again while reading it", () =>
        {
            byte[] region = BuildParity(payload);
            using var file = ParityFile(region, out long start);
            var set = Par2Metadata.Read(file, start, region.Length, payload.Length, CancellationToken.None);
            var last = set.Packets[^1];
            file.Position = start + last.Offset + 70;
            file.WriteByte(0x5a);
            file.Flush();
            using var output = new MemoryStream();
            Assert(Par2Metadata.Copy(file, start, set, output, CancellationToken.None) == 1 &&
                output.Length == set.Packets.Sum(p => p.Length) - last.Length, "A packet changed after validation was copied.");
            return Task.CompletedTask;
        });
        await Run("PAR2 parser cancellation stops before work", () =>
        {
            using var cts = new CancellationTokenSource();
            cts.Cancel();
            return MustCancel(() => Task.FromResult(ReadParity(BuildParity(payload), payload.Length, cts.Token)));
        });
        await Run("PAR2 repeated descriptions, tables and Creator packets retain one bounded set and the true end", () =>
        {
            byte[] valid = BuildParity(payload);
            byte[] description = FindParityPacket(valid, FileDescPacket);
            byte[] table = FindParityPacket(valid, "PAR 2.0\0IFSC\0\0\0\0");
            byte[] creator = FindParityPacket(valid, "PAR 2.0\0Creator\0");
            using var region = new MemoryStream();
            region.Write(valid);
            for (int i = 0; i < 64000; i++) region.Write(description);
            // These repeated table bodies exceed the retained-byte budget in aggregate,
            // but only one copy should be charged and retained.
            for (int i = 0; i < 300; i++) region.Write(table);
            for (int i = 0; i < 1000; i++) region.Write(creator);
            var set = ReadParity(region.ToArray(), payload.Length);
            Assert(set.Packets.Count == 5 && set.RecoveryBlocks == 2, "Repeated metadata was retained.");
            Assert(set.End == region.Length, "Discarding duplicates or Creator packets shortened the recovery region.");
            return Task.CompletedTask;
        });
        await Run("PAR2 selected metadata keeps its physical packet order", () =>
        {
            byte[] valid = BuildParity(payload);
            byte[] main = FindParityPacket(valid, MainPacket);
            byte[] description = FindParityPacket(valid, FileDescPacket);
            byte[] table = FindParityPacket(valid, "PAR 2.0\0IFSC\0\0\0\0");
            byte[] recovery = FindParityPacket(valid, RecoveryPacket);
            var set = ReadParity([.. recovery, .. table, .. main, .. description], payload.Length);
            Assert(set.Packets.Select(p => p.Offset).SequenceEqual(new long[] { 0, recovery.Length, recovery.Length + table.Length,
                recovery.Length + table.Length + main.Length }), "The selected packets were reordered.");
            return Task.CompletedTask;
        });
        await Run("PAR2 physical end includes irrelevant file metadata and invalid exponents but excludes false Main identities", () =>
        {
            byte[] valid = BuildParity(payload);
            byte[] foreign = RewriteParityPacket(FindParityPacket(valid, FileDescPacket), FileDescPacket, body => body[0] ^= 1);
            byte[] recovery = RewriteParityPacket(FindParityPacket(valid, RecoveryPacket), RecoveryPacket,
                body => BinaryPrimitives.WriteUInt32LittleEndian(body, 65535));
            byte[] invalidMain = RewriteParityPacket(FindParityPacket(valid, MainPacket), MainPacket, body => body[0] ^= 1);
            var set = ReadParity([.. valid, .. foreign, .. recovery, .. invalidMain], payload.Length);
            Assert(set.Packets.Count == 5 && set.End == valid.Length + foreign.Length + recovery.Length,
                "The end or packet selection changed when unrelated metadata was discarded.");
            return Task.CompletedTask;
        });
        await Run("PAR2 conflicting tables of the selected FileID fail closed", () =>
        {
            const string type = "PAR 2.0\0IFSC\0\0\0\0";
            byte[] valid = BuildParity(payload);
            byte[] conflicting = RewriteParityPacket(FindParityPacket(valid, type), type, body => body[16] ^= 1);
            return MustFail(() => Task.FromResult(ReadParity([.. valid, .. conflicting], payload.Length)));
        });
        await Run("PAR2 conflicting descriptions for an unrelated FileID remain ignored", () =>
        {
            byte[] valid = BuildParity(payload);
            byte[] foreign = RewriteParityPacket(FindParityPacket(valid, FileDescPacket), FileDescPacket, body => body[0] ^= 1);
            byte[] conflicting = RewriteParityPacket(foreign, FileDescPacket, body => body[16] ^= 1);
            var set = ReadParity([.. valid, .. foreign, .. conflicting], payload.Length);
            Assert(set.Packets.Count == 5 && set.End == valid.Length + foreign.Length + conflicting.Length,
                "Unrelated FileID conflicts affected the selected file or physical end.");
            return Task.CompletedTask;
        });
        await Run("PAR2 orphan recovery-set tracking has an explicit boundary", async () =>
        {
            byte[] valid = BuildParity(payload);
            using var region = new MemoryStream();
            region.Write(valid);
            for (int i = 1; i <= Par2Metadata.MaxRecoverySets; i++)
            {
                byte[] setId = new byte[16];
                BinaryPrimitives.WriteInt32LittleEndian(setId, i);
                region.Write(ParityPacket("PAR 2.0\0Creator\0", new byte[4], setId));
                if (i == Par2Metadata.MaxRecoverySets - 1)
                {
                    var set = ReadParity(region.ToArray(), payload.Length);
                    Assert(set.End == valid.Length && set.Packets.Count == 5, "Foreign Creator sets changed the selected set.");
                }
            }
            await MustFail(() => Task.FromResult(ReadParity(region.ToArray(), payload.Length)));
        });
        await Run("PAR2 unique candidate count is bounded independently of body size", async () =>
        {
            byte[] valid = BuildParity(payload);
            byte[] setId = valid.AsSpan(32, 16).ToArray();
            byte[] body = FindParityPacket(valid, FileDescPacket)[64..];
            body.AsSpan(0, 16).Clear();
            using var region = new MemoryStream();
            region.Write(valid);
            int foreignCount = Par2Metadata.MaxRetainedPackets - 5;
            for (int i = 1; i <= foreignCount; i++)
            {
                BinaryPrimitives.WriteInt32LittleEndian(body, i);
                region.Write(ParityPacket(FileDescPacket, body, setId));
            }
            Assert(ReadParity(region.ToArray(), payload.Length).Packets.Count == 5, "The permitted candidate boundary was rejected.");
            BinaryPrimitives.WriteInt32LittleEndian(body, foreignCount + 1);
            region.Write(ParityPacket(FileDescPacket, body, setId));
            await MustFail(() => Task.FromResult(ReadParity(region.ToArray(), payload.Length)));
        });
        await Run("PAR2 unique checksum-table bodies have a separate memory budget", async () =>
        {
            const string type = "PAR 2.0\0IFSC\0\0\0\0";
            byte[] valid = BuildParity(payload);
            byte[] setId = valid.AsSpan(32, 16).ToArray();
            byte[] body = FindParityPacket(valid, type)[64..];
            body.AsSpan(0, 16).Clear();
            long initialBytes = 28 + 64 + body.Length + 2 * 4;
            int foreignCount = (int)((Par2Metadata.MaxMetadataBytes - initialBytes) / body.Length);
            using var region = new MemoryStream();
            region.Write(valid);
            for (int i = 1; i <= foreignCount; i++)
            {
                BinaryPrimitives.WriteInt32LittleEndian(body, i);
                region.Write(ParityPacket(type, body, setId));
            }
            Assert(ReadParity(region.ToArray(), payload.Length).Packets.Count == 5, "The permitted body budget was rejected.");
            BinaryPrimitives.WriteInt32LittleEndian(body, foreignCount + 1);
            region.Write(ParityPacket(type, body, setId));
            await MustFail(() => Task.FromResult(ReadParity(region.ToArray(), payload.Length)));
        });
        await Run("PAR2 cancellation interrupts a long repeated-metadata scan", async () =>
        {
            byte[] valid = BuildParity(payload);
            byte[] description = FindParityPacket(valid, FileDescPacket);
            using var region = new MemoryStream();
            region.Write(valid);
            for (int i = 0; i < 100000; i++) region.Write(description);
            using var file = ParityFile(region.ToArray(), out long start);
            using var cts = new CancellationTokenSource();
            cts.CancelAfter(10);
            await MustCancel(() => Task.Run(() => Par2Metadata.Read(file, start, region.Length, payload.Length, cts.Token)));
        });
    }

    private static byte[] FindParityPacket(byte[] region, string type)
    {
        for (int at = 0; at < region.Length;)
        {
            int length = checked((int)BinaryPrimitives.ReadUInt64LittleEndian(region.AsSpan(at + 8)));
            if (Encoding.ASCII.GetString(region, at + 48, 16) == type) return region.AsSpan(at, length).ToArray();
            at += length;
        }
        throw new InvalidOperationException("Expected PAR2 packet was missing from the fixture.");
    }

    private static Par2Set ReadParity(byte[] region, long sourceLength, CancellationToken cancellationToken = default)
    {
        using var file = ParityFile(region, out long start);
        return Par2Metadata.Read(file, start, region.Length, sourceLength, cancellationToken);
    }

    /// <summary>Places the region between unrelated bytes, as it sits between the payload and the trailer.</summary>
    private static FileStream ParityFile(byte[] region, out long start)
    {
        string path = Path.Combine(_root, "par2-" + Guid.NewGuid().ToString("N")[..10] + ".bin");
        byte[] before = RandomNumberGenerator.GetBytes(37), after = RandomNumberGenerator.GetBytes(192);
        File.WriteAllBytes(path, [.. before, .. region, .. after]);
        start = before.Length;
        return new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None, 4096, FileOptions.DeleteOnClose);
    }

    private static byte[] BuildParity(byte[] data, string name = Par2Metadata.SourceName, long? blockSize = null,
        bool critical = true, int recovery = 2)
    {
        long size = blockSize ?? Par2Metadata.BlockSize(data.Length);
        byte[] nameBytes = Encoding.UTF8.GetBytes(name);
        byte[] description = new byte[56 + (nameBytes.Length + 3) / 4 * 4];
        MD5.HashData(data).CopyTo(description, 16);
        MD5.HashData(data.AsSpan(0, Math.Min(16384, data.Length))).CopyTo(description, 32);
        BinaryPrimitives.WriteUInt64LittleEndian(description.AsSpan(48), (ulong)data.Length);
        nameBytes.CopyTo(description, 56);
        MD5.HashData(description.AsSpan(32, 24 + nameBytes.Length)).CopyTo(description, 0);
        int count = (int)((data.Length + size - 1) / size);
        byte[] checks = new byte[16 + count * 20];
        description.AsSpan(0, 16).CopyTo(checks);
        for (int i = 0; i < count; i++)
        {
            byte[] padded = new byte[size];
            data.AsSpan((int)(i * size), (int)Math.Min(size, data.Length - i * size)).CopyTo(padded);
            MD5.HashData(padded).CopyTo(checks, 16 + i * 20);
            BinaryPrimitives.WriteUInt32LittleEndian(checks.AsSpan(32 + i * 20), ParityCrc32(padded));
        }
        byte[] main = new byte[28];
        BinaryPrimitives.WriteUInt64LittleEndian(main, (ulong)size);
        BinaryPrimitives.WriteUInt32LittleEndian(main.AsSpan(8), 1);
        description.AsSpan(0, 16).CopyTo(main.AsSpan(12));
        byte[] setId = MD5.HashData(main);
        using var output = new MemoryStream();
        if (critical)
        {
            output.Write(ParityPacket(MainPacket, main, setId));
            output.Write(ParityPacket(FileDescPacket, description, setId));
            output.Write(ParityPacket("PAR 2.0\0IFSC\0\0\0\0", checks, setId));
            output.Write(ParityPacket("PAR 2.0\0Creator\0", Encoding.ASCII.GetBytes("2Password independent tests"), setId));
        }
        for (int exponent = 0; exponent < recovery; exponent++)
        {
            byte[] body = new byte[4 + size];
            BinaryPrimitives.WriteUInt32LittleEndian(body, (uint)exponent);
            RandomNumberGenerator.Fill(body.AsSpan(4));
            output.Write(ParityPacket(RecoveryPacket, body, setId));
        }
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
