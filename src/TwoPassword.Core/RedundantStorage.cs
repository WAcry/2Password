using System.Buffers.Binary;
using System.Security.Cryptography;

namespace TwoPassword.Core;

/// <summary>Fixed-size, bounded replicas. Checksums select intact copies; AEAD authenticates their logical content.</summary>
internal static class RedundantStorage
{
    internal const int Copies = 3;
    internal const int HeaderRecordSize = 2048;
    internal const int HeaderRegionSize = Copies * HeaderRecordSize;
    internal const int FooterRecordSize = 64;
    internal const int FooterRegionSize = Copies * FooterRecordSize;
    private const int HeaderPrefixSize = 48;

    internal static void WriteHeader(Stream output, ReadOnlySpan<byte> magic, ReadOnlySpan<byte> value)
    {
        if (magic.Length != 8 || value.Length > HeaderRecordSize - HeaderPrefixSize) throw new ArgumentOutOfRangeException(nameof(value));
        var record = new byte[HeaderRecordSize];
        magic.CopyTo(record);
        BinaryPrimitives.WriteInt32LittleEndian(record.AsSpan(8), value.Length);
        SHA256.HashData(value, record.AsSpan(16, 32));
        value.CopyTo(record.AsSpan(HeaderPrefixSize));
        for (int i = 0; i < Copies; i++) output.Write(record);
    }

    internal static byte[] ReadHeader(Stream input, ReadOnlySpan<byte> magic, int minimum, int maximum)
    {
        byte[]? chosen = null;
        var record = new byte[HeaderRecordSize];
        Span<byte> checksum = stackalloc byte[32];
        for (int i = 0; i < Copies; i++)
        {
            input.ReadExactly(record);
            int length = BinaryPrimitives.ReadInt32LittleEndian(record.AsSpan(8));
            if (!record.AsSpan(0, 8).SequenceEqual(magic) || length < minimum || length > maximum ||
                length > HeaderRecordSize - HeaderPrefixSize || BinaryPrimitives.ReadInt32LittleEndian(record.AsSpan(12)) != 0) continue;
            var value = record.AsSpan(HeaderPrefixSize, length);
            SHA256.HashData(value, checksum);
            if (!CryptographicOperations.FixedTimeEquals(checksum, record.AsSpan(16, 32))) continue;
            bool paddingValid = true;
            foreach (byte b in record.AsSpan(HeaderPrefixSize + length)) if (b != 0) { paddingValid = false; break; }
            if (!paddingValid) continue;
            if (chosen is null) chosen = value.ToArray();
            else if (!chosen.AsSpan().SequenceEqual(value))
                throw new PackageException(Text.Get("冗余元数据副本相互冲突，请先用恢复数据修复。"));
        }
        return chosen ?? throw new PackageException(Text.Get("所有元数据副本均损坏，请先用恢复数据修复。"));
    }

    internal static void WriteFooter(Stream output, ReadOnlySpan<byte> magic, long offset, long payloadLength)
    {
        if (magic.Length != 8) throw new ArgumentOutOfRangeException(nameof(magic));
        Span<byte> record = stackalloc byte[FooterRecordSize];
        record.Clear();
        magic.CopyTo(record);
        BinaryPrimitives.WriteInt64LittleEndian(record[8..], offset);
        BinaryPrimitives.WriteInt64LittleEndian(record[16..], payloadLength);
        SHA256.HashData(record[..32], record[32..]);
        for (int i = 0; i < Copies; i++) output.Write(record);
    }

    internal static (long Offset, long Length, long End) ReadFooter(FileStream file, ReadOnlySpan<byte> magic)
    {
        if (file.Length < FooterRegionSize) throw new PackageException(Text.Get("文件缺少完整的冗余尾部。"));
        file.Position = file.Length - FooterRegionSize;
        byte[]? chosen = null;
        Span<byte> record = stackalloc byte[FooterRecordSize];
        Span<byte> checksum = stackalloc byte[32];
        for (int i = 0; i < Copies; i++)
        {
            file.ReadExactly(record);
            if (!record[..8].SequenceEqual(magic)) continue;
            SHA256.HashData(record[..32], checksum);
            if (!CryptographicOperations.FixedTimeEquals(checksum, record[32..])) continue;
            if (chosen is null) chosen = record[..32].ToArray();
            else if (!chosen.AsSpan().SequenceEqual(record[..32]))
                throw new PackageException(Text.Get("冗余文件尾部相互冲突，请先用恢复数据修复。"));
        }
        if (chosen is null) throw new PackageException(Text.Get("文件尾部损坏或格式不受支持，请先用恢复数据修复。"));
        long offset = BinaryPrimitives.ReadInt64LittleEndian(chosen.AsSpan(8));
        long length = BinaryPrimitives.ReadInt64LittleEndian(chosen.AsSpan(16));
        long end = file.Length - FooterRegionSize;
        if (BinaryPrimitives.ReadInt64LittleEndian(chosen.AsSpan(24)) != 0 ||
            offset < 0 || offset > end || length != end - offset)
            throw new PackageException(Text.Get("加密包的文件边界无效。"));
        return (offset, length, end);
    }

    internal static bool HasFooterMarker(FileStream file, ReadOnlySpan<byte> magic, bool requireChecksum = false)
    {
        if (file.Length < FooterRegionSize) return false;
        long previous = file.Position;
        try
        {
            Span<byte> record = stackalloc byte[FooterRecordSize];
            Span<byte> checksum = stackalloc byte[32];
            for (int i = 0; i < Copies; i++)
            {
                file.Position = file.Length - FooterRegionSize + i * FooterRecordSize;
                file.ReadExactly(record);
                if (!record[..8].SequenceEqual(magic)) continue;
                if (!requireChecksum) return true;
                SHA256.HashData(record[..32], checksum);
                if (CryptographicOperations.FixedTimeEquals(checksum, record[32..])) return true;
            }
            return false;
        }
        finally { file.Position = previous; }
    }
}
