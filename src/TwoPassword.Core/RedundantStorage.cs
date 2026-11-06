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
        for (int i = 0; i < Copies; i++)
        {
            input.ReadExactly(record);
            if (!IsIntact(record, magic, minimum, maximum, out int length)) continue;
            var value = record.AsSpan(HeaderPrefixSize, length);
            if (chosen is null) chosen = value.ToArray();
            else if (!chosen.AsSpan().SequenceEqual(value))
                throw new PackageException(Text.Get("冗余元数据副本相互冲突，请先用恢复数据修复。"));
        }
        return chosen ?? throw new PackageException(Text.Get("所有元数据副本均损坏，请先用恢复数据修复。"));
    }

    /// <summary>
    /// Position of the first intact header record in the file, or -1. Used only when the footer is lost.
    /// The magic alone is not enough: an EXE stub can contain it as a constant.
    /// </summary>
    internal static long FindHeader(FileStream file, ReadOnlySpan<byte> magic, int minimum, int maximum, CancellationToken ct)
    {
        byte[] buffer = new byte[1024 * 1024], record = new byte[HeaderRecordSize];
        long last = file.Length - HeaderRecordSize;
        for (long at = 0; at <= last;)
        {
            ct.ThrowIfCancellationRequested();
            int read = RandomAccess.Read(file.SafeFileHandle, buffer.AsSpan(0, (int)Math.Min(buffer.Length, last - at + magic.Length)), at);
            if (read < magic.Length) break;
            var window = buffer.AsSpan(0, read);
            for (int index = window.IndexOf(magic); index >= 0;)
            {
                long position = at + index;
                if (RandomAccess.Read(file.SafeFileHandle, record, position) == HeaderRecordSize &&
                    IsIntact(record, magic, minimum, maximum, out _)) return position;
                int next = window[(index + 1)..].IndexOf(magic);
                index = next < 0 ? -1 : index + 1 + next;
            }
            at += read - (magic.Length - 1);
        }
        return -1;
    }

    private static bool IsIntact(ReadOnlySpan<byte> record, ReadOnlySpan<byte> magic, int minimum, int maximum, out int length)
    {
        length = BinaryPrimitives.ReadInt32LittleEndian(record[8..]);
        if (!record[..8].SequenceEqual(magic) || length < minimum || length > maximum ||
            length > HeaderRecordSize - HeaderPrefixSize || BinaryPrimitives.ReadInt32LittleEndian(record[12..]) != 0) return false;
        Span<byte> checksum = stackalloc byte[32];
        SHA256.HashData(record.Slice(HeaderPrefixSize, length), checksum);
        return CryptographicOperations.FixedTimeEquals(checksum, record.Slice(16, 32)) &&
            !record[(HeaderPrefixSize + length)..].ContainsAnyExcept((byte)0);
    }

    internal static void WriteFooter(Stream output, ReadOnlySpan<byte> magic, long offset, long payloadLength, long trailingLength = 0)
    {
        if (magic.Length != 8) throw new ArgumentOutOfRangeException(nameof(magic));
        Span<byte> record = stackalloc byte[FooterRecordSize];
        record.Clear();
        magic.CopyTo(record);
        BinaryPrimitives.WriteInt64LittleEndian(record[8..], offset);
        BinaryPrimitives.WriteInt64LittleEndian(record[16..], payloadLength);
        BinaryPrimitives.WriteInt64LittleEndian(record[24..], trailingLength);
        SHA256.HashData(record[..32], record[32..]);
        for (int i = 0; i < Copies; i++) output.Write(record);
    }

    /// <summary>Returns the payload range and the length of the data between the payload and the footer.</summary>
    internal static (long Offset, long Length, long Trailing) ReadFooter(FileStream file, ReadOnlySpan<byte> magic)
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
        long trailing = BinaryPrimitives.ReadInt64LittleEndian(chosen.AsSpan(24));
        long end = file.Length - FooterRegionSize;
        if (offset < 0 || length < 0 || trailing < 0 || offset > end || length > end - offset || trailing != end - offset - length)
            throw new PackageException(Text.Get("加密包的文件边界无效。"));
        return (offset, length, trailing);
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
