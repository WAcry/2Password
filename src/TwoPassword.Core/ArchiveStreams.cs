using System.Globalization;

namespace TwoPassword.Core;


/// <summary>
/// A bounded framing guard in front of the BCL PAX reader. Checks the raw TAR header before
/// TarReader can allocate metadata using an attacker-controlled size. TarReader still owns
/// archive decoding/checksums/PAX semantics; this guard preserves the original bytes.
/// </summary>
internal sealed class TarGuardStream : Stream
{
    private readonly Stream inner;
    private readonly long totalFileBytes;
    private readonly int maxEntries;
    private byte[] pending = [];
    private int pendingAt;
    private long dataRemaining;
    private long? paxSize;
    private long fileBytes;
    private int entries, metadataRecords, zeroBlocks;
    private bool eof;
    internal TarGuardStream(Stream inner, long totalBytes, int count)
    { this.inner = inner; totalFileBytes = totalBytes; maxEntries = count; }
    private void NextHeader()
    {
        var header = new byte[512];
        int first = inner.Read(header);
        if (first == 0)
        {
            if (zeroBlocks != 2) throw new PackageException(Text.Get("TAR 结束标记缺失。"));
            eof = true;
            return;
        }
        inner.ReadExactly(header.AsSpan(first));
        if (header.All(b => b == 0))
        {
            if (++zeroBlocks > 2) throw new PackageException(Text.Get("TAR 归档结束后存在额外数据。"));
            pending = header; pendingAt = 0; return;
        }
        if (zeroBlocks != 0) throw new PackageException(Text.Get("TAR 归档结束后存在额外条目。"));
        long size = ParseTarSize(header.AsSpan(124, 12));
        byte type = header[156];
        if (type == (byte)'x')
        {
            if (++metadataRecords > maxEntries || size < 1 || size > 262144) throw new PackageException(Text.Get("PAX 元数据大小或数量超出安全限制。"));
            int padded = checked((int)((size + 511) / 512 * 512));
            pending = new byte[512 + padded];
            header.CopyTo(pending, 0);
            inner.ReadExactly(pending.AsSpan(512, padded));
            ParsePax(pending.AsSpan(512, (int)size));
            pendingAt = 0;
            return;
        }
        if (type != 0 && type != (byte)'0' && type != (byte)'5')
            throw new PackageException(Text.Get("归档包含不支持的链接、设备或特殊条目。"));
        if (++entries > maxEntries) throw new PackageException(Text.Get("归档条目数量与认证信息不一致。"));
        long effectiveSize = paxSize ?? size;
        paxSize = null;
        if (type == (byte)'5' && effectiveSize != 0) throw new PackageException(Text.Get("文件夹条目不能包含文件数据。"));
        fileBytes = checked(fileBytes + effectiveSize);
        if (effectiveSize < 0 || fileBytes > totalFileBytes) throw new PackageException(Text.Get("归档文件长度超过认证声明。"));
        // Reject invalid UTF-8 instead of allowing the BCL reader to replace bytes.
        ValidateHeaderText(header.AsSpan(0, 100));
        dataRemaining = checked((effectiveSize + 511) / 512 * 512);
        pending = header;
        pendingAt = 0;
    }
    private static void ValidateHeaderText(ReadOnlySpan<byte> bytes)
    {
        int nullAt = bytes.IndexOf((byte)0);
        if (nullAt >= 0) bytes = bytes[..nullAt];
        try { _ = Envelope.Utf8.GetString(bytes); }
        catch (System.Text.DecoderFallbackException e) { throw new PackageException(Text.Get("归档名称包含无效 UTF-8 编码。"), e); }
    }
    private void ParsePax(ReadOnlySpan<byte> bytes)
    {
        paxSize = null;
        int count = 0;
        var keys = new HashSet<string>(StringComparer.Ordinal);
        while (!bytes.IsEmpty)
        {
            if (++count > 64) throw new PackageException(Text.Get("PAX 元数据字段过多。"));
            int space = bytes.IndexOf((byte)' ');
            if (space is < 1 or > 8) throw new PackageException(Text.Get("PAX 元数据格式无效。"));
            int length = 0;
            foreach (byte c in bytes[..space])
            {
                if (c is < (byte)'0' or > (byte)'9') throw new PackageException(Text.Get("PAX 长度无效。"));
                length = checked(length * 10 + c - (byte)'0');
            }
            if (length <= space + 3 || length > bytes.Length || bytes[length - 1] != (byte)'\n')
                throw new PackageException(Text.Get("PAX 记录长度无效。"));
            string record;
            try { record = Envelope.Utf8.GetString(bytes.Slice(space + 1, length - space - 2)); }
            catch (System.Text.DecoderFallbackException e) { throw new PackageException(Text.Get("PAX 字段包含无效 UTF-8 编码。"), e); }
            int equals = record.IndexOf('=');
            if (equals < 1) throw new PackageException(Text.Get("PAX 字段无效。"));
            string key = record[..equals], value = record[(equals + 1)..];
            if (!keys.Add(key)) throw new PackageException(Text.Get("PAX 元数据字段重复。"));
            if (key == "size")
            {
                if (!long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out long s) || s > totalFileBytes)
                    throw new PackageException(Text.Get("PAX 文件大小超出认证声明。"));
                paxSize = s;
            }
            if (key is "path" or "linkpath")
            {
                if (value.Length >= SafePaths.MaxPathChars) throw new PackageException(Text.Get("PAX 路径过长。"));
                if (key == "linkpath" && value.Length != 0) throw new PackageException(Text.Get("不支持链接条目。"));
            }
            bytes = bytes[length..];
        }
    }
    private static long ParseTarSize(ReadOnlySpan<byte> bytes)
    {
        if ((bytes[0] & 0x80) != 0) throw new PackageException(Text.Get("仅支持标准 PAX 大文件长度编码。"));
        long value = 0;
        bool digits = false, end = false;
        foreach (byte c in bytes)
        {
            if (c is 0 or (byte)' ') { if (digits) end = true; continue; }
            if (end || c is < (byte)'0' or > (byte)'7') throw new PackageException(Text.Get("TAR 文件长度无效。"));
            value = checked(value * 8 + c - (byte)'0');
            digits = true;
        }
        return value;
    }
    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
    public override int Read(Span<byte> buffer)
    {
        if (buffer.IsEmpty) return 0;
        if (pendingAt < pending.Length)
        {
            int length = Math.Min(buffer.Length, pending.Length - pendingAt);
            pending.AsSpan(pendingAt, length).CopyTo(buffer);
            pendingAt += length;
            return length;
        }
        if (dataRemaining > 0)
        {
            int size = (int)Math.Min(buffer.Length, dataRemaining);
            int read = inner.Read(buffer[..size]);
            if (read == 0) throw new PackageException(Text.Get("TAR 文件数据被截断。"));
            dataRemaining -= read;
            return read;
        }
        if (eof) return 0;
        NextHeader();
        return eof ? 0 : Read(buffer);
    }
    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

internal sealed class LimitedWriteStream : Stream
{
    private readonly Stream inner;
    private readonly long limit;
    internal LimitedWriteStream(Stream inner, long limit) { this.inner = inner; this.limit = limit; }
    public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));
    public override void Write(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length > limit - inner.Position) throw new PackageException(Text.Get("单文件 EXE 超过 Windows 的 4 GiB 限制。请选择自动布局或分离布局。"));
        inner.Write(buffer);
    }
    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => inner.Length;
    public override long Position { get => inner.Position; set => throw new NotSupportedException(); }
    public override void Flush() => inner.Flush();
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
}
