using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace TwoPassword.Core;

internal sealed class Envelope
{
    internal const int ChunkSize = 1024 * 1024;
    internal const int MaxEntries = 1_000_000;
    internal const long MaxBytes = 16L * 1024 * 1024 * 1024 * 1024;
    internal const int FooterSize = RedundantStorage.FooterRegionSize;
    internal const int FormatVersion = 1;
    internal static readonly byte[] Magic = "2PWPKG01"u8.ToArray();
    internal static readonly byte[] TailMagic = "2PWTAIL1"u8.ToArray();
    internal static readonly byte[] HeaderReplicaMagic = "2PWHDR01"u8.ToArray();
    internal static readonly UTF8Encoding Utf8 = new(false, true);
    internal readonly byte[] Header;
    internal readonly byte[] Hash;
    internal readonly byte[] NoncePrefix;
    internal readonly PackageCompression Compression;
    internal readonly long TotalBytes;
    internal readonly int Files;
    internal readonly int Directories;
    internal readonly int Slots;
    internal readonly long Offset;
    internal readonly long PayloadEnd;
    internal readonly long RecoveryLength;

    private const int FixedHeaderSize = 48;
    private const int SlotSize = 76;
    internal const int MinimumFrameSize = 28;
    internal const int MinimumHeaderSize = FixedHeaderSize + SlotSize;
    internal const int MaximumHeaderSize = FixedHeaderSize + 16 * SlotSize;
    private Envelope(byte[] header, long offset, long end, long recoveryLength)
    {
        Header = header;
        Hash = SHA256.HashData(header);
        Compression = (PackageCompression)header[16];
        TotalBytes = BinaryPrimitives.ReadInt64LittleEndian(header.AsSpan(20));
        Files = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(28));
        Directories = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(32));
        NoncePrefix = header.AsSpan(36, 4).ToArray();
        Slots = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(40));
        Offset = offset;
        PayloadEnd = end;
        RecoveryLength = recoveryLength;
    }

    internal static byte[] PasswordBytes(string password)
    {
        if (password is null) throw new PackageException(Text.Get("密码必须是字符串。"));
        if (password.Length > 1024) throw new PackageException(Text.Get("密码最多支持 1024 个 UTF-16 字符。"));
        try
        {
            // V1 prefixes every password equally: empty => 00, U+0000 => 00 00.
            // This keeps the encoding injective while satisfying Argon2's nonempty-input API.
            byte[] encoded = new byte[1 + Utf8.GetByteCount(password)];
            Utf8.GetBytes(password, encoded.AsSpan(1));
            return encoded;
        }
        catch (EncoderFallbackException e) { throw new PackageException(Text.Get("密码包含无效的 Unicode 字符。"), e); }
    }

    internal static Envelope Create(IReadOnlyList<string> passwords, PackageCompression compression, long total, int files, int dirs, out byte[] key, CancellationToken ct, IProgress<PackageProgress>? progress)
    {
        if (passwords.Count is < 1 or > 16) throw new PackageException(Text.Get("请设置 1 至 16 个独立密码。"));
        if (passwords.Distinct(StringComparer.Ordinal).Count() != passwords.Count) throw new PackageException(Text.Get("多个密码必须不同。"));
        if (compression is not PackageCompression.None and not PackageCompression.Brotli and not PackageCompression.Zstd) throw new PackageException(Text.Get("不支持的压缩选项。"));
        var header = new byte[FixedHeaderSize + passwords.Count * SlotSize];
        Magic.CopyTo(header, 0);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(8), FormatVersion);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(12), ChunkSize);
        header[16] = (byte)compression;
        BinaryPrimitives.WriteInt64LittleEndian(header.AsSpan(20), total);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(28), files);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(32), dirs);
        RandomNumberGenerator.Fill(header.AsSpan(36, 4));
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(40), passwords.Count);
        key = RandomNumberGenerator.GetBytes(32);
        try
        {
            for (int i = 0; i < passwords.Count; i++)
            {
                ct.ThrowIfCancellationRequested();
                progress?.Report(new(Text.Get("保护独立密码"), "", 0, total, i, passwords.Count));
                int pos = FixedHeaderSize + i * SlotSize;
                RandomNumberGenerator.Fill(header.AsSpan(pos, 16 + 12));
                byte[] pw = PasswordBytes(passwords[i]);
                byte[]? kek = null;
                try
                {
                    kek = Derive(pw, header.AsSpan(pos, 16).ToArray());
                    using var aes = new AesGcm(kek, 16);
                    aes.Encrypt(header.AsSpan(pos + 16, 12), key, header.AsSpan(pos + 28, 32), header.AsSpan(pos + 60, 16), SlotAad(header, i));
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(pw);
                    if (kek is not null) CryptographicOperations.ZeroMemory(kek);
                }
            }
            return new Envelope(header, 0, 0, 0);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(key);
            throw;
        }
    }

    private static byte[] SlotAad(byte[] header, int slot)
    {
        var aad = new byte[FixedHeaderSize + 4];
        header.AsSpan(0, FixedHeaderSize).CopyTo(aad);
        BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(FixedHeaderSize), slot);
        return aad;
    }

    internal byte[] Unlock(string password, CancellationToken ct, IProgress<PackageProgress>? progress)
    {
        byte[] pw = PasswordBytes(password);
        var key = new byte[32];
        try
        {
            for (int i = 0; i < Slots; i++)
            {
                ct.ThrowIfCancellationRequested();
                progress?.Report(new(Text.Get("验证密码"), "", 0, TotalBytes, i, Slots));
                int pos = FixedHeaderSize + i * SlotSize;
                byte[] kek = Derive(pw, Header.AsSpan(pos, 16).ToArray());
                try
                {
                    using var aes = new AesGcm(kek, 16);
                    aes.Decrypt(Header.AsSpan(pos + 16, 12), Header.AsSpan(pos + 28, 32), Header.AsSpan(pos + 60, 16), key, SlotAad(Header, i));
                    return key;
                }
                catch (AuthenticationTagMismatchException) { }
                finally { CryptographicOperations.ZeroMemory(kek); }
            }
            throw new PasswordNotRecognizedException(Text.Get("密码不正确，或加密包已经损坏。"));
        }
        catch
        {
            CryptographicOperations.ZeroMemory(key);
            throw;
        }
        finally { CryptographicOperations.ZeroMemory(pw); }
    }

    // Fixed, versioned parameters: untrusted containers cannot request excessive KDF resources.
    private static byte[] Derive(byte[] password, byte[] salt)
    {
        using var kdf = new Argon2id(password) { Salt = salt, MemorySize = 65536, Iterations = 3, DegreeOfParallelism = 4 };
        return kdf.GetBytes(32);
    }

    internal void WriteHeader(Stream destination) =>
        RedundantStorage.WriteHeader(destination, HeaderReplicaMagic, Header);

    internal static void WriteFooter(Stream destination, long offset, long length, long recoveryLength) =>
        RedundantStorage.WriteFooter(destination, TailMagic, offset, length, recoveryLength);

    internal static bool HasFooter(string path)
    {
        using var file = new FileStream(SafePaths.Extended(path), FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.RandomAccess);
        return RedundantStorage.HasFooterMarker(file, TailMagic);
    }

    internal static Envelope Read(FileStream source)
    {
        if (source.Length < FooterSize + RedundantStorage.HeaderRegionSize + MinimumFrameSize)
            throw new PackageException(Text.Get("不是有效的 2Password 加密包，或文件被截断。"));
        var footer = RedundantStorage.ReadFooter(source, TailMagic);
        if (footer.Length < RedundantStorage.HeaderRegionSize + MinimumFrameSize)
            throw new PackageException(Text.Get("加密包长度无效。"));
        source.Position = footer.Offset;
        byte[] header = ReadHeader(source);
        return new Envelope(header, footer.Offset, footer.Offset + footer.Length, footer.Trailing);
    }

    /// <summary>Reads and validates the current logical header without requiring a trailer.</summary>
    internal static byte[] ReadHeader(Stream source)
    {
        byte[] header = RedundantStorage.ReadHeader(source, HeaderReplicaMagic, MinimumHeaderSize, MaximumHeaderSize);
        if (!header.AsSpan(0, 8).SequenceEqual(Magic) || BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(8)) != FormatVersion ||
            BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(12)) != ChunkSize ||
            header[16] > 2 || header[17] != 0 || header[18] != 0 || header[19] != 0 ||
            BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(44)) != 0)
            throw new PackageException(Text.Get("加密包版本或加密参数不受支持。"));
        int slots = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(40));
        int files = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(28));
        int dirs = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(32));
        long total = BinaryPrimitives.ReadInt64LittleEndian(header.AsSpan(20));
        if (slots is < 1 or > 16 || header.Length != FixedHeaderSize + slots * SlotSize ||
            files < 0 || dirs < 0 || (long)files + dirs is < 1 or > MaxEntries ||
            total < 0 || total > MaxBytes)
            throw new PackageException(Text.Get("加密包声明的文件数量或数据大小无效。"));
        return header;
    }
}

internal abstract class CryptoStreamBase : Stream
{
    protected readonly Stream Inner;
    protected readonly AesGcm Aes;
    protected readonly Envelope Info;
    protected readonly CancellationToken Cancellation;
    protected ulong Index;
    protected bool Finished;
    protected CryptoStreamBase(Stream inner, byte[] key, Envelope info, CancellationToken cancellation)
    { Inner = inner; Aes = new AesGcm(key, 16); Info = info; Cancellation = cancellation; }
    protected void Parameters(ReadOnlySpan<byte> recordHeader, Span<byte> nonce, Span<byte> aad)
    {
        if (Index == ulong.MaxValue) throw new PackageException(Text.Get("加密记录数量超出格式限制。"));
        Info.NoncePrefix.CopyTo(nonce);
        BinaryPrimitives.WriteUInt64BigEndian(nonce[4..], Index);
        Info.Hash.CopyTo(aad);
        BinaryPrimitives.WriteUInt64BigEndian(aad[32..], Index);
        recordHeader.CopyTo(aad[40..]);
    }
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    protected override void Dispose(bool disposing) { if (disposing) Aes.Dispose(); base.Dispose(disposing); }
}

internal sealed class EncryptingStream : CryptoStreamBase
{
    private readonly byte[] plain = new byte[Envelope.ChunkSize];
    private readonly byte[] compressed = new byte[Envelope.ChunkSize];
    private readonly byte[] cipher = new byte[Envelope.ChunkSize];
    private ZstdSharp.Compressor? compressor;
    private int used;
    internal EncryptingStream(Stream inner, byte[] key, Envelope info, CancellationToken cancellation) : base(inner, key, info, cancellation) { }
    public override bool CanRead => false;
    public override bool CanWrite => !Finished;
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));
    public override void Write(ReadOnlySpan<byte> input)
    {
        if (Finished) throw new InvalidOperationException();
        while (!input.IsEmpty)
        {
            Cancellation.ThrowIfCancellationRequested();
            int size = Math.Min(input.Length, plain.Length - used);
            input[..size].CopyTo(plain.AsSpan(used));
            used += size;
            input = input[size..];
            if (used == plain.Length) Emit(used);
        }
    }
    private void Emit(int size)
    {
        Cancellation.ThrowIfCancellationRequested();
        byte codec = 0;
        int encodedSize = size == 0 ? 0 : BlockCompression.Encode(Info.Compression, plain.AsSpan(0, size), compressed, ref compressor, out codec);
        ReadOnlySpan<byte> encoded = codec == 0 ? plain.AsSpan(0, size) : compressed.AsSpan(0, encodedSize);
        Span<byte> record = stackalloc byte[12];
        record.Clear();
        BinaryPrimitives.WriteInt32LittleEndian(record, size);
        BinaryPrimitives.WriteInt32LittleEndian(record[4..], encodedSize);
        record[8] = codec;
        Span<byte> nonce = stackalloc byte[12];
        Span<byte> aad = stackalloc byte[52];
        Span<byte> tag = stackalloc byte[16];
        Parameters(record, nonce, aad);
        Aes.Encrypt(nonce, encoded, cipher.AsSpan(0, encodedSize), tag, aad);
        Inner.Write(record);
        Inner.Write(cipher.AsSpan(0, encodedSize));
        Inner.Write(tag);
        CryptographicOperations.ZeroMemory(plain.AsSpan(0, size));
        CryptographicOperations.ZeroMemory(compressed);
        used = 0;
        Index++;
    }
    internal void Complete()
    {
        if (Finished) return;
        if (used > 0) Emit(used);
        Emit(0);
        Finished = true;
    }
    public override void Flush() => Inner.Flush();
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            compressor?.Dispose();
            CryptographicOperations.ZeroMemory(plain);
            CryptographicOperations.ZeroMemory(compressed);
            CryptographicOperations.ZeroMemory(cipher);
        }
        base.Dispose(disposing);
    }
}

internal sealed class DecryptingStream : CryptoStreamBase
{
    private readonly byte[] cipher = new byte[Envelope.ChunkSize];
    private readonly byte[] encoded = new byte[Envelope.ChunkSize];
    private readonly byte[] plain = new byte[Envelope.ChunkSize + 1];
    private ZstdSharp.Decompressor? decompressor;
    private int available;
    private int consumed;
    internal DecryptingStream(FileStream inner, byte[] key, Envelope info, CancellationToken cancellation) : base(inner, key, info, cancellation)
    {
        try { ReadFrame(); } // Authenticate selected logical metadata before trusting counts or creating plaintext.
        catch { Dispose(); throw; }
    }
    public override bool CanRead => true;
    public override bool CanWrite => false;
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override void Flush() { }
    private void ReadFrame()
    {
        Cancellation.ThrowIfCancellationRequested();
        if (Finished) return;
        if (Info.PayloadEnd - Inner.Position < 28) throw new PackageException(Text.Get("缺少完整的认证记录，加密包可能被截断。"));
        Span<byte> record = stackalloc byte[12];
        Inner.ReadExactly(record);
        int rawSize = BinaryPrimitives.ReadInt32LittleEndian(record);
        int encodedSize = BinaryPrimitives.ReadInt32LittleEndian(record[4..]);
        byte codec = record[8];
        if (rawSize < 0 || rawSize > Envelope.ChunkSize || encodedSize < 0 || encodedSize > rawSize ||
            (rawSize == 0) != (encodedSize == 0) || record[9] != 0 || record[10] != 0 || record[11] != 0 ||
            codec > 2 || (codec != 0 && codec != (byte)Info.Compression) ||
            (codec == 0 && encodedSize != rawSize) || (codec != 0 && encodedSize >= rawSize) ||
            encodedSize > Info.PayloadEnd - Inner.Position - 16)
            throw new PackageException(Text.Get("加密块的长度、压缩算法或参数无效。"));
        Inner.ReadExactly(cipher.AsSpan(0, encodedSize));
        Span<byte> tag = stackalloc byte[16];
        Inner.ReadExactly(tag);
        Span<byte> nonce = stackalloc byte[12];
        Span<byte> aad = stackalloc byte[52];
        Parameters(record, nonce, aad);
        try
        {
            Aes.Decrypt(nonce, cipher.AsSpan(0, encodedSize), tag, encoded.AsSpan(0, encodedSize), aad);
            if (rawSize != 0) BlockCompression.Decode(codec, encoded.AsSpan(0, encodedSize), plain, rawSize, ref decompressor);
        }
        catch (AuthenticationTagMismatchException e) { throw new PackageException(Text.Get("完整性校验失败，加密包已损坏或被修改。"), e); }
        finally { CryptographicOperations.ZeroMemory(encoded.AsSpan(0, encodedSize)); }
        Index++;
        consumed = 0;
        available = rawSize;
        if (rawSize == 0)
        {
            Finished = true;
            if (Inner.Position != Info.PayloadEnd) throw new PackageException(Text.Get("加密包包含未经允许的尾随数据。"));
        }
    }
    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
    public override int Read(Span<byte> output)
    {
        if (output.IsEmpty) return 0;
        Cancellation.ThrowIfCancellationRequested();
        if (consumed == available && !Finished) ReadFrame();
        if (Finished) return 0;
        int length = Math.Min(output.Length, available - consumed);
        plain.AsSpan(consumed, length).CopyTo(output);
        CryptographicOperations.ZeroMemory(plain.AsSpan(consumed, length));
        consumed += length;
        return length;
    }
    internal void VerifyEnd()
    {
        if (consumed != available) throw new PackageException(Text.Get("归档结束后存在额外数据。"));
        if (!Finished) ReadFrame();
        if (!Finished) throw new PackageException(Text.Get("归档结束后存在额外加密记录。"));
    }
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            decompressor?.Dispose();
            CryptographicOperations.ZeroMemory(cipher);
            CryptographicOperations.ZeroMemory(encoded);
            CryptographicOperations.ZeroMemory(plain);
        }
        base.Dispose(disposing);
    }
}
