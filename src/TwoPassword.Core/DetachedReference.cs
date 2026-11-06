using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace TwoPassword.Core;

/// <summary>
/// A launcher reference is a single sibling filename, never a path or URL. The expected
/// immutable header hash detects swapped datasets before password work. Content integrity
/// remains protected by the ordinary authenticated envelope in the sidecar.
/// </summary>
internal sealed record DetachedReference(string FileName, byte[] HeaderHash)
{
    internal static readonly byte[] FooterMagic = "2PWLINK2"u8.ToArray();
    private static readonly byte[] DescriptorMagic = "2PWREF02"u8.ToArray();
    private static readonly byte[] ReplicaMagic = "2PWLHDR2"u8.ToArray();
    private const int FixedSize = 48;
    private const int MaximumNameBytes = 1024;
    internal const int MaximumOverhead = RedundantStorage.HeaderRegionSize + RedundantStorage.FooterRegionSize;

    internal static bool HasMarker(FileStream file) => RedundantStorage.HasFooterMarker(file, FooterMagic, requireChecksum: true);

    internal static void ValidateName(string name)
    {
        SafePaths.ValidateRelative(name);
        if (name.Contains('/') || name.Length > 255 || !name.EndsWith(".2pw", StringComparison.OrdinalIgnoreCase))
            throw new PackageException(Text.Get("分离数据文件必须是同一文件夹内的单个 .2pw 文件。"));
        if (Envelope.Utf8.GetByteCount(name) > MaximumNameBytes)
            throw new PackageException(Text.Get("分离数据文件名称过长。"));
    }

    internal void Write(Stream output)
    {
        ValidateName(FileName);
        if (HeaderHash.Length != 32) throw new InvalidOperationException(Text.Get("Expected a SHA-256 header hash."));
        byte[] name = Envelope.Utf8.GetBytes(FileName);
        var descriptor = new byte[FixedSize + name.Length];
        DescriptorMagic.CopyTo(descriptor, 0);
        BinaryPrimitives.WriteInt32LittleEndian(descriptor.AsSpan(8), name.Length);
        HeaderHash.CopyTo(descriptor, 16);
        name.CopyTo(descriptor, FixedSize);
        long offset = output.Position;
        RedundantStorage.WriteHeader(output, ReplicaMagic, descriptor);
        RedundantStorage.WriteFooter(output, FooterMagic, offset, RedundantStorage.HeaderRegionSize);
    }

    internal static DetachedReference Read(FileStream file)
    {
        if (file.Length < 512 + MaximumOverhead || file.Length > uint.MaxValue)
            throw new PackageException(Text.Get("分离式解密程序的大小无效。"));
        var footer = RedundantStorage.ReadFooter(file, FooterMagic);
        if (footer.Offset < 512 || footer.Length != RedundantStorage.HeaderRegionSize)
            throw new PackageException(Text.Get("分离数据引用的边界无效。"));
        file.Position = footer.Offset;
        byte[] descriptor = RedundantStorage.ReadHeader(file, ReplicaMagic, FixedSize + 1, FixedSize + MaximumNameBytes);
        int nameLength = BinaryPrimitives.ReadInt32LittleEndian(descriptor.AsSpan(8));
        if (!descriptor.AsSpan(0, 8).SequenceEqual(DescriptorMagic) ||
            BinaryPrimitives.ReadInt32LittleEndian(descriptor.AsSpan(12)) != 0 ||
            nameLength < 1 || nameLength != descriptor.Length - FixedSize)
            throw new PackageException(Text.Get("分离数据引用格式无效。"));
        string name;
        try { name = Envelope.Utf8.GetString(descriptor.AsSpan(FixedSize, nameLength)); }
        catch (DecoderFallbackException e) { throw new PackageException(Text.Get("分离数据文件名的 UTF-8 编码无效。"), e); }
        ValidateName(name);
        return new(name, descriptor.AsSpan(16, 32).ToArray());
    }
}

internal sealed class ResolvedPackage : IDisposable
{
    internal FileStream File { get; }
    internal Envelope Envelope { get; }
    internal string? DataPath { get; }
    internal bool IsDetached => DataPath is not null;
    private readonly FileStream? launcher;
    private ResolvedPackage(FileStream file, Envelope envelope, string? dataPath, FileStream? launcher)
    { File = file; Envelope = envelope; DataPath = dataPath; this.launcher = launcher; }

    internal static ResolvedPackage Open(string input)
    {
        string path = SafePaths.Full(input);
        FileStream? first = null;
        FileStream? data = null;
        try
        {
            first = OpenFile(path);
            bool detached = DetachedReference.HasMarker(first);
            if (detached && RedundantStorage.HasFooterMarker(first, Envelope.TailMagic, requireChecksum: true))
                throw new PackageException(Text.Get("冗余文件尾部的格式类型相互冲突，请先修复文件。"));
            if (!detached)
            {
                var info = Envelope.Read(first);
                var direct = new ResolvedPackage(first, info, null, null);
                first = null;
                return direct;
            }
            SafePaths.EnsureNoReparseAncestors(path, true);
            var reference = DetachedReference.Read(first);
            string parent = Path.GetDirectoryName(path)!;
            string dataPath = SafePaths.Full(Path.Combine(parent, reference.FileName));
            if (!string.Equals(Path.GetDirectoryName(dataPath), parent, StringComparison.OrdinalIgnoreCase) ||
                dataPath.Equals(path, StringComparison.OrdinalIgnoreCase))
                throw new PackageException(Text.Get("分离数据引用必须指向旁边的不同文件。"));
            SafePaths.EnsureNoReparseAncestors(parent, true);
            try
            {
                SafePaths.EnsureNoReparseAncestors(dataPath, true);
                data = OpenFile(dataPath);
            }
            catch (FileNotFoundException e) { throw Missing(reference.FileName, e); }
            catch (DirectoryNotFoundException e) { throw Missing(reference.FileName, e); }
            var envelope = Envelope.Read(data);
            if (envelope.Offset != 0 || !CryptographicOperations.FixedTimeEquals(reference.HeaderHash, envelope.Hash))
                throw new PackageException(Text.Get("旁边的 .2pw 数据文件与此解密程序不匹配。请使用创建时产生的完整配套文件。"));
            var resolved = new ResolvedPackage(data, envelope, dataPath, first);
            data = null;
            first = null;
            return resolved;
        }
        finally { data?.Dispose(); first?.Dispose(); }
    }

    private static PackageException Missing(string fileName, Exception inner) =>
        new(Text.Get("缺少外部加密数据文件：{0}。请把解密 EXE 和对应的 .2pw 文件放在同一文件夹。", fileName), inner);

    internal static FileStream OpenFile(string path) =>
        new(SafePaths.Extended(path), FileMode.Open, FileAccess.Read, FileShare.Read, 128 * 1024, FileOptions.SequentialScan);

    public void Dispose() { File.Dispose(); launcher?.Dispose(); }
}
