using TwoPassword.Localization;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace TwoPassword.Recovery;

internal sealed record Par2Source(string Name, long Length, byte[] Md5);
internal sealed record Par2Set(string Directory, string IndexPath, string[] RecoveryFiles,
    IReadOnlyList<Par2Source> Sources, string BaseName);

/// <summary>
/// Validates complete PAR2 volumes before handing their copies to the native repairer.
/// Only this application's one-package / optional-one-sidecar layout is accepted.
/// The caller must validate the private staged copies again before invoking native code.
/// MD5 here is the PAR2 format's damage checksum, not a cryptographic origin signature.
/// </summary>
internal static class Par2Metadata
{
    private const long MaxBlockSize = 64L * 1024 * 1024;
    private const long MaxSourceBytes = 2L * 1024 * 1024 * 1024 * 1024;
    private const int MaxSourceBlocks = 32768;
    private const int MaxRecoveryFiles = 128;
    private const int MaxPackets = 131072;
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private static readonly byte[] Magic = "PAR2\0PKT"u8.ToArray();
    private static readonly HashSet<string> Reserved = new(StringComparer.OrdinalIgnoreCase)
        { "CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$" };

    internal static Task<Par2Set> LoadAsync(string path, CancellationToken cancellationToken) =>
        Task.Run(() => Load(path, cancellationToken), cancellationToken);

    private static Par2Set Load(string selected, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        selected = FullPath(selected);
        string directory = Path.GetDirectoryName(selected)!;
        EnsureNoReparseAncestors(directory);
        // An index may be missing while replicated metadata in a volume survives.
        // Do not require the selected index pathname to exist before finding siblings.
        try
        {
            var selectedAttributes = File.GetAttributes(Extended(selected));
            if ((selectedAttributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
                throw Unsafe(Text.Get("所选恢复路径不是普通文件。"));
        }
        catch (FileNotFoundException) { }
        catch (DirectoryNotFoundException) { }
        string selectedName = Path.GetFileName(selected);
        ValidateName(selectedName);
        if (!selectedName.EndsWith(".par2", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException(Text.Get("请选择 2Password 创建的 .par2 恢复文件。"));
        var suffix = Regex.Match(selectedName, @"^(?<base>.+)\.vol[0-9]{1,10}\+[0-9]{1,10}\.par2$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
        string baseName = suffix.Success ? suffix.Groups["base"].Value : selectedName[..^5];
        ValidateName(baseName);
        if (!baseName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
            !baseName.EndsWith(".2pw", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException(Text.Get("恢复集名称必须对应一个 .exe 或 .2pw 加密包。"));

        var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { baseName };
        if (baseName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            allowed.Add(Path.ChangeExtension(baseName, ".2pw"));
        var pattern = new Regex("^" + Regex.Escape(baseName) + @"(?:\.vol[0-9]{1,10}\+[0-9]{1,10})?\.par2$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
        var candidates = new List<string>();
        var candidateNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string entry in System.IO.Directory.EnumerateFileSystemEntries(Extended(directory)))
        {
            ct.ThrowIfCancellationRequested();
            string name = Path.GetFileName(entry);
            if (!pattern.IsMatch(name)) continue;
            if (!candidateNames.Add(name)) throw Unsafe(Text.Get("恢复卷存在大小写冲突。"));
            if (candidates.Count == MaxRecoveryFiles) throw Unsafe(Text.Get("恢复卷数量超过 128 个的安全限制。"));
            candidates.Add(FullPath(entry));
        }
        candidates.Sort((a, b) =>
        {
            int pa = Priority(a, selected, baseName), pb = Priority(b, selected, baseName);
            return pa != pb ? pa.CompareTo(pb) : StringComparer.Ordinal.Compare(a, b);
        });

        var volumes = new List<Volume>();
        int packetCount = 0;
        foreach (string candidate in candidates)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                EnsureNoReparseAncestors(candidate);
                var attrs = File.GetAttributes(Extended(candidate));
                if ((attrs & FileAttributes.Directory) != 0) throw new InvalidDataException(Text.Get("恢复卷不是普通文件。"));
                volumes.Add(Scan(candidate, allowed, ct, ref packetCount));
            }
            catch (UnsafePar2Exception) { throw; }
            catch (InvalidDataException) { /* A damaged or truncated packet invalidates the whole volume. */ }
            catch (IOException) { /* A damaged/incomplete volume is excluded in its entirety. */ }
            catch (UnauthorizedAccessException) { /* Never copy an unreadable volume to the native stage. */ }
        }
        if (volumes.Count == 0) throw new InvalidDataException(Text.Get("没有完整可用的恢复卷；所有候选恢复文件都已损坏或不可读取。"));

        string setId = volumes[0].SetId;
        var descriptions = new Dictionary<string, Description>(StringComparer.Ordinal);
        var verification = new Dictionary<string, Verification>(StringComparer.Ordinal);
        var recovery = new Dictionary<uint, Recovery>();
        Main? main = null;
        foreach (var volume in volumes)
        {
            if (volume.SetId != setId) throw Unsafe(Text.Get("同名恢复卷包含不同的恢复集 ID，已停止以避免混用。"));
            foreach (var entry in volume.Mains)
            {
                if (main is not null && main.Fingerprint != entry.Fingerprint)
                    throw Unsafe(Text.Get("恢复卷包含互相冲突的主元数据。"));
                main = entry;
            }
            foreach (var entry in volume.Descriptions.Values)
                Merge(descriptions, entry.Id, entry, x => x.Fingerprint, Text.Get("同一个文件 ID 对应冲突的文件描述。"));
            foreach (var entry in volume.Verifications.Values)
                Merge(verification, entry.Id, entry, x => x.Fingerprint, Text.Get("同一个文件 ID 对应冲突的数据校验表。"));
            foreach (var entry in volume.Recoveries.Values)
            {
                if (recovery.TryGetValue(entry.Exponent, out var previous) && previous.Fingerprint != entry.Fingerprint)
                    throw Unsafe(Text.Get("恢复块编号相同但内容冲突。"));
                recovery[entry.Exponent] = entry;
            }
        }
        if (main is null) throw new InvalidDataException(Text.Get("恢复卷缺少完整的主元数据。"));
        if (descriptions.Count != main.Ids.Length || verification.Count != main.Ids.Length)
            throw new InvalidDataException(Text.Get("恢复卷缺少文件描述或切片校验表。"));
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var sources = new List<Par2Source>();
        long blocks = 0, total = 0;
        foreach (string id in main.Ids)
        {
            if (!descriptions.TryGetValue(id, out var description) || !verification.TryGetValue(id, out var checks))
                throw new InvalidDataException(Text.Get("恢复卷中的文件 ID 与主元数据不匹配。"));
            if (!names.Add(description.Name)) throw Unsafe(Text.Get("不同文件 ID 使用了相同或大小写冲突的文件名。"));
            long expected = description.Length / main.BlockSize + (description.Length % main.BlockSize == 0 ? 0 : 1);
            if (checks.Slices != expected) throw Unsafe(Text.Get("恢复文件切片数量与文件长度不匹配。"));
            blocks = checked(blocks + expected);
            total = checked(total + description.Length);
            if (blocks > MaxSourceBlocks || total > MaxSourceBytes)
                throw Unsafe(Text.Get("恢复集超过 32768 个源切片或 2 TiB 的安全限制。"));
            sources.Add(new(description.Name, description.Length, (byte[])description.FullHash.Clone()));
        }
        if (!names.Contains(baseName)) throw Unsafe(Text.Get("恢复元数据没有包含所选恢复集对应的加密包。"));
        foreach (var block in recovery.Values)
            if (block.PayloadLength != main.BlockSize) throw Unsafe(Text.Get("恢复块大小与主元数据不一致。"));
        return new(directory, volumes[0].Path, volumes.Select(x => x.Path).ToArray(), sources, baseName);
    }

    private static int Priority(string path, string selected, string baseName) =>
        path.Equals(selected, StringComparison.OrdinalIgnoreCase) ? 0 :
        Path.GetFileName(path).Equals(baseName + ".par2", StringComparison.OrdinalIgnoreCase) ? 1 : 2;

    private static Volume Scan(string path, HashSet<string> allowed, CancellationToken ct, ref int packetCount)
    {
        using var file = new FileStream(Extended(path), FileMode.Open, FileAccess.Read, FileShare.Read,
            128 * 1024, FileOptions.SequentialScan);
        if (file.Length < 64) throw new InvalidDataException(Text.Get("PAR2 文件被截断。"));
        var result = new Volume(path);
        byte[] header = new byte[64], buffer = new byte[128 * 1024];
        while (file.Position < file.Length)
        {
            ct.ThrowIfCancellationRequested();
            if (++packetCount > MaxPackets) throw Unsafe(Text.Get("恢复集的包数量超过安全限制。"));
            long start = file.Position;
            file.ReadExactly(header);
            if (!header.AsSpan(0, 8).SequenceEqual(Magic)) throw new InvalidDataException(Text.Get("PAR2 包标记无效。"));
            ulong length = BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(8, 8));
            if (length < 64 || (length & 3) != 0 || length > (ulong)(file.Length - start) ||
                length > (ulong)(MaxBlockSize + 68))
                throw new InvalidDataException(Text.Get("PAR2 包长度无效或过大。"));
            string type = Encoding.ASCII.GetString(header, 48, 16);
            bool receive = type == "PAR 2.0\0RecvSlic";
            bool known = receive || type is "PAR 2.0\0Main\0\0\0\0" or "PAR 2.0\0FileDesc" or
                "PAR 2.0\0IFSC\0\0\0\0" or "PAR 2.0\0Creator\0";
            long bodyLength = (long)length - 64;
            int capture = receive ? (int)Math.Min(4, bodyLength) :
                known ? (int)Math.Min(1024 * 1024, bodyLength) : 0;
            byte[] body = new byte[capture];
            using var md5 = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
            md5.AppendData(header, 32, 32);
            long consumed = 0;
            while (consumed < bodyLength)
            {
                ct.ThrowIfCancellationRequested();
                int read = file.Read(buffer, 0, (int)Math.Min(buffer.Length, bodyLength - consumed));
                if (read == 0) throw new EndOfStreamException(Text.Get("PAR2 包被截断。"));
                md5.AppendData(buffer, 0, read);
                if (consumed < capture)
                    buffer.AsSpan(0, (int)Math.Min(read, capture - consumed)).CopyTo(body.AsSpan((int)consumed));
                consumed += read;
            }
            byte[] digest = md5.GetHashAndReset();
            if (!CryptographicOperations.FixedTimeEquals(digest, header.AsSpan(16, 16)))
                throw new InvalidDataException(Text.Get("PAR2 包校验失败。"));
            if (!known) throw Unsafe(Text.Get("恢复文件包含未支持的包类型（包括文件名覆盖扩展），已停止。"));
            string setId = Convert.ToHexString(header.AsSpan(32, 16));
            if (result.SetId.Length != 0 && result.SetId != setId) throw Unsafe(Text.Get("一个恢复文件混入了不同的恢复集。"));
            result.SetId = setId;
            string fingerprint = Convert.ToHexString(digest);
            switch (type)
            {
                case "PAR 2.0\0Main\0\0\0\0":
                    if (bodyLength is < 28 or > 44 || (bodyLength - 12) % 16 != 0)
                        throw Unsafe(Text.Get("只支持包含一到两个文件的恢复主元数据。"));
                    ulong rawBlockSize = BinaryPrimitives.ReadUInt64LittleEndian(body.AsSpan(0, 8));
                    int count = (int)((bodyLength - 12) / 16);
                    uint recoverable = BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(8, 4));
                    if (rawBlockSize == 0 || rawBlockSize > (ulong)MaxBlockSize || (rawBlockSize & 3) != 0 || recoverable != count)
                        throw Unsafe(Text.Get("恢复切片大小或文件数量超出安全限制。"));
                    long blockSize = (long)rawBlockSize;
                    if (!CryptographicOperations.FixedTimeEquals(MD5.HashData(body), header.AsSpan(32, 16)))
                        throw Unsafe(Text.Get("恢复集 ID 与主元数据不一致。"));
                    string[] ids = Enumerable.Range(0, count).Select(i => Convert.ToHexString(body.AsSpan(12 + i * 16, 16))).ToArray();
                    if (ids.Distinct(StringComparer.Ordinal).Count() != count) throw Unsafe(Text.Get("恢复主元数据包含重复文件 ID。"));
                    result.Mains.Add(new(blockSize, ids, fingerprint));
                    break;
                case "PAR 2.0\0FileDesc":
                    if (bodyLength is <= 56 or > 1080) throw Unsafe(Text.Get("文件描述的长度无效。"));
                    int nameLength = (int)bodyLength - 56;
                    int padded = nameLength;
                    while (nameLength > 0 && body[56 + nameLength - 1] == 0) nameLength--;
                    if (nameLength == 0 || padded - nameLength > 3) throw Unsafe(Text.Get("文件名为空或填充不符合 PAR2 格式。"));
                    string name;
                    try { name = Utf8.GetString(body.AsSpan(56, nameLength)); }
                    catch (DecoderFallbackException) { throw Unsafe(Text.Get("PAR2 文件名包含无效 UTF-8。")); }
                    ValidateName(name);
                    if (!allowed.Contains(name)) throw Unsafe(Text.Get("恢复文件试图访问所选加密包之外的文件：") + name);
                    ulong declared = BinaryPrimitives.ReadUInt64LittleEndian(body.AsSpan(48, 8));
                    if (declared > (ulong)MaxSourceBytes) throw Unsafe(Text.Get("恢复文件声明的数据超过 2 TiB。"));
                    if (!CryptographicOperations.FixedTimeEquals(MD5.HashData(body.AsSpan(32, 24 + nameLength)), body.AsSpan(0, 16)))
                        throw Unsafe(Text.Get("PAR2 文件 ID 与文件名和数据描述不一致。"));
                    if (declared <= 16384 && !body.AsSpan(16, 16).SequenceEqual(body.AsSpan(32, 16)))
                        throw Unsafe(Text.Get("短文件的两个 PAR2 数据摘要不一致。"));
                    string id = Convert.ToHexString(body.AsSpan(0, 16));
                    var description = new Description(id, name, (long)declared, body.AsSpan(16, 16).ToArray(), fingerprint);
                    Merge(result.Descriptions, id, description, x => x.Fingerprint, Text.Get("一个恢复文件包含冲突的文件描述。"));
                    if (result.Descriptions.Count > 2) throw Unsafe(Text.Get("恢复文件描述数量超过两个。"));
                    break;
                case "PAR 2.0\0IFSC\0\0\0\0":
                    if (bodyLength < 16 || (bodyLength - 16) % 20 != 0 || (bodyLength - 16) / 20 > MaxSourceBlocks)
                        throw Unsafe(Text.Get("PAR2 切片校验表大小无效。"));
                    string checkId = Convert.ToHexString(body.AsSpan(0, 16));
                    var verification = new Verification(checkId, (bodyLength - 16) / 20, fingerprint);
                    Merge(result.Verifications, checkId, verification, x => x.Fingerprint, Text.Get("一个恢复文件包含冲突的切片校验表。"));
                    if (result.Verifications.Count > 2) throw Unsafe(Text.Get("切片校验表对应的文件超过两个。"));
                    break;
                case "PAR 2.0\0RecvSlic":
                    if (bodyLength < 8 || bodyLength > MaxBlockSize + 4) throw Unsafe(Text.Get("PAR2 恢复块大小无效。"));
                    uint exponent = BinaryPrimitives.ReadUInt32LittleEndian(body);
                    if (exponent >= 65535) throw Unsafe(Text.Get("PAR2 恢复块编号超出范围。"));
                    var recovery = new Recovery(exponent, bodyLength - 4, fingerprint);
                    if (result.Recoveries.TryGetValue(exponent, out var previous) && previous.Fingerprint != fingerprint)
                        throw Unsafe(Text.Get("一个恢复文件包含冲突的恢复块。"));
                    result.Recoveries[exponent] = recovery;
                    break;
                case "PAR 2.0\0Creator\0":
                    if (bodyLength > 4096) throw Unsafe(Text.Get("PAR2 创建者元数据过大。"));
                    break;
            }
        }
        if (result.SetId.Length == 0) throw new InvalidDataException(Text.Get("PAR2 文件没有有效数据包。"));
        return result;
    }

    private static void Merge<T>(Dictionary<string, T> target, string key, T value, Func<T, string> fingerprint, string message)
    {
        if (target.TryGetValue(key, out var previous) && fingerprint(previous) != fingerprint(value)) throw Unsafe(message);
        target[key] = value;
    }

    private static void ValidateName(string name)
    {
        if (string.IsNullOrEmpty(name) || name.Length > 255 || name is "." or ".." ||
            name.EndsWith('.') || name.EndsWith(' ') || name.Any(c => c < 32 || "<>:\"/\\|?*".Contains(c)))
            throw Unsafe(Text.Get("恢复元数据包含不安全的文件名。"));
        try { _ = Utf8.GetByteCount(name); }
        catch (EncoderFallbackException) { throw Unsafe(Text.Get("恢复文件名包含无效 Unicode。")); }
        string stem = name.Split('.')[0].TrimEnd(' ');
        if (Reserved.Contains(stem) ||
            stem.Length == 4 && (stem.StartsWith("COM", StringComparison.OrdinalIgnoreCase) ||
            stem.StartsWith("LPT", StringComparison.OrdinalIgnoreCase)) && (stem[3] is >= '1' and <= '9' or '¹' or '²' or '³'))
            throw Unsafe(Text.Get("恢复文件名使用了 Windows 保留设备名称。"));
    }

    private static string FullPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.StartsWith(@"\\.\", StringComparison.Ordinal) ||
            path.StartsWith(@"\??\", StringComparison.Ordinal)) throw Unsafe(Text.Get("不支持空路径或设备路径。"));
        if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) path = @"\\" + path[8..];
        else if (path.StartsWith(@"\\?\", StringComparison.Ordinal)) path = path[4..];
        string full = Path.GetFullPath(path);
        if (full.Length >= 32700 || full.IndexOf(':', 2) >= 0) throw Unsafe(Text.Get("恢复文件路径过长或包含备用数据流。"));
        return full;
    }

    private static string Extended(string path)
    {
        string full = FullPath(path);
        if (!OperatingSystem.IsWindows()) return full;
        return full.StartsWith(@"\\", StringComparison.Ordinal) ? @"\\?\UNC\" + full[2..] : @"\\?\" + full;
    }

    private static void EnsureNoReparseAncestors(string path)
    {
        string? current = FullPath(path);
        while (current is not null)
        {
            if ((File.GetAttributes(Extended(current)) & FileAttributes.ReparsePoint) != 0)
                throw Unsafe(Text.Get("恢复路径不能包含符号链接、联接点或其他重解析点。"));
            current = Path.GetDirectoryName(current);
        }
    }

    private static UnsafePar2Exception Unsafe(string message) => new(message);
    private sealed class UnsafePar2Exception(string message) : IOException(message);
    private sealed record Main(long BlockSize, string[] Ids, string Fingerprint);
    private sealed record Description(string Id, string Name, long Length, byte[] FullHash, string Fingerprint);
    private sealed record Verification(string Id, long Slices, string Fingerprint);
    private sealed record Recovery(uint Exponent, long PayloadLength, string Fingerprint);
    private sealed class Volume(string path)
    {
        internal string Path { get; } = path;
        internal string SetId { get; set; } = "";
        internal List<Main> Mains { get; } = [];
        internal Dictionary<string, Description> Descriptions { get; } = new(StringComparer.Ordinal);
        internal Dictionary<string, Verification> Verifications { get; } = new(StringComparer.Ordinal);
        internal Dictionary<uint, Recovery> Recoveries { get; } = [];
    }
}
