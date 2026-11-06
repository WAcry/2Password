using System.Diagnostics;
using System.Formats.Tar;
using System.Globalization;
using System.Security.Cryptography;

namespace TwoPassword.Core;

public static class PackageService
{
    private const FileAttributes PreservedAttributes = FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.System | FileAttributes.Archive | FileAttributes.NotContentIndexed;

    /// <summary>Validate the exact password syntax without deriving keys, normalizing, or retaining password bytes.</summary>
    public static void ValidatePassword(string password) => CryptographicOperations.ZeroMemory(Envelope.PasswordBytes(password));

    public static Task<PackageResult> CreateAsync(CreateOptions options, IProgress<PackageProgress>? progress = null, CancellationToken cancellationToken = default) =>
        Task.Run(() => Create(options, progress, cancellationToken), cancellationToken);

    public static Task<PackageResult> ExtractAsync(ExtractOptions options, IProgress<PackageProgress>? progress = null, CancellationToken cancellationToken = default) =>
        Task.Run(() => Extract(options, progress, cancellationToken), cancellationToken);

    public static Task<PackageInfo> InspectAsync(string path, CancellationToken cancellationToken = default) =>
        Task.Run(() =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var resolved = ResolvedPackage.Open(path);
            var info = resolved.Envelope;
            return new PackageInfo(info.Slots, info.Compression, info.PayloadEnd - info.Offset, resolved.DataPath, resolved.IsDetached, info.RecoveryLength);
        }, cancellationToken);

    /// <summary>Reads only the redundant trailer, so it still works when the header or the encrypted blocks are damaged.</summary>
    public static PackageRegions LocateRegions(string path) => ResolvedPackage.Locate(path);

    public static PayloadCandidates FindPayloadCandidates(string path, CancellationToken cancellationToken = default) =>
        ResolvedPackage.Candidates(path, cancellationToken);

    /// <summary>Cuts <paramref name="file"/> right after the recovery data and writes a new trailer for these regions.</summary>
    public static void RewriteTrailer(FileStream file, PackageRegions regions)
    {
        ArgumentNullException.ThrowIfNull(file);
        ArgumentNullException.ThrowIfNull(regions);
        long end = regions.RecoveryOffset + regions.RecoveryLength;
        if (regions.PayloadOffset < 0 || regions.PayloadLength < 0 || regions.RecoveryLength < 0 || end > file.Length)
            throw new ArgumentOutOfRangeException(nameof(regions));
        file.SetLength(end);
        file.Position = end;
        Envelope.WriteFooter(file, regions.PayloadOffset, regions.PayloadLength, regions.RecoveryLength);
        file.Flush(flushToDisk: true);
    }

    /// <summary>Appends a trailer that frames the whole file as a payload without recovery data.</summary>
    public static void FramePayload(string path)
    {
        using var file = new FileStream(SafePaths.Extended(path), FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        long length = file.Length;
        file.Position = length;
        Envelope.WriteFooter(file, 0, length, 0);
        file.Flush(flushToDisk: true);
    }

    public static bool HasPackage(string path)
    {
        try { using var file = OpenPackage(path); return HasPackageMarker(file); }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
    }

    private static FileStream OpenPackage(string path) =>
        new(SafePaths.Extended(path), FileMode.Open, FileAccess.Read, FileShare.Read, 128 * 1024, FileOptions.SequentialScan);

    private static bool HasPackageMarker(FileStream file)
    {
        return RedundantStorage.HasFooterMarker(file, Envelope.TailMagic) ||
            RedundantStorage.HasFooterMarker(file, DetachedReference.FooterMagic);
    }

    private static PackageResult Create(CreateOptions options, IProgress<PackageProgress>? progress, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(options.Passwords);
        if (options.Layout is not PackageLayout.Auto and not PackageLayout.Embedded and not PackageLayout.Detached)
            throw new PackageException(Text.Get("不支持的文件布局选项。"));
        if (options.Layout == PackageLayout.Detached && options.StubPath is null)
            throw new PackageException(Text.Get("分离布局需要独立解密 EXE 模板。"));
        string source = SafePaths.Full(options.SourcePath);
        string output = SafePaths.Full(options.OutputPath);
        SafePaths.EnsureDestination(output);
        if (SafePaths.IsInside(output, source)) throw new PackageException(Text.Get("输出文件不能放在正在打包的源文件夹内。"));
        string? sidecar = null;
        if (options.StubPath is not null)
        {
            if (!output.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                throw new PackageException(Text.Get("自解密程序的输出文件名必须以 .exe 结尾。"));
            if (SafePaths.Full(options.StubPath).Equals(output, StringComparison.OrdinalIgnoreCase))
                throw new PackageException(Text.Get("输出路径不能覆盖程序自身。"));
            sidecar = SafePaths.Full(Path.ChangeExtension(output, ".2pw"));
            DetachedReference.ValidateName(Path.GetFileName(sidecar));
            if (SafePaths.IsInside(sidecar, source))
                throw new PackageException(Text.Get("外部数据文件不能与源文件相同，也不能放在源文件夹内。"));
            if (options.Layout == PackageLayout.Detached) SafePaths.EnsureDestination(sidecar);
        }
        if (options.Passwords.Count is < 1 or > 16) throw new PackageException(Text.Get("请设置 1 至 16 个独立密码。"));
        foreach (string password in options.Passwords) CryptographicOperations.ZeroMemory(Envelope.PasswordBytes(password));
        ct.ThrowIfCancellationRequested();
        using var stub = options.StubPath is null ? null : OpenPackage(options.StubPath);
        if (stub is not null) ValidateStub(stub);
        progress?.Report(new(Text.Get("检查文件"), "", 0, 0, 0, 0));
        var entries = SafePaths.Scan(source, ct, progress);
        int files = entries.Count(e => !e.IsDirectory), dirs = entries.Count - files;
        long total = entries.Sum(e => e.Length);
        byte[]? key = null;
        string parent = Path.GetDirectoryName(output)!;
        string id = Guid.NewGuid().ToString("N");
        string payloadTemp = Path.Combine(parent, ".2password-" + id + ".payload.partial");
        string recoveryTemp = Path.Combine(parent, ".2password-" + id + ".recovery.partial");
        string launcherTemp = Path.Combine(parent, ".2password-" + id + ".launcher.partial");
        bool payloadCreated = false, recoveryCreated = false, launcherCreated = false, sidecarPublished = false, committed = false, detached = false;
        try
        {
            var info = Envelope.Create(options.Passwords, options.Compression, total, files, dirs, out key, ct, progress);
            long bodyLength;
            using (var payload = new FileStream(SafePaths.Extended(payloadTemp), FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 128 * 1024, FileOptions.SequentialScan))
            {
                payloadCreated = true;
                long limit = stub is not null && options.Layout == PackageLayout.Embedded ? uint.MaxValue - stub.Length - Envelope.FooterSize : long.MaxValue;
                using var limitedPayload = new LimitedWriteStream(payload, limit);
                info.WriteHeader(limitedPayload);
                using (var encrypted = new EncryptingStream(limitedPayload, key, info, ct))
                {
                    WriteArchive(encrypted, entries, total, ct, progress);
                    encrypted.Complete();
                }
                bodyLength = payload.Position;
                CryptographicOperations.ZeroMemory(key);
                key = null;
                progress?.Report(new(Text.Get("核对源文件"), "", total, total, entries.Count, entries.Count));
                SafePaths.ValidateInventory(entries, SafePaths.Scan(source, ct, null));
                ct.ThrowIfCancellationRequested();
                payload.Flush(flushToDisk: true);
            }

            long recoveryLength = 0;
            if (options.Recovery is { } writeRecovery)
            {
                using var recovery = new FileStream(SafePaths.Extended(recoveryTemp), FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 128 * 1024, FileOptions.SequentialScan);
                recoveryCreated = true;
                writeRecovery(payloadTemp, bodyLength, recovery, ct);
                ct.ThrowIfCancellationRequested();
                recovery.Flush(flushToDisk: true);
                recoveryLength = recovery.Length;
            }

            long packed = bodyLength + recoveryLength + Envelope.FooterSize;
            if (stub is not null)
            {
                detached = options.Layout == PackageLayout.Detached ||
                    (options.Layout == PackageLayout.Auto && packed > uint.MaxValue - stub.Length);
                if (!detached && packed > uint.MaxValue - stub.Length)
                    throw new PackageException(Text.Get("单文件 EXE 超过 Windows 的 4 GiB 限制。请选择自动布局或分离布局。"));
                if (detached) SafePaths.EnsureDestination(sidecar!);
            }
            if (stub is null || detached)
            {
                using var payload = new FileStream(SafePaths.Extended(payloadTemp), FileMode.Open, FileAccess.ReadWrite, FileShare.None, 128 * 1024, FileOptions.SequentialScan);
                if (payload.Length != bodyLength) throw new PackageException(Text.Get("加密数据在生成恢复记录期间被修改。"));
                payload.Position = bodyLength;
                AppendFile(recoveryTemp, recoveryLength, payload, ct, null);
                Envelope.WriteFooter(payload, 0, bodyLength, recoveryLength);
                payload.Flush(flushToDisk: true);
            }
            if (stub is not null)
            {
                using var launcher = new FileStream(SafePaths.Extended(launcherTemp), FileMode.CreateNew, FileAccess.Write, FileShare.None, 128 * 1024, FileOptions.SequentialScan);
                launcherCreated = true;
                using var limitedLauncher = new LimitedWriteStream(launcher, uint.MaxValue);
                string stage = detached ? Text.Get("生成配套解密程序") : Text.Get("组装独立 EXE");
                long assemblyTotal = stub.Length + (detached ? 0 : bodyLength + recoveryLength);
                long assembled = 0;
                var assemblyClock = Stopwatch.StartNew();
                progress?.Report(new(stage, Path.GetFileName(output), 0, assemblyTotal, 0, 1));
                void ReportAssembly(int count)
                {
                    assembled += count;
                    if (assemblyClock.ElapsedMilliseconds < 80) return;
                    progress?.Report(new(stage, Path.GetFileName(output), assembled, assemblyTotal, 0, 1));
                    assemblyClock.Restart();
                }
                stub.Position = 0;
                CopyWithCancellation(stub, limitedLauncher, stub.Length, ct, ReportAssembly);
                if (detached) new DetachedReference(Path.GetFileName(sidecar!), info.Hash).Write(limitedLauncher);
                else
                {
                    using (var payload = new FileStream(SafePaths.Extended(payloadTemp), FileMode.Open, FileAccess.Read, FileShare.None, 128 * 1024, FileOptions.SequentialScan))
                    {
                        if (payload.Length != bodyLength) throw new PackageException(Text.Get("加密数据在生成恢复记录期间被修改。"));
                        CopyWithCancellation(payload, limitedLauncher, bodyLength, ct, ReportAssembly);
                    }
                    AppendFile(recoveryTemp, recoveryLength, limitedLauncher, ct, ReportAssembly);
                    Envelope.WriteFooter(limitedLauncher, stub.Length, bodyLength, recoveryLength);
                }
                ct.ThrowIfCancellationRequested();
                launcher.Flush(flushToDisk: true);
            }
            ct.ThrowIfCancellationRequested();
            SafePaths.EnsureDestination(output);
            if (detached)
            {
                SafePaths.EnsureDestination(sidecar!);
                File.Move(SafePaths.Extended(payloadTemp), SafePaths.Extended(sidecar!), overwrite: false);
                payloadCreated = false;
                sidecarPublished = true;
                // Publish the executable last, so a visible launcher always has a complete data file.
                ct.ThrowIfCancellationRequested();
                SafePaths.EnsureDestination(output);
                File.Move(SafePaths.Extended(launcherTemp), SafePaths.Extended(output), overwrite: false);
                launcherCreated = false;
            }
            else if (stub is not null)
            {
                File.Move(SafePaths.Extended(launcherTemp), SafePaths.Extended(output), overwrite: false);
                launcherCreated = false;
            }
            else
            {
                File.Move(SafePaths.Extended(payloadTemp), SafePaths.Extended(output), overwrite: false);
                payloadCreated = false;
            }
            committed = true;
            progress?.Report(new(Text.Get("完成"), output, total, total, entries.Count, entries.Count));
            return new(output, files, dirs, total, detached ? sidecar : null, detached, recoveryLength);
        }
        catch (EndOfStreamException e) { throw new PackageException(Text.Get("文件被截断或在读取期间发生变化。"), e); }
        finally
        {
            if (key is not null) CryptographicOperations.ZeroMemory(key);
            if (payloadCreated && File.Exists(SafePaths.Extended(payloadTemp))) File.Delete(SafePaths.Extended(payloadTemp));
            if (recoveryCreated && File.Exists(SafePaths.Extended(recoveryTemp))) File.Delete(SafePaths.Extended(recoveryTemp));
            if (launcherCreated && File.Exists(SafePaths.Extended(launcherTemp))) File.Delete(SafePaths.Extended(launcherTemp));
            if (!committed && sidecarPublished && File.Exists(SafePaths.Extended(sidecar!))) File.Delete(SafePaths.Extended(sidecar!));
        }
    }

    private static void ValidateStub(FileStream stub)
    {
        if (stub.Length < 512 || stub.Length > uint.MaxValue - DetachedReference.MaximumOverhead)
            throw new PackageException(Text.Get("自解密程序模板大小无效，模板本身必须小于 Windows EXE 限制。"));
        if (HasPackageMarker(stub)) throw new PackageException(Text.Get("自解密程序模板不能已经包含加密数据或分离引用。"));
        stub.Position = 0;
        Span<byte> mz = stackalloc byte[2];
        stub.ReadExactly(mz);
        if (mz[0] != 'M' || mz[1] != 'Z') throw new PackageException(Text.Get("自解密程序模板不是 Windows EXE。"));
        stub.Position = 0;
    }

    private static void WriteArchive(Stream output, List<SourceEntry> entries, long total, CancellationToken ct, IProgress<PackageProgress>? progress)
    {
        using var writer = new TarWriter(output, TarEntryFormat.Pax, leaveOpen: true);
        long processed = 0;
        int completed = 0;
        foreach (var item in entries)
        {
            ct.ThrowIfCancellationRequested();
            SafePaths.ValidateUnchanged(item);
            var fields = new Dictionary<string, string>
            {
                ["2Password.creationTicks"] = item.CreationTicks.ToString(CultureInfo.InvariantCulture),
                ["2Password.writeTicks"] = item.WriteTicks.ToString(CultureInfo.InvariantCulture),
                ["2Password.attributes"] = ((int)(item.Attributes & PreservedAttributes)).ToString(CultureInfo.InvariantCulture)
            };
            if (item.ZoneIdentifier is not null) fields["2Password.zoneIdentifier"] = item.ZoneIdentifier;
            var entry = new PaxTarEntry(item.IsDirectory ? TarEntryType.Directory : TarEntryType.RegularFile, item.RelativePath, fields)
            {
                ModificationTime = new DateTimeOffset(new DateTime(item.WriteTicks, DateTimeKind.Utc)),
                Uid = 0, Gid = 0, UserName = "", GroupName = "",
                Mode = item.IsDirectory ? UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute : UnixFileMode.UserRead | UnixFileMode.UserWrite
            };
            progress?.Report(new(Text.Get("加密打包"), item.RelativePath, processed, total, completed, entries.Count));
            if (item.IsDirectory) writer.WriteEntry(entry);
            else
            {
                using var input = new FileStream(SafePaths.Extended(item.FullPath), FileMode.Open, FileAccess.Read, FileShare.Read, 128 * 1024, FileOptions.SequentialScan);
                if (input.Length != item.Length) throw new PackageException(Text.Get("源文件大小已经变化：{0}", item.RelativePath));
                using var tracked = new ProgressReadStream(input, count =>
                {
                    processed += count;
                    progress?.Report(new(Text.Get("加密打包"), item.RelativePath, processed, total, completed, entries.Count));
                }, ct);
                entry.DataStream = tracked;
                writer.WriteEntry(entry);
                if (tracked.ReadTotal != item.Length) throw new PackageException(Text.Get("源文件读取不完整：{0}", item.RelativePath));
                tracked.ReportRemaining();
                SafePaths.ValidateUnchanged(item);
            }
            completed++;
        }
    }

    private static PackageResult Extract(ExtractOptions options, IProgress<PackageProgress>? progress, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(options);
        string destination = SafePaths.Full(options.OutputDirectory);
        SafePaths.EnsureDestination(destination);
        string? staging = null;
        byte[]? key = null;
        bool committed = false;
        var metadata = new List<(string Path, bool Directory, long Created, long Written, FileAttributes Attributes)>();
        try
        {
            using var resolved = ResolvedPackage.Open(options.PackagePath);
            var file = resolved.File;
            var info = resolved.Envelope;
            key = info.Unlock(options.Password, ct, progress);
            using var decrypted = new DecryptingStream(file, key, info, ct);
            ct.ThrowIfCancellationRequested();
            string parent = Path.GetDirectoryName(destination)!;
            SafePaths.EnsureNoReparseAncestors(parent, true);
            CheckFreeSpace(parent, info.TotalBytes);
            string candidate = Path.Combine(parent, ".2password-" + Guid.NewGuid().ToString("N") + ".extracting");
            SafePaths.CreatePrivateDirectory(candidate);
            staging = candidate; // take cleanup ownership only after private-directory verification succeeds
            using var guarded = new TarGuardStream(decrypted, info.TotalBytes, checked(info.Files + info.Directories));
            long total = 0;
            int files = 0, directories = 0;
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var directoryNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var metadataBudget = new MetadataBudget(MetadataBudget.ExtractionLimit);
            string? root = null;
            using (var reader = new TarReader(guarded, leaveOpen: true))
            {
                TarEntry? entry;
                while ((entry = reader.GetNextEntry(copyData: false)) is not null)
                {
                    ct.ThrowIfCancellationRequested();
                    if (entry is not PaxTarEntry pax || entry.EntryType is not TarEntryType.Directory and not TarEntryType.RegularFile)
                        throw new PackageException(Text.Get("只支持 PAX 普通文件和文件夹。"));
                    bool directory = entry.EntryType == TarEntryType.Directory;
                    string relative = entry.Name;
                    if (directory && relative.EndsWith('/')) relative = relative[..^1];
                    SafePaths.ValidateRelative(relative);
                    string path = SafePaths.Full(Path.Combine(staging, relative.Replace('/', Path.DirectorySeparatorChar)));
                    pax.ExtendedAttributes.TryGetValue("2Password.zoneIdentifier", out string? zoneMetadata);
                    metadataBudget.AddEntry(relative, path, zoneMetadata);
                    if (!names.Add(relative)) throw new PackageException(Text.Get("归档包含重复或大小写冲突的路径：{0}", relative));
                    string first = relative.Split('/')[0];
                    if (root is null) root = first;
                    else if (first != root) throw new PackageException(Text.Get("归档必须只包含一个源根目录或源文件。"));
                    int slash = relative.LastIndexOf('/');
                    if (slash >= 0 && !directoryNames.Contains(relative[..slash])) throw new PackageException(Text.Get("归档的父文件夹缺失或不是文件夹。"));
                    if (directory) { directories++; directoryNames.Add(relative); }
                    else files++;
                    if (files > info.Files || directories > info.Directories) throw new PackageException(Text.Get("归档条目数量与认证声明不符。"));
                    if (entry.Length < 0 || entry.Length > info.TotalBytes - total) throw new PackageException(Text.Get("文件长度超过认证声明。"));
                    if (!SafePaths.IsInside(path, staging)) throw new PackageException(Text.Get("归档路径试图越过目标文件夹。"));
                    string entryParent = Path.GetDirectoryName(path)!;
                    SafePaths.EnsureNoReparseAncestors(entryParent, true);
                    if (File.Exists(SafePaths.Extended(path)) || Directory.Exists(SafePaths.Extended(path)))
                        throw new PackageException(Text.Get("目标文件名发生文件系统冲突。"));
                    var values = ReadMetadata(pax);
                    if (directory) Directory.CreateDirectory(SafePaths.Extended(path));
                    else
                    {
                        using var output = new FileStream(SafePaths.Extended(path), FileMode.CreateNew, FileAccess.Write, FileShare.None, 128 * 1024, FileOptions.SequentialScan);
                        if (entry.DataStream is null && entry.Length != 0) throw new PackageException(Text.Get("归档缺少文件数据。"));
                        if (entry.DataStream is not null)
                        {
                            CopyWithCancellation(entry.DataStream, output, entry.Length, ct, count =>
                            {
                                total += count;
                                progress?.Report(new(Text.Get("验证并解包"), relative, total, info.TotalBytes, files + directories - 1, info.Files + info.Directories));
                            });
                            if (entry.DataStream.ReadByte() != -1) throw new PackageException(Text.Get("文件数据长度不匹配。"));
                        }
                        output.Flush(flushToDisk: true);
                    }
                    if (values.Zone is not null)
                    {
                        try
                        {
                            using var zoneStream = new FileStream(SafePaths.Extended(path) + ":Zone.Identifier", FileMode.CreateNew, FileAccess.Write, FileShare.None);
                            zoneStream.Write(values.Zone);
                            zoneStream.Flush(flushToDisk: true);
                        }
                        finally { CryptographicOperations.ZeroMemory(values.Zone); }
                    }
                    metadata.Add((path, directory, values.Created, values.Written, values.Attributes));
                    progress?.Report(new(Text.Get("验证并解包"), relative, total, info.TotalBytes, files + directories, info.Files + info.Directories));
                }
            }
            // TarReader stops at its EOF marker; consume the rest through the framing guard.
            Span<byte> tail = stackalloc byte[1024];
            int n;
            while ((n = guarded.Read(tail)) != 0)
            {
                ct.ThrowIfCancellationRequested();
                for (int i = 0; i < n; i++) if (tail[i] != 0) throw new PackageException(Text.Get("归档结束后存在非零数据。"));
            }
            decrypted.VerifyEnd();
            if (files != info.Files || directories != info.Directories || total != info.TotalBytes)
                throw new PackageException(Text.Get("文件数量或总字节数不匹配，未提交解包结果。"));
            progress?.Report(new(Text.Get("恢复文件属性"), "", total, total, files + directories, files + directories));
            foreach (var item in metadata.AsEnumerable().Reverse())
            {
                ct.ThrowIfCancellationRequested();
                string path = SafePaths.Extended(item.Path);
                if (item.Directory)
                {
                    Directory.SetCreationTimeUtc(path, new DateTime(item.Created, DateTimeKind.Utc));
                    Directory.SetLastWriteTimeUtc(path, new DateTime(item.Written, DateTimeKind.Utc));
                }
                else
                {
                    File.SetCreationTimeUtc(path, new DateTime(item.Created, DateTimeKind.Utc));
                    File.SetLastWriteTimeUtc(path, new DateTime(item.Written, DateTimeKind.Utc));
                }
                // Keep attributes writable until the authenticated tree is ready to commit.
                File.SetAttributes(path, item.Attributes & ~FileAttributes.ReadOnly);
            }
            ct.ThrowIfCancellationRequested();
            foreach (var item in metadata.Where(e => (e.Attributes & FileAttributes.ReadOnly) != 0))
                File.SetAttributes(SafePaths.Extended(item.Path), item.Attributes);
            SafePaths.EnsureDestination(destination);
            Directory.Move(SafePaths.Extended(staging), SafePaths.Extended(destination));
            committed = true;
            progress?.Report(new(Text.Get("完成"), destination, total, total, files + directories, files + directories));
            return new(destination, files, directories, total, resolved.DataPath, resolved.IsDetached);
        }
        catch (EndOfStreamException e) { throw new PackageException(Text.Get("加密包或归档已被截断。"), e); }
        catch (InvalidDataException e) { throw new PackageException(Text.Get("归档数据无效，未提交解包结果。"), e); }
        finally
        {
            if (key is not null) CryptographicOperations.ZeroMemory(key);
            if (!committed && staging is not null && Directory.Exists(SafePaths.Extended(staging)))
            {
                foreach (var item in metadata)
                    if (File.Exists(SafePaths.Extended(item.Path)) || Directory.Exists(SafePaths.Extended(item.Path)))
                        File.SetAttributes(SafePaths.Extended(item.Path), FileAttributes.Normal);
                Directory.Delete(SafePaths.Extended(staging), recursive: true);
            }
        }
    }

    private static (long Created, long Written, FileAttributes Attributes, byte[]? Zone) ReadMetadata(PaxTarEntry entry)
    {
        var fields = entry.ExtendedAttributes;
        long ReadTicks(string key)
        {
            if (!fields.TryGetValue(key, out string? text) || !long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out long ticks) ||
                ticks < DateTime.UnixEpoch.Ticks - TimeSpan.TicksPerDay * 134774L || ticks > DateTime.MaxValue.Ticks)
                throw new PackageException(Text.Get("归档时间戳缺失或无效。"));
            return ticks;
        }
        if (!fields.TryGetValue("2Password.attributes", out string? attrs) ||
            !int.TryParse(attrs, NumberStyles.None, CultureInfo.InvariantCulture, out int bits) ||
            (bits & ~(int)PreservedAttributes) != 0)
            throw new PackageException(Text.Get("归档文件属性缺失或无效。"));
        byte[]? zone = null;
        if (fields.TryGetValue("2Password.zoneIdentifier", out string? encoded))
        {
            if (encoded.Length > 87384) throw new PackageException(Text.Get("Zone.Identifier 元数据过大。"));
            try { zone = Convert.FromBase64String(encoded); }
            catch (FormatException e) { throw new PackageException(Text.Get("Zone.Identifier 元数据编码无效。"), e); }
            if (zone.Length > 65536) throw new PackageException(Text.Get("Zone.Identifier 元数据超过 64 KiB。"));
        }
        return (ReadTicks("2Password.creationTicks"), ReadTicks("2Password.writeTicks"), (FileAttributes)bits, zone);
    }

    private static void CheckFreeSpace(string parent, long total)
    {
        string? root = Path.GetPathRoot(parent);
        if (root is null || root.StartsWith(@"\\", StringComparison.Ordinal)) return;
        var drive = new DriveInfo(root);
        if (drive.IsReady && drive.AvailableFreeSpace < total)
            throw new PackageException(Text.Get("目标磁盘可用空间不足以容纳完整解包数据。"));
    }

    private static void AppendFile(string path, long expected, Stream output, CancellationToken ct, Action<int>? progress)
    {
        if (expected == 0) return;
        using var input = new FileStream(SafePaths.Extended(path), FileMode.Open, FileAccess.Read, FileShare.None, 128 * 1024, FileOptions.SequentialScan);
        if (input.Length != expected) throw new PackageException(Text.Get("恢复记录在写入期间被修改。"));
        CopyWithCancellation(input, output, expected, ct, progress);
    }

    private static void CopyWithCancellation(Stream input, Stream output, long expected, CancellationToken ct, Action<int>? progress = null)
    {
        byte[] buffer = new byte[128 * 1024];
        long remaining = expected;
        try
        {
            while (remaining > 0)
            {
                ct.ThrowIfCancellationRequested();
                int read = input.Read(buffer, 0, (int)Math.Min(remaining, buffer.Length));
                if (read == 0) throw new EndOfStreamException();
                output.Write(buffer, 0, read);
                remaining -= read;
                progress?.Invoke(read);
            }
        }
        finally { CryptographicOperations.ZeroMemory(buffer); }
    }
}

internal sealed class ProgressReadStream : Stream
{
    private readonly Stream inner;
    private readonly Action<int> progress;
    private readonly CancellationToken cancellation;
    private readonly Stopwatch clock = Stopwatch.StartNew();
    private int unreported;
    internal long ReadTotal { get; private set; }
    internal ProgressReadStream(Stream inner, Action<int> progress, CancellationToken cancellation)
    { this.inner = inner; this.progress = progress; this.cancellation = cancellation; }
    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
    public override int Read(Span<byte> buffer)
    {
        cancellation.ThrowIfCancellationRequested();
        int read = inner.Read(buffer);
        ReadTotal += read; unreported += read;
        if (clock.ElapsedMilliseconds >= 80 || unreported > 8 * 1024 * 1024) ReportRemaining();
        return read;
    }
    internal void ReportRemaining() { if (unreported != 0) progress(unreported); unreported = 0; clock.Restart(); }
    public override bool CanRead => true;
    public override bool CanSeek => inner.CanSeek;
    public override bool CanWrite => false;
    public override long Length => inner.Length;
    public override long Position { get => inner.Position; set => inner.Position = value; }
    public override long Seek(long offset, SeekOrigin origin) => inner.Seek(offset, origin);
    public override void Flush() { }
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
