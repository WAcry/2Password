using TwoPassword.Localization;
using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using TwoPassword.Core;

namespace TwoPassword.Recovery;

public sealed record RecoveryProgress(string Stage, int? Percent, string Message);
public sealed record RecoveryResult(string RecoveryFile, IReadOnlyList<string> Files, int ExitCode, string Summary, bool Repaired = false)
{
    public bool Success => ExitCode == 0;
    public bool Repairable => ExitCode == 1;
}

/// <summary>Runs a pinned, separately licensed PAR2 program on ciphertext only.</summary>
public static class RecoveryService
{
    private const string ToolHash = "36CE11D92C895A552485BA8CB1AD4B92CA62A00333F1AA6308DAAFBC371E69E9";
    private static readonly Regex Percentage = new(@"(\d+(?:\.\d+)?)%", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public static Task<RecoveryResult> CreateAsync(string packagePath, int redundancyPercent,
        IProgress<RecoveryProgress>? progress = null, CancellationToken cancellationToken = default) =>
        Task.Run(() => CreateCoreAsync(packagePath, redundancyPercent, progress, cancellationToken), cancellationToken);

    public static Task<RecoveryResult> VerifyAsync(string recoveryFile, IProgress<RecoveryProgress>? progress = null,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => VerifyCoreAsync(recoveryFile, progress, cancellationToken), cancellationToken);

    public static Task<RecoveryResult> RepairAsync(string recoveryFile, IProgress<RecoveryProgress>? progress = null,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => RepairCoreAsync(recoveryFile, progress, cancellationToken), cancellationToken);

    /// <summary>Healthy packages take only the normal authenticated streaming pass. PAR2 is
    /// invoked only after a data/format failure, or when the caller explicitly requests a precheck.</summary>
    public static async Task<PackageResult> ExtractAsync(ExtractOptions options,
        IProgress<PackageProgress>? packageProgress = null, IProgress<RecoveryProgress>? recoveryProgress = null,
        CancellationToken cancellationToken = default, bool verifyFirst = false)
    {
        ArgumentNullException.ThrowIfNull(options);
        cancellationToken.ThrowIfCancellationRequested();
        PackageService.ValidatePassword(options.Password);
        ValidateExtractionTarget(options.OutputDirectory);
        if (verifyFirst)
        {
            await PrepareForExtractionAsync(options.PackagePath, recoveryProgress, cancellationToken).ConfigureAwait(false);
            return await PackageService.ExtractAsync(options, packageProgress, cancellationToken).ConfigureAwait(false);
        }
        try
        {
            return await PackageService.ExtractAsync(options, packageProgress, cancellationToken).ConfigureAwait(false);
        }
        catch (PasswordNotRecognizedException) { throw; }
        catch (Exception error) when (error is PackageException or InvalidDataException or EndOfStreamException or FileNotFoundException or CryptographicException)
        {
            // Core has already removed its unauthenticated staging directory. Never merge into
            // an output another process created while that first attempt was running.
            ValidateExtractionTarget(options.OutputDirectory);
            if (!HasRecoveryFiles(options.PackagePath)) throw;
            recoveryProgress?.Report(new(Text.Get("检测到损坏"), null, Text.Get("正在检查恢复记录，修复后会重新认证并解包。")));
            var recovery = await PrepareForExtractionAsync(options.PackagePath, recoveryProgress, cancellationToken).ConfigureAwait(false);
            if (recovery is { Success: true, Repaired: true })
            {
                recoveryProgress?.Report(new(Text.Get("重新认证并解包"), null, Text.Get("恢复完成，正在重新认证并解包。")));
                return await PackageService.ExtractAsync(options, packageProgress, cancellationToken).ConfigureAwait(false);
            }
            // PAR2 can certify the original damaged/unsupported bytes too. It cannot make an
            // invalid archive valid, and a healthy recovery set must not cause an endless retry.
            throw;
        }
    }

    public static bool HasRecoveryFiles(string packagePath) => FindRelatedRecoveryFile(Full(packagePath)) is not null;

    private static void ValidateExtractionTarget(string output)
    {
        string path = Full(output);
        if (File.Exists(Extended(path)) || Directory.Exists(Extended(path)))
            throw new IOException(Text.Get("还原目标已存在。请选择新的文件夹，程序不会合并或覆盖。"));
        AssertAncestors(path, true);
    }

    public static async Task<RecoveryResult?> PrepareForExtractionAsync(string packagePath,
        IProgress<RecoveryProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        string path = Full(packagePath);
        string? candidate = FindRelatedRecoveryFile(path);
        if (candidate is null) return null;
        var result = await VerifyAsync(candidate, progress, cancellationToken).ConfigureAwait(false);
        if (result.Success) return result;
        if (result.Repairable)
        {
            result = await RepairAsync(candidate, progress, cancellationToken).ConfigureAwait(false);
            if (result.Success) return result;
        }
        throw new IOException(Text.Get("恢复记录检查失败，未提交解包结果。") + result.Summary);

    }

    private static string? FindRelatedRecoveryFile(string path)
    {
        string? candidate = FindRecovery(path);
        return candidate ?? (path.EndsWith(".2pw", StringComparison.OrdinalIgnoreCase) ? FindRecovery(Path.ChangeExtension(path, ".exe")) : null);

        static string? FindRecovery(string package)
        {
            string index = package + ".par2";
            if (File.Exists(Extended(index))) return index;
            string directory = Path.GetDirectoryName(package)!;
            string basename = Path.GetFileName(package);
            if (!Directory.Exists(Extended(directory))) return null;
            return Directory.EnumerateFiles(Extended(directory), "*.par2", SearchOption.TopDirectoryOnly)
                .Select(Full).FirstOrDefault(p => Regex.IsMatch(Path.GetFileName(p),
                    "^" + Regex.Escape(basename) + @"\.vol[0-9]+\+[0-9]+\.par2$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant));
        }
    }

    public static async Task<string> ExportSourceAsync(string outputPath, CancellationToken cancellationToken = default)
    {
        string path = Full(outputPath);
        AssertAncestors(path, allowMissingLeaf: true);
        using var source = Resource("TwoPassword.Par2.Source.tar.xz");
        await using var destination = new FileStream(Extended(path), FileMode.CreateNew, FileAccess.Write, FileShare.None,
            131072, FileOptions.Asynchronous | FileOptions.SequentialScan);
        await source.CopyToAsync(destination, cancellationToken).ConfigureAwait(false);
        return path;
    }

    private static async Task<RecoveryResult> CreateCoreAsync(string packagePath, int percent,
        IProgress<RecoveryProgress>? progress, CancellationToken ct)
    {
        if (percent is < 1 or > 50) throw new ArgumentOutOfRangeException(nameof(percent), Text.Get("恢复冗余比例必须在 1%–50% 之间。"));
        string package = Full(packagePath);
        if (!package.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && !package.EndsWith(".2pw", StringComparison.OrdinalIgnoreCase))
            throw new IOException(Text.Get("请选择 2Password 的 EXE 或 .2pw 加密文件。"));
        AssertAncestors(package, false);
        var info = await PackageService.InspectAsync(package, ct).ConfigureAwait(false);
        var inputs = new List<string> { package };
        if (info.DataPath is not null && !string.Equals(Full(info.DataPath), package, StringComparison.OrdinalIgnoreCase))
            inputs.Add(Full(info.DataPath));
        string parent = Path.GetDirectoryName(package)!;
        string baseName = Path.GetFileName(package);
        string finalIndex = package + ".par2";
        var existing = Directory.EnumerateFiles(Extended(parent), "*.par2", SearchOption.TopDirectoryOnly)
            .Any(p => Path.GetFileName(p).Equals(baseName + ".par2", StringComparison.OrdinalIgnoreCase) ||
                Regex.IsMatch(Path.GetFileName(p), "^" + Regex.Escape(baseName) + @"\.vol[0-9]+\+[0-9]+\.par2$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant));
        if (existing) throw new IOException(Text.Get("此加密包已有 PAR2 文件，程序不会覆盖。请先将已有恢复记录移至其他位置。"));
        long total = 0;
        var locks = new List<FileStream>();
        string work = CreateWorkspace(parent);
        var committed = new List<string>();
        try
        {
            foreach (string input in inputs)
            {
                AssertAncestors(input, false);
                if (!string.Equals(Path.GetDirectoryName(input), parent, StringComparison.OrdinalIgnoreCase))
                    throw new IOException(Text.Get("独立数据文件必须与 EXE 位于同一个文件夹。"));
                var held = new FileStream(Extended(input), FileMode.Open, FileAccess.Read, FileShare.Read);
                locks.Add(held);
                total = checked(total + held.Length);
            }
            long blockSize = Math.Clamp(((total + 8191) / 8192) * 4, 4096, 64L * 1024 * 1024);
            long blocks = inputs.Sum(p => (new FileInfo(Extended(p)).Length + blockSize - 1) / blockSize);
            if (blocks > 32768) throw new IOException(Text.Get("本版本 PAR2 恢复集支持最多 2 TiB 的加密数据。加密包已经保留，可不生成恢复记录。"));
            string index = Path.Combine(work, baseName + ".par2");
            var args = new List<string> { "c", "-q", "-m256", "-t4", "-T2", "-s" + blockSize.ToString(CultureInfo.InvariantCulture),
                "-r" + percent.ToString(CultureInfo.InvariantCulture), "-n" + Math.Min(4, Math.Max(1, (blocks * percent + 99) / 100)).ToString(CultureInfo.InvariantCulture), "-u", "-B" + Extended(parent), "--", Extended(index) };
            args.AddRange(inputs.Select(Extended));
            var native = await RunAsync(work, args, Text.Get("生成 PAR2 恢复记录"), progress, ct).ConfigureAwait(false);
            if (native.ExitCode != 0) throw new IOException(Text.Get("生成恢复记录失败。") + Explain(native.ExitCode, native.Log));
            // The same strict metadata validator is used for our own output and externally supplied sets.
            var validated = await Par2Metadata.LoadAsync(index, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested();
            foreach (string staged in validated.RecoveryFiles)
            {
                string target = Path.Combine(parent, Path.GetFileName(staged));
                if (File.Exists(Extended(target)) || Directory.Exists(Extended(target))) throw new IOException(Text.Get("恢复记录目标已存在，已停止以避免覆盖。"));
            }
            foreach (string staged in validated.RecoveryFiles)
            {
                ct.ThrowIfCancellationRequested();
                string target = Path.Combine(parent, Path.GetFileName(staged));
                File.Move(Extended(staged), Extended(target), false);
                committed.Add(target);
            }
            progress?.Report(new(Text.Get("恢复记录已生成"), 100, Text.Get("请将加密包和所有 PAR2 文件一起保存。")));
            return new(finalIndex, committed.ToArray(), 0, Text.Get("已生成 {0}% PAR2 冗余；请同时保留索引和全部恢复分卷。", percent));
        }
        catch
        {
            foreach (string path in committed) TryDeleteOwnedFile(path);
            throw;
        }
        finally
        {
            foreach (var held in locks) held.Dispose();
            CleanupWorkspace(work);
        }
    }

    private static async Task<RecoveryResult> VerifyCoreAsync(string recoveryFile, IProgress<RecoveryProgress>? progress, CancellationToken ct)
    {
        var set = await Par2Metadata.LoadAsync(recoveryFile, ct).ConfigureAwait(false);
        string work = CreateWorkspace(set.Directory);
        var heldInputs = new List<FileStream>();
        try
        {
            string index = await StageParityAsync(set, work, progress, ct).ConfigureAwait(false);
            foreach (var source in set.Sources)
            {
                string path = Path.Combine(set.Directory, source.Name);
                AssertAncestors(path, true);
                if (File.Exists(Extended(path)))
                {
                    var held = new FileStream(Extended(path), FileMode.Open, FileAccess.Read, FileShare.Read, 131072, FileOptions.Asynchronous | FileOptions.SequentialScan);
                    heldInputs.Add(held);
                    string staged = Path.Combine(work, source.Name);
                    // Read-only hard links keep verification fast on NTFS. The held handle denies writes
                    // through every alias; on filesystems without hard links use a bounded streaming copy.
                    if ((File.GetAttributes(Extended(path)) & FileAttributes.ReadOnly) != 0 ||
                        !CreateHardLinkW(Extended(staged), Extended(path), IntPtr.Zero))
                        await CopyWithHashAsync(held, staged, null, progress, ct).ConfigureAwait(false);
                }
            }
            var native = await RunAsync(work, ["v", "-q", "-m256", "-t4", "-T2", "-B" + Extended(work), "--", Extended(index)],
                Text.Get("检查 PAR2 恢复记录"), progress, ct).ConfigureAwait(false);
            return new(set.IndexPath, set.RecoveryFiles, native.ExitCode, Explain(native.ExitCode, native.Log));
        }
        finally { foreach (var held in heldInputs) held.Dispose(); CleanupWorkspace(work); }
    }

    private static async Task<RecoveryResult> RepairCoreAsync(string recoveryFile, IProgress<RecoveryProgress>? progress, CancellationToken ct)
    {
        var set = await Par2Metadata.LoadAsync(recoveryFile, ct).ConfigureAwait(false);
        string work = CreateWorkspace(set.Directory);
        var originals = new Dictionary<string, (long Length, DateTime Write, byte[] Md5)>(StringComparer.OrdinalIgnoreCase);
        var heldInputs = new List<FileStream>();
        var commits = new List<(string Target, string? Backup)>();
        try
        {
            string index = await StageParityAsync(set, work, progress, ct).ConfigureAwait(false);
            foreach (var source in set.Sources)
            {
                ct.ThrowIfCancellationRequested();
                string original = Path.Combine(set.Directory, source.Name);
                AssertAncestors(original, true);
                if (!File.Exists(Extended(original))) continue;
                var info = new FileInfo(Extended(original));
                var held = new FileStream(Extended(original), FileMode.Open, FileAccess.Read, FileShare.Read, 131072, FileOptions.Asynchronous | FileOptions.SequentialScan);
                heldInputs.Add(held);
                using var hash = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
                await CopyWithHashAsync(held, Path.Combine(work, source.Name), hash, progress, ct).ConfigureAwait(false);
                originals[source.Name] = (info.Length, info.LastWriteTimeUtc, hash.GetHashAndReset());
            }
            var native = await RunAsync(work, ["r", "-q", "-m256", "-t4", "-T2", "-B" + Extended(work), "--", Extended(index)],
                Text.Get("修复加密数据"), progress, ct).ConfigureAwait(false);
            if (native.ExitCode != 0) return new(set.IndexPath, set.RecoveryFiles, native.ExitCode, Explain(native.ExitCode, native.Log));
            // Independently check every reconstructed file, before any original is replaced.
            foreach (var source in set.Sources)
            {
                string staged = Path.Combine(work, source.Name);
                if (!File.Exists(Extended(staged)) || new FileInfo(Extended(staged)).Length != source.Length)
                    throw new IOException(Text.Get("PAR2 返回成功，但重建文件的长度不匹配。原文件未改动。"));
                await using var stream = File.OpenRead(Extended(staged));
                byte[] hash = await MD5.HashDataAsync(stream, ct).ConfigureAwait(false);
                if (!CryptographicOperations.FixedTimeEquals(hash, source.Md5))
                    throw new IOException(Text.Get("PAR2 重建结果未通过独立校验。原文件未改动。"));
            }
            ct.ThrowIfCancellationRequested();
            foreach (var held in heldInputs) held.Dispose();
            heldInputs.Clear();
            // There is no cancellation point in this short commit phase; all reconstructed files are ready.
            foreach (var source in set.Sources)
            {
                string target = Path.Combine(set.Directory, source.Name);
                AssertAncestors(target, true);
                if (originals.TryGetValue(source.Name, out var prior))
                {
                    var current = new FileInfo(Extended(target));
                    if (!current.Exists || current.Length != prior.Length || current.LastWriteTimeUtc != prior.Write)
                        throw new IOException(Text.Get("修复期间原文件发生变化，已停止提交。"));
                    if (prior.Length == source.Length && CryptographicOperations.FixedTimeEquals(prior.Md5, source.Md5)) continue;
                    string backup = Path.Combine(set.Directory, ".2pw-before-repair-" + Guid.NewGuid().ToString("N") + ".bak");
                    File.Replace(Extended(Path.Combine(work, source.Name)), Extended(target), Extended(backup), false);
                    commits.Add((target, backup));
                }
                else
                {
                    File.Move(Extended(Path.Combine(work, source.Name)), Extended(target), false);
                    commits.Add((target, null));
                }
            }
            var files = commits.SelectMany(c => c.Backup is null ? new[] { c.Target } : new[] { c.Target, c.Backup }).ToArray();
            progress?.Report(new(Text.Get("修复完成"), 100, Text.Get("损坏的原文件已保留为 .2pw-before-repair-*.bak。")));
            return new(set.IndexPath, files, 0, commits.Count == 0 ? Text.Get("文件完整，无需修复。") : Text.Get("修复完成。已保留损坏文件的备份；解包时仍会执行 AES-GCM 认证。"), commits.Count > 0);
        }
        catch
        {
            for (int i = commits.Count - 1; i >= 0; i--)
            {
                try
                {
                    var item = commits[i];
                    if (item.Backup is not null) File.Replace(Extended(item.Backup), Extended(item.Target), null, false);
                    else File.Delete(Extended(item.Target));
                }
                catch { /* Retain backups if rollback is blocked by an external process. */ }
            }
            throw;
        }
        finally { foreach (var held in heldInputs) held.Dispose(); CleanupWorkspace(work); }
    }

    private static async Task<string> StageParityAsync(Par2Set set, string work, IProgress<RecoveryProgress>? progress, CancellationToken ct)
    {
        foreach (string file in set.RecoveryFiles)
        {
            AssertAncestors(file, false);
            await using var input = new FileStream(Extended(file), FileMode.Open, FileAccess.Read, FileShare.Read, 131072, FileOptions.Asynchronous | FileOptions.SequentialScan);
            await CopyWithHashAsync(input, Path.Combine(work, Path.GetFileName(file)), null, progress, ct).ConfigureAwait(false);
        }
        // Revalidate the copies, eliminating the validate-then-copy race for native input metadata.
        var checkedCopy = await Par2Metadata.LoadAsync(Path.Combine(work, Path.GetFileName(set.IndexPath)), ct).ConfigureAwait(false);
        if (checkedCopy.RecoveryFiles.Length != set.RecoveryFiles.Length ||
            !checkedCopy.RecoveryFiles.Select(Path.GetFileName).Order(StringComparer.Ordinal).SequenceEqual(
                set.RecoveryFiles.Select(Path.GetFileName).Order(StringComparer.Ordinal), StringComparer.Ordinal))
            throw new IOException(Text.Get("复制后的恢复卷损坏或缺失，已停止，未启动原生修复程序。"));
        if (checkedCopy.Sources.Count != set.Sources.Count || checkedCopy.Sources.Any(s => !set.Sources.Any(expected =>
            expected.Name == s.Name && expected.Length == s.Length && CryptographicOperations.FixedTimeEquals(expected.Md5, s.Md5))))
            throw new IOException(Text.Get("复制期间恢复记录发生变化。"));
        return checkedCopy.IndexPath;
    }

    private static async Task CopyWithHashAsync(FileStream input, string destination, IncrementalHash? hash,
        IProgress<RecoveryProgress>? progress, CancellationToken ct)
    {
        await using var output = new FileStream(Extended(destination), FileMode.CreateNew, FileAccess.Write, FileShare.None,
            131072, FileOptions.Asynchronous | FileOptions.SequentialScan);
        byte[] buffer = new byte[131072];
        long copied = 0;
        var timer = Stopwatch.StartNew();
        int read;
        while ((read = await input.ReadAsync(buffer, ct).ConfigureAwait(false)) != 0)
        {
            hash?.AppendData(buffer, 0, read);
            await output.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
            copied += read;
            if (timer.ElapsedMilliseconds > 150)
            {
                progress?.Report(new(Text.Get("准备恢复工作区"), input.Length == 0 ? 100 : (int)Math.Min(100, copied * 100.0 / input.Length), Path.GetFileName(destination)));
                timer.Restart();
            }
        }
    }

    private static async Task<(int ExitCode, string Log)> RunAsync(string work, IEnumerable<string> args, string stage,
        IProgress<RecoveryProgress>? progress, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        string engineDir = Path.Combine(work, ".engine");
        Directory.CreateDirectory(Extended(engineDir));
        string tool = Path.Combine(engineDir, "par2.exe");
        if (!File.Exists(Extended(tool)))
        {
            using var resource = Resource("TwoPassword.Par2.Tool.exe");
            await using var output = new FileStream(Extended(tool), FileMode.CreateNew, FileAccess.Write, FileShare.None);
            await resource.CopyToAsync(output, ct).ConfigureAwait(false);
        }
        await using (var input = File.OpenRead(Extended(tool)))
        {
            var hash = await SHA256.HashDataAsync(input, ct).ConfigureAwait(false);
            if (Convert.ToHexString(hash) != ToolHash) throw new IOException(Text.Get("PAR2 工具校验失败，已停止。"));
        }
        var start = new ProcessStartInfo(tool)
        {
            WorkingDirectory = work, UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8
        };
        foreach (string arg in args) start.ArgumentList.Add(arg);
        using var process = new Process { StartInfo = start };
        if (!process.Start()) throw new IOException(Text.Get("无法启动 PAR2 工具。"));
        progress?.Report(new(stage, null, Text.Get("正在处理加密数据，不需要密码。")));
        using var cancel = ct.Register(() => { try { if (!process.HasExited) process.Kill(true); } catch (InvalidOperationException) { } });
        var log = new StringBuilder();
        var sync = new object();
        Task drainOutput = DrainAsync(process.StandardOutput);
        Task drainError = DrainAsync(process.StandardError);
        try { await process.WaitForExitAsync(ct).ConfigureAwait(false); }
        finally
        {
            if (!process.HasExited) { try { process.Kill(true); } catch (InvalidOperationException) { } }
            await Task.WhenAll(drainOutput, drainError).ConfigureAwait(false);
        }
        ct.ThrowIfCancellationRequested();
        return (process.ExitCode, log.ToString());

        async Task DrainAsync(StreamReader reader)
        {
            char[] buffer = new char[2048];
            var line = new StringBuilder();
            var throttle = Stopwatch.StartNew();
            int count;
            while ((count = await reader.ReadAsync(buffer).ConfigureAwait(false)) != 0)
            {
                for (int i = 0; i < count; i++)
                {
                    char c = buffer[i];
                    if (c is '\r' or '\n')
                    {
                        if (line.Length == 0) continue;
                        string text = line.ToString();
                        lock (sync) { log.AppendLine(text); if (log.Length > 16384) log.Remove(0, log.Length - 16384); }
                        if (throttle.ElapsedMilliseconds > 120)
                        {
                            Match match = Percentage.Match(text);
                            int? pct = match.Success && double.TryParse(match.Groups[1].Value, CultureInfo.InvariantCulture, out double value)
                                ? (int)Math.Clamp(value, 0, 100) : null;
                            progress?.Report(new(stage, pct, text.Length > 180 ? text[..180] : text));
                            throttle.Restart();
                        }
                        line.Clear();
                    }
                    else if (line.Length < 2048) line.Append(c);
                }
            }
            if (line.Length > 0) lock (sync) log.AppendLine(line.ToString());
        }
    }

    private static string Explain(int code, string log) => code switch
    {
        0 => Text.Get("文件完整，校验通过。"),
        1 => Text.Get("检测到损坏，现有恢复块足够，可以修复。"),
        2 => Text.Get("恢复块不足，无法完整修复。请寻找其他 PAR2 分卷或完好的备份。"),
        4 => Text.Get("恢复记录缺少关键元数据，无法修复。"),
        5 => Text.Get("重建结果仍有损坏，原文件未替换。"),
        6 => Text.Get("读取或写入失败，请检查空间、文件占用和访问权限。"),
        8 => Text.Get("PAR2 内存不足。"),
        _ => Text.Get("PAR2 返回 {0}。{1}", code, log.Length > 1000 ? log[^1000..] : log)
    };

    private static Stream Resource(string name) => typeof(RecoveryService).Assembly.GetManifestResourceStream(name)
        ?? throw new IOException(Text.Get("缺少内置恢复组件，请重新安装完整版本。"));

    private static string CreateWorkspace(string parent)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException(Text.Get("PAR2 恢复组件需要 Windows x64。"));
        AssertAncestors(parent, false);
        string path = Path.Combine(parent, ".2pw-recovery-" + Guid.NewGuid().ToString("N"));
        var identity = WindowsIdentity.GetCurrent().User ?? throw new IOException(Text.Get("无法确定当前 Windows 用户。"));
        var acl = new DirectorySecurity();
        acl.SetAccessRuleProtection(true, false);
        foreach (var sid in new[] { identity, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null) })
            acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        FileSystemAclExtensions.Create(new DirectoryInfo(Extended(path)), acl);
        return path;
    }

    internal static string Full(string path)
    {
        if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) path = @"\\" + path[8..];
        else if (path.StartsWith(@"\\?\", StringComparison.Ordinal)) path = path[4..];
        if (path.StartsWith(@"\\.\", StringComparison.Ordinal) || path.StartsWith(@"\??\", StringComparison.Ordinal)) throw new IOException(Text.Get("不支持设备路径。"));
        string full = Path.GetFullPath(path);
        if (full.Length > 32700 || full.IndexOf(':', 2) >= 0) throw new IOException(Text.Get("路径过长或包含备用数据流。"));
        return full;
    }

    internal static string Extended(string path)
    {
        string full = Full(path);
        return full.StartsWith(@"\\", StringComparison.Ordinal) ? @"\\?\UNC\" + full[2..] : @"\\?\" + full;
    }

    internal static void AssertAncestors(string path, bool allowMissingLeaf)
    {
        string? current = Full(path);
        bool leaf = true;
        while (current is not null)
        {
            try
            {
                var attributes = File.GetAttributes(Extended(current));
                if ((attributes & FileAttributes.ReparsePoint) != 0) throw new IOException(Text.Get("恢复操作不支持符号链接或联接点。"));
                if (!leaf && (attributes & FileAttributes.Directory) == 0) throw new IOException(Text.Get("父路径不是文件夹。"));
            }
            catch (FileNotFoundException) when (leaf && allowMissingLeaf) { }
            catch (DirectoryNotFoundException) when (leaf && allowMissingLeaf) { }
            leaf = false;
            current = Path.GetDirectoryName(current);
        }
    }

    private static void TryDeleteOwnedFile(string path)
    {
        try { File.Delete(Extended(path)); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLinkW(string fileName, string existingFileName, IntPtr securityAttributes);

    private static void CleanupWorkspace(string path)
    {
        try
        {
            foreach (string file in Directory.EnumerateFiles(Extended(path), "*", SearchOption.AllDirectories))
            {
                var attributes = File.GetAttributes(file);
                if ((attributes & FileAttributes.ReadOnly) != 0) File.SetAttributes(file, attributes & ~FileAttributes.ReadOnly);
            }
            Directory.Delete(Extended(path), true);
        }
        catch (IOException) { } catch (UnauthorizedAccessException) { }
    }
}
