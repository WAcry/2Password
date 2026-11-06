using TwoPassword.Localization;
using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using TwoPassword.Core;

namespace TwoPassword.Recovery;

public sealed record RecoveryProgress(string Stage, int? Percent, string Message);
public sealed record RecoveryResult(string PackagePath, int ExitCode, string Summary, int DamagedBlocks = 0, int RecoveryBlocks = 0, bool Repaired = false)
{
    public bool Success => ExitCode == 0;
    public bool Repairable => ExitCode == 1;
}

/// <summary>
/// Stores a PAR2 recovery set after the encrypted payload and uses it to check and repair that payload.
/// The pinned, separately licensed par2 program only ever sees ciphertext and validated PAR2 packets.
/// </summary>
public static class RecoveryService
{
    public const int DefaultPercent = 5;
    private const string ToolHash = "36CE11D92C895A552485BA8CB1AD4B92CA62A00333F1AA6308DAAFBC371E69E9";
    private static readonly Regex Percentage = new(@"(\d+(?:\.\d+)?)%", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>Creates a package with recovery data. If only the recovery step fails, the package is still
    /// published without it and the error is returned.</summary>
    public static async Task<(PackageResult Package, Exception? RecoveryError)> CreateAsync(CreateOptions options, int redundancyPercent,
        IProgress<PackageProgress>? packageProgress = null, IProgress<RecoveryProgress>? recoveryProgress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (redundancyPercent == 0) return (await PackageService.CreateAsync(options, packageProgress, cancellationToken).ConfigureAwait(false), null);
        var writer = Writer(redundancyPercent, recoveryProgress);
        Exception? failure = null;
        void Guarded(string payload, long length, Stream output, CancellationToken ct)
        {
            try { writer(payload, length, output, ct); }
            catch (Exception error) when (error is not OperationCanceledException)
            {
                output.SetLength(0);
                failure = error;
            }
        }
        var package = await PackageService.CreateAsync(options with { Recovery = Guarded }, packageProgress, cancellationToken).ConfigureAwait(false);
        return (package, failure);
    }

    public static RecoveryWriter Writer(int redundancyPercent, IProgress<RecoveryProgress>? progress = null)
    {
        if (redundancyPercent is < 1 or > 50) throw new ArgumentOutOfRangeException(nameof(redundancyPercent), Text.Get("恢复冗余比例必须在 1%–50% 之间。"));
        return (payload, length, output, ct) => WriteAsync(payload, length, output, redundancyPercent, progress, ct).GetAwaiter().GetResult();
    }

    public static Task<RecoveryResult> VerifyAsync(string packagePath, IProgress<RecoveryProgress>? progress = null,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => VerifyCore(packagePath, progress, cancellationToken), cancellationToken);

    public static Task<RecoveryResult> RepairAsync(string packagePath, IProgress<RecoveryProgress>? progress = null,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => RepairCoreAsync(packagePath, progress, cancellationToken), cancellationToken);

    /// <summary>Healthy packages take only the normal authenticated pass. Recovery runs after a data or format
    /// failure, or first when the caller asks for it. Repair works on a copy; the package itself is not changed.</summary>
    public static async Task<PackageResult> ExtractAsync(ExtractOptions options,
        IProgress<PackageProgress>? packageProgress = null, IProgress<RecoveryProgress>? recoveryProgress = null,
        CancellationToken cancellationToken = default, bool verifyFirst = false)
    {
        ArgumentNullException.ThrowIfNull(options);
        cancellationToken.ThrowIfCancellationRequested();
        PackageService.ValidatePassword(options.Password);
        ValidateExtractionTarget(options.OutputDirectory);
        options = options with { Provenance = options.Provenance.Include(options.PackagePath) };
        if (verifyFirst && TryLocate(options.PackagePath, cancellationToken) is { Regions.RecoveryLength: > 0 } checkedFirst)
            return await ExtractRepairedAsync(options, checkedFirst, packageProgress, recoveryProgress, cancellationToken).ConfigureAwait(false)
                ?? await PackageService.ExtractAsync(options, packageProgress, cancellationToken).ConfigureAwait(false);
        try
        {
            return await PackageService.ExtractAsync(options, packageProgress, cancellationToken).ConfigureAwait(false);
        }
        catch (PasswordNotRecognizedException) { throw; }
        catch (Exception error) when (error is PackageException or InvalidDataException or EndOfStreamException or CryptographicException)
        {
            // Core has already removed its unauthenticated staging directory. Never merge into
            // an output another process created while that first attempt was running.
            ValidateExtractionTarget(options.OutputDirectory);
            if (TryLocate(options.PackagePath, cancellationToken) is not { Regions.RecoveryLength: > 0 } location) throw;
            recoveryProgress?.Report(new(Text.Get("检测到损坏"), null, Text.Get("正在用恢复记录修复，修复后重新解密。")));
            var repaired = await ExtractRepairedAsync(options, location, packageProgress, recoveryProgress, cancellationToken).ConfigureAwait(false);
            // Intact payload bytes mean the failure is not damage that recovery data can fix.
            if (repaired is null) throw;
            return repaired;
        }
    }

    /// <summary>True when the package has recovery data, including when only a scan past a damaged trailer finds it.</summary>
    public static bool HasRecovery(string packagePath) => TryLocate(packagePath, CancellationToken.None)?.Regions.RecoveryLength > 0;

    /// <summary>Like <see cref="PackageService.LocateRegions"/>, but scans the file when the trailer is unreadable.</summary>
    public static PackageRegions LocateRegions(string packagePath, CancellationToken cancellationToken = default) =>
        Locate(packagePath, cancellationToken).Regions;

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

    private static async Task WriteAsync(string payloadPath, long payloadLength, Stream output, int percent,
        IProgress<RecoveryProgress>? progress, CancellationToken ct)
    {
        string payload = Full(payloadPath);
        string work = CreateWorkspace(Path.GetDirectoryName(payload)!);
        try
        {
            string source = Path.Combine(work, Par2Metadata.SourceName);
            string index = source + ".par2";
            using (var held = new FileStream(Extended(payload), FileMode.Open, FileAccess.Read, FileShare.Read, 131072, FileOptions.SequentialScan))
            {
                if (held.Length != payloadLength) throw new IOException(Text.Get("加密数据在生成恢复记录期间被修改。"));
                // The held handle denies writers through every alias of a hard link.
                if (!CreateHardLinkW(Extended(source), Extended(payload), IntPtr.Zero))
                    await CopyAsync(held, 0, payloadLength, source, progress, ct).ConfigureAwait(false);
                var native = await RunAsync(work, ["c", "-r" + percent.ToString(CultureInfo.InvariantCulture), "-B" + Extended(work), "--", Extended(index), Extended(source)],
                    Text.Get("生成恢复记录"), progress, ct).ConfigureAwait(false);
                if (native.ExitCode != 0) throw new IOException(Text.Get("生成恢复记录失败。") + Explain(native.ExitCode, native.Log));
            }
            string blob = Path.Combine(work, "recovery.bin");
            await using (var combined = new FileStream(Extended(blob), FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 131072, FileOptions.Asynchronous))
            {
                foreach (string file in Directory.EnumerateFiles(Extended(work), Par2Metadata.SourceName + "*.par2").Order(StringComparer.Ordinal))
                {
                    await using var part = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read, 131072, FileOptions.Asynchronous | FileOptions.SequentialScan);
                    await part.CopyToAsync(combined, ct).ConfigureAwait(false);
                }
                await combined.FlushAsync(ct).ConfigureAwait(false);
                // Our own output passes the same validator that guards repair.
                var set = Par2Metadata.Read(combined, 0, combined.Length, payloadLength, ct);
                if (set.RecoveryBlocks == 0) throw new IOException(Text.Get("生成恢复记录失败。"));
                combined.Position = 0;
                await combined.CopyToAsync(output, ct).ConfigureAwait(false);
            }
            progress?.Report(new(Text.Get("恢复记录已生成"), 100, ""));
        }
        finally { CleanupWorkspace(work); }
    }

    private static RecoveryResult VerifyCore(string packagePath, IProgress<RecoveryProgress>? progress, CancellationToken ct)
    {
        var location = Locate(packagePath, ct);
        if (location.Regions.RecoveryLength == 0) return new(packagePath, 4, Text.Get("这个加密包没有恢复记录。"));
        using var file = new FileStream(Extended(location.Regions.DataPath), FileMode.Open, FileAccess.Read, FileShare.Read, 131072, FileOptions.SequentialScan);
        var result = Inspect(packagePath, file, location, progress, ct, out _, out _);
        if (result.DamagedBlocks == 0 && (result.Success || result.Repairable))
        {
            PackageService.ValidatePayloadHeader(file, location.Regions.PayloadOffset);
            if (location.Regions.IsDetached) PackageService.ValidateDetachedPayload(packagePath, file);
        }
        return result;
    }

    private static async Task<RecoveryResult> RepairCoreAsync(string packagePath, IProgress<RecoveryProgress>? progress, CancellationToken ct)
    {
        var location = Locate(packagePath, ct);
        var regions = location.Regions;
        if (regions.RecoveryLength == 0) return new(packagePath, 4, Text.Get("这个加密包没有恢复记录。"));
        AssertAncestors(regions.DataPath, false);
        // Read-write with read sharing: nobody else can change the bytes between checking and writing back.
        using var file = new FileStream(Extended(regions.DataPath), FileMode.Open, FileAccess.ReadWrite, FileShare.Read, 131072, FileOptions.SequentialScan);
        var result = Inspect(packagePath, file, location, progress, ct, out var set, out var damaged);
        if (damaged.Count == 0 && (result.Success || result.Repairable))
        {
            PackageService.ValidatePayloadHeader(file, regions.PayloadOffset);
            if (regions.IsDetached) PackageService.ValidateDetachedPayload(packagePath, file);
        }
        if (!result.Repairable) return result;
        if (damaged.Count > 0)
        {
            string work = CreateWorkspace(Path.GetDirectoryName(regions.DataPath)!);
            try
            {
                string repaired = await RebuildAsync(file, regions, set!, work, progress, ct).ConfigureAwait(false);
                ct.ThrowIfCancellationRequested();
                await using var source = new FileStream(Extended(repaired), FileMode.Open, FileAccess.Read, FileShare.Read, 131072, FileOptions.Asynchronous);
                PackageService.ValidatePayloadHeader(source, 0);
                if (regions.IsDetached) PackageService.ValidateDetachedPayload(packagePath, source);
                foreach (int slice in damaged)
                {
                    long offset = slice * set!.BlockSize;
                    await CopyRangeAsync(source, offset, file, regions.PayloadOffset + offset, Math.Min(set.BlockSize, regions.PayloadLength - offset), ct).ConfigureAwait(false);
                }
            }
            finally { CleanupWorkspace(work); }
        }
        if (location.Scanned) PackageService.RewriteTrailer(file, regions);
        file.Flush(flushToDisk: true);
        progress?.Report(new(Text.Get("修复完成"), 100, ""));
        string summary = !location.Scanned ? Text.Get("已修复 {0} 个损坏的数据块。", damaged.Count)
            : damaged.Count == 0 ? Text.Get("已修复文件尾部。")
            : Text.Get("已修复文件尾部和 {0} 个损坏的数据块。", damaged.Count);
        return new(packagePath, 0, summary, damaged.Count, set!.RecoveryBlocks, Repaired: true);
    }

    /// <summary>Repairs a private copy of the payload next to the destination and extracts from it.
    /// Returns null when the payload and trailer are intact, so there is nothing to repair.</summary>
    private static async Task<PackageResult?> ExtractRepairedAsync(ExtractOptions options, Location location, IProgress<PackageProgress>? packageProgress,
        IProgress<RecoveryProgress>? recoveryProgress, CancellationToken ct)
    {
        var regions = location.Regions;
        options = options with { Provenance = options.Provenance.Include(options.PackagePath).Include(regions.DataPath) };
        string work = CreateWorkspace(Path.GetDirectoryName(Full(options.OutputDirectory))!);
        try
        {
            string repaired;
            using (var file = new FileStream(Extended(regions.DataPath), FileMode.Open, FileAccess.Read, FileShare.Read, 131072, FileOptions.SequentialScan))
            {
                var check = Inspect(options.PackagePath, file, location, recoveryProgress, ct, out var set, out var damaged);
                if (check.Success) return null;
                if (!check.Repairable) throw new IOException(Text.Get("无法修复：{0}", check.Summary));
                if (damaged.Count > 0) repaired = await RebuildAsync(file, regions, set!, work, recoveryProgress, ct).ConfigureAwait(false);
                else
                {
                    repaired = Path.Combine(work, Par2Metadata.SourceName);
                    await CopyAsync(file, regions.PayloadOffset, regions.PayloadLength, repaired, recoveryProgress, ct).ConfigureAwait(false);
                }
            }
            PackageService.FramePayload(repaired);
            if (regions.IsDetached)
            {
                using var payload = new FileStream(Extended(repaired), FileMode.Open, FileAccess.Read, FileShare.Read);
                PackageService.ValidateDetachedPayload(options.PackagePath, payload);
            }
            recoveryProgress?.Report(new(Text.Get("重新解密"), null, Text.Get("修复完成，正在重新解密。")));
            var result = await PackageService.ExtractAsync(options with { PackagePath = repaired }, packageProgress, ct).ConfigureAwait(false);
            return result with { DataPath = regions.IsDetached ? regions.DataPath : null, IsDetached = regions.IsDetached };
        }
        finally { CleanupWorkspace(work); }
    }

    /// <summary>A lost trailer is damage too: the file is repairable once the payload checks out.</summary>
    private static RecoveryResult Inspect(string packagePath, FileStream file, Location location, IProgress<RecoveryProgress>? progress,
        CancellationToken ct, out Par2Set? set, out List<int> damaged)
    {
        var regions = location.Regions;
        damaged = [];
        try { set = Par2Metadata.Read(file, regions.RecoveryOffset, regions.RecoveryLength, regions.PayloadLength, ct); }
        catch (InvalidDataException error)
        {
            set = null;
            return new(packagePath, 4, error.Message);
        }
        damaged = DamagedSlices(file, regions.PayloadOffset, regions.PayloadLength, set, progress, ct);
        int count = damaged.Count, blocks = set.RecoveryBlocks;
        if (count == 0)
            return location.Scanned ? new(packagePath, 1, Text.Get("文件尾部损坏，加密数据完整，可以修复。"), 0, blocks)
                : new(packagePath, 0, Text.Get("加密数据完整。"), 0, blocks);
        string summary = count <= blocks
            ? Text.Get("{0} 个数据块损坏，恢复记录有 {1} 个恢复块，可以修复。", count, blocks)
            : Text.Get("{0} 个数据块损坏，恢复记录只有 {1} 个恢复块，无法修复。", count, blocks);
        if (location.Scanned) summary = Text.Get("文件尾部损坏。{0}", summary);
        return new(packagePath, count <= blocks ? 1 : 2, summary, count, blocks);
    }

    /// <summary>Package regions, and whether they had to be found by scanning because the trailer is unreadable.</summary>
    private sealed record Location(PackageRegions Regions, bool Scanned);

    private static Location Locate(string packagePath, CancellationToken ct)
    {
        try { return new(PackageService.LocateRegions(packagePath), false); }
        catch (PackageException)
        {
            PackageRegions? scanned;
            try { scanned = Scan(packagePath, ct); }
            catch (PackageException) { scanned = null; }
            if (scanned is null) throw;
            return new(scanned, true);
        }
    }

    private static Location? TryLocate(string packagePath, CancellationToken ct)
    {
        try { return Locate(packagePath, ct); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException or InvalidDataException) { return null; }
    }

    /// <summary>
    /// Rebuilds the regions without the trailer: an intact header replica gives the possible payload starts,
    /// a FileDesc packet near the end gives the payload length, and the slice checksums pick the start.
    /// </summary>
    private static PackageRegions? Scan(string packagePath, CancellationToken ct)
    {
        var candidates = PackageService.FindPayloadCandidates(packagePath, ct);
        using var file = new FileStream(Extended(candidates.DataPath), FileMode.Open, FileAccess.Read, FileShare.Read, 131072, FileOptions.RandomAccess);
        long lowest = candidates.Offsets.Min(), minimum = candidates.MinimumPayloadLength;
        long length = Par2Metadata.FindSourceLength(file, lowest + minimum, file.Length, ct);
        if (length < minimum || length >= file.Length - lowest) return null;
        // The recovery data is read from the lowest start, so it may begin with up to two header replicas'
        // worth of payload bytes. Par2Metadata skips them while it resyncs on packet markers.
        long start = lowest + length;
        Par2Set set;
        try { set = Par2Metadata.Read(file, start, file.Length - start, length, ct); }
        catch (InvalidDataException) { return null; }
        long chosen = -1;
        int best = -1;
        foreach (long offset in candidates.Offsets)
        {
            int score = MatchingSamples(file, offset, length, candidates.HeaderLength, set, ct);
            if (score > best) (chosen, best) = (offset, score);
        }
        if (best <= 0)
            chosen = FindAdditionalSample(file, candidates.Offsets, length, candidates.HeaderLength, set, ct);
        long end = start + set.End;
        if (chosen < 0 || end <= chosen + length) return null;
        return new(candidates.DataPath, chosen, length, end - chosen - length, candidates.IsDetached);
    }

    /// <summary>The fast samples can all hit damaged slices. Probe other nonzero slices across all candidate
    /// starts before giving up; a repairable set has at most RecoveryBlocks damaged slices.</summary>
    private static long FindAdditionalSample(FileStream file, IReadOnlyList<long> offsets, long length, int skip, Par2Set set, CancellationToken ct)
    {
        int slices = set.SliceMd5.Length;
        int first = (int)Math.Min(slices - 1, (skip + set.BlockSize - 1) / set.BlockSize);
        int samples = (int)Math.Clamp(64L * 1024 * 1024 / set.BlockSize, 2, 16);
        var sampled = Enumerable.Range(0, samples)
            .Select(i => first + (int)((long)(slices - 1 - first) * i / Math.Max(1, samples - 1))).ToHashSet();
        byte[] buffer = new byte[1024 * 1024];
        byte[] zero = HashPaddedSample(file, 0, 0, set.BlockSize, buffer, ct)!;
        int examined = 0, limit = Math.Min(slices - first, set.RecoveryBlocks + 1);
        for (int index = first; index < slices && examined < limit; index++)
        {
            ct.ThrowIfCancellationRequested();
            if (sampled.Contains(index) || set.SliceMd5[index].AsSpan().SequenceEqual(zero)) continue;
            examined++;
            long position = (long)index * set.BlockSize;
            long count = Math.Min(set.BlockSize, length - position);
            foreach (long offset in offsets)
            {
                byte[]? actual = HashPaddedSample(file, offset + position, count, set.BlockSize, buffer, ct);
                if (actual is not null && actual.AsSpan().SequenceEqual(set.SliceMd5[index])) return offset;
            }
        }
        return -1;
    }

    /// <summary>
    /// Counts sample slices whose checksum matches when the payload starts at <paramref name="offset"/>. Slices in the
    /// identical header replicas and all-zero slices match at more than one start, so only ciphertext slices count.
    /// </summary>
    private static int MatchingSamples(FileStream file, long offset, long length, int skip, Par2Set set, CancellationToken ct)
    {
        int slices = set.SliceMd5.Length;
        int first = (int)Math.Min(slices - 1, (skip + set.BlockSize - 1) / set.BlockSize);
        int samples = (int)Math.Clamp(64L * 1024 * 1024 / set.BlockSize, 2, 16);
        byte[] buffer = new byte[1024 * 1024];
        byte[] zero = HashPaddedSample(file, 0, 0, set.BlockSize, buffer, ct)!;
        int matches = 0;
        foreach (int index in Enumerable.Range(0, samples).Select(i => first + (int)((long)(slices - 1 - first) * i / Math.Max(1, samples - 1))).Distinct())
        {
            ct.ThrowIfCancellationRequested();
            if (set.SliceMd5[index].AsSpan().SequenceEqual(zero)) continue;
            long position = (long)index * set.BlockSize;
            long count = Math.Min(set.BlockSize, length - position);
            byte[]? actual = HashPaddedSample(file, offset + position, count, set.BlockSize, buffer, ct);
            if (actual is not null && actual.AsSpan().SequenceEqual(set.SliceMd5[index])) matches++;
        }
        return matches;
    }

    /// <summary>Hashes one sample with PAR2 zero padding, using bounded memory even for multi-GiB blocks.
    /// A zero-length sample computes the all-zero block hash; a short file read cannot match a sample.</summary>
    private static byte[]? HashPaddedSample(FileStream file, long offset, long count, long blockSize, byte[] buffer, CancellationToken ct)
    {
        using var md5 = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
        long done = 0;
        while (done < count)
        {
            ct.ThrowIfCancellationRequested();
            int read = RandomAccess.Read(file.SafeFileHandle, buffer.AsSpan(0, (int)Math.Min(buffer.Length, count - done)), offset + done);
            if (read == 0) return null;
            md5.AppendData(buffer, 0, read);
            done += read;
        }
        long padding = blockSize - count;
        if (padding > 0) Array.Clear(buffer);
        while (padding > 0)
        {
            ct.ThrowIfCancellationRequested();
            int chunk = (int)Math.Min(buffer.Length, padding);
            md5.AppendData(buffer, 0, chunk);
            padding -= chunk;
        }
        return md5.GetHashAndReset();
    }

    /// <summary>PAR2 checksums each slice with its tail padded by zeros to the full block size.</summary>
    private static List<int> DamagedSlices(FileStream file, long offset, long length, Par2Set set, IProgress<RecoveryProgress>? progress, CancellationToken ct)
    {
        var damaged = new List<int>();
        byte[] buffer = new byte[1024 * 1024];
        using var md5 = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
        var timer = Stopwatch.StartNew();
        string stage = Text.Get("检查加密数据");
        progress?.Report(new(stage, 0, ""));
        for (int slice = 0; slice < set.SliceMd5.Length; slice++)
        {
            long start = slice * set.BlockSize;
            long remaining = Math.Min(set.BlockSize, length - start), padding = set.BlockSize - remaining;
            long position = offset + start;
            while (remaining > 0)
            {
                ct.ThrowIfCancellationRequested();
                int read = RandomAccess.Read(file.SafeFileHandle, buffer.AsSpan(0, (int)Math.Min(buffer.Length, remaining)), position);
                if (read == 0) throw new EndOfStreamException(Text.Get("加密数据被截断。"));
                md5.AppendData(buffer, 0, read);
                position += read;
                remaining -= read;
            }
            Array.Clear(buffer);
            while (padding > 0)
            {
                int count = (int)Math.Min(buffer.Length, padding);
                md5.AppendData(buffer, 0, count);
                padding -= count;
            }
            if (!CryptographicOperations.FixedTimeEquals(md5.GetHashAndReset(), set.SliceMd5[slice])) damaged.Add(slice);
            if (timer.ElapsedMilliseconds > 150)
            {
                progress?.Report(new(stage, (int)((position - offset) * 100 / length), ""));
                timer.Restart();
            }
        }
        return damaged;
    }

    /// <summary>Lets par2 rebuild a private copy of the payload and returns the copy once every slice checks out.</summary>
    private static async Task<string> RebuildAsync(FileStream file, PackageRegions regions, Par2Set set, string work,
        IProgress<RecoveryProgress>? progress, CancellationToken ct)
    {
        string source = Path.Combine(work, Par2Metadata.SourceName);
        string index = source + ".par2";
        await CopyAsync(file, regions.PayloadOffset, regions.PayloadLength, source, progress, ct).ConfigureAwait(false);
        await using (var packets = new FileStream(Extended(index), FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
            Par2Metadata.Copy(file, regions.RecoveryOffset, set, packets, ct);
        var native = await RunAsync(work, ["r", "-B" + Extended(work), "--", Extended(index)], Text.Get("修复加密数据"), progress, ct).ConfigureAwait(false);
        if (native.ExitCode != 0) throw new IOException(Text.Get("修复失败。") + Explain(native.ExitCode, native.Log));
        await using var rebuilt = new FileStream(Extended(source), FileMode.Open, FileAccess.Read, FileShare.Read, 131072, FileOptions.SequentialScan);
        if (rebuilt.Length != regions.PayloadLength || DamagedSlices(rebuilt, 0, regions.PayloadLength, set, null, ct).Count != 0)
            throw new IOException(Text.Get("修复结果没有通过校验，加密包没有改动。"));
        rebuilt.Position = 0;
        byte[] whole = await MD5.HashDataAsync(rebuilt, ct).ConfigureAwait(false);
        if (!CryptographicOperations.FixedTimeEquals(whole, set.SourceMd5))
            throw new IOException(Text.Get("修复结果没有通过校验，加密包没有改动。"));
        return source;
    }

    private static async Task CopyAsync(FileStream input, long offset, long length, string destination,
        IProgress<RecoveryProgress>? progress, CancellationToken ct)
    {
        await using var output = new FileStream(Extended(destination), FileMode.CreateNew, FileAccess.Write, FileShare.None,
            131072, FileOptions.Asynchronous | FileOptions.SequentialScan);
        output.SetLength(length);
        byte[] buffer = new byte[1024 * 1024];
        long copied = 0;
        var timer = Stopwatch.StartNew();
        string stage = Text.Get("准备修复");
        while (copied < length)
        {
            int read = await RandomAccess.ReadAsync(input.SafeFileHandle, buffer.AsMemory(0, (int)Math.Min(buffer.Length, length - copied)), offset + copied, ct).ConfigureAwait(false);
            if (read == 0) throw new EndOfStreamException(Text.Get("加密数据被截断。"));
            await output.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
            copied += read;
            if (timer.ElapsedMilliseconds > 150)
            {
                progress?.Report(new(stage, (int)(copied * 100 / length), ""));
                timer.Restart();
            }
        }
    }

    private static async Task CopyRangeAsync(FileStream input, long from, FileStream output, long to, long length, CancellationToken ct)
    {
        byte[] buffer = new byte[1024 * 1024];
        for (long done = 0; done < length;)
        {
            int read = await RandomAccess.ReadAsync(input.SafeFileHandle, buffer.AsMemory(0, (int)Math.Min(buffer.Length, length - done)), from + done, ct).ConfigureAwait(false);
            if (read == 0) throw new EndOfStreamException(Text.Get("加密数据被截断。"));
            RandomAccess.Write(output.SafeFileHandle, buffer.AsSpan(0, read), to + done);
            done += read;
        }
    }

    private static void ValidateExtractionTarget(string output)
    {
        string path = Full(output);
        if (File.Exists(Extended(path)) || Directory.Exists(Extended(path)))
            throw new IOException(Text.Get("还原目标已存在。请选择新的文件夹，程序不会合并或覆盖。"));
        AssertAncestors(path, true);
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
        progress?.Report(new(stage, null, ""));
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
                        Match match = Percentage.Match(text);
                        if (match.Success && throttle.ElapsedMilliseconds > 120 &&
                            double.TryParse(match.Groups[1].Value, CultureInfo.InvariantCulture, out double value))
                        {
                            progress?.Report(new(stage, (int)Math.Clamp(value, 0, 100), ""));
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
        2 => Text.Get("恢复块不够，无法完整修复。"),
        4 => Text.Get("恢复记录缺少关键元数据，无法修复。"),
        5 => Text.Get("修复后的数据仍有损坏。"),
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
        WindowsPrivateDirectory.Create(path);
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
