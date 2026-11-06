using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using TwoPassword.Core;

internal static class Program
{
    private const long GiB = 1024L * 1024 * 1024;
    private static readonly string[] TestPasswords = ["large-file-alpha-6f8d-test-only", "large-file-beta-中文_日本語-test-only"];
    private static readonly List<LargeCase> Cases = [];
    private static long _peakManaged, _peakWorkingSet;

    public static async Task<int> Main()
    {
        string repo = FindRepository();
        string work = Path.Combine(repo, "artifacts", "large-work", DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(work);
        string reportPath = Path.Combine(repo, "artifacts", "large-results.json");
        var started = DateTime.UtcNow;
        var all = Stopwatch.StartNew();
        var process = Process.GetCurrentProcess();
        using var monitor = new Timer(_ =>
        {
            try
            {
                process.Refresh();
                InterlockedExtensions.Max(ref _peakManaged, GC.GetTotalMemory(forceFullCollection: false));
                InterlockedExtensions.Max(ref _peakWorkingSet, process.WorkingSet64);
            }
            catch (InvalidOperationException) { }
        }, null, TimeSpan.Zero, TimeSpan.FromMilliseconds(250));
        bool realTemplate = false;
        string templateSource = Path.Combine(repo, "artifacts", "publish", "win-x64", "2Password.exe");
        string template = Path.Combine(work, "template-snapshot.exe");
        string? setupError = null;
        string? templateHash = null;
        try
        {
            if (File.Exists(templateSource))
            {
                File.Copy(templateSource, template, overwrite: false);
                realTemplate = true;
            }
            else
            {
                var synthetic = new byte[512];
                synthetic[0] = (byte)'M'; synthetic[1] = (byte)'Z';
                await File.WriteAllBytesAsync(template, synthetic);
                templateSource = "Synthetic MZ marker, 512 bytes; NOT a runnable Windows template";
            }
            templateHash = await Hash(template);
            Console.WriteLine("Real large-file integration; synthetic fixtures only.");
            Console.WriteLine("Workspace: " + work);
            Console.WriteLine("Template: " + templateSource);
            await RunCase(work, template, "4GiB_123MiB_日本語", 4 * GiB + 123L * 1024 * 1024, PackageCompression.None, expectedDetached: true);
            await RunCase(work, template, "8GiB_123bytes_中文", 8 * GiB + 123, PackageCompression.Zstd, expectedDetached: false);
        }
        catch (Exception e) { setupError = e.ToString(); Console.Error.WriteLine(setupError); }
        finally
        {
            all.Stop();
            process.Refresh();
            var report = new
            {
                SchemaVersion = 1,
                Status = setupError is null && Cases.Count == 2 && Cases.All(c => c.Passed) ? "passed" : "failed",
                StartedUtc = started,
                CompletedUtc = DateTime.UtcNow,
                TotalSeconds = all.Elapsed.TotalSeconds,
                OperatingSystem = RuntimeInformation.OSDescription,
                Architecture = RuntimeInformation.ProcessArchitecture.ToString(),
                Runtime = RuntimeInformation.FrameworkDescription,
                WorkDirectory = work,
                TemplateSource = templateSource,
                TemplateSnapshot = template,
                TemplateSha256 = templateHash,
                RealPublishedTemplate = realTemplate,
                TemplateWasExecuted = false,
                TemplateNote = realTemplate ? "Snapshot of published app; these tests exercise core APIs, separate process SFX execution is covered elsewhere." : "Synthetic MZ marker; size/layout tests only, not an executable.",
                PeakWorkingSetBytes = Math.Max(process.PeakWorkingSet64, _peakWorkingSet),
                PeakManagedBytes = _peakManaged,
                TotalManagedAllocatedBytes = GC.GetTotalAllocatedBytes(precise: true),
                SetupError = setupError,
                Cases
            };
            await File.WriteAllTextAsync(reportPath, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
            Console.WriteLine("Report: " + reportPath);
            Console.WriteLine($"Peak working set: {report.PeakWorkingSetBytes:N0} bytes; peak managed: {report.PeakManagedBytes:N0} bytes.");
        }
        return setupError is null && Cases.Count == 2 && Cases.All(c => c.Passed) ? 0 : 1;
    }

    private static async Task RunCase(string work, string template, string label, long length, PackageCompression compression, bool expectedDetached)
    {
        var result = new LargeCase { Name = label, SourceLength = length, Compression = compression.ToString(), ExpectedDetached = expectedDetached };
        Cases.Add(result);
        var total = Stopwatch.StartNew();
        try
        {
            string source = Path.Combine(work, label + ".bin");
            string output = Path.Combine(work, label + ".exe");
            result.SourcePath = source;
            result.ExecutablePath = output;
            var phase = Stopwatch.StartNew();
            await MakeSparseSource(source, length);
            result.SourceCreationSeconds = phase.Elapsed.TotalSeconds;
            phase.Restart();
            result.SourceSha256 = await Hash(source);
            result.SourceHashSeconds = phase.Elapsed.TotalSeconds;
            Console.WriteLine($"{label}: source SHA-256 complete ({length:N0} bytes). Creating package...");
            phase.Restart();
            var created = await PackageService.CreateAsync(new(source, output, TestPasswords, compression, template, PackageLayout.Auto));
            result.CreateSeconds = phase.Elapsed.TotalSeconds;
            result.IsDetached = created.IsDetached;
            result.DataPath = created.DataPath;
            result.ExecutableLength = new FileInfo(output).Length;
            result.DataLength = created.DataPath is null ? 0 : new FileInfo(created.DataPath).Length;
            Require(created.TotalBytes == length && created.FileCount == 1, "Creation counts mismatch.");
            Require(created.IsDetached == expectedDetached, "Auto layout chose the wrong layout.");
            Require(result.ExecutableLength <= uint.MaxValue, "Executable exceeds Windows loader limit.");
            Require(PackageService.HasPackage(output), "Created executable is not recognized.");
            var inspected = await PackageService.InspectAsync(output);
            Require(inspected.IsDetached == created.IsDetached && inspected.DataPath == created.DataPath, "Inspection did not resolve the expected dataset.");
            if (expectedDetached)
            {
                Require(created.DataPath is not null, "Missing sidecar path.");
                Require(result.DataLength > uint.MaxValue, "Large external payload did not exceed 4 GiB.");
                Require(result.ExecutableLength == new FileInfo(template).Length + 6336, "Detached launcher contains unexpected payload bytes.");
            }
            Console.WriteLine($"{label}: created in {result.CreateSeconds:F2}s; EXE={result.ExecutableLength:N0}; data={result.DataLength:N0}. Extracting...");
            string restoredDirectory = Path.Combine(work, label + "-restored");
            phase.Restart();
            var extracted = await PackageService.ExtractAsync(new(output, restoredDirectory, TestPasswords[1]));
            result.ExtractSeconds = phase.Elapsed.TotalSeconds;
            Require(extracted.TotalBytes == length && extracted.FileCount == 1, "Extracted byte count or file count mismatch.");
            string restored = Path.Combine(restoredDirectory, Path.GetFileName(source));
            result.RestoredPath = restored;
            result.RestoredLength = new FileInfo(restored).Length;
            Require(result.RestoredLength == length, "Large file was truncated.");
            phase.Restart();
            result.RestoredSha256 = await Hash(restored);
            result.RestoredHashSeconds = phase.Elapsed.TotalSeconds;
            Require(result.RestoredSha256 == result.SourceSha256, "SHA-256 mismatch across complete large file.");
            result.Passed = true;
            Console.WriteLine($"PASS {label}: complete length and SHA-256 match; create={result.CreateSeconds:F2}s; extract={result.ExtractSeconds:F2}s.");
        }
        catch (Exception e)
        {
            result.Error = e.ToString();
            Console.Error.WriteLine("FAIL " + label + ": " + e);
        }
        finally { result.TotalSeconds = total.Elapsed.TotalSeconds; }
    }

    private static async Task MakeSparseSource(string path, long length)
    {
        using (var empty = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { }
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "fsutil.exe"))
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true
        };
        start.ArgumentList.Add("sparse");
        start.ArgumentList.Add("setflag");
        start.ArgumentList.Add(path);
        using var command = Process.Start(start) ?? throw new IOException("Cannot launch fsutil.");
        Task<string> stdout = command.StandardOutput.ReadToEndAsync();
        Task<string> stderr = command.StandardError.ReadToEndAsync();
        await command.WaitForExitAsync();
        string output = await stdout + await stderr;
        Require(command.ExitCode == 0, "fsutil sparse setflag failed: " + output);
        using var file = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None, 128 * 1024, FileOptions.RandomAccess);
        file.SetLength(length);
        long[] candidates = [0, 1024 * 1024 - 32, 2 * GiB + 29, 4 * GiB - 32, 4 * GiB + 71, 8 * GiB - 32, 8 * GiB + 31, length - 64];
        foreach (long position in candidates.Distinct())
        {
            if (position < 0 || position > length - 64) continue;
            file.Position = position;
            file.Write(RandomNumberGenerator.GetBytes(64));
        }
        file.Flush(flushToDisk: true);
        Require(new FileInfo(path).Length == length, "Sparse source length mismatch.");
        Require((File.GetAttributes(path) & FileAttributes.SparseFile) != 0, "Source is not marked sparse.");
    }

    private static async Task<string> Hash(string path)
    {
        await using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        return Convert.ToHexString(await SHA256.HashDataAsync(file));
    }

    private static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private static string FindRepository()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "2Password.slnx"))) return directory.FullName;
            directory = directory.Parent;
        }
        throw new DirectoryNotFoundException("Cannot locate repository root.");
    }

    private sealed class LargeCase
    {
        public string Name { get; set; } = "";
        public bool Passed { get; set; }
        public string Compression { get; set; } = "";
        public bool ExpectedDetached { get; set; }
        public bool IsDetached { get; set; }
        public string? SourcePath { get; set; }
        public string? ExecutablePath { get; set; }
        public string? DataPath { get; set; }
        public string? RestoredPath { get; set; }
        public long SourceLength { get; set; }
        public long RestoredLength { get; set; }
        public long ExecutableLength { get; set; }
        public long DataLength { get; set; }
        public string? SourceSha256 { get; set; }
        public string? RestoredSha256 { get; set; }
        public double SourceCreationSeconds { get; set; }
        public double SourceHashSeconds { get; set; }
        public double CreateSeconds { get; set; }
        public double ExtractSeconds { get; set; }
        public double RestoredHashSeconds { get; set; }
        public double TotalSeconds { get; set; }
        public string? Error { get; set; }
    }

    private static class InterlockedExtensions
    {
        internal static void Max(ref long location, long candidate)
        {
            long current;
            do
            {
                current = Volatile.Read(ref location);
                if (candidate <= current) return;
            } while (Interlocked.CompareExchange(ref location, candidate, current) != current);
        }
    }
}
