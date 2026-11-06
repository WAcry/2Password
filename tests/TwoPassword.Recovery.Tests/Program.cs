using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using TwoPassword.Core;
using TwoPassword.Recovery;

string repo = Directory.GetCurrentDirectory();
while (!File.Exists(Path.Combine(repo, "2Password.slnx")))
    repo = Path.GetDirectoryName(repo) ?? throw new Exception("Run inside the repository.");
string work = Path.Combine(repo, "artifacts", "recovery-tests", Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(work);
var checks = new List<object>();
int passed = 0, failed = 0;
var watch = Stopwatch.StartNew();
const string password = "PAR2-test-only-独立パスワード🔑";
string source = Path.Combine(work, "资料_日本語_📦.bin");
byte[] contents = RandomNumberGenerator.GetBytes(3 * 1024 * 1024 + 137);
await File.WriteAllBytesAsync(source, contents);
string folder = Path.Combine(work, "package");
Directory.CreateDirectory(folder);
string package = Path.Combine(folder, "資料 日本語 🗝️.2pw");
PackageResult? created = null;
byte[]? originalHash = null;

await Check("create stores the recovery set inside the Unicode-named package", async () =>
{
    var (result, error) = await RecoveryService.CreateAsync(new(source, package, [password, "Other-test-only-password-2"], PackageCompression.None), RecoveryService.DefaultPercent);
    Assert(error is null, error?.ToString() ?? "");
    created = result;
    originalHash = await Hash(package);
    Assert(result.RecoveryBytes > 0, "No recovery data was embedded.");
    Assert(Directory.GetFiles(folder).Length == 1, "Creation left extra files next to the package.");
    var info = await PackageService.InspectAsync(package);
    Assert(info.RecoveryBytes == result.RecoveryBytes, "Inspection reports a different recovery size.");
});
await Check("verification recognizes intact ciphertext", async () =>
{
    var result = await RecoveryService.VerifyAsync(package);
    Assert(result.Success && result.DamagedBlocks == 0 && result.RecoveryBlocks > 0, result.Summary);
});
await Check("healthy default extraction performs no recovery pass", async () =>
{
    var progress = new RecoveryEvents();
    string output = Path.Combine(work, "healthy-no-precheck");
    await RecoveryService.ExtractAsync(new(package, output, password), recoveryProgress: progress);
    Assert(progress.Count == 0, "Healthy extraction started recovery.");
    Assert(await SameHash(SHA256.HashData(contents), Path.Combine(output, Path.GetFileName(source))), "Healthy output differs.");
});
await Check("wrong password returns directly without recovery", async () =>
{
    var progress = new RecoveryEvents();
    string output = Path.Combine(work, "wrong-password-no-output");
    bool recognized = false;
    try { await RecoveryService.ExtractAsync(new(package, output, "wrong-test-password"), recoveryProgress: progress); }
    catch (PasswordNotRecognizedException) { recognized = true; }
    Assert(recognized, "Expected the password-specific exception.");
    Assert(progress.Count == 0 && !Directory.Exists(output), "Wrong password invoked recovery or committed plaintext.");
    Assert(await SameHash(originalHash!, package), "Wrong password changed ciphertext.");
});
await Check("explicit precheck checks the payload before authenticated extraction", async () =>
{
    var progress = new RecoveryEvents();
    string output = Path.Combine(work, "explicit-precheck");
    await RecoveryService.ExtractAsync(new(package, output, password), recoveryProgress: progress, verifyFirst: true);
    Assert(progress.Count > 0, "Explicit verification did not report progress.");
    Assert(await SameHash(SHA256.HashData(contents), Path.Combine(output, Path.GetFileName(source))), "Prechecked output differs.");
});
await Check("invalid password syntax never starts recovery even with precheck requested", async () =>
{
    foreach (string invalid in new[] { "", new string('x', 1025), "broken-" + (char)0xD800 })
    {
        var progress = new RecoveryEvents();
        string output = Path.Combine(work, "invalid-password-output");
        await MustFail(() => RecoveryService.ExtractAsync(new(package, output, invalid), recoveryProgress: progress, verifyFirst: true));
        Assert(progress.Count == 0 && !Directory.Exists(output), "Invalid password invoked recovery or published output.");
    }
});
await Check("damaged recovery packets do not block healthy extraction or verification", async () =>
{
    var regions = PackageService.LocateRegions(package);
    long[] offsets = [regions.RecoveryOffset + 70, regions.RecoveryOffset + regions.RecoveryLength / 2];
    foreach (long offset in offsets) Flip(package, offset);
    try
    {
        var progress = new RecoveryEvents();
        string output = Path.Combine(work, "healthy-with-damaged-parity");
        await RecoveryService.ExtractAsync(new(package, output, password), recoveryProgress: progress);
        Assert(progress.Count == 0, "Damaged recovery data blocked healthy authenticated extraction.");
        var result = await RecoveryService.VerifyAsync(package);
        Assert(result.Success, result.Summary);
    }
    finally { foreach (long offset in offsets) Flip(package, offset); }
});
await Check("existing extraction target is preserved without a recovery pass", async () =>
{
    var progress = new RecoveryEvents();
    string output = Path.Combine(work, "existing-target");
    Directory.CreateDirectory(output);
    string sentinel = Path.Combine(output, "keep.txt");
    await File.WriteAllTextAsync(sentinel, "preserve existing content");
    await MustFail(() => RecoveryService.ExtractAsync(new(package, output, password), recoveryProgress: progress, verifyFirst: true));
    Assert(progress.Count == 0 && await File.ReadAllTextAsync(sentinel) == "preserve existing content", "Existing target triggered recovery or changed.");
});
await Check("read-only verification preserves original attributes", async () =>
{
    var original = File.GetAttributes(package);
    File.SetAttributes(package, original | FileAttributes.ReadOnly);
    try
    {
        Assert((await RecoveryService.VerifyAsync(package)).Success, "Verification failed.");
        Assert((File.GetAttributes(package) & FileAttributes.ReadOnly) != 0, "Verification cleared original read-only attribute.");
    }
    finally { File.SetAttributes(package, original); }
});
await Check("ciphertext corruption fails authentication before recovery", async () =>
{
    Flip(package, PackageService.LocateRegions(package).PayloadLength / 2);
    string output = Path.Combine(work, "must-not-exist");
    await MustFail(() => PackageService.ExtractAsync(new(package, output, password)));
    Assert(!Directory.Exists(output), "Unauthenticated plaintext was committed.");
});
await Check("verification counts a single damaged block as repairable", async () =>
{
    var result = await RecoveryService.VerifyAsync(package);
    Assert(result.Repairable && result.DamagedBlocks == 1, result.Summary);
});
await Check("wrong password still skips recovery when payload is damaged", async () =>
{
    var progress = new RecoveryEvents();
    byte[] damagedHash = await Hash(package);
    bool recognized = false;
    try { await RecoveryService.ExtractAsync(new(package, Path.Combine(work, "wrong-corrupt-no-output"), "wrong-test-password"), recoveryProgress: progress); }
    catch (PasswordNotRecognizedException) { recognized = true; }
    Assert(recognized && progress.Count == 0, "Wrong password started an unnecessary repair.");
    Assert(await SameHash(damagedHash, package), "Wrong password modified damaged original.");
});
await Check("detected corruption repairs a copy and extracts without touching the package", async () =>
{
    var progress = new RecoveryEvents();
    byte[] damagedHash = await Hash(package);
    string output = Path.Combine(work, "automatic-retry");
    await RecoveryService.ExtractAsync(new(package, output, password), recoveryProgress: progress);
    Assert(progress.Count > 0, "Corruption did not start recovery.");
    Assert(await SameHash(damagedHash, package), "Extraction modified the package.");
    Assert(await SameHash(SHA256.HashData(contents), Path.Combine(output, Path.GetFileName(source))), "Repaired extraction output differs.");
});
await Check("repair restores the package in place byte for byte", async () =>
{
    var result = await RecoveryService.RepairAsync(package);
    Assert(result is { Success: true, Repaired: true, DamagedBlocks: 1 }, result.Summary);
    Assert(await SameHash(originalHash!, package), "Repaired package differs from the original SHA256.");
    Assert(Directory.GetFiles(folder).Length == 1, "Repair left backup or temporary files.");
    await PackageService.ExtractAsync(new(package, Path.Combine(work, "restored"), password));
});
await Check("destroyed header replicas are rebuilt during extraction", async () =>
{
    byte[] saved = new byte[3 * 2048];
    using (var f = new FileStream(package, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
    {
        f.ReadExactly(saved);
        f.Position = 0;
        f.Write(new byte[saved.Length]);
    }
    try
    {
        await MustFail(() => PackageService.InspectAsync(package));
        Assert(RecoveryService.HasRecovery(package), "Recovery data was not found behind a damaged header.");
        string output = Path.Combine(work, "header-rebuilt");
        await RecoveryService.ExtractAsync(new(package, output, password));
        Assert(await SameHash(SHA256.HashData(contents), Path.Combine(output, Path.GetFileName(source))), "Output differs.");
    }
    finally
    {
        using var f = new FileStream(package, FileMode.Open, FileAccess.Write, FileShare.None);
        f.Write(saved);
    }
    Assert(await SameHash(originalHash!, package), "Header restore failed.");
});
await Check("insufficient redundancy is reported without changing ciphertext", async () =>
{
    using (var f = new FileStream(package, FileMode.Open, FileAccess.Write, FileShare.None))
    {
        f.Position = 256 * 1024;
        f.Write(new byte[1536 * 1024]);
    }
    byte[] damagedHash = await Hash(package);
    var verification = await RecoveryService.VerifyAsync(package);
    Assert(verification.ExitCode == 2, "Expected insufficient recovery blocks.");
    var repair = await RecoveryService.RepairAsync(package);
    Assert(repair.ExitCode == 2, "Repair unexpectedly succeeded beyond redundancy.");
    Assert(await SameHash(damagedHash, package), "Failed recovery modified original.");
    await MustFail(() => RecoveryService.ExtractAsync(new(package, Path.Combine(work, "beyond-redundancy"), password)));
    Assert(!Directory.Exists(Path.Combine(work, "beyond-redundancy")), "Unrepairable package published output.");
});
await Check("cancellation does not leave private recovery workspaces", async () =>
{
    using var cancelled = new CancellationTokenSource();
    cancelled.Cancel();
    await MustFail(() => RecoveryService.VerifyAsync(package, cancellationToken: cancelled.Token));
    Assert(!Directory.EnumerateDirectories(folder, ".2pw-recovery-*").Any(), "Recovery workspace leaked.");
});
await Check("package without recovery data reports it plainly", async () =>
{
    string plain = Path.Combine(work, "plain.2pw");
    var (result, _) = await RecoveryService.CreateAsync(new(source, plain, [password], PackageCompression.None), 0);
    Assert(result.RecoveryBytes == 0 && !RecoveryService.HasRecovery(plain), "Unexpected recovery data.");
    Assert((await RecoveryService.VerifyAsync(plain)).ExitCode == 4, "Missing recovery data was not reported.");
});
byte[] stub = new byte[1024]; stub[0] = (byte)'M'; stub[1] = (byte)'Z';
string template = Path.Combine(work, "template.exe");
await File.WriteAllBytesAsync(template, stub);
await Check("single EXE carries its recovery data and survives payload damage", async () =>
{
    string dir = Path.Combine(work, "单文件_日本語");
    Directory.CreateDirectory(dir);
    string exe = Path.Combine(dir, "独立包.exe");
    var (pack, error) = await RecoveryService.CreateAsync(new(source, exe, [password], PackageCompression.None, template, PackageLayout.Embedded), 10);
    Assert(error is null && !pack.IsDetached && pack.RecoveryBytes > 0, "Embedded package has no recovery data.");
    Assert(Directory.GetFiles(dir).Length == 1, "Embedded layout produced more than one file.");
    var regions = PackageService.LocateRegions(exe);
    Assert(regions.PayloadOffset == stub.Length && regions.DataPath == exe, "Embedded regions are wrong.");
    byte[] before = await Hash(exe);
    Flip(exe, regions.PayloadOffset + regions.PayloadLength - 100);
    string output = Path.Combine(dir, "output");
    await RecoveryService.ExtractAsync(new(exe, output, password));
    Assert(await SameHash(SHA256.HashData(contents), Path.Combine(output, Path.GetFileName(source))), "Output differs.");
    Assert((await RecoveryService.RepairAsync(exe)).Repaired && await SameHash(before, exe), "In-place repair of the EXE failed.");
});
await Check("detached pair keeps recovery data in the .2pw file", async () =>
{
    string dir = Path.Combine(work, "分离_日本語");
    Directory.CreateDirectory(dir);
    string launcher = Path.Combine(dir, "独立包.exe");
    var (pack, error) = await RecoveryService.CreateAsync(new(source, launcher, [password], PackageCompression.None, template, PackageLayout.Detached), 10);
    Assert(error is null && pack.IsDetached && pack.DataPath is not null && pack.RecoveryBytes > 0, "Detached pair has no recovery data.");
    Assert(Directory.GetFiles(dir).Length == 2, "Detached layout should produce exactly two files.");
    var regions = PackageService.LocateRegions(launcher);
    Assert(regions.IsDetached && regions.DataPath == pack.DataPath && regions.PayloadOffset == 0, "Launcher did not resolve the data file.");
    byte[] before = await Hash(pack.DataPath!);
    Flip(pack.DataPath!, regions.PayloadLength / 3);
    string output = Path.Combine(dir, "output");
    var result = await RecoveryService.ExtractAsync(new(launcher, output, password));
    Assert(result.IsDetached && result.DataPath == pack.DataPath, "Repaired extraction lost the data path.");
    Assert(await SameHash(SHA256.HashData(contents), Path.Combine(output, Path.GetFileName(source))), "Output differs.");
    Assert((await RecoveryService.RepairAsync(launcher)).Repaired && await SameHash(before, pack.DataPath!), "Repair through the launcher failed.");
});
await Check("truncated .2pw is found without its footer, extracted, and repaired", async () =>
{
    string dir = Path.Combine(work, "截断_日本語");
    Directory.CreateDirectory(dir);
    string launcher = Path.Combine(dir, "截断.exe");
    var (pack, _) = await RecoveryService.CreateAsync(new(source, launcher, [password], PackageCompression.None, template, PackageLayout.Detached), RecoveryService.DefaultPercent);
    var original = PackageService.LocateRegions(launcher);
    byte[] payload = await RangeHash(pack.DataPath!, 0, original.PayloadLength);
    using (var f = new FileStream(pack.DataPath!, FileMode.Open, FileAccess.Write, FileShare.None)) f.SetLength(f.Length - 192 - 1000);
    byte[] truncated = await Hash(pack.DataPath!);
    await MustFail(() => Task.FromResult(PackageService.LocateRegions(launcher)));
    Assert(RecoveryService.HasRecovery(launcher), "Recovery data was not found behind a truncated footer.");
    string output = Path.Combine(dir, "output");
    var progress = new RecoveryEvents();
    var extracted = await RecoveryService.ExtractAsync(new(launcher, output, password), recoveryProgress: progress);
    Assert(progress.Count > 0 && extracted.IsDetached && extracted.DataPath == pack.DataPath, "Extraction did not go through recovery.");
    Assert(await SameHash(SHA256.HashData(contents), Path.Combine(output, Path.GetFileName(source))), "Output differs.");
    Assert(await SameHash(truncated, pack.DataPath!), "Extraction modified the data file.");
    var verified = await RecoveryService.VerifyAsync(launcher);
    Assert(verified is { ExitCode: 1, DamagedBlocks: 0 }, verified.Summary);
    var repaired = await RecoveryService.RepairAsync(launcher);
    Assert(repaired is { Success: true, Repaired: true, DamagedBlocks: 0 }, repaired.Summary);
    var regions = PackageService.LocateRegions(launcher);
    Assert(regions.PayloadOffset == 0 && regions.PayloadLength == original.PayloadLength && regions.RecoveryLength is > 0 and < 1_000_000_000, "Rewritten footer is wrong.");
    Assert(await SameHash(payload, pack.DataPath!, 0, regions.PayloadLength), "Repair changed the payload.");
    Assert((await RecoveryService.VerifyAsync(launcher)).Success, "Repaired package does not verify.");
    await PackageService.ExtractAsync(new(launcher, Path.Combine(dir, "after-repair"), password));
});
await Check("EXE with a lost footer, a lost header replica and payload damage is repaired", async () =>
{
    string dir = Path.Combine(work, "尾部_日本語");
    Directory.CreateDirectory(dir);
    // A larger stub that contains the header magic, as the real stub does, followed by bytes that are not a valid record.
    byte[] decoy = RandomNumberGenerator.GetBytes(8192);
    decoy[0] = (byte)'M'; decoy[1] = (byte)'Z';
    "2PWHDR03"u8.CopyTo(decoy.AsSpan(700));
    "2PWHDR03"u8.CopyTo(decoy.AsSpan(5000));
    string decoyTemplate = Path.Combine(dir, "decoy.exe");
    await File.WriteAllBytesAsync(decoyTemplate, decoy);
    string exe = Path.Combine(dir, "尾部.exe");
    await RecoveryService.CreateAsync(new(source, exe, [password], PackageCompression.None, decoyTemplate, PackageLayout.Embedded), 10);
    var original = PackageService.LocateRegions(exe);
    byte[] payload = await RangeHash(exe, original.PayloadOffset, original.PayloadLength);
    long length = new FileInfo(exe).Length;
    Zero(exe, length - 4096, 4096);
    Zero(exe, original.PayloadOffset, 2048);
    Flip(exe, original.PayloadOffset + original.PayloadLength / 2);
    byte[] damaged = await Hash(exe);
    Assert(RecoveryService.HasRecovery(exe), "Recovery data was not found behind a zeroed footer.");
    string output = Path.Combine(dir, "output");
    await RecoveryService.ExtractAsync(new(exe, output, password));
    Assert(await SameHash(SHA256.HashData(contents), Path.Combine(output, Path.GetFileName(source))), "Output differs.");
    Assert(await SameHash(damaged, exe), "Extraction modified the EXE.");
    var verified = await RecoveryService.VerifyAsync(exe);
    Assert(verified is { ExitCode: 1, DamagedBlocks: > 1 }, verified.Summary);
    var repaired = await RecoveryService.RepairAsync(exe);
    Assert(repaired is { Success: true, Repaired: true }, repaired.Summary);
    var regions = PackageService.LocateRegions(exe);
    Assert(regions.PayloadOffset == original.PayloadOffset && regions.PayloadLength == original.PayloadLength, "Rewritten footer points at the wrong payload.");
    Assert(await SameHash(payload, exe, regions.PayloadOffset, regions.PayloadLength), "Repair did not restore the payload.");
    Assert(await SameHash(SHA256.HashData(decoy), exe, 0, decoy.Length), "Repair changed the stub.");
    Assert((await RecoveryService.VerifyAsync(exe)).Success, "Repaired EXE does not verify.");
    await PackageService.ExtractAsync(new(exe, Path.Combine(dir, "after-repair"), password));
});
await Check("a file cut inside its payload is reported, not guessed", async () =>
{
    string cut = Path.Combine(work, "cut.2pw");
    await RecoveryService.CreateAsync(new(source, cut, [password], PackageCompression.None), RecoveryService.DefaultPercent);
    using (var f = new FileStream(cut, FileMode.Open, FileAccess.Write, FileShare.None)) f.SetLength(f.Length / 2);
    Assert(!RecoveryService.HasRecovery(cut), "Recovery data was invented for a payload with no PAR2 data left.");
    await MustFail(() => RecoveryService.VerifyAsync(cut));
    await MustFail(() => RecoveryService.RepairAsync(cut));
});
await Check("complete corresponding PAR2 source is exportable offline", async () =>
{
    string export = Path.Combine(work, "par2-source.tar.xz");
    await RecoveryService.ExportSourceAsync(export);
    Assert(Convert.ToHexString(await Hash(export)).Equals("035584144D3AC3B08FB5D7D4B844F60CF97404B6469F6AED7D9B9430A25BEF0E", StringComparison.Ordinal), "Source checksum differs.");
    await MustFail(() => RecoveryService.ExportSourceAsync(export));
});
await Check("successful and failed operations clean all private workspaces", () =>
{
    Assert(!Directory.EnumerateDirectories(work, ".2pw-recovery-*", SearchOption.AllDirectories).Any(), "Temporary recovery workspace remains.");
    Assert(!Directory.EnumerateFiles(work, ".2password-*", SearchOption.AllDirectories).Any(), "Temporary package file remains.");
    return Task.CompletedTask;
});

var report = new { Passed = passed, Failed = failed, Seconds = Math.Round(watch.Elapsed.TotalSeconds, 3), Checks = checks };
await File.WriteAllTextAsync(Path.Combine(repo, "artifacts", "recovery-results.json"), JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
Console.WriteLine($"Recovery: {passed} passed, {failed} failed ({watch.Elapsed.TotalSeconds:F1}s)");
return failed == 0 ? 0 : 1;

async Task Check(string name, Func<Task> action)
{
    try { await action(); passed++; checks.Add(new { Name = name, Passed = true }); Console.WriteLine("PASS " + name); }
    catch (Exception e) { failed++; checks.Add(new { Name = name, Passed = false, Error = e.Message }); Console.WriteLine("FAIL " + name + " :: " + e); }
}
static void Assert(bool condition, string message) { if (!condition) throw new Exception(message); }
static async Task MustFail(Func<Task> action) { try { await action(); } catch { return; } throw new Exception("Expected operation to fail."); }
static async Task<byte[]> Hash(string path) { await using var input = File.OpenRead(path); return await SHA256.HashDataAsync(input); }
static async Task<bool> SameHash(byte[] expected, string path, long offset = 0, long length = -1)
{
    byte[] actual = length < 0 ? await Hash(path) : await RangeHash(path, offset, length);
    return expected.AsSpan().SequenceEqual(actual);
}
static async Task<byte[]> RangeHash(string path, long offset, long length)
{
    byte[] bytes = new byte[length];
    await using var input = File.OpenRead(path);
    input.Position = offset;
    await input.ReadExactlyAsync(bytes);
    return SHA256.HashData(bytes);
}
static void Zero(string path, long offset, int count)
{
    using var stream = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None);
    stream.Position = offset;
    stream.Write(new byte[count]);
}
static void Flip(string path, long offset)
{
    using var stream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
    stream.Position = offset; int value = stream.ReadByte();
    if (value < 0) throw new Exception("Invalid corruption offset.");
    stream.Position = offset; stream.WriteByte((byte)(value ^ 0x40));
}

sealed class RecoveryEvents : IProgress<RecoveryProgress>
{
    private readonly System.Collections.Concurrent.ConcurrentQueue<RecoveryProgress> items = new();
    public int Count => items.Count;
    public void Report(RecoveryProgress value) => items.Enqueue(value);
}
