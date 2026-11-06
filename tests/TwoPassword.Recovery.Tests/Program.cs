using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
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
string package = Path.Combine(work, "資料 日本語 🗝️.2pw");
RecoveryResult? created = null;
byte[]? originalHash = null;

await Check("create encrypted Unicode fixture", async () =>
{
    await PackageService.CreateAsync(new(source, package, [password, "Other-test-only-password-2"], PackageCompression.None));
    originalHash = await Hash(package);
});
await Check("PAR2 native create uses Chinese/Japanese/emoji names", async () =>
{
    created = await RecoveryService.CreateAsync(package, 10);
    Assert(created.Success && created.Files.Count == 5, "Expected index plus four recovery volumes.");
});
await Check("native verification recognizes intact ciphertext", async () =>
{
    var result = await RecoveryService.VerifyAsync(created!.RecoveryFile);
    Assert(result.Success, result.Summary);
});
await Check("healthy default extraction performs no PAR2 pass", async () =>
{
    var progress = new RecoveryEvents();
    string output = Path.Combine(work, "healthy-no-precheck");
    await RecoveryService.ExtractAsync(new(package, output, password), recoveryProgress: progress);
    Assert(progress.Count == 0, "Healthy extraction started PAR2.");
    Assert(await SameHash(SHA256.HashData(contents), Path.Combine(output, Path.GetFileName(source))), "Healthy output differs.");
});
await Check("wrong password returns directly without PAR2", async () =>
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
await Check("explicit precheck runs PAR2 before authenticated extraction", async () =>
{
    var progress = new RecoveryEvents();
    string output = Path.Combine(work, "explicit-precheck");
    await RecoveryService.ExtractAsync(new(package, output, password), recoveryProgress: progress, verifyFirst: true);
    Assert(progress.Count > 0, "Explicit verification did not report a PAR2 pass.");
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
await Check("direct .2pw precheck finds recovery volumes when index is missing", async () =>
{
    string moved = created!.RecoveryFile + ".test-held";
    File.Move(created.RecoveryFile, moved);
    try
    {
        Assert(RecoveryService.HasRecoveryFiles(package), "Matching raw-container recovery volumes were not found.");
        Assert(await RecoveryService.PrepareForExtractionAsync(package) is { Success: true, Repaired: false }, "Missing index fallback failed.");
    }
    finally { File.Move(moved, created.RecoveryFile); }
});
await Check("healthy default extraction ignores damaged optional recovery records", async () =>
{
    foreach (string file in created!.Files) Flip(file, 0);
    try
    {
        var progress = new RecoveryEvents();
        string output = Path.Combine(work, "healthy-with-damaged-parity");
        await RecoveryService.ExtractAsync(new(package, output, password), recoveryProgress: progress);
        Assert(progress.Count == 0, "Optional damaged parity blocked healthy authenticated extraction.");
        Assert(await SameHash(SHA256.HashData(contents), Path.Combine(output, Path.GetFileName(source))), "Output differs.");
    }
    finally { foreach (string file in created.Files) Flip(file, 0); }
});
await Check("existing extraction target is preserved without a PAR2 pass", async () =>
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
        Assert((await RecoveryService.VerifyAsync(created!.RecoveryFile)).Success, "Verification failed.");
        Assert((File.GetAttributes(package) & FileAttributes.ReadOnly) != 0, "Verification cleared original read-only attribute.");
    }
    finally { File.SetAttributes(package, original); }
});
await Check("existing recovery records are never overwritten", async () =>
{
    byte[] before = await Hash(created!.RecoveryFile);
    await MustFail(() => RecoveryService.CreateAsync(package, 10));
    Assert(await SameHash(before, created.RecoveryFile), "Existing PAR2 was modified.");
});
await Check("ciphertext corruption fails authentication before recovery", async () =>
{
    Flip(package, new FileInfo(package).Length / 2);
    string output = Path.Combine(work, "must-not-exist");
    await MustFail(() => PackageService.ExtractAsync(new(package, output, password)));
    Assert(!Directory.Exists(output), "Unauthenticated plaintext was committed.");
});
await Check("PAR2 classifies a single damaged block as repairable", async () =>
{
    var result = await RecoveryService.VerifyAsync(created!.RecoveryFile);
    Assert(result.Repairable, result.Summary);
});
await Check("wrong password still skips PAR2 when payload is damaged", async () =>
{
    var progress = new RecoveryEvents();
    byte[] damagedHash = await Hash(package);
    bool recognized = false;
    try { await RecoveryService.ExtractAsync(new(package, Path.Combine(work, "wrong-corrupt-no-output"), "wrong-test-password"), recoveryProgress: progress); }
    catch (PasswordNotRecognizedException) { recognized = true; }
    Assert(recognized && progress.Count == 0, "Wrong password started an unnecessary repair.");
    Assert(await SameHash(damagedHash, package), "Wrong password modified damaged original.");
});
await Check("detected corruption triggers automatic repair and authenticated retry", async () =>
{
    var progress = new RecoveryEvents();
    string output = Path.Combine(work, "automatic-retry");
    await RecoveryService.ExtractAsync(new(package, output, password), recoveryProgress: progress);
    Assert(progress.Count > 0, "Corruption did not start recovery.");
    Assert(await SameHash(originalHash!, package), "Repaired ciphertext differs from original SHA256.");
    Assert(await SameHash(SHA256.HashData(contents), Path.Combine(output, Path.GetFileName(source))), "Authenticated retry output differs.");
    Assert(Directory.EnumerateFiles(work, ".2pw-before-repair-*.bak").Any(), "Damaged original backup is missing.");
});
await Check("repaired archive still passes GCM and plaintext SHA256", async () =>
{
    string output = Path.Combine(work, "restored");
    await PackageService.ExtractAsync(new(package, output, password));
    Assert(await SameHash(SHA256.HashData(contents), Path.Combine(output, Path.GetFileName(source))), "Restored content differs.");
});
await Check("corrupted PAR2 index can be replaced by intact recovery volume metadata", async () =>
{
    Flip(created!.RecoveryFile, 0);
    try
    {
        var result = await RecoveryService.VerifyAsync(created.RecoveryFile);
        Assert(result.Success, result.Summary);
    }
    finally { Flip(created.RecoveryFile, 0); }
});
await Check("insufficient redundancy is reported without changing ciphertext", async () =>
{
    using (var f = new FileStream(package, FileMode.Open, FileAccess.Write, FileShare.None))
    {
        f.Position = 256 * 1024;
        f.Write(new byte[1536 * 1024]);
    }
    byte[] damagedHash = await Hash(package);
    var verification = await RecoveryService.VerifyAsync(created!.RecoveryFile);
    Assert(verification.ExitCode == 2, "Expected insufficient recovery blocks.");
    var repair = await RecoveryService.RepairAsync(created.RecoveryFile);
    Assert(repair.ExitCode == 2, "Repair unexpectedly succeeded beyond redundancy.");
    Assert(await SameHash(damagedHash, package), "Failed recovery modified original.");
});
await Check("cancellation does not leave private recovery workspaces", async () =>
{
    using var cancelled = new CancellationTokenSource();
    cancelled.Cancel();
    await MustFail(() => RecoveryService.VerifyAsync(created!.RecoveryFile, cancellationToken: cancelled.Token));
    Assert(!Directory.EnumerateDirectories(work, ".2pw-recovery-*").Any(), "Recovery workspace leaked.");
});
await Check("malicious PAR2 traversal descriptor is refused", async () =>
{
    string evilDir = Path.Combine(work, "malicious");
    Directory.CreateDirectory(evilDir);
    string evil = Path.Combine(evilDir, Path.GetFileName(created!.RecoveryFile));
    byte[] data = await File.ReadAllBytesAsync(created.RecoveryFile);
    int offset = 0;
    bool modified = false;
    while (offset + 64 <= data.Length)
    {
        int size = checked((int)BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(offset + 8, 8)));
        if (Encoding.ASCII.GetString(data, offset + 48, 16).TrimEnd('\0') == "PAR 2.0\0FileDesc")
        {
            data[offset + 120] = (byte)'.';
            data[offset + 121] = (byte)'.';
            data[offset + 122] = (byte)'/';
            MD5.HashData(data.AsSpan(offset + 32, size - 32)).CopyTo(data, offset + 16);
            modified = true;
        }
        offset += size;
    }
    Assert(modified, "No descriptor found in test fixture.");
    await File.WriteAllBytesAsync(evil, data);
    await MustFail(() => RecoveryService.RepairAsync(evil));
    Assert(!Directory.EnumerateDirectories(evilDir, ".2pw-recovery-*").Any(), "Malicious input reached native tool.");
});
await Check("detached pair recovery reconstructs a completely missing small launcher", async () =>
{
    string detachedDir = Path.Combine(work, "分离_日本語");
    Directory.CreateDirectory(detachedDir);
    string template = Path.Combine(detachedDir, "template.exe");
    byte[] stub = new byte[1024]; stub[0] = (byte)'M'; stub[1] = (byte)'Z';
    await File.WriteAllBytesAsync(template, stub);
    string launcher = Path.Combine(detachedDir, "独立包.exe");
    var pack = await PackageService.CreateAsync(new(source, launcher, [password], PackageCompression.None, template, PackageLayout.Detached));
    Assert(pack.IsDetached && pack.DataPath is not null, "Detached pair was not created.");
    byte[] before = await Hash(launcher);
    var recovery = await RecoveryService.CreateAsync(launcher, 10);
    File.Delete(launcher);
    var verification = await RecoveryService.VerifyAsync(recovery.RecoveryFile);
    Assert(verification.Repairable, verification.Summary);
    var repair = await RecoveryService.RepairAsync(recovery.RecoveryFile);
    Assert(repair.Success, repair.Summary);
    Assert(await SameHash(before, launcher), "Launcher reconstruction differs.");
    await PackageService.ExtractAsync(new(launcher, Path.Combine(detachedDir, "output"), password));
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
static async Task<bool> SameHash(byte[] expected, string path) { byte[] actual = await Hash(path); return expected.AsSpan().SequenceEqual(actual); }
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
