using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Konscious.Security.Cryptography;
using TwoPassword.Core;

namespace TwoPassword.Tests;

internal static partial class Program
{
    private const string PasswordA = "Raven-Cobalt-2026-test-only!";
    private const string PasswordB = "中文🔑日本語パスワード-اختبار";
    private const string PasswordC = "  exact whitespace stays  ";
    private static readonly string[] Passwords = [PasswordA, PasswordB, PasswordC];
    private static readonly List<TestResult> Results = [];
    private static string _root = "";
    private static string _fixture = "";
    private static string _package = "";
    private static Dictionary<string, string> _snapshot = [];

    public static async Task<int> Main(string[] args)
    {
        Console.OutputEncoding = new UTF8Encoding(false);
        var repository = FindRepository();
        _root = Path.Combine(repository, "artifacts", "test-work",
            DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_root);
        Console.WriteLine("2Password adversarial tests; synthetic data only");
        Console.WriteLine("Workspace: " + _root);

        await RunGuiLaunchOptionsTests();
        if (args.Contains("--gui-arguments-only", StringComparer.Ordinal)) return await SaveResults(repository);
        await RunPar2MetadataTests();
        if (args.Contains("--par2-only", StringComparer.Ordinal)) return await SaveResults(repository);
        await RunWindowsAclTests();
        await Run("Recovery offset samples use bounded memory and exact final-block padding", RecoverySampleBoundaries);
        await Run("Argon2id RFC 9106 section 5.3 known-answer vector", Argon2KnownVector);
        await Run("AES-256-GCM published known-answer vector and bad-tag rejection", AesGcmKnownVector);
        await Run("Create multilingual/deep-path fixture and authenticated package", CreateFixture);
        if (!File.Exists(_package))
        {
            Console.WriteLine("Baseline package unavailable; dependent cases cannot run.");
            return await SaveResults(repository);
        }
        await Run("Inspect header reports three independent password slots", async () =>
        {
            var info = await PackageService.InspectAsync(_package);
            Assert(info.PasswordSlots == 3, "Expected three password slots.");
            Assert(info.Compression == PackageCompression.None, "Unexpected compression.");
            Assert(PackageService.HasPackage(_package), "Valid package not recognized.");
        });
        for (int i = 0; i < Passwords.Length; i++)
        {
            var slot = i;
            await Run($"Password slot {slot + 1} independently restores exact tree and hashes", async () =>
            {
                string output = Path.Combine(_root, "restore-slot-" + slot);
                var result = await PackageService.ExtractAsync(new(_package, output, Passwords[slot]));
                Assert(result.FileCount == _snapshot.Count(kv => kv.Value != "<directory>"),
                    "Reported file count does not match fixture.");
                AssertTreeEqual(_fixture, Path.Combine(output, Path.GetFileName(_fixture)));
                AssertNoStagingRemains();
            });
        }
        await Run("Wrong password never commits plaintext destination", async () =>
            await ExpectExtractFailure(_package, "absolutely-wrong-password"));
        await Run("Empty password never commits plaintext destination", async () =>
            await ExpectExtractFailure(_package, ""));
        await Run("Password whitespace is not silently trimmed", async () =>
            await ExpectExtractFailure(_package, PasswordC.Trim()));
        await Run("Changed Unicode password never unlocks", async () =>
            await ExpectExtractFailure(_package, PasswordB.Replace("中文", "中問", StringComparison.Ordinal)));
        await Run("Existing extraction directory and sentinel remain unchanged", ExistingDestination);
        await Run("Existing output package is never overwritten", ExistingPackage);
        await Run("Output inside source is rejected", OutputInsideSource);
        await Run("A source file cannot overwrite itself", SourceEqualsOutput);
        await Run("Duplicate passwords are rejected", async () =>
            await ExpectCreateFailure(_fixture, [PasswordA, PasswordA]));
        await Run("Zero passwords are rejected", async () =>
            await ExpectCreateFailure(_fixture, []));
        await Run("More than sixteen passwords are rejected", async () =>
            await ExpectCreateFailure(_fixture, Enumerable.Range(0, 17).Select(i => "test-password-" + i).ToArray()));
        await Run("Empty password in a slot is rejected", async () =>
            await ExpectCreateFailure(_fixture, [PasswordA, ""]));
        await Run("Oversized password is rejected before KDF allocation", async () =>
            await ExpectCreateFailure(_fixture, [new string('x', 1_000_001)]));
        await Run("Invalid Unicode password is rejected without replacement", async () =>
            await ExpectCreateFailure(_fixture, ["bad\uD800password"]));
        await Run("Cancellation before creation leaves no output", CancelCreateBefore);
        await Run("Cancellation during creation removes partial output", CancelCreateDuring);
        await Run("Cancellation before extraction leaves no output", CancelExtractBefore);
        await Run("Cancellation during extraction removes staged plaintext", CancelExtractDuring);
        await Run("Brotli compression restores exact Unicode tree and hashes", CompressedRoundTrip);
        await Run("Zstd independent blocks restore exact data with incompressible fallback", ZstdRoundTrip);
        await Run("Sixteen-password boundary accepts the final independent password", SixteenPasswords);
        await Run("One-character passwords are accepted and stay distinct", OneCharacterPasswords);
        await Run("Single-file source preserves original filename and exact bytes", SingleFileRoundTrip);
        await Run("Empty source directory survives a round trip", EmptyDirectoryRoundTrip);
        await Run("Composed and decomposed Unicode passwords remain distinct", UnicodePasswordNormalization);
        await Run("A locked source file aborts without publishing a package", LockedSource);
        await Run("A source change after preflight aborts without publishing a package", SourceMutation);
        await Run("A destination created concurrently is preserved", ConcurrentDestination);
        await Run("NTFS alternate data streams are rejected, never silently lost", AlternateDataStream);
        await Run("Downloaded-file Zone.Identifier bytes survive exactly", ZoneIdentifierRoundTrip);
        await Run("Oversized Zone.Identifier fails explicitly instead of being lost", OversizedZoneIdentifier);
        await Run("Source directory junction is rejected, never followed", SourceJunction);
        await Run("Reparse point in extraction parent is rejected", ExtractionParentJunction);
        await Run("Identical input produces different randomized packages", RandomizedPackages);
        await Run("Oversized sparse SFX stub is rejected before copying gigabytes", OversizedStub);

        var original = await File.ReadAllBytesAsync(_package);
        foreach (var pair in new (string Name, int Offset)[]
        {
            ("middle ciphertext", original.Length / 2),
            ("end of encrypted stream", original.Length - FooterRegion - 40)
        })
        {
            await Run($"Tampering with {pair.Name} fails closed", async () =>
            {
                byte[] damaged = (byte[])original.Clone();
                damaged[pair.Offset] ^= 0x40;
                var path = Path.Combine(_root, "tampered-" + pair.Offset + ".2pw");
                await File.WriteAllBytesAsync(path, damaged);
                await ExpectExtractFailure(path, PasswordA);
            });
        }
        foreach (int keep in new[] { 0, 7, 32, 100, original.Length / 2, original.Length - 1 })
        {
            await Run($"Truncation to {keep} bytes fails closed", async () =>
            {
                var path = Path.Combine(_root, "truncated-" + keep + ".2pw");
                await File.WriteAllBytesAsync(path, original[..keep]);
                await ExpectExtractFailure(path, PasswordA);
            });
        }
        await Run("Bytes appended after footer are rejected", async () =>
        {
            string path = Path.Combine(_root, "appended.2pw");
            await File.WriteAllBytesAsync(path, [.. original, 1, 2, 3, 4]);
            await ExpectExtractFailure(path, PasswordA);
        });
        await RunFormatAdversarialTests();
        return await SaveResults(repository);
    }

    private static Task Argon2KnownVector()
    {
        // RFC 9106 §5.3. This intentionally uses the RFC's small 32 KiB vector,
        // not the application's much stronger production KDF parameters.
        using var argon2 = new Argon2id(Enumerable.Repeat((byte)1, 32).ToArray())
        {
            Salt = Enumerable.Repeat((byte)2, 16).ToArray(),
            KnownSecret = Enumerable.Repeat((byte)3, 8).ToArray(),
            AssociatedData = Enumerable.Repeat((byte)4, 12).ToArray(),
            Iterations = 3, MemorySize = 32, DegreeOfParallelism = 4
        };
        var actual = argon2.GetBytes(32);
        Assert(Convert.ToHexString(actual).Equals(
            "0D640DF58D78766C08C037A34A8B53C9D01EF0452D75B65EB52520E96B01E659",
            StringComparison.Ordinal), "RFC 9106 vector mismatch.");
        return Task.CompletedTask;
    }

    private static Task AesGcmKnownVector()
    {
        // McGrew/Viega GCM test case 14; also checked into Google's BoringSSL tests.
        using var aes = new AesGcm(new byte[32], 16);
        byte[] ciphertext = new byte[16], tag = new byte[16];
        aes.Encrypt(new byte[12], new byte[16], ciphertext, tag);
        Assert(Convert.ToHexString(ciphertext) == "CEA7403D4D606B6E074EC5D3BAF39D18", "AES ciphertext vector mismatch.");
        Assert(Convert.ToHexString(tag) == "D0D1C8A799996BF0265B98B5D48AB919", "AES tag vector mismatch.");
        byte[] restored = new byte[16];
        aes.Decrypt(new byte[12], ciphertext, tag, restored);
        Assert(restored.All(b => b == 0), "AES known vector did not decrypt.");
        tag[0] ^= 1;
        bool rejected = false;
        try { aes.Decrypt(new byte[12], ciphertext, tag, restored); }
        catch (AuthenticationTagMismatchException) { rejected = true; }
        Assert(rejected, "Modified AES-GCM tag was accepted.");
        return Task.CompletedTask;
    }

    private static async Task CreateFixture()
    {
        _fixture = Path.Combine(_root, "sources", "资料_日本語_Archive");
        Directory.CreateDirectory(_fixture);
        WriteText("中文目录/说明_日本語-العربية-🙂.txt", "UTF-8 原文\n日本語\nالعربية\nEnglish\n🙂 café cafe\u0301\n");
        WriteText("accents/café.txt", "NFC name");
        WriteText("accents/cafe\u0301.txt", "NFD name; different exact codepoints");
        WriteText("English/spaces & symbols # (test).txt", "Symbols stay exact");
        WriteText("control-languages/עברית_हिन्दी_한국어.txt", "Hebrew Hindi Korean");
        Directory.CreateDirectory(Path.Combine(_fixture, "日本語", "空目录"));
        Directory.CreateDirectory(Path.Combine(_fixture, "empty-dir"));
        Directory.CreateDirectory(Path.Combine(_fixture, "English"));
        File.WriteAllBytes(Path.Combine(_fixture, "English", "empty.bin"), []);
        byte[] random = new byte[3 * 1024 * 1024 + 37];
        new Random(7331).NextBytes(random);
        File.WriteAllBytes(Path.Combine(_fixture, "random.bin"), random);
        File.WriteAllBytes(Path.Combine(_fixture, "compressible.bin"), Enumerable.Repeat((byte)0x41, 2 * 1024 * 1024).ToArray());
        string deep = _fixture;
        for (int i = 0; i < 36; i++)
            deep = Path.Combine(deep, $"层级_日本語_abcdefghijklmnopqrstuvwxyz_{i:D2}");
        Directory.CreateDirectory(deep);
        File.WriteAllText(Path.Combine(deep, "終点_emoji_🚀.txt"), "Deep path bytes stay exact", new UTF8Encoding(false));
        Assert(Path.Combine(deep, "終点_emoji_🚀.txt").Length > 1000, "Deep path fixture too short.");
        string attributes = Path.Combine(_fixture, "hidden-readonly.txt");
        File.WriteAllText(attributes, "Do not skip hidden/system/read-only files", new UTF8Encoding(false));
        File.SetLastWriteTimeUtc(attributes, new DateTime(2020, 2, 3, 4, 5, 6, DateTimeKind.Utc));
        File.SetAttributes(attributes, FileAttributes.Hidden | FileAttributes.ReadOnly | FileAttributes.Archive);
        _snapshot = Snapshot(_fixture);
        _package = Path.Combine(_root, "baseline.2pw");
        var result = await PackageService.CreateAsync(new(_fixture, _package, Passwords, PackageCompression.None));
        Assert(File.Exists(_package), "Package was not published.");
        Assert(result.TotalBytes == EnumerateFiles(_fixture).Sum(p => new FileInfo(p).Length), "Reported total byte count mismatch.");
    }

    private static void WriteText(string relative, string text)
    {
        string file = Path.Combine(_fixture, relative.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        File.WriteAllText(file, text, new UTF8Encoding(false));
    }

    private static async Task ExistingDestination()
    {
        string output = Path.Combine(_root, "existing-destination");
        Directory.CreateDirectory(output);
        string sentinel = Path.Combine(output, "sentinel.txt");
        File.WriteAllText(sentinel, "never overwrite me");
        await MustFail(() => PackageService.ExtractAsync(new(_package, output, PasswordA)));
        Assert(File.ReadAllText(sentinel) == "never overwrite me", "Existing data was modified.");
        Assert(Directory.EnumerateFileSystemEntries(output).Count() == 1, "Extra output appeared in existing destination.");
    }

    private static async Task ExistingPackage()
    {
        string output = Path.Combine(_root, "existing-package.exe");
        File.WriteAllText(output, "original executable sentinel");
        await MustFail(() => PackageService.CreateAsync(new(_fixture, output, [PasswordA])));
        Assert(File.ReadAllText(output) == "original executable sentinel", "Existing package was overwritten.");
    }

    private static async Task OutputInsideSource()
    {
        string output = Path.Combine(_fixture, "would-recursively-include.2pw");
        await MustFail(() => PackageService.CreateAsync(new(_fixture, output, [PasswordA])));
        Assert(!File.Exists(output), "Output was created inside the source.");
        AssertTreeEqual(_fixture, _fixture);
    }

    private static async Task SourceEqualsOutput()
    {
        string source = Path.Combine(_root, "source-equals-output.txt");
        File.WriteAllText(source, "source sentinel");
        await MustFail(() => PackageService.CreateAsync(new(source, source, [PasswordA])));
        Assert(File.ReadAllText(source) == "source sentinel", "Source was overwritten.");
    }

    private static async Task CancelCreateBefore()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        string output = Path.Combine(_root, "cancel-create-before.2pw");
        await MustCancel(() => PackageService.CreateAsync(new(_fixture, output, [PasswordA]), cancellationToken: cts.Token));
        Assert(!File.Exists(output), "Canceled package was published.");
        AssertNoStagingRemains();
    }

    private static async Task CancelCreateDuring()
    {
        using var cts = new CancellationTokenSource();
        string output = Path.Combine(_root, "cancel-create-during.2pw");
        var progress = new InlineProgress<PackageProgress>(p =>
        {
            if (p.BytesProcessed > 0 && p.BytesProcessed < p.TotalBytes)
                cts.Cancel();
        });
        await MustCancel(() => PackageService.CreateAsync(new(_fixture, output, [PasswordA], PackageCompression.None),
            progress, cts.Token));
        Assert(cts.IsCancellationRequested, "Progress was not cancellable mid-stream.");
        Assert(!File.Exists(output), "Canceled package was published.");
        AssertNoStagingRemains();
    }

    private static async Task CancelExtractBefore()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        string output = Path.Combine(_root, "cancel-extract-before");
        await MustCancel(() => PackageService.ExtractAsync(new(_package, output, PasswordA), cancellationToken: cts.Token));
        Assert(!Directory.Exists(output), "Canceled extraction was published.");
        AssertNoStagingRemains();
    }

    private static async Task CancelExtractDuring()
    {
        using var cts = new CancellationTokenSource();
        string output = Path.Combine(_root, "cancel-extract-during");
        var progress = new InlineProgress<PackageProgress>(p =>
        {
            if (p.BytesProcessed > 0 && p.BytesProcessed < p.TotalBytes)
                cts.Cancel();
        });
        await MustCancel(() => PackageService.ExtractAsync(new(_package, output, PasswordA), progress, cts.Token));
        Assert(cts.IsCancellationRequested, "Extraction progress was not cancellable mid-stream.");
        Assert(!Directory.Exists(output), "Canceled extraction was published.");
        AssertNoStagingRemains();
    }

    private static async Task CompressedRoundTrip()
    {
        string compressed = Path.Combine(_root, "compressed.2pw");
        await PackageService.CreateAsync(new(_fixture, compressed, [PasswordA], PackageCompression.Brotli));
        Assert(new FileInfo(compressed).Length < new FileInfo(_package).Length - 1024 * 1024,
            "Brotli did not reduce highly compressible content.");
        string output = Path.Combine(_root, "restore-compressed");
        await PackageService.ExtractAsync(new(compressed, output, PasswordA));
        AssertTreeEqual(_fixture, Path.Combine(output, Path.GetFileName(_fixture)));
    }

    private static async Task SingleFileRoundTrip()
    {
        string source = Path.Combine(_root, "single-文件_🎵.bin");
        byte[] data = new byte[257];
        new Random(1904).NextBytes(data);
        await File.WriteAllBytesAsync(source, data);
        string package = Path.Combine(_root, "single.2pw");
        await PackageService.CreateAsync(new(source, package, [PasswordA], PackageCompression.None));
        string output = Path.Combine(_root, "single-output");
        var result = await PackageService.ExtractAsync(new(package, output, PasswordA));
        Assert(result.FileCount == 1 && result.TotalBytes == data.Length, "Single-file totals incorrect.");
        Assert((await File.ReadAllBytesAsync(Path.Combine(output, Path.GetFileName(source)))).SequenceEqual(data), "Single-file bytes mismatch.");
        Assert(Directory.GetFileSystemEntries(output).Length == 1, "Unexpected single-file output entries.");
    }

    private static async Task ZstdRoundTrip()
    {
        string package = Path.Combine(_root, "zstd.2pw");
        await PackageService.CreateAsync(new(_fixture, package, [PasswordA], PackageCompression.Zstd));
        string output = Path.Combine(_root, "restore-zstd");
        await PackageService.ExtractAsync(new(package, output, PasswordA));
        AssertTreeEqual(_fixture, Path.Combine(output, Path.GetFileName(_fixture)));
        var decoded = await ReferenceDecode(package);
        Assert(decoded.Codecs.Contains((byte)PackageCompression.Zstd), "Fixture never used Zstd compression.");
        Assert(decoded.Codecs.Contains((byte)PackageCompression.None), "Incompressible blocks did not fall back to raw encoding.");
        AssertReferenceTar(decoded.Tar);
    }

    private static async Task SixteenPasswords()
    {
        string source = Path.Combine(_root, "sixteen-passwords.txt");
        File.WriteAllText(source, "All sixteen passwords wrap the same random content key.");
        string[] passwords = Enumerable.Range(0, 16).Select(i => $"Synthetic-independent-password-{i:D2}!").ToArray();
        string package = Path.Combine(_root, "sixteen.2pw");
        await PackageService.CreateAsync(new(source, package, passwords));
        Assert((await PackageService.InspectAsync(package)).PasswordSlots == 16, "Maximum slot count incorrect.");
        string output = Path.Combine(_root, "sixteen-output");
        await PackageService.ExtractAsync(new(package, output, passwords[^1]));
        Assert(File.ReadAllText(Path.Combine(output, Path.GetFileName(source))) == File.ReadAllText(source),
            "The final password slot did not restore data.");
    }

    private static async Task OneCharacterPasswords()
    {
        string source = Path.Combine(_root, "one-character.txt");
        File.WriteAllText(source, "Password length is the user's choice.");
        string package = Path.Combine(_root, "one-character.2pw");
        await PackageService.CreateAsync(new(source, package, ["x", "密"]));
        foreach (string password in new[] { "x", "密" })
        {
            string output = Path.Combine(_root, "one-character-output-" + (int)password[0]);
            await PackageService.ExtractAsync(new(package, output, password));
            Assert(File.ReadAllText(Path.Combine(output, Path.GetFileName(source))) == File.ReadAllText(source), "A one-character password did not restore data.");
        }
        await ExpectExtractFailure(package, "X");
    }

    private static async Task EmptyDirectoryRoundTrip()
    {
        string source = Path.Combine(_root, "empty-source");
        Directory.CreateDirectory(source);
        string package = Path.Combine(_root, "empty.2pw");
        await PackageService.CreateAsync(new(source, package, [PasswordA]));
        string output = Path.Combine(_root, "empty-output");
        await PackageService.ExtractAsync(new(package, output, PasswordA));
        Assert(Directory.Exists(Path.Combine(output, "empty-source")), "Empty source root was lost.");
    }

    private static async Task UnicodePasswordNormalization()
    {
        string source = Path.Combine(_root, "unicode-password.txt");
        File.WriteAllText(source, "Exact Unicode password encoding");
        string password = "cafe\u0301-is-decomposed";
        string package = Path.Combine(_root, "unicode-password.2pw");
        await PackageService.CreateAsync(new(source, package, [password]));
        await ExpectExtractFailure(package, password.Normalize(NormalizationForm.FormC));
        string output = Path.Combine(_root, "unicode-password-output");
        await PackageService.ExtractAsync(new(package, output, password));
        Assert(File.Exists(Path.Combine(output, Path.GetFileName(source))), "Exact decomposed password did not unlock.");
    }

    private static async Task LockedSource()
    {
        string source = Path.Combine(_root, "locked-source.txt");
        File.WriteAllText(source, "File locked by another process");
        using var locked = new FileStream(source, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        await ExpectCreateFailure(source, [PasswordA]);
    }

    private static async Task SourceMutation()
    {
        string source = Path.Combine(_root, "mutating-source.txt");
        File.WriteAllText(source, "Original data");
        string output = Path.Combine(_root, "mutating-source-output.2pw");
        bool changed = false;
        var progress = new InlineProgress<PackageProgress>(p =>
        {
            if (!changed && p.Stage == TwoPassword.Localization.Text.Get("保护独立密码"))
            {
                File.AppendAllText(source, " changed after preflight");
                changed = true;
            }
        });
        await MustFail(() => PackageService.CreateAsync(new(source, output, [PasswordA]), progress));
        Assert(changed, "Source mutation was not injected after preflight.");
        Assert(!File.Exists(output), "Changed source was published as a successful package.");
        AssertNoStagingRemains();
    }

    private static async Task ConcurrentDestination()
    {
        string output = Path.Combine(_root, "concurrent-destination");
        bool created = false;
        var progress = new InlineProgress<PackageProgress>(p =>
        {
            if (!created && p.BytesProcessed > 0 && p.BytesProcessed < p.TotalBytes)
            {
                Directory.CreateDirectory(output);
                File.WriteAllText(Path.Combine(output, "sentinel.txt"), "Created by another process");
                created = true;
            }
        });
        await MustFail(() => PackageService.ExtractAsync(new(_package, output, PasswordA), progress));
        Assert(created, "Concurrent target creation was not injected.");
        Assert(File.ReadAllText(Path.Combine(output, "sentinel.txt")) == "Created by another process",
            "Concurrent destination data was overwritten.");
        Assert(Directory.GetFileSystemEntries(output).Length == 1, "Extraction merged into a concurrently created directory.");
        AssertNoStagingRemains();
    }

    private static async Task AlternateDataStream()
    {
        string source = Path.Combine(_root, "ads-source.txt");
        File.WriteAllText(source, "main stream");
        try { File.WriteAllText(source + ":private-test-stream", "alternate stream must not be lost"); }
        catch (IOException e) { throw new SkipException("Volume does not support ADS: " + e.Message); }
        await ExpectCreateFailure(source, [PasswordA]);
    }

    private static async Task ZoneIdentifierRoundTrip()
    {
        string source = Path.Combine(_root, "下载_ZoneIdentifier.txt");
        File.WriteAllText(source, "Downloaded file content");
        byte[] zone = Encoding.UTF8.GetBytes("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.invalid/资料_日本語.zip\r\n");
        try { File.WriteAllBytes(source + ":Zone.Identifier", zone); }
        catch (IOException e) { throw new SkipException("Volume does not support ADS: " + e.Message); }
        string package = Path.Combine(_root, "zone-identifier.2pw");
        await PackageService.CreateAsync(new(source, package, [PasswordA]));
        string output = Path.Combine(_root, "zone-identifier-output");
        await PackageService.ExtractAsync(new(package, output, PasswordA));
        string restored = Path.Combine(output, Path.GetFileName(source));
        Assert(File.ReadAllText(restored) == "Downloaded file content", "Zone.Identifier test file bytes changed.");
        Assert(File.ReadAllBytes(restored + ":Zone.Identifier").SequenceEqual(zone), "Zone.Identifier bytes were lost or changed.");
    }

    private static async Task OversizedZoneIdentifier()
    {
        string source = Path.Combine(_root, "oversized-zone.txt");
        File.WriteAllText(source, "Main stream must survive failure");
        try { File.WriteAllBytes(source + ":Zone.Identifier", new byte[65537]); }
        catch (IOException e) { throw new SkipException("Volume does not support ADS: " + e.Message); }
        await ExpectCreateFailure(source, [PasswordA]);
        Assert(File.ReadAllText(source) == "Main stream must survive failure", "Source main stream changed.");
    }

    private static async Task SourceJunction()
    {
        string source = Path.Combine(_root, "junction-source");
        string target = Path.Combine(_root, "junction-target");
        Directory.CreateDirectory(source);
        Directory.CreateDirectory(target);
        File.WriteAllText(Path.Combine(target, "outside.txt"), "Must never follow source junction");
        CreateJunction(Path.Combine(source, "link"), target);
        await ExpectCreateFailure(source, [PasswordA]);
    }

    private static async Task ExtractionParentJunction()
    {
        string target = Path.Combine(_root, "extract-parent-target");
        string link = Path.Combine(_root, "extract-parent-link");
        Directory.CreateDirectory(target);
        CreateJunction(link, target);
        string output = Path.Combine(link, "would-extract");
        await MustFail(() => PackageService.ExtractAsync(new(_package, output, PasswordA)));
        Assert(!Directory.Exists(Path.Combine(target, "would-extract")), "Extraction followed parent junction.");
    }

    private static void CreateJunction(string link, string target)
    {
        var info = new ProcessStartInfo("cmd.exe") { RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
        foreach (string arg in new[] { "/d", "/c", "mklink", "/J", link, target }) info.ArgumentList.Add(arg);
        using var process = Process.Start(info)!;
        string stdout = process.StandardOutput.ReadToEnd();
        string stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();
        if (process.ExitCode != 0) throw new SkipException("Could not create junction fixture: " + stdout + stderr);
    }

    private static async Task RandomizedPackages()
    {
        string source = Path.Combine(_root, "randomization-source.txt");
        File.WriteAllText(source, "same source, same password, distinct random salt/key/nonces");
        string a = Path.Combine(_root, "randomized-a.2pw"), b = Path.Combine(_root, "randomized-b.2pw");
        await PackageService.CreateAsync(new(source, a, [PasswordA]));
        await PackageService.CreateAsync(new(source, b, [PasswordA]));
        Assert(!File.ReadAllBytes(a).SequenceEqual(File.ReadAllBytes(b)), "Encryption was deterministic.");
    }

    private static async Task ExpectCreateFailure(string source, IReadOnlyList<string> passwords)
    {
        string output = Path.Combine(_root, "must-fail-create-" + Guid.NewGuid().ToString("N") + ".2pw");
        await MustFail(() => PackageService.CreateAsync(new(source, output, passwords)));
        Assert(!File.Exists(output), "Invalid source/password set published an output.");
        AssertNoStagingRemains();
    }

    private static async Task ExpectExtractFailure(string package, string password)
    {
        string output = Path.Combine(_root, "must-fail-extract-" + Guid.NewGuid().ToString("N"));
        await MustFail(() => PackageService.ExtractAsync(new(package, output, password)));
        Assert(!Directory.Exists(output) && !File.Exists(output), "Failed extraction published a destination.");
        AssertNoStagingRemains();
    }

    private static async Task MustFail(Func<Task> action)
    {
        Exception? exception = null;
        try { await action(); }
        catch (Exception e) when (e is not OutOfMemoryException && e is not StackOverflowException)
        { exception = e; }
        Assert(exception is not null, "Operation unexpectedly succeeded.");
    }

    private static async Task MustCancel(Func<Task> action)
    {
        bool canceled = false;
        try { await action(); }
        catch (OperationCanceledException) { canceled = true; }
        Assert(canceled, "Operation did not report cancellation.");
    }

    private static IEnumerable<string> EnumerateFiles(string root)
    {
        var pending = new Stack<string>();
        pending.Push(root);
        while (pending.TryPop(out var current))
        {
            foreach (string entry in Directory.EnumerateFileSystemEntries(current))
            {
                var attributes = File.GetAttributes(entry);
                if ((attributes & FileAttributes.ReparsePoint) != 0) continue;
                if ((attributes & FileAttributes.Directory) != 0) pending.Push(entry);
                else yield return entry;
            }
        }
    }

    private static Dictionary<string, string> Snapshot(string root)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        var pending = new Stack<string>();
        pending.Push(root);
        while (pending.TryPop(out var current))
        {
            foreach (string entry in Directory.EnumerateFileSystemEntries(current))
            {
                var attributes = File.GetAttributes(entry);
                string relative = Path.GetRelativePath(root, entry);
                Assert((attributes & FileAttributes.ReparsePoint) == 0, "Snapshot unexpectedly encountered a link.");
                if ((attributes & FileAttributes.Directory) != 0)
                {
                    result.Add(relative, "<directory>");
                    pending.Push(entry);
                }
                else
                {
                    using var stream = File.OpenRead(entry);
                    result.Add(relative, Convert.ToHexString(SHA256.HashData(stream)));
                }
            }
        }
        return result;
    }

    private static void AssertTreeEqual(string source, string restored)
    {
        var expected = source == _fixture ? _snapshot : Snapshot(source);
        var actual = Snapshot(restored);
        Assert(expected.Count == actual.Count, $"Entry count changed: {expected.Count} vs {actual.Count}.");
        foreach (var entry in expected)
        {
            Assert(actual.TryGetValue(entry.Key, out var digest), "Missing exact filename: " + entry.Key);
            Assert(entry.Value == digest, "SHA-256 mismatch: " + entry.Key);
        }
        if (source == _fixture && !string.Equals(source, restored, StringComparison.Ordinal))
        {
            string restoredFile = Path.Combine(restored, "hidden-readonly.txt");
            var attrs = File.GetAttributes(restoredFile);
            Assert((attrs & FileAttributes.Hidden) != 0 && (attrs & FileAttributes.ReadOnly) != 0,
                "Hidden/read-only attributes were not preserved.");
            Assert(Math.Abs((File.GetLastWriteTimeUtc(restoredFile) -
                new DateTime(2020, 2, 3, 4, 5, 6, DateTimeKind.Utc)).TotalSeconds) < 2,
                "Last-write timestamp was not preserved.");
        }
    }

    private static void AssertNoStagingRemains()
    {
        foreach (var path in Directory.EnumerateFileSystemEntries(_root))
        {
            string name = Path.GetFileName(path);
            Assert(!name.Contains(".partial", StringComparison.OrdinalIgnoreCase) &&
                   !name.Contains(".staging", StringComparison.OrdinalIgnoreCase) &&
                   !name.StartsWith(".2password-", StringComparison.OrdinalIgnoreCase) &&
                   !name.StartsWith(".2pw-", StringComparison.OrdinalIgnoreCase),
                   "Temporary data was left behind: " + name);
        }
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    private static async Task Run(string name, Func<Task> action)
    {
        var stopwatch = Stopwatch.StartNew();
        try
        {
            await action();
            Results.Add(new(name, "PASS", stopwatch.ElapsedMilliseconds, null));
            Console.WriteLine($"PASS {name} ({stopwatch.ElapsedMilliseconds} ms)");
        }
        catch (SkipException e)
        {
            Results.Add(new(name, "SKIP", stopwatch.ElapsedMilliseconds, e.Message));
            Console.WriteLine($"SKIP {name}: {e.Message}");
        }
        catch (Exception e)
        {
            Results.Add(new(name, "FAIL", stopwatch.ElapsedMilliseconds, e.ToString()));
            Console.WriteLine($"FAIL {name}: {e.GetType().Name}: {e.Message}");
            Console.WriteLine(e.StackTrace);
        }
    }

    private static string FindRepository()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (Directory.Exists(Path.Combine(directory.FullName, "src")) &&
                Directory.Exists(Path.Combine(directory.FullName, "tests")))
                return directory.FullName;
            directory = directory.Parent;
        }
        throw new InvalidOperationException("Run the test project from the repository.");
    }

    private static async Task<int> SaveResults(string repository)
    {
        int failed = Results.Count(x => x.Status == "FAIL");
        var report = new
        {
            FinishedUtc = DateTime.UtcNow,
            Runtime = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,
            OperatingSystem = System.Runtime.InteropServices.RuntimeInformation.OSDescription,
            Workspace = _root,
            Passed = Results.Count(x => x.Status == "PASS"),
            Failed = failed,
            Skipped = Results.Count(x => x.Status == "SKIP"),
            Tests = Results
        };
        string json = JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(Path.Combine(repository, "artifacts", "test-results.json"), json);
        await File.WriteAllTextAsync(Path.Combine(_root, "test-results.json"), json);
        Console.WriteLine($"Results: {report.Passed} passed, {failed} failed, {report.Skipped} skipped.");
        Console.WriteLine("Report: " + Path.Combine(repository, "artifacts", "test-results.json"));
        return failed == 0 ? 0 : 1;
    }

    private static partial Task RunFormatAdversarialTests();
    private sealed record TestResult(string Name, string Status, long ElapsedMilliseconds, string? Detail);
    private sealed class SkipException(string message) : Exception(message);
    private sealed class InlineProgress<T>(Action<T> report) : IProgress<T>
    {
        public void Report(T value) => report(value);
    }
}
