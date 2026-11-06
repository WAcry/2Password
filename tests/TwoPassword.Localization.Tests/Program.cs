using System.Collections;
using System.Globalization;
using System.Resources;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using TwoPassword.Core;
using TwoPassword.Localization;

namespace TwoPassword.Localization.Tests;

internal static class Program
{
    private static readonly List<Result> Results = [];
    private static int _resourceEntries, _sourceKeys;
    private static Dictionary<string, string> _english = new(StringComparer.Ordinal);
    private static Dictionary<string, string> _chinese = new(StringComparer.Ordinal);

    public static async Task<int> Main()
    {
        string repository = FindRepository();
        string work = Path.Combine(repository, "artifacts", "localization-work", DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(work);
        DateTime started = DateTime.UtcNow;
        CultureInfo originalCulture = CultureInfo.CurrentCulture, originalUiCulture = CultureInfo.CurrentUICulture;
        CultureInfo? originalDefaultCulture = CultureInfo.DefaultThreadCurrentCulture, originalDefaultUiCulture = CultureInfo.DefaultThreadCurrentUICulture;
        try
        {
            Check("English and Chinese catalogs have matching keys and format arguments", ValidateResources);
            Check("Every Core and Recovery Text.Get key has both translations", () => ValidateSourceCoverage(repository));
            Check("English neutral resources", () =>
            {
                Text.UseLanguage("en");
                Require(Text.Language == "en" && Text.Get("密码不能为空。") == "The password cannot be empty.", "English translation is missing.");
            });
            Check("Formatting preserves multilingual filenames exactly", () =>
            {
                Text.UseLanguage("en");
                Require(Text.Get("源文件大小已经变化：{0}", "中文_日本語_cafe\u0301.bin") ==
                    "The source file size has changed: 中文_日本語_cafe\u0301.bin", "A filename changed during formatting.");
            });
            Check("Unknown resource keys fall back to the supplied key", () =>
            {
                Text.UseLanguage("en");
                Require(Text.Get("unregistered literal") == "unregistered literal", "Literal fallback failed.");
                Require(Text.Get("unregistered {0}", 17) == "unregistered 17", "Formatted fallback failed.");
            });
            await CheckAsync("Background work inherits the selected culture", async () =>
            {
                Text.UseLanguage("en");
                Require(await Task.Run(() => Text.Get("验证密码")) == "Verifying password", "Background culture changed.");
            });
            Check("Any Chinese UI culture selects the Chinese satellite", () =>
            {
                CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo("zh-HK");
                Require(Text.Language == "zh-CN" && Text.Get("密码不能为空。") == "密码不能为空。", "zh-HK fallback failed.");
            });
            Check("Other UI cultures select English", () =>
            {
                CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo("fr-FR");
                Require(Text.Language == "en" && Text.Get("密码不能为空。") == "The password cannot be empty.", "English fallback failed.");
            });
            Check("Explicit switch sets thread defaults", () =>
            {
                Text.UseLanguage("zh-CN");
                Require(CultureInfo.CurrentCulture.Name == "zh-CN" && CultureInfo.CurrentUICulture.Name == "zh-CN", "Current cultures were not set.");
                Require(CultureInfo.DefaultThreadCurrentCulture?.Name == "zh-CN" &&
                    CultureInfo.DefaultThreadCurrentUICulture?.Name == "zh-CN", "Thread defaults were not set.");
            });

            string sourcePath = Path.Combine(work, "中文_日本語_cafe\u0301.bin");
            byte[] original = RandomNumberGenerator.GetBytes(1024 * 1024 + 333);
            await File.WriteAllBytesAsync(sourcePath, original);
            string package = Path.Combine(work, "culture.2pw");
            await CheckAsync("Core progress messages use English resources", async () =>
            {
                var stages = new List<string>();
                Text.UseLanguage("en");
                await PackageService.CreateAsync(new(sourcePath, package, ["test-password-1", "中文パスワード-2"]),
                    new InlineProgress(p => stages.Add(p.Stage)));
                Require(stages.Contains("Checking files") && stages.Contains("Protecting independent passwords") &&
                    stages.Contains("Encrypting archive") && stages.Contains("Complete"), "Untranslated Core progress stage.");
            });
            foreach (string language in new[] { "en", "zh-CN" })
            {
                await CheckAsync("Recognized-password failure is typed and localized: " + language, async () =>
                {
                    Text.UseLanguage(language);
                    try
                    {
                        await PackageService.ExtractAsync(new(package, Path.Combine(work, "wrong-" + language), "incorrect-test-password"));
                        throw new InvalidOperationException("An incorrect password was accepted.");
                    }
                    catch (PasswordNotRecognizedException e)
                    {
                        Require(e.Message == Text.Get("密码不正确，或加密包已经损坏。"), "Wrong-password diagnostic is untranslated.");
                    }
                });
                Check("Password syntax validation is localized without key derivation: " + language, () =>
                {
                    Text.UseLanguage(language);
                    (string Password, string Key)[] invalid =
                    [
                        ("", "密码不能为空。"),
                        (new string('x', 1025), "密码最多支持 1024 个 UTF-16 字符。"),
                        ("\uD800", "密码包含无效的 Unicode 字符。")
                    ];
                    foreach (var item in invalid)
                    {
                        try { PackageService.ValidatePassword(item.Password); throw new InvalidOperationException("Invalid syntax was accepted."); }
                        catch (PackageException e) { Require(e.Message == Text.Get(item.Key), "Password syntax diagnostic is untranslated."); }
                    }
                    PackageService.ValidatePassword("  exact 中文 café cafe\u0301  ");
                });
            }
            await CheckAsync("English creation and Chinese extraction preserve exact names and bytes", async () =>
            {
                Text.UseLanguage("zh-CN");
                string restored = Path.Combine(work, "restored");
                await PackageService.ExtractAsync(new(package, restored, "中文パスワード-2"));
                string restoredFile = Path.Combine(restored, Path.GetFileName(sourcePath));
                Require(File.Exists(restoredFile), "The exact Unicode filename was not preserved.");
                Require(SHA256.HashData(await File.ReadAllBytesAsync(restoredFile)).SequenceEqual(SHA256.HashData(original)),
                    "File bytes changed across UI cultures.");
            });
        }
        catch (Exception e)
        {
            Results.Add(new("Setup/runtime", false, e.ToString()));
            Console.Error.WriteLine(e);
        }
        finally
        {
            CultureInfo.DefaultThreadCurrentCulture = originalDefaultCulture;
            CultureInfo.DefaultThreadCurrentUICulture = originalDefaultUiCulture;
            CultureInfo.CurrentCulture = originalCulture;
            CultureInfo.CurrentUICulture = originalUiCulture;
            var report = new
            {
                SchemaVersion = 1,
                Status = Results.All(r => r.Passed) ? "passed" : "failed",
                Passed = Results.Count(r => r.Passed),
                Failed = Results.Count(r => !r.Passed),
                Skipped = 0,
                ResourceEntries = _resourceEntries,
                CheckedSourceKeys = _sourceKeys,
                StartedUtc = started,
                CompletedUtc = DateTime.UtcNow,
                Runtime = RuntimeInformation.FrameworkDescription,
                WorkDirectory = work,
                Tests = Results
            };
            string reportPath = Path.Combine(repository, "artifacts", "localization-results.json");
            await File.WriteAllTextAsync(reportPath, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
            Console.WriteLine($"Localization: {report.Passed} passed, {report.Failed} failed. Report: {reportPath}");
        }
        return Results.All(r => r.Passed) ? 0 : 1;
    }

    private static void ValidateResources()
    {
        var manager = new ResourceManager("TwoPassword.Localization.Resources.Strings", typeof(Text).Assembly);
        _english = ReadSet(manager.GetResourceSet(CultureInfo.GetCultureInfo("en"), true, true)!);
        _chinese = ReadSet(manager.GetResourceSet(CultureInfo.GetCultureInfo("zh-CN"), true, true)!);
        Require(_english.Count > 0, "The shared resource catalog is empty.");
        Require(_english.Keys.ToHashSet(StringComparer.Ordinal).SetEquals(_chinese.Keys), "Language catalog keys differ.");
        foreach (var item in _english)
        {
            string translated = _chinese[item.Key];
            Require(!string.IsNullOrWhiteSpace(item.Value) && !string.IsNullOrWhiteSpace(translated), "Empty translation: " + item.Key);
            int expected = CompositeFormat.Parse(item.Key).MinimumArgumentCount;
            Require(CompositeFormat.Parse(item.Value).MinimumArgumentCount == expected &&
                CompositeFormat.Parse(translated).MinimumArgumentCount == expected, "Format arguments differ: " + item.Key);
        }
        _resourceEntries = _english.Count;
    }

    private static Dictionary<string, string> ReadSet(ResourceSet set)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (DictionaryEntry item in set) result.Add((string)item.Key, (string)item.Value!);
        return result;
    }

    private static void ValidateSourceCoverage(string repository)
    {
        var keys = new HashSet<string>(StringComparer.Ordinal);
        foreach (string project in new[] { "TwoPassword.Core", "TwoPassword.Recovery" })
        foreach (string file in Directory.EnumerateFiles(Path.Combine(repository, "src", project), "*.cs", SearchOption.AllDirectories))
        {
            string normalized = file.Replace('\\', '/');
            if (normalized.Contains("/obj/", StringComparison.OrdinalIgnoreCase) || normalized.Contains("/bin/", StringComparison.OrdinalIgnoreCase)) continue;
            var tree = CSharpSyntaxTree.ParseText(File.ReadAllText(file));
            foreach (var literalText in tree.GetRoot().DescendantNodes().OfType<LiteralExpressionSyntax>())
            {
                if (!literalText.IsKind(SyntaxKind.StringLiteralExpression) ||
                    !literalText.Token.ValueText.Any(c => c is >= '\u3400' and <= '\u9fff')) continue;
                Require(literalText.Ancestors().OfType<InvocationExpressionSyntax>().Any(IsResourceCall),
                    $"Unlocalized user-facing literal in {file}: {literalText.Token.ValueText}");
            }
            foreach (var call in tree.GetRoot().DescendantNodes().OfType<InvocationExpressionSyntax>())
            {
                if (call.Expression is not MemberAccessExpressionSyntax member ||
                    member.Name.Identifier.ValueText != "Get" || !member.Expression.ToString().EndsWith("Text", StringComparison.Ordinal) ||
                    call.ArgumentList.Arguments.FirstOrDefault()?.Expression is not LiteralExpressionSyntax literal ||
                    !literal.IsKind(SyntaxKind.StringLiteralExpression)) continue;
                string key = literal.Token.ValueText;
                keys.Add(key);
                Require(_english.ContainsKey(key) && _chinese.ContainsKey(key), $"Missing shared translation in {file}: {key}");
            }
        }
        _sourceKeys = keys.Count;
        Require(keys.Count > 0, "Source-key coverage did not inspect the expected projects.");
    }

    private static bool IsResourceCall(InvocationExpressionSyntax call) =>
        call.Expression is MemberAccessExpressionSyntax member && member.Name.Identifier.ValueText == "Get" &&
        member.Expression.ToString().EndsWith("Text", StringComparison.Ordinal);

    private static void Check(string name, Action check)
    {
        try { check(); Results.Add(new(name, true, null)); Console.WriteLine("PASS " + name); }
        catch (Exception e) { Results.Add(new(name, false, e.ToString())); Console.Error.WriteLine("FAIL " + name + ": " + e.Message); }
    }
    private static async Task CheckAsync(string name, Func<Task> check)
    {
        try { await check(); Results.Add(new(name, true, null)); Console.WriteLine("PASS " + name); }
        catch (Exception e) { Results.Add(new(name, false, e.ToString())); Console.Error.WriteLine("FAIL " + name + ": " + e.Message); }
    }
    private static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private static string FindRepository()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "2Password.slnx"))) return current.FullName;
            current = current.Parent;
        }
        throw new DirectoryNotFoundException("Repository root not found.");
    }
    private sealed record Result(string Name, bool Passed, string? Error);
    private sealed class InlineProgress(Action<PackageProgress> report) : IProgress<PackageProgress>
    {
        public void Report(PackageProgress value) => report(value);
    }
}
