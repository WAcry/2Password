using TwoPassword.App;

namespace TwoPassword.Tests;

internal static partial class Program
{
    private static async Task RunGuiLaunchOptionsTests()
    {
        await Run("Elevation preserves all creation choices and exact Unicode paths without passwords", () =>
        {
            var selected = new GuiLaunchOptions(
                StubPath: @"C:\发布版\2Password.exe",
                InitialPath: @"C:\资料\source & 日本語",
                Encrypt: true,
                Target: @"D:\输出文件\safe (2).exe",
                Compression: "none",
                Layout: "detached",
                RecoveryPercent: 0);
            var arguments = selected.ElevationArguments("zh-CN", "dark");
            Assert(GuiLaunchOptions.Parse(arguments) == selected, "Elevation lost a selected creation option or changed a path.");
            Assert(!arguments.Any(value => value.StartsWith("--password", StringComparison.Ordinal)), "A password argument entered the elevation handoff.");
            return Task.CompletedTask;
        });

        await Run("Every supported creation option survives the GUI launch round trip", () =>
        {
            foreach (var compression in new[] { "none", "brotli", "zstd" })
            foreach (var layout in new[] { "auto", "embedded", "detached" })
            foreach (var recovery in new[] { 0, 5, 10, 20 })
            {
                var selected = new GuiLaunchOptions(InitialPath: @"C:\source", Encrypt: true,
                    Compression: compression, Layout: layout, RecoveryPercent: recovery);
                Assert(GuiLaunchOptions.Parse(selected.ElevationArguments("en", null)) == selected,
                    $"Lost creation choices: {compression}/{layout}/{recovery}.");
            }
            return Task.CompletedTask;
        });

        await Run("Elevation preserves verify-first for both a package and a self-extractor", () =>
        {
            foreach (string? package in new string?[] { @"D:\Shared files\数据.2pw", null })
            foreach (bool verifyFirst in new[] { false, true })
            {
                var selected = new GuiLaunchOptions(InitialPath: package, Target: @"D:\New output", VerifyFirst: verifyFirst);
                var arguments = selected.ElevationArguments("en", null);
                Assert(GuiLaunchOptions.Parse(arguments) == selected, "The restore destination or verification choice changed.");
                Assert(!arguments.Contains("--extract") && !arguments.Contains("--extract-self"), "GUI handoff accidentally selects CLI extraction.");
            }
            return Task.CompletedTask;
        });

        await Run("GUI option values do not replace the selected file, and absent choices retain defaults", () =>
        {
            var plain = GuiLaunchOptions.Parse(["--language", "en", "--theme", "light", @"C:\original.exe"]);
            Assert(plain == new GuiLaunchOptions(InitialPath: @"C:\original.exe"), "A default was forced or a language/theme value became the input path.");
            var ordered = GuiLaunchOptions.Parse(["--compression", "brotli", "--layout", "embedded", "--recovery-percent", "20",
                "--target", @"D:\output.exe", "--encrypt", @"C:\source with spaces"]);
            Assert(ordered == new GuiLaunchOptions(InitialPath: @"C:\source with spaces", Encrypt: true, Target: @"D:\output.exe",
                Compression: "brotli", Layout: "embedded", RecoveryPercent: 20), "Options before the input path were not consumed correctly.");
            return Task.CompletedTask;
        });

        await Run("Repair elevation retains its GUI route and paths that resemble option values", () =>
        {
            var selected = new GuiLaunchOptions(InitialPath: @"C:\packages\--compression none.exe", Repair: true);
            Assert(GuiLaunchOptions.Parse(selected.ElevationArguments("en", "light")) == selected, "Repair was routed as another operation or the path was split.");
            return Task.CompletedTask;
        });

        await Run("GUI encryption retains every selected file and folder around option values", () =>
        {
            string[] paths = [@"C:\资料\日本語 & one.txt", @"D:\另一个文件夹", @"C:\emoji 🔑\two.exe"];
            var parsed = GuiLaunchOptions.Parse(["--explorer-encrypt", paths[0], paths[1], "--language", "en",
                "--target", @"D:\输出", "--encrypt", paths[2], "--compression", "none"]);
            Assert(parsed.Encrypt && parsed.ExplorerEncrypt, "Explorer selection did not select encryption.");
            Assert(parsed.InitialPath == paths[0] && parsed.InputPaths!.SequenceEqual(paths), "A selected path was lost or split.");
            Assert(parsed.Target == @"D:\输出" && parsed.Compression == "none", "An option became a selected path.");
            return Task.CompletedTask;
        });

        await Run("Elevation retains the full batch but never forwards it back to an Explorer window", () =>
        {
            string[] paths = [@"C:\source.txt", @"C:\中文 🔑 & (folder)", "--path-looking-like-a-switch"];
            var selected = new GuiLaunchOptions(InitialPath: paths[0], Encrypt: true, Target: @"D:\输出",
                Compression: "brotli", Layout: "detached", RecoveryPercent: 10, InputPaths: paths, ExplorerEncrypt: true);
            var arguments = selected.ElevationArguments("zh-CN", "dark");
            var parsed = GuiLaunchOptions.Parse(arguments);
            Assert(parsed.InputPaths!.SequenceEqual(paths), "Elevation lost or reparsed a batch path.");
            Assert(parsed with { InputPaths = null } == selected with { InputPaths = null, ExplorerEncrypt = false },
                "Elevation changed a selected batch option.");
            Assert(!arguments.Contains("--explorer-encrypt"), "An elevation restart could join an unrelated Explorer window.");
            return Task.CompletedTask;
        });

        await RunExplorerSelectionBrokerTests();
    }
}
