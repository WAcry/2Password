using System.Collections;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using System.Xml.Linq;
using TwoPassword.App;
using TwoPassword.Core;

namespace TwoPassword.Gui.Tests;

/// <summary>
/// Exercises real WPF windows and their asynchronous creation flow on a Dispatcher.
/// Reflection reaches private event handlers; package creation/extraction is not mocked.
/// No Explorer registration, saved preferences, or user files are changed.
/// </summary>
internal static class Program
{
    private const string Password = "GUI-test-only-中文-🔑";
    private const BindingFlags Members = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;
    private static readonly List<CheckResult> Results = [];
    private static readonly List<Window> Windows = [];
    private static string _repository = "", _work = "", _stub = "";
    private static int _exitCode;

    [STAThread]
    private static int Main(string[] args)
    {
        Console.OutputEncoding = new UTF8Encoding(false);
        _repository = FindRepository();
        _work = Path.Combine(_repository, "artifacts", "multiselect-work", DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_work);
        int stubIndex = Array.IndexOf(args, "--stub");
        if (stubIndex >= 0) _stub = Path.GetFullPath(args[stubIndex + 1]);
        else
        {
            _stub = Path.Combine(_work, "synthetic-template.exe");
            byte[] template = new byte[512];
            "MZ"u8.CopyTo(template);
            File.WriteAllBytes(_stub, template);
        }
        Console.WriteLine("WPF multiselect integration checks; synthetic fixtures only");
        Console.WriteLine("Workspace: " + _work);
        Console.WriteLine(stubIndex >= 0 ? "Template: " + _stub : "Synthetic MZ template: generated packages are checked through PackageService, not executed.");
        var application = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
        application.Resources.MergedDictionaries.Add(new ResourceDictionary { Source = new Uri("/2Password;component/Theme/Light.xaml", UriKind.Relative) });
        application.Resources.MergedDictionaries.Add(new ResourceDictionary { Source = new Uri("/2Password;component/Theme/Controls.xaml", UriKind.Relative) });
        application.Dispatcher.InvokeAsync(async () =>
        {
            try
            {
                await Run("English and Chinese UI catalogs cover new resources with matching placeholders", ValidateUiResources);
                await Run("Multiple startup inputs, Explorer append and duplicate selection retain all roots", SelectionAndAppend);
                await Run("A missing earlier input does not block appending or removing selections", MissingSelectionRemainsEditable);
                await Run("Native shell drop accepts a mixed file/folder selection", ShellDropSelection);
                await Run("Mixed selections create independent packages with exact restored contents", MixedRoundTrip);
                await Run("Detached batches list and restore both members of each package", DetachedRoundTrip);
                await Run("A later source failure preserves and lists completed packages", PartialFailure);
                await Run("Cancel during a later item preserves completed packages and cleans partial output", CancelLaterItem);
                if (args.Contains("--screenshots", StringComparer.Ordinal)) await CaptureLayouts();
            }
            catch (Exception error) { Results.Add(new("Test harness", false, error.ToString())); }
            finally
            {
                foreach (var window in Windows.ToArray())
                {
                    try { if (Field<bool>(window, "_busy")) Field<CancellationTokenSource>(window, "_operation").Cancel(); }
                    catch { }
                    try { window.Close(); } catch { }
                }
                _exitCode = Results.All(result => result.Passed) ? 0 : 1;
                var report = new { Status = _exitCode == 0 ? "passed" : "failed", Passed = Results.Count(r => r.Passed), Failed = Results.Count(r => !r.Passed), Workspace = _work, RealStub = stubIndex >= 0, Checks = Results };
                File.WriteAllText(Path.Combine(_work, "results.json"), JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
                File.WriteAllText(Path.Combine(_repository, "artifacts", "multiselect-results.json"), JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
                application.Shutdown(_exitCode);
            }
        });
        application.Run();
        return _exitCode;
    }

    private static async Task SelectionAndAppend()
    {
        var fixture = Fixture("selection");
        var window = await WindowFor([fixture.File, fixture.Folder], fixture.Output);
        try
        {
            Require(Sources(window).SequenceEqual(new[] { fixture.File, fixture.Folder }), "Startup lost or reordered selected roots.");
            Require(Field<string>(window, "_outputPath") == fixture.Output, "Multi-input target was not interpreted as a directory.");
            string extra = Path.Combine(fixture.Root, "another.txt");
            File.WriteAllText(extra, "another selected item");
            Require((bool)Call(window, "TryAddExplorerPaths", (object)new[] { fixture.File, extra })!, "Idle encryption page refused Explorer inputs.");
            Require(Sources(window).SequenceEqual(new[] { fixture.File, fixture.Folder, extra }), "Explorer append lost inputs or duplicated an existing input.");
            Require(Control<TextBlock>(window, "SourceName").Text.Contains('3'), "Selection summary does not show all selected roots.");
            var rows = Control<Panel>(window, "SourceItems");
            Require(rows.Children.Count == 3, "Selection list does not expose every selected root.");
            var remove = Descendants<Button>(rows).Last();
            remove.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            Require(Sources(window).SequenceEqual(new[] { fixture.File, fixture.Folder }), "Removing one selection removed the wrong root.");
        }
        finally { window.Close(); }
    }

    private static async Task ShellDropSelection()
    {
        var fixture = Fixture("drop");
        var window = await WindowFor([], null);
        try
        {
            Call(window, "ShellDrop", (object)new[] { fixture.File, fixture.Folder });
            Require(Sources(window).SequenceEqual(new[] { fixture.File, fixture.Folder }), "Native shell drop did not retain a mixed selection.");
            Require(Field<object>(window, "_screen").ToString() == "Encrypt", "Multiselect drop did not open the encryption page.");
        }
        finally { window.Close(); }
    }

    private static async Task MissingSelectionRemainsEditable()
    {
        var fixture = Fixture("missing-selection");
        var window = await WindowFor([fixture.File, fixture.Folder], fixture.Output);
        try
        {
            File.Move(fixture.File, fixture.File + ".moved");
            string added = Path.Combine(fixture.Root, "new selection.txt");
            File.WriteAllText(added, "a newly selected existing file");
            Require((bool)Call(window, "TryAddExplorerPaths", (object)new[] { added })!, "Missing earlier input caused an incoming Explorer selection to be rejected.");
            Require(Sources(window).SequenceEqual(new[] { fixture.File, fixture.Folder, added }), "Append lost an earlier or incoming selection.");
            Call(window, "RemoveSource", fixture.Folder);
            Require(Sources(window).SequenceEqual(new[] { fixture.File, added }), "A missing earlier input prevented removing a different selection.");
            Require(Control<Panel>(window, "SourceItems").Children.Count == 2, "Selection list no longer represents the retained inputs.");
        }
        finally { window.Close(); }
    }

    private static async Task CaptureLayouts()
    {
        var fixture = Fixture("screenshots");
        string secondFile = Path.Combine(fixture.Root, "合同 final.pdf");
        string secondFolder = Path.Combine(fixture.Root, "照片 2026");
        File.WriteAllText(secondFile, "synthetic screenshot fixture only");
        Directory.CreateDirectory(secondFolder);
        var window = await WindowFor([fixture.File, fixture.Folder, secondFile, secondFolder], fixture.Output, "zh-CN");
        try
        {
            foreach (int width in new[] { 680, 520 })
            {
                window.Width = width;
                window.Height = 620;
                window.UpdateLayout();
                await Task.Delay(250);
                var image = new RenderTargetBitmap((int)window.ActualWidth, (int)window.ActualHeight, 96, 96, PixelFormats.Pbgra32);
                image.Render(window);
                var encoder = new PngBitmapEncoder();
                encoder.Frames.Add(BitmapFrame.Create(image));
                string output = Path.Combine(_work, "multiselect-zh-" + width + ".png");
                using var file = File.Create(output);
                encoder.Save(file);
                Console.WriteLine("Screenshot: " + output);
            }
            Call(window, "UseTarget", Path.GetPathRoot(fixture.Output)!);
            Require(Control<TextBlock>(window, "OutputPathText").Inlines.Count > 0, "Drive-root output has no rendered path.");
        }
        finally { window.Close(); }
    }

    private static async Task MixedRoundTrip()
    {
        var fixture = Fixture("roundtrip");
        var window = await WindowFor([fixture.File, fixture.Folder], fixture.Output, "zh-CN");
        try
        {
            SetPassword(window);
            await Encrypt(window);
            var packages = Completed(window);
            Require(packages.Count == 2, "GUI did not report exactly two independent packages.");
            Require(Field<object>(window, "_screen").ToString() == "Done", "Successful batch did not reach completion.");
            Require(Control<Panel>(window, "DoneFiles").Children.Count == 2, "Completion page omitted generated packages.");
            await RestoreAndCheck(packages[0], fixture.File, Path.Combine(fixture.Root, "restored-file"));
            await RestoreAndCheck(packages[1], fixture.Folder, Path.Combine(fixture.Root, "restored-folder"));
            Require(PasswordBoxes(window).All(box => box.Password.Length == 0), "Completed encryption retained password fields.");
        }
        finally { window.Close(); }
    }

    private static async Task DetachedRoundTrip()
    {
        var fixture = Fixture("detached");
        var window = await WindowFor([fixture.File, fixture.Folder], fixture.Output);
        try
        {
            Control<RadioButton>(window, "LayoutDetached").IsChecked = true;
            SetPassword(window);
            await Encrypt(window);
            var packages = Completed(window);
            Require(packages.Count == 2 && packages.All(p => p.IsDetached && File.Exists(p.DataPath)), "Detached batch has missing launcher/data pairs.");
            Require(Control<Panel>(window, "DoneFiles").Children.Count == 4, "Completion omitted detached pair members.");
            await RestoreAndCheck(packages[0], fixture.File, Path.Combine(fixture.Root, "restored-file"));
            await RestoreAndCheck(packages[1], fixture.Folder, Path.Combine(fixture.Root, "restored-folder"));
        }
        finally { window.Close(); }
    }

    private static async Task PartialFailure()
    {
        var fixture = Fixture("failure");
        string locked = Path.Combine(fixture.Root, "locked.bin");
        File.WriteAllText(locked, "held exclusively during creation");
        var window = await WindowFor([fixture.File, locked], fixture.Output);
        try
        {
            SetPassword(window);
            using (var handle = new FileStream(locked, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) await Encrypt(window);
            var packages = Completed(window);
            Require(packages.Count == 1 && File.Exists(packages[0].OutputPath), "Later failure lost the completed package or omitted it from results.");
            Require(Control<TextBlock>(window, "DoneWarning").Visibility == Visibility.Visible, "Partial failure is not reported on completion page.");
            Require(Directory.GetFiles(fixture.Output).Length == 1, "Failed item left an output or partial temporary file.");
            await RestoreAndCheck(packages[0], fixture.File, Path.Combine(fixture.Root, "restored-first"));
            string firstHash = Hash(packages[0].OutputPath);
            Control<Button>(window, "DoneSecondary").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            Require(Sources(window).SequenceEqual(new[] { locked }), "Resume did not retain only the unfinished input.");
            SetPassword(window);
            await Encrypt(window);
            Require(Directory.GetFiles(fixture.Output).Length == 2 && Hash(packages[0].OutputPath) == firstHash,
                "Resume recreated or changed an already completed package.");
            await RestoreAndCheck(Completed(window).Single(), locked, Path.Combine(fixture.Root, "restored-second"));
        }
        finally { window.Close(); }
    }

    private static async Task CancelLaterItem()
    {
        var fixture = Fixture("cancel");
        string large = Path.Combine(fixture.Root, "later.bin");
        using (var file = File.Create(large)) file.SetLength(64L * 1024 * 1024);
        var window = await WindowFor([fixture.File, large], fixture.Output);
        try
        {
            SetPassword(window);
            bool cancelled = false;
            var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(5) };
            timer.Tick += (_, _) =>
            {
                if (!Equals(Control<TextBlock>(window, "WorkBatch").ToolTip, large)) return;
                if (!Directory.EnumerateFiles(fixture.Output, "*.exe").Any()) return;
                if (!Directory.EnumerateFiles(fixture.Output, "*.partial").Any()) return;
                cancelled = true;
                timer.Stop();
                Call(window, "Cancel_Click", window, new RoutedEventArgs());
            };
            timer.Start();
            try
            {
                var encryption = Encrypt(window);
                Require(!(bool)Call(window, "TryAddExplorerPaths", (object)new[] { fixture.Folder })!, "Busy encryption accepted and mutated the active selection.");
                await encryption;
            }
            finally { timer.Stop(); }
            Require(cancelled, "The cancellation trigger did not run during the later item.");
            var packages = Completed(window);
            Require(packages.Count == 1 && File.Exists(packages[0].OutputPath), "Cancellation lost the completed first package.");
            Require(Control<TextBlock>(window, "DoneWarning").Visibility == Visibility.Visible, "Partial cancellation is not reported.");
            Require(Directory.GetFiles(fixture.Output).Length == 1, "Cancellation retained partial files for the later item.");
            await RestoreAndCheck(packages[0], fixture.File, Path.Combine(fixture.Root, "restored-first"));
        }
        finally { window.Close(); }
    }

    private static Task ValidateUiResources()
    {
        string uiDirectory = Path.Combine(_repository, "src", "TwoPassword.App", "Resources");
        var english = XDocument.Load(Path.Combine(uiDirectory, "Ui.resx")).Root!.Elements("data").ToDictionary(e => e.Attribute("name")!.Value, e => e.Element("value")!.Value);
        var chinese = XDocument.Load(Path.Combine(uiDirectory, "Ui.zh-CN.resx")).Root!.Elements("data").ToDictionary(e => e.Attribute("name")!.Value, e => e.Element("value")!.Value);
        Require(english.Keys.ToHashSet().SetEquals(chinese.Keys), "UI language catalogs have different keys.");
        foreach (string key in english.Keys)
        {
            string[] Slots(string value) => Regex.Matches(value, @"\{(\d+)(?:[^{}]*)\}").Select(m => m.Groups[1].Value).Order().ToArray();
            Require(Slots(english[key]).SequenceEqual(Slots(chinese[key])), "UI format arguments differ: " + key);
        }
        var mapping = (IEnumerable)typeof(MainWindow).Assembly.GetType("TwoPassword.App.UiXamlKeys")!.GetField("Values", BindingFlags.Static | BindingFlags.NonPublic)!.GetValue(null)!;
        foreach (var pair in mapping)
        {
            string key = (string)pair.GetType().GetProperty("Value")!.GetValue(pair)!;
            Require(english.ContainsKey(key), "XAML resource has no UI catalog entry: " + key);
        }
        return Task.CompletedTask;
    }

    private static async Task<MainWindow> WindowFor(string[] paths, string? target, string language = "en")
    {
        Type uiText = typeof(MainWindow).Assembly.GetType("TwoPassword.App.UiText")!;
        uiText.GetMethod("UseLanguage", BindingFlags.Static | BindingFlags.NonPublic)!.Invoke(null, [language]);
        List<string> args = ["--stub", _stub, "--recovery-percent", "0", "--layout", "embedded", "--compression", "none"];
        foreach (string path in paths) args.AddRange(["--encrypt", path]);
        if (target is not null) args.AddRange(["--target", target]);
        Type launchType = typeof(MainWindow).Assembly.GetType("TwoPassword.App.GuiLaunchOptions")!;
        object launch = launchType.GetMethod("Parse", BindingFlags.Static | BindingFlags.NonPublic)!.Invoke(null, [args])!;
        var window = new MainWindow(stubOverride: _stub, initialPath: paths.FirstOrDefault(), initialEncrypt: paths.Length > 0, initialTarget: target)
        {
            ShowActivated = false, ShowInTaskbar = false, WindowStartupLocation = WindowStartupLocation.Manual,
            Left = -30000, Top = -30000,
        };
        Windows.Add(window);
        window.Closed += (_, _) => Windows.Remove(window);
        Call(window, "ApplyLaunchOptions", launch);
        window.Show();
        await Dispatcher.Yield(DispatcherPriority.ContextIdle);
        return window;
    }

    private static void SetPassword(MainWindow window)
    {
        foreach (var box in PasswordBoxes(window)) box.Password = Password;
    }

    private static IEnumerable<PasswordBox> PasswordBoxes(MainWindow window) => Descendants<PasswordBox>(Control<Panel>(window, "PasswordRows"));
    private static async Task Encrypt(MainWindow window) => await ((Task)Call(window, "EncryptAsync")!).WaitAsync(TimeSpan.FromMinutes(2));
    private static IReadOnlyList<PackageResult> Completed(MainWindow window) => ((IEnumerable)Field<object>(window, "_donePackages")).Cast<PackageResult>().ToArray();
    private static string[] Sources(MainWindow window) => ((IEnumerable)Field<object>(window, "_sourcePaths")).Cast<string>().ToArray();

    private static async Task RestoreAndCheck(PackageResult package, string source, string destination)
    {
        await PackageService.ExtractAsync(new(package.OutputPath, destination, Password));
        string restored = Path.Combine(destination, Path.GetFileName(source));
        if (File.Exists(source))
        {
            Require(Directory.GetFileSystemEntries(destination).Length == 1, "A single-file package contains another selected root.");
            Require(File.Exists(restored) && Hash(source) == Hash(restored), "Restored file name or SHA256 differs.");
        }
        else
        {
            Require(Directory.GetFileSystemEntries(destination).Length == 1 && Directory.Exists(restored), "Folder package contains another selected root or lost its root folder.");
            var expected = Directory.EnumerateFileSystemEntries(source, "*", SearchOption.AllDirectories).Select(p => Path.GetRelativePath(source, p)).Order().ToArray();
            var actual = Directory.EnumerateFileSystemEntries(restored, "*", SearchOption.AllDirectories).Select(p => Path.GetRelativePath(restored, p)).Order().ToArray();
            Require(expected.SequenceEqual(actual), "Restored folder structure differs, including empty folders.");
            foreach (string file in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories))
                Require(Hash(file) == Hash(Path.Combine(restored, Path.GetRelativePath(source, file))), "Restored folder content differs.");
        }
    }

    private static (string Root, string File, string Folder, string Output) Fixture(string name)
    {
        string root = Path.Combine(_work, name);
        string folder = Path.Combine(root, "资料_日本語_📦");
        string output = Path.Combine(root, "output");
        Directory.CreateDirectory(Path.Combine(folder, "空文件夹"));
        Directory.CreateDirectory(output);
        string file = Path.Combine(root, "单独 文件-🙂.txt");
        File.WriteAllText(file, "independent file\n中文 content");
        File.WriteAllText(Path.Combine(folder, "inside.txt"), "folder content stays inside folder package");
        return (root, file, folder, output);
    }

    private static string Hash(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static T Field<T>(object instance, string name) => (T)(instance.GetType().GetField(name, Members)?.GetValue(instance)
        ?? throw new MissingFieldException(instance.GetType().Name, name));
    private static T Control<T>(MainWindow window, string name) where T : FrameworkElement => (T)(window.FindName(name) ?? throw new InvalidOperationException("Missing control: " + name));
    private static object? Call(object instance, string name, params object?[] args)
    {
        try { return instance.GetType().GetMethod(name, Members)!.Invoke(instance, args); }
        catch (TargetInvocationException error) { throw error.InnerException ?? error; }
    }
    private static IEnumerable<T> Descendants<T>(DependencyObject root) where T : DependencyObject
    {
        for (int i = 0; i < VisualTreeHelper.GetChildrenCount(root); i++)
        {
            var child = VisualTreeHelper.GetChild(root, i);
            if (child is T match) yield return match;
            foreach (var descendant in Descendants<T>(child)) yield return descendant;
        }
    }
    private static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private static async Task Run(string name, Func<Task> action)
    {
        try { await action(); Results.Add(new(name, true, null)); Console.WriteLine("PASS " + name); }
        catch (Exception error) { Results.Add(new(name, false, error.ToString())); Console.Error.WriteLine("FAIL " + name + ": " + error.Message); }
    }
    private static string FindRepository()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
            if (File.Exists(Path.Combine(directory.FullName, "2Password.slnx"))) return directory.FullName;
        throw new DirectoryNotFoundException("Repository root not found.");
    }
    private sealed record CheckResult(string Name, bool Passed, string? Error);
}
