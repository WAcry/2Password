using System.IO;
using System.Text;
using System.Text.Json;
using System.Windows;
using TwoPassword.Core;
using TwoPassword.Recovery;
using static TwoPassword.App.UiText;

namespace TwoPassword.App;

public partial class App : Application
{
    protected override async void OnStartup(StartupEventArgs e)
    {
        UiText.Initialize(e.Args);
        base.OnStartup(e);
        if (CommandLine.IsCommand(e.Args))
        {
            var code = await CommandLine.RunAsync(e.Args);
            Shutdown(code);
            return;
        }
        string? stubOverride = null;
        for (var i = 0; i + 1 < e.Args.Length; i++)
            if (e.Args[i] == "--stub") stubOverride = e.Args[i + 1];

        var processPath = Environment.ProcessPath;
        var embedded = processPath is not null && PackageService.HasPackage(processPath);
        if (!embedded && processPath is not null)
        {
            try { embedded = RecoveryService.HasRecoveryFiles(processPath); }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException) { }
        }
        Theme.Initialize(e.Args);
        string? external = null, target = null;
        var encrypt = false;
        for (var index = 0; index < e.Args.Length; index++)
        {
            if (e.Args[index] is "--stub" or "--language" or "--theme") { index++; continue; }
            if (e.Args[index] == "--target" && index + 1 < e.Args.Length) { target = e.Args[++index]; continue; }
            if (e.Args[index] == "--encrypt" && index + 1 < e.Args.Length) { encrypt = true; external ??= e.Args[++index]; continue; }
            if (!e.Args[index].StartsWith("--", StringComparison.Ordinal)) external ??= e.Args[index];
        }
        MainWindow = new MainWindow(embedded ? processPath : null, stubOverride, embedded ? null : external, encrypt && !embedded, target);
        ShutdownMode = ShutdownMode.OnMainWindowClose;
        MainWindow.Show();
    }
}

internal static class CommandLine
{
    private static readonly HashSet<string> Commands =
        ["--inspect", "--inspect-self", "--extract", "--extract-self", "--create", "--verify-recovery", "--repair-recovery", "--export-recovery-source", "--explorer-menu", "--help", "-h"];
    internal static bool IsCommand(string[] args) => args.Any(Commands.Contains);

    internal static async Task<int> RunAsync(string[] args)
    {
        string? reportPath = null;
        FileStream? reportStream = null;
        PackageResult? createdPackage = null;
        try
        {
            var options = Parse(args);
            if (options.TryGetValue("--language", out var language))
            {
                if (language is not ("en" or "zh-CN")) throw new ArgumentException(L("Language must be en or zh-CN."));
                UiText.UseLanguage(language);
            }
            options.TryGetValue("--report", out reportPath);
            if (reportPath is not null)
            {
                reportPath = Path.GetFullPath(reportPath);
                if (File.Exists(reportPath) || Directory.Exists(reportPath))
                    throw new ArgumentException(L("Report path already exists; select a new filename."));
                var parent = Path.GetDirectoryName(reportPath);
                if (string.IsNullOrEmpty(parent) || !Directory.Exists(parent))
                    throw new ArgumentException(L("The report's parent directory must already exist."));
                if (options.TryGetValue("--output", out var outputPath) && outputPath is not null &&
                    string.Equals(reportPath, Path.GetFullPath(outputPath), StringComparison.OrdinalIgnoreCase))
                    throw new ArgumentException(L("The report and output paths must be different."));
                if (options.TryGetValue("--export-recovery-source", out var sourceOutput) && sourceOutput is not null &&
                    string.Equals(reportPath, Path.GetFullPath(sourceOutput), StringComparison.OrdinalIgnoreCase))
                    throw new ArgumentException(L("The report and source-export paths must be different."));
                if (options.TryGetValue("--create", out var source) && source is not null && Directory.Exists(source))
                {
                    var sourceRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(source)) + Path.DirectorySeparatorChar;
                    if (reportPath.StartsWith(sourceRoot, StringComparison.OrdinalIgnoreCase))
                        throw new ArgumentException(L("The report must be outside the source folder."));
                }
                reportStream = new FileStream(reportPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.Asynchronous);
            }
            if (options.ContainsKey("--help") || options.ContainsKey("-h"))
            {
                var help = L("CliHelp", typeof(App).Assembly.GetName().Version?.ToString(3) ?? "1.0.0");
                if (reportStream is not null) await ReportAsync(reportStream, new { success = true, operation = "help", text = help });
                else WriteOutput(help);
                return 0;
            }
            using var cancellation = new CancellationTokenSource();
            Console.CancelKeyPress += (_, eventArgs) => { eventArgs.Cancel = true; cancellation.Cancel(); };
            var commandCount = options.Keys.Count(Commands.Contains);
            if (commandCount != 1) throw new ArgumentException(L("Choose exactly one operation."));
            object result;
            string operation;
            RecoveryResult? recovery = null;
            if (options.ContainsKey("--inspect") || options.ContainsKey("--inspect-self"))
            {
                operation = "inspect";
                result = await PackageService.InspectAsync(options.ContainsKey("--inspect-self")
                    ? ProcessPath() : Required(options, "--inspect"), cancellation.Token);
            }
            else if (options.ContainsKey("--verify-recovery") || options.ContainsKey("--repair-recovery"))
            {
                var repairing = options.ContainsKey("--repair-recovery");
                operation = repairing ? "repair-recovery" : "verify-recovery";
                var recoveryResult = repairing
                    ? await RecoveryService.RepairAsync(Required(options, "--repair-recovery"), cancellationToken: cancellation.Token)
                    : await RecoveryService.VerifyAsync(Required(options, "--verify-recovery"), cancellationToken: cancellation.Token);
                await ReportAsync(reportStream, new { success = recoveryResult.Success, operation, result = recoveryResult });
                return recoveryResult.ExitCode;
            }
            else if (options.TryGetValue("--explorer-menu", out var menuState))
            {
                operation = "explorer-menu";
                var executable = ProcessPath();
                if (menuState == "on") ExplorerMenu.Enable(executable);
                else if (menuState == "off") ExplorerMenu.Disable(executable);
                else throw new ArgumentException(L("Unsupported argument: {0}", "--explorer-menu " + menuState));
                result = new { Enabled = ExplorerMenu.IsEnabled(executable), Executable = executable };
            }
            else if (options.ContainsKey("--export-recovery-source"))
            {
                operation = "export-recovery-source";
                result = new { OutputPath = await RecoveryService.ExportSourceAsync(Required(options, "--export-recovery-source"), cancellation.Token) };
            }
            else if (options.ContainsKey("--extract") || options.ContainsKey("--extract-self"))
            {
                operation = "extract";
                if (!options.ContainsKey("--password-stdin")) throw new ArgumentException(L("Use --password-stdin; passwords are never accepted as command-line arguments."));
                var packagePath = options.ContainsKey("--extract-self") ? ProcessPath() : Required(options, "--extract");
                var outputDirectory = Path.GetFullPath(Required(options, "--output"));
                if (File.Exists(outputDirectory) || Directory.Exists(outputDirectory))
                    throw new ArgumentException(L("The extraction output already exists. Select a new directory."));
                var password = "";
                try
                {
                    password = await ReadInputAsync();
                    if (password.EndsWith("\r\n", StringComparison.Ordinal)) password = password[..^2];
                    else if (password.EndsWith('\n')) password = password[..^1];
                    result = await RecoveryService.ExtractAsync(new ExtractOptions(packagePath,
                        outputDirectory, password), cancellationToken: cancellation.Token, verifyFirst: options.ContainsKey("--verify-first"));
                }
                finally { password = ""; }
            }
            else
            {
                operation = "create";
                if (!options.ContainsKey("--passwords-stdin")) throw new ArgumentException(L("Use --passwords-stdin with a JSON array; passwords are never accepted as command-line arguments."));
                var compressionText = options.GetValueOrDefault("--compression", "zstd");
                var compression = compressionText switch { "none" => PackageCompression.None, "brotli" => PackageCompression.Brotli, "zstd" => PackageCompression.Zstd, _ => throw new ArgumentException(L("Compression must be zstd, brotli or none.")) };
                var layout = options.GetValueOrDefault("--layout", "auto") switch
                {
                    "auto" => PackageLayout.Auto, "embedded" => PackageLayout.Embedded, "detached" => PackageLayout.Detached,
                    _ => throw new ArgumentException(L("Layout must be auto, embedded or detached."))
                };
                if (!int.TryParse(options.GetValueOrDefault("--recovery-percent", "10"), out var redundancyPercent) || redundancyPercent is not (0 or 5 or 10 or 20))
                    throw new ArgumentException(L("Recovery percentage must be 0, 5, 10 or 20."));
                string json = "";
                string[]? passwords = null;
                try
                {
                    json = await ReadInputAsync();
                    passwords = JsonSerializer.Deserialize<string[]>(json) ?? throw new ArgumentException(L("Standard input must contain a JSON password array."));
                    var stub = options.GetValueOrDefault("--stub") ?? StandaloneStub();
                    var output = Required(options, "--output");
                    if (!output.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) throw new ArgumentException(L("Self-extracting output must end in .exe."));
                    createdPackage = await PackageService.CreateAsync(new CreateOptions(Required(options, "--create"),
                        output, passwords, compression, stub, layout), cancellationToken: cancellation.Token);
                    result = createdPackage;
                }
                finally
                {
                    if (passwords is not null) Array.Clear(passwords);
                    json = "";
                }
                if (redundancyPercent > 0)
                    recovery = await RecoveryService.CreateAsync(createdPackage.OutputPath, redundancyPercent, cancellationToken: cancellation.Token);
            }
            await ReportAsync(reportStream, new { success = true, operation, result, recovery });
            return 0;
        }
        catch (Exception error)
        {
            var exitCode = error is ArgumentException ? 2 : 1;
            try
            {
                await ReportAsync(reportStream, new { success = false, error = UiText.DescribeException(error), errorType = error.GetType().Name,
                    packageSucceeded = createdPackage is not null, package = createdPackage,
                    note = createdPackage is null ? null : L("The encrypted package was successfully created and kept; the recovery stage or result report did not complete.") });
            }
            catch { WriteOutput(L("Unable to write command result.") + "\n"); }
            return exitCode;
        }
        finally { if (reportStream is not null) await reportStream.DisposeAsync(); }
    }

    internal static string StandaloneStub()
    {
#pragma warning disable IL3000
        if (!string.IsNullOrEmpty(typeof(App).Assembly.Location))
            throw new InvalidOperationException(L("请使用发布版 2Password.exe 创建独立加密包。开发运行可通过 --stub 指定已发布的独立 EXE。"));
#pragma warning restore IL3000
        return ProcessPath();
    }

    private static string ProcessPath() => Environment.ProcessPath ?? throw new InvalidOperationException(L("Cannot locate executable."));

    private static Dictionary<string, string?> Parse(string[] args)
    {
        HashSet<string> flags = ["--inspect-self", "--extract-self", "--password-stdin", "--passwords-stdin", "--verify-first", "--help", "-h"];
        HashSet<string> values = ["--inspect", "--extract", "--create", "--output", "--report", "--compression", "--layout", "--recovery-percent", "--stub", "--verify-recovery", "--repair-recovery", "--export-recovery-source", "--explorer-menu", "--language", "--theme"];
        var result = new Dictionary<string, string?>(StringComparer.Ordinal);
        for (var i = 0; i < args.Length; i++)
        {
            var key = args[i];
            if (flags.Contains(key)) { if (!result.TryAdd(key, null)) throw new ArgumentException(L("Duplicate argument: {0}", key)); }
            else if (values.Contains(key))
            {
                if (++i >= args.Length) throw new ArgumentException(L("Missing value for {0}", key));
                if (!result.TryAdd(key, args[i])) throw new ArgumentException(L("Duplicate argument: {0}", key));
            }
            else throw new ArgumentException(L("Unsupported argument: {0}", key));
        }
        return result;
    }

    private static string Required(Dictionary<string, string?> options, string key) =>
        options.TryGetValue(key, out var value) && !string.IsNullOrEmpty(value) ? value : throw new ArgumentException(L("Missing {0}", key));

    private static async Task<string> ReadInputAsync()
    {
        using var input = new StreamReader(Console.OpenStandardInput(), new UTF8Encoding(false, true), detectEncodingFromByteOrderMarks: false);
        var builder = new StringBuilder();
        var buffer = new char[4096];
        int read;
        while ((read = await input.ReadAsync(buffer)) > 0)
        {
            builder.Append(buffer, 0, read);
            if (builder.Length > 131072) throw new ArgumentException(L("Password input exceeds the supported limit."));
        }
        return builder.ToString();
    }

    private static async Task ReportAsync(FileStream? stream, object value)
    {
        var json = JsonSerializer.Serialize(value, new JsonSerializerOptions { WriteIndented = true });
        if (stream is not null)
        {
            stream.Position = 0;
            stream.SetLength(0);
            await stream.WriteAsync(Encoding.UTF8.GetBytes(json));
            await stream.FlushAsync();
        }
        else WriteOutput(json + "\n");
    }

    private static void WriteOutput(string text)
    {
        using var writer = new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false), leaveOpen: true);
        writer.Write(text);
        writer.Flush();
    }
}
