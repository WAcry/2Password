using System.Globalization;

namespace TwoPassword.App;

/// <summary>Non-secret GUI state carried across an elevation restart. Passwords are entered again.</summary>
internal sealed record GuiLaunchOptions(
    string? StubPath = null,
    string? InitialPath = null,
    bool Encrypt = false,
    string? Target = null,
    bool Repair = false,
    string? Compression = null,
    string? Layout = null,
    int? RecoveryPercent = null,
    bool VerifyFirst = false)
{
    internal static GuiLaunchOptions Parse(IReadOnlyList<string> arguments)
    {
        var options = new GuiLaunchOptions();
        for (var index = 0; index < arguments.Count; index++)
        {
            var key = arguments[index];
            if (key == "--verify-first")
            {
                options = options with { VerifyFirst = true };
                continue;
            }
            if (key is "--stub" or "--language" or "--theme" or "--target" or "--encrypt" or "--repair"
                or "--compression" or "--layout" or "--recovery-percent")
            {
                if (index + 1 >= arguments.Count) continue;
                var value = arguments[++index];
                options = key switch
                {
                    "--stub" => options with { StubPath = value },
                    "--target" => options with { Target = value },
                    "--encrypt" => options with { Encrypt = true, InitialPath = options.InitialPath ?? value },
                    "--repair" => options with { Repair = true, InitialPath = options.InitialPath ?? value },
                    "--compression" when value is "none" or "brotli" or "zstd" => options with { Compression = value },
                    "--layout" when value is "auto" or "embedded" or "detached" => options with { Layout = value },
                    "--recovery-percent" when value is "0" or "5" or "10" or "20" =>
                        options with { RecoveryPercent = int.Parse(value, CultureInfo.InvariantCulture) },
                    _ => options,
                };
            }
            else if (!key.StartsWith("--", StringComparison.Ordinal))
                options = options with { InitialPath = options.InitialPath ?? key };
        }
        return options;
    }

    internal List<string> ElevationArguments(string language, string? theme)
    {
        var arguments = new List<string> { "--language", language };
        if (theme is not null) arguments.AddRange(["--theme", theme]);
        if (StubPath is not null) arguments.AddRange(["--stub", StubPath]);
        if (InitialPath is not null)
        {
            if (Repair) arguments.Add("--repair");
            else if (Encrypt) arguments.Add("--encrypt");
            arguments.Add(InitialPath);
        }
        if (Target is not null) arguments.AddRange(["--target", Target]);
        if (Compression is not null) arguments.AddRange(["--compression", Compression]);
        if (Layout is not null) arguments.AddRange(["--layout", Layout]);
        if (RecoveryPercent is { } percent) arguments.AddRange(["--recovery-percent", percent.ToString(CultureInfo.InvariantCulture)]);
        if (VerifyFirst) arguments.Add("--verify-first");
        return arguments;
    }
}
