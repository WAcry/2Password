using System.Globalization;
using System.IO;
using System.Resources;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Windows;
using SharedText = TwoPassword.Localization.Text;

namespace TwoPassword.App;

/// <summary>Display text only. User paths, names and passwords never pass through the resource catalog.</summary>
internal static class UiText
{
    private static readonly ResourceManager Catalog = new("TwoPassword.App.Resources.Ui", typeof(UiText).Assembly);
    private static readonly string PreferencePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "2Password", "language.json");

    internal static string Language => SharedText.Language;

    internal static string L(string key, params object?[] args)
    {
        var template = Catalog.GetString(key, CultureInfo.GetCultureInfo(Language));
        if (template is null) return SharedText.Get(key, args);
        return args.Length == 0 ? template : string.Format(CultureInfo.CurrentCulture, template, args);
    }

    internal static void Initialize(string[] arguments)
    {
        var language = CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == "zh" ? "zh-CN" : "en";
        try
        {
            if (File.Exists(PreferencePath) && new FileInfo(PreferencePath).Length <= 1024)
            {
                var preference = JsonSerializer.Deserialize<LanguagePreference>(File.ReadAllText(PreferencePath, Encoding.UTF8));
                if (preference?.Language is "en" or "zh-CN") language = preference.Language;
            }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException) { }
        for (var index = 0; index + 1 < arguments.Length; index++)
            if (arguments[index] == "--language" && arguments[index + 1] is "en" or "zh-CN") language = arguments[index + 1];
        SharedText.UseLanguage(language);
    }

    internal static void UseLanguage(string language) => SharedText.UseLanguage(language);

    internal static string DescribeException(Exception error) => error switch
    {
        FileNotFoundException missing => L("找不到文件：{0}", missing.FileName ?? ""),
        DirectoryNotFoundException => L("找不到所需文件夹，请检查所选路径。"),
        UnauthorizedAccessException => L("没有访问权限。请检查文件权限，或选择你有权限读写的位置。"),
        PathTooLongException => L("此路径超过 Windows 或目标文件系统的限制。请使用更短的还原位置。"),
        OutOfMemoryException => L("可用内存不足，请关闭其他占用内存的程序后重试。"),
        CryptographicException => L("密码不正确，或加密包已损坏。请确认大小写、空格及文件完整性。"),
        DecoderFallbackException => L("输入不是有效的 UTF-8。"),
        JsonException => L("Standard input must contain a JSON password array."),
        OperationCanceledException => L("已取消"),
        _ => error.Message
    };

    internal static void Apply(ResourceDictionary dictionary)
    {
        foreach (var pair in UiXamlKeys.Values) dictionary[pair.Key] = L(pair.Value);
    }

    internal static void SaveLanguage()
    {
        var directory = Path.GetDirectoryName(PreferencePath)!;
        Directory.CreateDirectory(directory);
        var temporary = Path.Combine(directory, ".language-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            File.WriteAllText(temporary, JsonSerializer.Serialize(new LanguagePreference(Language)), new UTF8Encoding(false));
            File.Move(temporary, PreferencePath, true);
        }
        finally
        {
            try { if (File.Exists(temporary)) File.Delete(temporary); } catch (IOException) { }
        }
    }

    private sealed record LanguagePreference(string Language);
}
