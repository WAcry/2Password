using System.Globalization;
using System.IO;
using System.Resources;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Media;
using SharedText = TwoPassword.Localization.Text;

namespace TwoPassword.App;

/// <summary>Display text only. User paths, names and passwords never pass through the resource catalog.</summary>
internal static class UiText
{
    private static readonly ResourceManager Catalog = new("TwoPassword.App.Resources.Ui", typeof(UiText).Assembly);
    private static readonly string PreferencePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "2Password", "language.json");

    private static string _language = "en";

    internal static string Language => _language;

    internal static string L(string key, params object?[] args)
    {
        var culture = CultureInfo.GetCultureInfo(_language);
        var template = Catalog.GetString(key, culture);
        if (template is null) return SharedText.Get(key, args);
        return args.Length == 0 ? template : string.Format(culture, template, args);
    }

    /// <summary>
    /// Re-applies the chosen culture to the current execution context. Operations started through UI Automation
    /// (screen readers, test drivers) run in a context that carries the automation client's culture.
    /// </summary>
    internal static void Pin()
    {
        if (SharedText.Language != _language) SharedText.UseLanguage(_language);
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
        UseLanguage(language);
    }

    internal static void UseLanguage(string language)
    {
        _language = language.StartsWith("zh", StringComparison.OrdinalIgnoreCase) ? "zh-CN" : "en";
        SharedText.UseLanguage(_language);
    }

    internal static string DescribeException(Exception error) => error switch
    {
        FileNotFoundException missing => L("找不到文件：{0}", missing.FileName ?? ""),
        DirectoryNotFoundException => L("找不到文件夹。"),
        _ when Elevation.IsAccessDenied(error) => L("没有权限访问这个位置。"),
        PathTooLongException => L("路径太长，换一个短一些的位置。"),
        OutOfMemoryException => L("内存不足。关掉一些程序再试。"),
        CryptographicException => L("密码不正确，或加密包已损坏。"),
        DecoderFallbackException => L("输入不是有效的 UTF-8。"),
        JsonException => L("Standard input must contain a JSON password array."),
        OperationCanceledException => L("已取消"),
        _ => error.Message
    };

    internal static void Apply(ResourceDictionary dictionary)
    {
        foreach (var pair in UiXamlKeys.Values) dictionary[pair.Key] = L(pair.Value);
        // Microsoft YaHei UI has no semibold face; leading with it keeps mixed Chinese and Latin headings at one weight.
        Application.Current.Resources["UiFont"] = new FontFamily(Language == "zh-CN" ? "Microsoft YaHei UI, Segoe UI" : "Segoe UI, Microsoft YaHei UI");
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
