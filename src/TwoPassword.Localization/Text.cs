using System.Globalization;
using System.Resources;

namespace TwoPassword.Localization;

/// <summary>Shared user-interface resources. File formats, filenames and passwords never pass through this class.</summary>
public static class Text
{
    private static readonly ResourceManager Resources = new("TwoPassword.Localization.Resources.Strings", typeof(Text).Assembly);
    private static readonly CultureInfo English = CultureInfo.GetCultureInfo("en");
    private static readonly CultureInfo Chinese = CultureInfo.GetCultureInfo("zh-CN");

    /// <summary>Any Chinese UI culture selects Simplified Chinese; all other cultures select English.</summary>
    public static string Language =>
        CultureInfo.CurrentUICulture.TwoLetterISOLanguageName.Equals("zh", StringComparison.OrdinalIgnoreCase) ? "zh-CN" : "en";

    /// <summary>Resolve a resource; unknown keys fall back to the supplied key. Arguments format display text only.</summary>
    public static string Get(string key, params object?[] args)
    {
        ArgumentNullException.ThrowIfNull(key);
        string template = Resources.GetString(key, Language == "zh-CN" ? Chinese : English) ?? key;
        return args is null || args.Length == 0 ? template : string.Format(CultureInfo.CurrentCulture, template, args);
    }

    /// <summary>Set the current UI thread and defaults inherited by subsequently created work.</summary>
    public static void UseLanguage(string language)
    {
        ArgumentNullException.ThrowIfNull(language);
        CultureInfo culture = language.StartsWith("zh", StringComparison.OrdinalIgnoreCase) ? Chinese : English;
        CultureInfo.DefaultThreadCurrentCulture = culture;
        CultureInfo.DefaultThreadCurrentUICulture = culture;
        CultureInfo.CurrentCulture = culture;
        CultureInfo.CurrentUICulture = culture;
    }
}
