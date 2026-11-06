using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using Microsoft.Win32;

namespace TwoPassword.App;

/// <summary>Follows the Windows app theme unless <c>--theme light|dark</c> is given.</summary>
internal static class Theme
{
    private static string? _forced;
    private static bool? _dark;

    internal static bool IsDark => _dark == true;
    internal static string? Forced => _forced;

    internal static void Initialize(string[] arguments)
    {
        for (var index = 0; index + 1 < arguments.Length; index++)
            if (arguments[index] == "--theme" && arguments[index + 1] is "light" or "dark") _forced = arguments[index + 1];
        Apply();
        if (_forced is null)
            SystemEvents.UserPreferenceChanged += (_, e) =>
            {
                if (e.Category == UserPreferenceCategory.General) Application.Current?.Dispatcher.InvokeAsync(Apply);
            };
    }

    private static void Apply()
    {
        var dark = _forced is null ? SystemUsesDarkTheme() : _forced == "dark";
        if (_dark == dark) return;
        _dark = dark;
        var palette = new ResourceDictionary
        {
            Source = new Uri(dark ? "/2Password;component/Theme/Dark.xaml" : "/2Password;component/Theme/Light.xaml", UriKind.Relative)
        };
        Application.Current.Resources.MergedDictionaries[0] = palette;
        foreach (Window window in Application.Current.Windows) ApplyFrame(window);
    }

    /// <summary>Rounded corners, dark-mode frame and a border colour that matches the palette (Windows 11; ignored elsewhere).</summary>
    internal static void ApplyFrame(Window window)
    {
        var handle = new WindowInteropHelper(window).Handle;
        if (handle == IntPtr.Zero) return;
        try
        {
            var round = 2;
            DwmSetWindowAttribute(handle, 33, ref round, sizeof(int));
            var dark = IsDark ? 1 : 0;
            DwmSetWindowAttribute(handle, 20, ref dark, sizeof(int));
            if (Application.Current.TryFindResource("LineStrong") is SolidColorBrush line)
            {
                var color = line.Color.R | (line.Color.G << 8) | (line.Color.B << 16);
                DwmSetWindowAttribute(handle, 34, ref color, sizeof(int));
            }
        }
        catch (Exception error) when (error is DllNotFoundException or EntryPointNotFoundException) { }
    }

    private static bool SystemUsesDarkTheme()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return key?.GetValue("AppsUseLightTheme") is int light && light == 0;
        }
        catch (Exception error) when (error is System.Security.SecurityException or UnauthorizedAccessException or IOException) { return false; }
    }

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);
}
