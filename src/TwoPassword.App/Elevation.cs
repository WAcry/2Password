using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace TwoPassword.App;

internal static class Elevation
{
    private const int WM_DROPFILES = 0x0233;
    private const int WM_COPYDATA = 0x004A;
    private const int WM_COPYGLOBALDATA = 0x0049;
    private const int ErrorAccessDenied = 5;
    private const int ErrorCancelled = 1223;

    internal static bool IsElevated { get; } = QueryElevated();

    /// <summary>The UAC shield Windows shows on commands that ask for elevation.</summary>
    internal static ImageSource? Shield { get; } = LoadShield();

    internal static bool IsAccessDenied(Exception error)
    {
        for (Exception? current = error; current is not null; current = current.InnerException)
        {
            if (current is UnauthorizedAccessException) return true;
            if (current is Win32Exception { NativeErrorCode: ErrorAccessDenied }) return true;
            if (current.HResult == unchecked((int)0x80070005)) return true;
        }
        return false;
    }

    /// <summary>Starts this executable elevated. Returns false when the user declines the UAC prompt.</summary>
    internal static bool Restart(IEnumerable<string> arguments)
    {
        var start = new ProcessStartInfo(Environment.ProcessPath ?? throw new InvalidOperationException(UiText.L("Cannot locate executable.")))
        {
            UseShellExecute = true,
            Verb = "runas",
            WorkingDirectory = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        };
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        try
        {
            Process.Start(start)?.Dispose();
            return true;
        }
        catch (Win32Exception error) when (error.NativeErrorCode == ErrorCancelled) { return false; }
    }

    /// <summary>
    /// UIPI blocks OLE drag and drop from a non-elevated Explorer into an elevated window. Explorer still delivers
    /// WM_DROPFILES once the window opts in to it and has no OLE drop target, at the cost of hover feedback.
    /// </summary>
    internal static void AcceptShellDrops(Window window, Action<string[]> drop)
    {
        var handle = new WindowInteropHelper(window).Handle;
        if (handle == IntPtr.Zero || HwndSource.FromHwnd(handle) is not { } source) return;
        RevokeDragDrop(handle);
        foreach (var message in new[] { WM_DROPFILES, WM_COPYDATA, WM_COPYGLOBALDATA }) ChangeWindowMessageFilterEx(handle, (uint)message, 1, IntPtr.Zero);
        DragAcceptFiles(handle, true);
        source.AddHook((IntPtr _, int message, IntPtr wParam, IntPtr _, ref bool handled) =>
        {
            if (message != WM_DROPFILES) return IntPtr.Zero;
            handled = true;
            string[] paths;
            try
            {
                var count = DragQueryFile(wParam, uint.MaxValue, null, 0);
                paths = new string[count];
                for (uint index = 0; index < count; index++)
                {
                    var length = DragQueryFile(wParam, index, null, 0);
                    var buffer = new char[length + 1];
                    DragQueryFile(wParam, index, buffer, (uint)buffer.Length);
                    paths[index] = new string(buffer, 0, (int)length);
                }
            }
            finally { DragFinish(wParam); }
            drop(paths);
            return IntPtr.Zero;
        });
    }

    private static bool QueryElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static ImageSource? LoadShield()
    {
        var info = new StockIconInfo { Size = (uint)Marshal.SizeOf<StockIconInfo>() };
        try
        {
            if (SHGetStockIconInfo(77, 0x101, ref info) != 0 || info.Icon == IntPtr.Zero) return null;
        }
        catch (Exception error) when (error is DllNotFoundException or EntryPointNotFoundException) { return null; }
        try
        {
            var image = Imaging.CreateBitmapSourceFromHIcon(info.Icon, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
            image.Freeze();
            return image;
        }
        catch (Exception error) when (error is COMException or ArgumentException or IOException) { return null; }
        finally { DestroyIcon(info.Icon); }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StockIconInfo
    {
        public uint Size;
        public IntPtr Icon;
        public int SystemImageIndex;
        public int IconIndex;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string Path;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SHGetStockIconInfo(uint id, uint flags, ref StockIconInfo info);

    [DllImport("user32.dll")]
    private static extern bool DestroyIcon(IntPtr icon);

    [DllImport("ole32.dll")]
    private static extern int RevokeDragDrop(IntPtr hwnd);

    [DllImport("user32.dll")]
    private static extern bool ChangeWindowMessageFilterEx(IntPtr hwnd, uint message, uint action, IntPtr filterStatus);

    [DllImport("shell32.dll")]
    private static extern void DragAcceptFiles(IntPtr hwnd, bool accept);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern uint DragQueryFile(IntPtr drop, uint index, char[]? buffer, uint size);

    [DllImport("shell32.dll")]
    private static extern void DragFinish(IntPtr drop);
}
