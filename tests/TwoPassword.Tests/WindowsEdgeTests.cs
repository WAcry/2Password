using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using TwoPassword.Core;

namespace TwoPassword.Tests;

internal static partial class Program
{
    private static async Task OversizedStub()
    {
        string stub = Path.Combine(_root, "oversized-sparse-template.exe");
        using (var file = new FileStream(stub, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
        {
            if (!DeviceIoControl(file.SafeFileHandle, 0x900C4, IntPtr.Zero, 0, IntPtr.Zero, 0, out _, IntPtr.Zero))
                throw new SkipException("Test volume does not support sparse files, Windows " + Marshal.GetLastWin32Error());
            file.Write("MZ"u8);
            file.SetLength(4L * 1024 * 1024 * 1024);
        }
        string source = Path.Combine(_root, "oversized-stub-source.txt");
        File.WriteAllText(source, "This should never trigger a four-gigabyte copy.");
        string output = Path.Combine(_root, "oversized-stub-output.exe");
        var timer = Stopwatch.StartNew();
        await MustFail(() => PackageService.CreateAsync(new(source, output, [PasswordA], PackageCompression.None, stub)));
        Assert(timer.Elapsed < TimeSpan.FromSeconds(10), "Oversized SFX stub was not rejected promptly.");
        Assert(!File.Exists(output), "Oversized SFX was published.");
        AssertNoStagingRemains();
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(SafeFileHandle device, uint controlCode,
        IntPtr input, uint inputSize, IntPtr output, uint outputSize, out uint returned, IntPtr overlapped);
}
