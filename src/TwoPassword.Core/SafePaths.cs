using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace TwoPassword.Core;

internal sealed record SourceEntry(string FullPath, string RelativePath, bool IsDirectory, long Length, long CreationTicks, long WriteTicks, FileAttributes Attributes, string? ZoneIdentifier);

internal static class SafePaths
{
    internal const int MaxPathChars = 32700;
    private static readonly HashSet<string> Devices = new(StringComparer.OrdinalIgnoreCase)
        { "CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$" };

    internal static string Full(string input)
    {
        if (string.IsNullOrWhiteSpace(input)) throw new PackageException(Text.Get("文件路径不能为空。"));
        if (input.StartsWith(@"\\.\", StringComparison.Ordinal) || input.StartsWith(@"\??\", StringComparison.Ordinal))
            throw new PackageException(Text.Get("不支持设备路径。"));
        string value = input;
        if (value.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) value = @"\\" + value[8..];
        else if (value.StartsWith(@"\\?\", StringComparison.Ordinal)) value = value[4..];
        string full = Path.GetFullPath(value);
        if (full.Length >= MaxPathChars) throw new PackageException(Text.Get("路径超过 Windows 可安全处理的长度。"));
        if (full.IndexOf(':', 2) >= 0) throw new PackageException(Text.Get("不支持备用数据流路径。"));
        return Path.TrimEndingDirectorySeparator(full);
    }

    internal static string Extended(string path)
    {
        string full = Full(path);
        if (!OperatingSystem.IsWindows()) return full;
        return full.StartsWith(@"\\", StringComparison.Ordinal) ? @"\\?\UNC\" + full[2..] : @"\\?\" + full;
    }

    internal static void ValidateRelative(string path)
    {
        if (string.IsNullOrEmpty(path) || path.Length >= MaxPathChars || path.Contains('\\') || path.StartsWith('/') || path.EndsWith('/'))
            throw new PackageException(Text.Get("归档中的相对路径无效。"));
        try { _ = Envelope.Utf8.GetByteCount(path); }
        catch (System.Text.EncoderFallbackException e) { throw new PackageException(Text.Get("文件名包含无法无损保存的 Unicode 字符。"), e); }
        foreach (string part in path.Split('/'))
        {
            if (part.Length is < 1 or > 255 || part is "." or ".." || part.EndsWith('.') || part.EndsWith(' ') ||
                part.Any(c => c < 32 || "<>:\"|?*".Contains(c)))
                throw new PackageException(Text.Get("无法安全保存文件名：{0}", path));
            string stem = part.Split('.')[0].TrimEnd(' ');
            if (Devices.Contains(stem) ||
                (stem.Length == 4 && (stem.StartsWith("COM", StringComparison.OrdinalIgnoreCase) || stem.StartsWith("LPT", StringComparison.OrdinalIgnoreCase)) &&
                 (stem[3] is >= '1' and <= '9' or '¹' or '²' or '³')))
                throw new PackageException(Text.Get("不支持 Windows 保留设备名：{0}", path));
        }
    }

    internal static bool IsInside(string path, string directory)
    {
        string p = Full(path);
        string d = Full(directory);
        return p.Equals(d, StringComparison.OrdinalIgnoreCase) ||
            p.StartsWith(d + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    internal static void EnsureNoReparseAncestors(string path, bool mustExist)
    {
        string full = Full(path);
        string? current = full;
        bool first = true;
        while (current is not null)
        {
            string extended = Extended(current);
            try
            {
                var attributes = File.GetAttributes(extended);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                    throw new PackageException(Text.Get("不支持符号链接、联接点或其他重解析点：{0}", current));
                if (!first && (attributes & FileAttributes.Directory) == 0)
                    throw new PackageException(Text.Get("父路径不是文件夹：{0}", current));
            }
            catch (FileNotFoundException) when (!mustExist && first) { }
            catch (DirectoryNotFoundException) when (!mustExist && first) { }
            first = false;
            current = Path.GetDirectoryName(current);
        }
    }

    internal static void EnsureDestination(string destination)
    {
        if (File.Exists(Extended(destination)) || Directory.Exists(Extended(destination)))
            throw new PackageException(Text.Get("目标已存在。请选择新的文件或文件夹名称，程序不会覆盖原有数据。"));
        string? parent = Path.GetDirectoryName(Full(destination));
        if (parent is null || !Directory.Exists(Extended(parent))) throw new PackageException(Text.Get("目标的父文件夹不存在。"));
        EnsureNoReparseAncestors(parent, true);
    }

    internal static List<SourceEntry> Scan(string source, CancellationToken ct, IProgress<PackageProgress>? progress)
    {
        source = Full(source);
        EnsureNoReparseAncestors(source, true);
        string rootName = Path.GetFileName(source);
        if (string.IsNullOrEmpty(rootName)) throw new PackageException(Text.Get("请选择具体文件或文件夹，不能直接打包磁盘根目录。"));
        var result = new List<SourceEntry>();
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var pending = new Stack<(string Path, string Relative)>();
        var budget = new MetadataBudget(MetadataBudget.InventoryLimit);
        budget.AddPending(source, rootName);
        pending.Push((source, rootName));
        long total = 0;
        while (pending.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var (path, relative) = pending.Pop();
            budget.RemovePending(path, relative);
            ValidateRelative(relative);
            if (names.Contains(relative)) throw new PackageException(Text.Get("存在不区分大小写的名称冲突：{0}", relative));
            if (result.Count >= Envelope.MaxEntries) throw new PackageException(Text.Get("文件及文件夹数量超过 100 万个的安全限制。"));
            var entry = ReadEntry(path, relative);
            budget.AddEntry(relative, path, entry.ZoneIdentifier);
            names.Add(relative);
            result.Add(entry);
            total = checked(total + entry.Length);
            if (total > Envelope.MaxBytes) throw new PackageException(Text.Get("原始数据超过 16 TiB 的格式限制。"));
            if (result.Count % 128 == 0) progress?.Report(new(Text.Get("检查文件"), relative, total, total, result.Count, result.Count));
            if (entry.IsDirectory)
            {
                // No IgnoreInaccessible or attributes filter: every entry is accounted for or the operation fails.
                var children = new List<(string Path, string Relative)>();
                foreach (string child in Directory.EnumerateFileSystemEntries(Extended(path), "*", new EnumerationOptions
                    { RecurseSubdirectories = false, IgnoreInaccessible = false, AttributesToSkip = 0, ReturnSpecialDirectories = false }))
                {
                    string fullChild = Full(child);
                    string childRelative = relative + "/" + Path.GetFileName(fullChild);
                    ValidateRelative(childRelative);
                    budget.AddPending(fullChild, childRelative);
                    children.Add((fullChild, childRelative));
                    if ((long)children.Count + pending.Count + result.Count > Envelope.MaxEntries)
                        throw new PackageException(Text.Get("文件及文件夹数量超过 100 万个的安全限制。"));
                }
                children.Sort((left, right) => StringComparer.Ordinal.Compare(Path.GetFileName(right.Path), Path.GetFileName(left.Path)));
                foreach (var child in children) pending.Push(child);
            }
        }
        return result;
    }

    internal static SourceEntry ReadEntry(string path, string relative)
    {
        string p = Extended(path);
        var attributes = File.GetAttributes(p);
        if ((attributes & (FileAttributes.ReparsePoint | FileAttributes.Encrypted | FileAttributes.Device | FileAttributes.Offline)) != 0)
            throw new PackageException(Text.Get("此项目具有不支持的链接、EFS、设备或离线属性，已停止以避免数据遗漏：{0}", relative));
        string? zone = ReadZoneIdentifier(p, relative);
        bool dir = (attributes & FileAttributes.Directory) != 0;
        var info = dir ? (FileSystemInfo)new DirectoryInfo(p) : new FileInfo(p);
        info.Refresh();
        long length = dir ? 0 : ((FileInfo)info).Length;
        return new(path, relative, dir, length, info.CreationTimeUtc.Ticks, info.LastWriteTimeUtc.Ticks, attributes, zone);
    }

    internal static void ValidateUnchanged(SourceEntry before)
    {
        EnsureNoReparseAncestors(before.FullPath, true);
        var after = ReadEntry(before.FullPath, before.RelativePath);
        if (before != after) throw new PackageException(Text.Get("打包期间源文件发生变化，请关闭修改此文件的程序后重试：{0}", before.RelativePath));
    }

    internal static void ValidateInventory(List<SourceEntry> before, List<SourceEntry> after)
    {
        if (before.Count != after.Count) throw new PackageException(Text.Get("打包期间文件夹内容发生变化，请重试。"));
        for (int i = 0; i < before.Count; i++)
            if (before[i] != after[i]) throw new PackageException(Text.Get("打包期间源数据发生变化：{0}", before[i].RelativePath));
    }

    internal static void CreatePrivateDirectory(string path) => WindowsPrivateDirectory.Create(path);

    internal static string? ReadZoneIdentifier(string path, string displayName)
    {
        if (!OperatingSystem.IsWindows()) return null;
        string? zone = null;
        using var handle = FindFirstStreamW(path, 0, out var data, 0);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            if (error == 38) return null; // the stream enumeration reached EOF
            if ((error is 1 or 50 or 87) &&
                (WindowsFileSystemCapabilities.Query(path) & WindowsFileSystemCapabilities.NamedStreams) == 0)
                return null; // absence of stream support was confirmed by the actual volume
            throw new PackageException(Text.Get("无法检查文件的数据流：{0} (Windows {1})", displayName, error));
        }
        do
        {
            if (data.StreamName.Equals(":Zone.Identifier:$DATA", StringComparison.OrdinalIgnoreCase))
            {
                if (data.StreamSize is < 0 or > 65536) throw new PackageException(Text.Get("Zone.Identifier 超过 64 KiB，已停止以避免遗漏：{0}", displayName));
                using var stream = new FileStream(path + ":Zone.Identifier", FileMode.Open, FileAccess.Read, FileShare.Read);
                if (stream.Length != data.StreamSize) throw new PackageException(Text.Get("Zone.Identifier 在检查期间发生变化。"));
                var bytes = new byte[(int)data.StreamSize];
                stream.ReadExactly(bytes);
                if (stream.ReadByte() != -1) throw new PackageException(Text.Get("Zone.Identifier 在检查期间发生变化。"));
                zone = Convert.ToBase64String(bytes);
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes);
            }
            else if (data.StreamName != "::$DATA")
                throw new PackageException(Text.Get("检测到 NTFS 备用数据流，已停止以避免丢失：{0} ({1})", displayName, data.StreamName));
        } while (FindNextStreamW(handle, out data));
        int last = Marshal.GetLastWin32Error();
        if (last != 38) throw new PackageException(Text.Get("读取数据流时失败：{0} (Windows {1})", displayName, last));
        return zone;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct FindStreamData
    {
        public long StreamSize;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)] public string StreamName;
    }
    private sealed class FindStreamHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private FindStreamHandle() : base(true) { }
        protected override bool ReleaseHandle() => FindClose(handle);
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern FindStreamHandle FindFirstStreamW(string fileName, int infoLevel, out FindStreamData data, uint flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FindNextStreamW(FindStreamHandle handle, out FindStreamData data);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FindClose(IntPtr handle);
}
