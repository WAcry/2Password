using System.Globalization;

namespace TwoPassword.Core;

/// <summary>One selected file or directory and its independently encrypted output.</summary>
public sealed record BatchPackageItem(string SourcePath, string OutputPath);

/// <summary>Plans independent packages without copying sources or changing the file system.</summary>
public static class BatchPackageService
{
    /// <summary>
    /// Assigns a unique .protected.exe name to each distinct input, in selection order.
    /// Both the executable and possible .2pw sidecar names are reserved in the plan.
    /// The output directory must exist and must be outside every selected directory.
    /// </summary>
    /// <remarks>
    /// A plan does not reserve files on disk. Create each item through PackageService or
    /// RecoveryService, which recheck destinations and never overwrite an existing file.
    /// Already completed items are independent and can be retained if a later item fails.
    /// </remarks>
    public static IReadOnlyList<BatchPackageItem> Plan(IReadOnlyList<string> sourcePaths, string outputDirectory)
    {
        ArgumentNullException.ThrowIfNull(sourcePaths);
        if (sourcePaths.Count == 0) throw new PackageException(Text.Get("请选择至少一个文件或文件夹。"));
        string output = SafePaths.Full(outputDirectory);
        SafePaths.EnsureNoReparseAncestors(output, true);
        if ((File.GetAttributes(SafePaths.Extended(output)) & FileAttributes.Directory) == 0)
            throw new PackageException(Text.Get("请选择已存在的输出文件夹。"));

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var sources = new List<string>();
        foreach (string input in sourcePaths)
        {
            string source = SafePaths.Full(input);
            if (!seen.Add(source)) continue;
            SafePaths.EnsureNoReparseAncestors(source, true);
            string name = Path.GetFileName(source);
            if (string.IsNullOrEmpty(name))
                throw new PackageException(Text.Get("请选择具体文件或文件夹，不能直接打包磁盘根目录。"));
            SafePaths.ValidateRelative(name);
            var attributes = File.GetAttributes(SafePaths.Extended(source));
            if ((attributes & (FileAttributes.Encrypted | FileAttributes.Device | FileAttributes.Offline)) != 0)
                throw new PackageException(Text.Get("此项目具有不支持的链接、EFS、设备或离线属性，已停止以避免数据遗漏：{0}", name));
            if ((attributes & FileAttributes.Directory) != 0 && SafePaths.IsInside(output, source))
                throw new PackageException(Text.Get("输出文件不能放在正在打包的源文件夹内。"));
            sources.Add(source);
        }

        var reserved = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var plan = new List<BatchPackageItem>(sources.Count);
        foreach (string source in sources)
        {
            string name = Path.GetFileName(source);
            string? available = null;
            for (int index = 1; index < 10000; index++)
            {
                string suffix = index == 1 ? ".protected.exe" : ".protected (" + index.ToString(CultureInfo.InvariantCulture) + ").exe";
                int length = Math.Min(name.Length, 255 - suffix.Length);
                // A valid long Unicode filename may need shortening for the output suffix.
                // Never split an emoji or another UTF-16 surrogate pair.
                if (length < name.Length && char.IsHighSurrogate(name[length - 1])) length--;
                string candidate = SafePaths.Full(Path.Combine(output, name[..length] + suffix));
                string data = Path.ChangeExtension(candidate, ".2pw");
                if (reserved.Contains(candidate) || reserved.Contains(data) || Exists(candidate) || Exists(data)) continue;
                SafePaths.EnsureDestination(candidate);
                SafePaths.EnsureDestination(data);
                DetachedReference.ValidateName(Path.GetFileName(data));
                reserved.Add(candidate);
                reserved.Add(data);
                available = candidate;
                break;
            }
            if (available is null) throw new PackageException(Text.Get("没有可用的名称，请手动选择位置。"));
            plan.Add(new(source, available));
        }
        return plan.AsReadOnly();
    }

    private static bool Exists(string path) => File.Exists(SafePaths.Extended(path)) || Directory.Exists(SafePaths.Extended(path));
}
