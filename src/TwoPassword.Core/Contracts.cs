namespace TwoPassword.Core;

public enum PackageCompression { None = 0, Brotli = 1, Zstd = 2 }
public enum PackageLayout { Auto = 0, Embedded = 1, Detached = 2 }
public sealed record CreateOptions(string SourcePath, string OutputPath, IReadOnlyList<string> Passwords, PackageCompression Compression = PackageCompression.Zstd, string? StubPath = null, PackageLayout Layout = PackageLayout.Auto);
public sealed record ExtractOptions(string PackagePath, string OutputDirectory, string Password);
public sealed record PackageProgress(string Stage, string CurrentPath, long BytesProcessed, long TotalBytes, int EntriesProcessed, int TotalEntries);
public sealed record PackageResult(string OutputPath, int FileCount, int DirectoryCount, long TotalBytes, string? DataPath = null, bool IsDetached = false);
public sealed record PackageInfo(int PasswordSlots, PackageCompression Compression, long EncryptedBytes, string? DataPath = null, bool IsDetached = false);

/// <summary>An input cannot be represented safely, was modified, or would lose data.</summary>
public sealed class PackageException : IOException
{
    public PackageException(string message) : base(message) { }
    public PackageException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>No password slot recognized the supplied password; incorrect passwords and damaged key data remain indistinguishable.</summary>
public sealed class PasswordNotRecognizedException : System.Security.Cryptography.CryptographicException
{
    public PasswordNotRecognizedException(string message) : base(message) { }
}
