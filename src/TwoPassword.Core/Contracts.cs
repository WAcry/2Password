namespace TwoPassword.Core;

public enum PackageCompression { None = 0, Brotli = 1, Zstd = 2 }
public enum PackageLayout { Auto = 0, Embedded = 1, Detached = 2 }
/// <summary>Writes recovery data for a finished payload file to <paramref name="output"/>. The payload file is closed and must not be modified.</summary>
public delegate void RecoveryWriter(string payloadPath, long payloadLength, Stream output, CancellationToken cancellationToken);
public sealed record CreateOptions(string SourcePath, string OutputPath, IReadOnlyList<string> Passwords, PackageCompression Compression = PackageCompression.Zstd, string? StubPath = null, PackageLayout Layout = PackageLayout.Auto, RecoveryWriter? Recovery = null);
public sealed record ExtractOptions(string PackagePath, string OutputDirectory, string Password)
{
    internal ExtractionProvenance Provenance { get; init; }
}
public sealed record PackageProgress(string Stage, string CurrentPath, long BytesProcessed, long TotalBytes, int EntriesProcessed, int TotalEntries);
public sealed record PackageResult(string OutputPath, int FileCount, int DirectoryCount, long TotalBytes, string? DataPath = null, bool IsDetached = false, long RecoveryBytes = 0);
public sealed record PackageInfo(int PasswordSlots, PackageCompression Compression, long EncryptedBytes, string? DataPath = null, bool IsDetached = false, long RecoveryBytes = 0);
/// <summary>Byte ranges of the file holding the encrypted payload, read from the redundant trailer only.</summary>
public sealed record PackageRegions(string DataPath, long PayloadOffset, long PayloadLength, long RecoveryLength, bool IsDetached)
{
    public long RecoveryOffset => PayloadOffset + PayloadLength;
}
/// <summary>Possible payload starts in <paramref name="DataPath"/> for a package whose footer cannot be read.</summary>
public sealed record PayloadCandidates(string DataPath, bool IsDetached, IReadOnlyList<long> Offsets)
{
    /// <summary>Length of the header replicas at the start of every payload. These bytes match at every candidate start.</summary>
    public int HeaderLength => RedundantStorage.HeaderRegionSize;
    public int MinimumPayloadLength => RedundantStorage.HeaderRegionSize + Envelope.MinimumFrameSize;
}

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
