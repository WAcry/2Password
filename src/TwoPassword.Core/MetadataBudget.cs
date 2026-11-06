namespace TwoPassword.Core;

/// <summary>
/// Conservative retained-string/collection accounting. Two creation inventories may coexist,
/// so each scan uses half the extraction budget. This is a format-independent resource guard.
/// </summary>
internal sealed class MetadataBudget(long limit)
{
    internal const long ExtractionLimit = 256L * 1024 * 1024;
    internal const long InventoryLimit = ExtractionLimit / 2;
    private long charged;

    internal void AddEntry(string relative, string full, string? zoneBase64)
        => Add(256L + 2L * ((long)relative.Length + full.Length + (zoneBase64?.Length ?? 0)));

    internal void AddPending(string full, string relative)
        => Add(PendingCharge(full, relative));

    internal void RemovePending(string full, string relative)
        => charged -= PendingCharge(full, relative);

    private static long PendingCharge(string full, string relative)
        => 128L + 2L * ((long)full.Length + relative.Length);

    private void Add(long amount)
    {
        if (amount < 0 || amount > limit - charged)
            throw new PackageException(Text.Get("文件名、路径或附加元数据超过 {0} MiB 的安全内存预算。请将源文件分成较小的包。", limit / 1024 / 1024));
        charged += amount;
    }
}
