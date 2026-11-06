using TwoPassword.Localization;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace TwoPassword.Recovery;

internal sealed record Par2Packet(long Offset, long Length);

/// <summary>Validated metadata of the PAR2 set stored after a package payload. <c>End</c> is where the last
/// intact packet of the set ends, relative to the start of the region.</summary>
internal sealed record Par2Set(long BlockSize, byte[] SourceMd5, byte[][] SliceMd5, int RecoveryBlocks, IReadOnlyList<Par2Packet> Packets, long End);

/// <summary>
/// Scans the recovery region packet by packet. A damaged packet is skipped and scanning resumes at the
/// next packet marker, so one bad byte costs one packet. Only packets that pass their checksum and
/// describe exactly this payload, under the fixed source name, are ever handed to the native tool.
/// MD5 here is the PAR2 format's damage checksum, not a signature.
/// </summary>
internal static class Par2Metadata
{
    internal const string SourceName = "payload";
    private const int HeaderSize = 64;
    private const int MaxSourceBlocks = 32768;
    private const int MaxCreatorBody = 1024;
    // Body bytes and object counts are separate limits: tiny packets must not create
    // unbounded dictionaries, and large checksum tables must not exhaust memory.
    internal const int MaxRecoverySets = 8;
    internal const int MaxRetainedPackets = 65535 + 3;
    internal const long MaxMetadataBytes = 8L * 1024 * 1024;
    private static readonly byte[] Magic = "PAR2\0PKT"u8.ToArray();
    private static readonly byte[] NameBytes = Encoding.ASCII.GetBytes(SourceName);
    private static readonly byte[] PaddedName = [.. NameBytes, 0];
    private const string MainType = "PAR 2.0\0Main\0\0\0\0";
    private const string FileDescType = "PAR 2.0\0FileDesc";
    private const string ChecksumType = "PAR 2.0\0IFSC\0\0\0\0";
    private const string RecoveryType = "PAR 2.0\0RecvSlic";
    private const string CreatorType = "PAR 2.0\0Creator\0";

    /// <summary>par2cmdline's default: about 2000 source blocks, a multiple of 4, never more than 32768 blocks.</summary>
    internal static long BlockSize(long sourceLength)
    {
        long size = Math.Max((sourceLength + 1999) / 2000, 4);
        size = Math.Max(size, (sourceLength + MaxSourceBlocks - 1) / MaxSourceBlocks);
        return (size + 3) & ~3L;
    }

    internal static Par2Set Read(FileStream file, long start, long length, long sourceLength, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (sourceLength <= 0 || start < 0 || length < 0 || start > file.Length - length)
            throw new InvalidDataException(Text.Get("恢复记录的位置无效。"));
        long blockSize = BlockSize(sourceLength);
        int slices = checked((int)((sourceLength + blockSize - 1) / blockSize));
        var expected = new Dictionary<string, (long Min, long Max)>(StringComparer.Ordinal)
        {
            [MainType] = (HeaderSize + 28, HeaderSize + 28),
            [FileDescType] = (HeaderSize + 56 + 8, HeaderSize + 56 + 8),
            [ChecksumType] = (HeaderSize + 16 + 20L * slices, HeaderSize + 16 + 20L * slices),
            [RecoveryType] = (HeaderSize + 4 + blockSize, HeaderSize + 4 + blockSize),
            [CreatorType] = (HeaderSize + 4, HeaderSize + MaxCreatorBody),
        };
        var found = new Dictionary<string, Candidates>(StringComparer.Ordinal);
        int retainedPackets = 0;
        long retainedBytes = 0;
        byte[] header = new byte[HeaderSize], buffer = new byte[1024 * 1024];
        // Bounds the rescanning work when many overlapping candidates fail their checksums.
        const long allowance = 64L * 1024 * 1024;
        long budget = length > (long.MaxValue - allowance) / 2 ? long.MaxValue : 2 * length + allowance;
        long hashed = 0;
        long at = 0;
        while (at <= length - HeaderSize)
        {
            ct.ThrowIfCancellationRequested();
            RandomAccess.Read(file.SafeFileHandle, header, start + at);
            string type = Encoding.ASCII.GetString(header, 48, 16);
            ulong declared = BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(8));
            if (!header.AsSpan(0, 8).SequenceEqual(Magic) || !expected.TryGetValue(type, out var bounds) ||
                declared < (ulong)bounds.Min || declared > (ulong)bounds.Max || (declared & 3) != 0 || (long)declared > length - at)
            {
                at = NextMarker(file, start, length, at + 1, buffer, ct);
                continue;
            }
            long size = (long)declared;
            if (size > budget - hashed) throw MetadataLimit();
            hashed += size;
            int capture = type == CreatorType ? 0 : type == RecoveryType ? 4 : (int)(size - HeaderSize);
            byte[] body = new byte[capture];
            if (Hash(file, start + at, size, header, body, buffer, ct))
            {
                // A Main packet with a false set ID is not part of any valid set,
                // and must not extend the reconstructed recovery region either.
                if (type == MainType && !CryptographicOperations.FixedTimeEquals(MD5.HashData(body), header.AsSpan(32, 16)))
                { at += size; continue; }
                string setId = Convert.ToHexString(header, 32, 16);
                if (!found.TryGetValue(setId, out var candidates))
                {
                    if (found.Count >= MaxRecoverySets) throw MetadataLimit();
                    found.Add(setId, candidates = new Candidates());
                }
                // Track the physical end independently of retained representatives.
                // Repeated metadata and Creator packets still belong to the region.
                candidates.End = at + size;
                if (type == RecoveryType)
                {
                    uint exponent = BinaryPrimitives.ReadUInt32LittleEndian(body);
                    if (exponent < 65535 && !candidates.Recovery.ContainsKey(exponent))
                    {
                        Charge(body.Length);
                        var candidate = new Candidate(at, size, body, Recovery: true);
                        candidates.Recovery.Add(exponent, candidate);
                        candidates.Ordered.Add(candidate);
                    }
                }
                else if (type != CreatorType)
                {
                    string fileId = type == MainType ? "" : Convert.ToHexString(body, 0, 16);
                    var identity = (type, fileId);
                    if (candidates.Metadata.TryGetValue(identity, out var existing))
                    {
                        // Keep conflicts for validation of the selected file only;
                        // unrelated FileIDs were ignored by the original reader.
                        existing.Conflict |= !existing.Packet.Body.AsSpan().SequenceEqual(body);
                    }
                    else
                    {
                        Charge(body.Length);
                        var candidate = new Candidate(at, size, body);
                        candidates.Metadata.Add(identity, new(candidate));
                        candidates.Ordered.Add(candidate);
                    }
                }
                at += size;
            }
            else at = NextMarker(file, start, length, at + 8, buffer, ct);
        }
        return Validate(found, sourceLength, blockSize, slices, ct);

        void Charge(int bytes)
        {
            if (retainedPackets >= MaxRetainedPackets || bytes > MaxMetadataBytes - retainedBytes) throw MetadataLimit();
            retainedPackets++;
            retainedBytes += bytes;
        }
    }

    /// <summary>Copies the selected packets, checking each one again as it is read.</summary>
    internal static int Copy(FileStream file, long start, Par2Set set, Stream output, CancellationToken ct)
    {
        byte[] header = new byte[HeaderSize], buffer = new byte[1024 * 1024];
        int recovery = 0;
        foreach (var packet in set.Packets)
        {
            ct.ThrowIfCancellationRequested();
            long mark = output.Position;
            RandomAccess.Read(file.SafeFileHandle, header, start + packet.Offset);
            output.Write(header);
            byte[] type = header[48..64];
            if (!Hash(file, start + packet.Offset, packet.Length, header, [], buffer, ct, output))
            {
                output.SetLength(mark);
                output.Position = mark;
                continue;
            }
            if (Encoding.ASCII.GetString(type) == RecoveryType) recovery++;
        }
        return recovery;
    }

    private static bool Hash(FileStream file, long position, long size, byte[] header, byte[] capture, byte[] buffer,
        CancellationToken ct, Stream? copy = null)
    {
        using var md5 = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
        md5.AppendData(header, 32, 32);
        long done = 0, body = size - HeaderSize;
        while (done < body)
        {
            ct.ThrowIfCancellationRequested();
            int read = RandomAccess.Read(file.SafeFileHandle, buffer.AsSpan(0, (int)Math.Min(buffer.Length, body - done)), position + HeaderSize + done);
            if (read == 0) return false;
            md5.AppendData(buffer, 0, read);
            copy?.Write(buffer, 0, read);
            if (done < capture.Length) buffer.AsSpan(0, (int)Math.Min(read, capture.Length - done)).CopyTo(capture.AsSpan((int)done));
            done += read;
        }
        return CryptographicOperations.FixedTimeEquals(md5.GetHashAndReset(), header.AsSpan(16, 16));
    }

    private static long NextMarker(FileStream file, long start, long length, long from, byte[] buffer, CancellationToken ct)
    {
        while (from <= length - HeaderSize)
        {
            ct.ThrowIfCancellationRequested();
            int read = RandomAccess.Read(file.SafeFileHandle, buffer.AsSpan(0, (int)Math.Min(buffer.Length, length - from)), start + from);
            if (read < Magic.Length) break;
            int index = buffer.AsSpan(0, read).IndexOf(Magic);
            if (index >= 0) return from + index;
            from += read - (Magic.Length - 1);
        }
        return length;
    }

    private static Par2Set Validate(Dictionary<string, Candidates> found, long sourceLength, long blockSize, int slices, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        Candidates? packets = null;
        foreach (var set in found.Values)
        {
            ct.ThrowIfCancellationRequested();
            if (!set.Metadata.ContainsKey((MainType, ""))) continue;
            if (packets is not null) throw new InvalidDataException(Text.Get("恢复记录里混有多个恢复集。"));
            packets = set;
        }
        if (packets is null) throw new InvalidDataException(Text.Get("恢复记录缺少主元数据。"));
        var mainPacket = Single(packets, MainType, "", Text.Get("恢复记录的主元数据相互冲突。"))!;
        byte[] main = mainPacket.Body;
        if (BinaryPrimitives.ReadUInt64LittleEndian(main) != (ulong)blockSize || BinaryPrimitives.ReadUInt32LittleEndian(main.AsSpan(8)) != 1)
            throw new InvalidDataException(Text.Get("恢复记录的块大小或文件数量与加密数据不符。"));
        byte[] fileId = main[12..28];
        string fileIdentity = Convert.ToHexString(fileId);
        var descriptionPacket = Single(packets, FileDescType, fileIdentity, Text.Get("恢复记录的文件描述相互冲突。"))
            ?? throw new InvalidDataException(Text.Get("恢复记录缺少文件描述。"));
        byte[] description = descriptionPacket.Body;
        if (!description.AsSpan(56).SequenceEqual(PaddedName) ||
            BinaryPrimitives.ReadUInt64LittleEndian(description.AsSpan(48)) != (ulong)sourceLength ||
            !CryptographicOperations.FixedTimeEquals(MD5.HashData(description.AsSpan(32, 24 + NameBytes.Length)), fileId))
            throw new InvalidDataException(Text.Get("恢复记录描述的不是这份加密数据。"));

        var tablePacket = Single(packets, ChecksumType, fileIdentity, Text.Get("恢复记录的切片校验表相互冲突。"))
            ?? throw new InvalidDataException(Text.Get("恢复记录缺少切片校验表。"));
        byte[] table = tablePacket.Body;
        var sliceMd5 = new byte[slices][];
        for (int i = 0; i < slices; i++)
        {
            ct.ThrowIfCancellationRequested();
            sliceMd5[i] = table.AsSpan(16 + i * 20, 16).ToArray();
        }

        var selected = new List<Par2Packet>(3 + packets.Recovery.Count);
        foreach (var packet in packets.Ordered)
        {
            ct.ThrowIfCancellationRequested();
            if (packet.Recovery || ReferenceEquals(packet, mainPacket) || ReferenceEquals(packet, descriptionPacket) || ReferenceEquals(packet, tablePacket))
                selected.Add(new(packet.Offset, packet.Size));
        }
        ct.ThrowIfCancellationRequested();
        return new(blockSize, description[16..32], sliceMd5, packets.Recovery.Count, selected, packets.End);
    }

    /// <summary>
    /// Searches backwards from <paramref name="end"/> to <paramref name="start"/> for an intact FileDesc of the
    /// payload and returns the payload length it records, or -1. par2 repeats this packet in every recovery
    /// file, so a damaged or truncated tail still leaves copies close to the end.
    /// </summary>
    internal static long FindSourceLength(FileStream file, long start, long end, CancellationToken ct)
    {
        const int size = HeaderSize + 56 + 8;
        byte[] buffer = new byte[1024 * 1024], packet = new byte[size];
        for (long top = end; top - start >= size;)
        {
            ct.ThrowIfCancellationRequested();
            long from = Math.Max(start, top - buffer.Length);
            var window = buffer.AsSpan(0, RandomAccess.Read(file.SafeFileHandle, buffer.AsSpan(0, (int)(top - from)), from));
            for (int index = window.LastIndexOf(Magic); index >= 0; index = window[..(index + Magic.Length - 1)].LastIndexOf(Magic))
            {
                ct.ThrowIfCancellationRequested();
                long position = from + index;
                if (position + size <= end && RandomAccess.Read(file.SafeFileHandle, packet, position) == size &&
                    DescribesPayload(packet, out long length)) return length;
            }
            if (from == start) break;
            top = from + Magic.Length - 1;
        }
        return -1;
    }

    private static bool DescribesPayload(byte[] packet, out long length)
    {
        length = -1;
        var body = packet.AsSpan(HeaderSize);
        if (BinaryPrimitives.ReadUInt64LittleEndian(packet.AsSpan(8)) != (ulong)packet.Length ||
            Encoding.ASCII.GetString(packet, 48, 16) != FileDescType ||
            !MD5.HashData(packet.AsSpan(32)).AsSpan().SequenceEqual(packet.AsSpan(16, 16)) ||
            !body[56..].SequenceEqual(PaddedName) ||
            !MD5.HashData(body.Slice(32, 24 + NameBytes.Length)).AsSpan().SequenceEqual(body[..16])) return false;
        ulong value = BinaryPrimitives.ReadUInt64LittleEndian(body[48..]);
        if (value > long.MaxValue) return false;
        length = (long)value;
        return true;
    }

    private static Candidate? Single(Candidates packets, string type, string fileId, string conflict)
    {
        if (!packets.Metadata.TryGetValue((type, fileId), out var value)) return null;
        if (value.Conflict) throw new InvalidDataException(conflict);
        return value.Packet;
    }

    private static InvalidDataException MetadataLimit() => new(Text.Get("恢复记录的元数据超过安全限制。"));

    private sealed record Candidate(long Offset, long Size, byte[] Body, bool Recovery = false);
    private sealed class RetainedMetadata(Candidate packet)
    {
        internal Candidate Packet { get; } = packet;
        internal bool Conflict { get; set; }
    }
    private sealed class Candidates
    {
        internal long End { get; set; }
        internal Dictionary<(string Type, string FileId), RetainedMetadata> Metadata { get; } = [];
        internal Dictionary<uint, Candidate> Recovery { get; } = [];
        internal List<Candidate> Ordered { get; } = [];
    }
}
