using System.Buffers.Binary;
using System.Formats.Tar;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using TwoPassword.Core;
using ZstdSharp;

namespace TwoPassword.Tests;

internal static partial class Program
{
    // Independent V1 reference framing implementation. This intentionally uses only
    // public crypto/codec libraries and the documented wire format, never core internals.
    private sealed record ReferenceFrame(byte[] Data, int RawLength, PackageCompression Codec);

    private static Task<string> WriteReferencePackage(byte[] archive, long total, int files, int dirs,
        PackageCompression compression = PackageCompression.None)
    {
        var frames = new List<ReferenceFrame>();
        for (int at = 0; at < archive.Length; at += 1024 * 1024)
        {
            byte[] raw = archive.AsSpan(at, Math.Min(1024 * 1024, archive.Length - at)).ToArray();
            byte[] encoded = compression switch
            {
                PackageCompression.Brotli => CompressReference(raw),
                PackageCompression.Zstd => CompressZstdReference(raw),
                _ => raw
            };
            bool compressed = compression != PackageCompression.None && encoded.Length < raw.Length;
            frames.Add(new(compressed ? encoded : raw, raw.Length, compressed ? compression : PackageCompression.None));
        }
        return WriteReferenceFrames(frames, total, files, dirs, compression);
    }

    private static async Task<string> WriteReferenceFrames(IReadOnlyList<ReferenceFrame> frames,
        long total, int files, int dirs, PackageCompression compression)
    {
        byte[] header = new byte[124];
        "2PWPKG01"u8.CopyTo(header);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(8), 1);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(12), 1024 * 1024);
        header[16] = (byte)compression;
        BinaryPrimitives.WriteInt64LittleEndian(header.AsSpan(20), total);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(28), files);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(32), dirs);
        RandomNumberGenerator.Fill(header.AsSpan(36, 4));
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(40), 1);
        AttackSalt.CopyTo(header, 48);
        RandomNumberGenerator.Fill(header.AsSpan(64, 12));
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] slotAad = new byte[52];
        header.AsSpan(0, 48).CopyTo(slotAad);
        using (var wrapper = new AesGcm(_attackWrappingKey!, 16))
            wrapper.Encrypt(header.AsSpan(64, 12), key, header.AsSpan(76, 32), header.AsSpan(108, 16), slotAad);
        using var output = new MemoryStream();
        WriteReferenceReplicas(output, "2PWHDR01"u8, header);
        byte[] hash = SHA256.HashData(header);
        ulong frame = 0;
        using (var aes = new AesGcm(key, 16))
        {
            foreach (var value in frames.Concat([new ReferenceFrame([], 0, PackageCompression.None)]))
            {
                byte[] frameHeader = new byte[12], nonce = new byte[12], aad = new byte[52];
                BinaryPrimitives.WriteInt32LittleEndian(frameHeader, value.RawLength);
                BinaryPrimitives.WriteInt32LittleEndian(frameHeader.AsSpan(4), value.Data.Length);
                frameHeader[8] = (byte)value.Codec;
                header.AsSpan(36, 4).CopyTo(nonce);
                BinaryPrimitives.WriteUInt64BigEndian(nonce.AsSpan(4), frame);
                hash.CopyTo(aad, 0);
                BinaryPrimitives.WriteUInt64BigEndian(aad.AsSpan(32), frame);
                frameHeader.CopyTo(aad, 40);
                byte[] cipher = new byte[value.Data.Length], tag = new byte[16];
                aes.Encrypt(nonce, value.Data, cipher, tag, aad);
                output.Write(frameHeader);
                output.Write(cipher);
                output.Write(tag);
                frame++;
            }
        }
        long length = output.Length;
        WriteReferenceFooter(output, "2PWTAIL1"u8, 0, length);
        CryptographicOperations.ZeroMemory(key);
        string path = Path.Combine(_root, "independent-" + Guid.NewGuid().ToString("N") + ".2pw");
        await File.WriteAllBytesAsync(path, output.ToArray());
        return path;
    }

    private static void WriteReferenceReplicas(Stream output, ReadOnlySpan<byte> magic, byte[] header)
    {
        byte[] record = new byte[2048];
        magic.CopyTo(record);
        BinaryPrimitives.WriteInt32LittleEndian(record.AsSpan(8), header.Length);
        SHA256.HashData(header, record.AsSpan(16, 32));
        header.CopyTo(record, 48);
        for (int i = 0; i < 3; i++) output.Write(record);
    }

    private static void WriteReferenceFooter(Stream output, ReadOnlySpan<byte> magic, long offset, long length, long recovery = 0)
    {
        byte[] record = new byte[64];
        magic.CopyTo(record);
        BinaryPrimitives.WriteInt64LittleEndian(record.AsSpan(8), offset);
        BinaryPrimitives.WriteInt64LittleEndian(record.AsSpan(16), length);
        BinaryPrimitives.WriteInt64LittleEndian(record.AsSpan(24), recovery);
        SHA256.HashData(record.AsSpan(0, 32), record.AsSpan(32, 32));
        for (int i = 0; i < 3; i++) output.Write(record);
    }

    private static byte[] CompressZstdReference(byte[] raw)
    {
        using var compressor = new Compressor(3);
        return compressor.Wrap(raw).ToArray();
    }

    private static async Task<(byte[] Tar, IReadOnlyList<byte> Codecs)> ReferenceDecode(string path, string passwordText = PasswordA)
    {
        byte[] data = await File.ReadAllBytesAsync(path);
        var trailer = data.AsSpan(data.Length - FooterRegion, 64);
        Assert(trailer[..8].SequenceEqual("2PWTAIL1"u8) && SHA256.HashData(trailer[..32]).AsSpan().SequenceEqual(trailer[32..]),
            "Reference decoder expects an intact first V1 trailer.");
        int offset = checked((int)BinaryPrimitives.ReadInt64LittleEndian(trailer[8..]));
        int end = checked(offset + (int)BinaryPrimitives.ReadInt64LittleEndian(trailer[16..]));
        long recovery = BinaryPrimitives.ReadInt64LittleEndian(trailer[24..]);
        Assert(end + recovery + FooterRegion == data.Length, "Payload, recovery data and trailer do not cover the file.");
        Assert(data.AsSpan(offset, 8).SequenceEqual("2PWHDR01"u8), "Reference decoder expects a V1 header record.");
        int headerLength = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(offset + 8));
        byte[] header = data.AsSpan(offset + 48, headerLength).ToArray();
        Assert(header.AsSpan(0, 8).SequenceEqual("2PWPKG01"u8) &&
            BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(8)) == 1, "Reference decoder expects schema V1.");
        byte[] password = [0, .. new UTF8Encoding(false, true).GetBytes(passwordText)];
        using var kdf = new Argon2id(password)
        {
            Salt = header.AsSpan(48, 16).ToArray(), MemorySize = 65536, Iterations = 3, DegreeOfParallelism = 4
        };
        byte[] wrappingKey = kdf.GetBytes(32), key = new byte[32], slotAad = new byte[52];
        header.AsSpan(0, 48).CopyTo(slotAad);
        using (var wrapper = new AesGcm(wrappingKey, 16))
            wrapper.Decrypt(header.AsSpan(64, 12), header.AsSpan(76, 32), header.AsSpan(108, 16), key, slotAad);
        using var plaintext = new MemoryStream();
        using var aes = new AesGcm(key, 16);
        byte[] hash = SHA256.HashData(header);
        var codecs = new List<byte>();
        ulong index = 0;
        bool terminal = false;
        for (int at = offset + HeaderRegion; at < end;)
        {
            byte[] frameHeader = data.AsSpan(at, 12).ToArray();
            int rawLength = BinaryPrimitives.ReadInt32LittleEndian(frameHeader);
            int encodedLength = BinaryPrimitives.ReadInt32LittleEndian(frameHeader.AsSpan(4));
            byte codec = frameHeader[8];
            Assert(rawLength is >= 0 and <= 1024 * 1024 && encodedLength >= 0 && encodedLength <= rawLength,
                "Independent frame bounds mismatch.");
            byte[] encoded = new byte[encodedLength], nonce = new byte[12], aad = new byte[52];
            header.AsSpan(36, 4).CopyTo(nonce);
            BinaryPrimitives.WriteUInt64BigEndian(nonce.AsSpan(4), index);
            hash.CopyTo(aad, 0);
            BinaryPrimitives.WriteUInt64BigEndian(aad.AsSpan(32), index);
            frameHeader.CopyTo(aad, 40);
            aes.Decrypt(nonce, data.AsSpan(at + 12, encodedLength),
                data.AsSpan(at + 12 + encodedLength, 16), encoded, aad);
            at += 12 + encodedLength + 16;
            index++;
            if (rawLength == 0)
            {
                Assert(encodedLength == 0 && codec == 0 && at == end,
                    "Independent terminal/boundary mismatch.");
                terminal = true;
                break;
            }
            byte[] raw = new byte[rawLength];
            switch (codec)
            {
                case 0:
                    Assert(encodedLength == rawLength, "Raw frame size mismatch.");
                    encoded.CopyTo(raw, 0);
                    break;
                case 1:
                    Assert(BrotliDecoder.TryDecompress(encoded, raw, out int written) && written == rawLength,
                        "Independent Brotli decompression failed.");
                    break;
                case 2:
                    using (var decoder = new Decompressor())
                        Assert(decoder.Unwrap(encoded, raw) == rawLength, "Independent Zstd decompression failed.");
                    break;
                default: throw new InvalidOperationException("Unknown independent frame codec.");
            }
            codecs.Add(codec);
            plaintext.Write(raw);
            CryptographicOperations.ZeroMemory(raw);
            CryptographicOperations.ZeroMemory(encoded);
        }
        Assert(terminal, "Independent decoder did not authenticate a terminal.");
        CryptographicOperations.ZeroMemory(key);
        CryptographicOperations.ZeroMemory(wrappingKey);
        CryptographicOperations.ZeroMemory(password);
        return (plaintext.ToArray(), codecs);
    }

    private static void AssertReferenceTar(byte[] tar)
    {
        using var input = new MemoryStream(tar);
        using var reader = new TarReader(input);
        int fileCount = 0;
        while (reader.GetNextEntry() is { } entry)
        {
            if (entry.EntryType != TarEntryType.RegularFile) continue;
            string relative = entry.Name[(entry.Name.IndexOf('/') + 1)..].Replace('/', Path.DirectorySeparatorChar);
            using var data = new MemoryStream();
            entry.DataStream?.CopyTo(data);
            Assert(_snapshot.TryGetValue(relative, out var expected) &&
                expected == Convert.ToHexString(SHA256.HashData(data.ToArray())), "Independent PAX bytes mismatch: " + relative);
            fileCount++;
        }
        Assert(fileCount == _snapshot.Count(x => x.Value != "<directory>"), "Independent PAX file count mismatch.");
    }
}
