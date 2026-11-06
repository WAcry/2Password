using System.Buffers.Binary;
using System.Formats.Tar;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using TwoPassword.Core;

namespace TwoPassword.Tests;

internal static partial class Program
{
    private sealed record PasswordSlotFixture(byte[] Bytes, byte[] Header, int PayloadStart, int PayloadEnd);

    private static async Task RunPasswordIndependenceTests()
    {
        string asciiBoundary = new('P', 1024);
        string unicodeBoundary = string.Concat(Enumerable.Repeat("🔐", 512));
        await Run("Password limits distinguish 1024 and 1025 UTF-16 units for ASCII and non-BMP text", () =>
        {
            Assert(asciiBoundary.Length == 1024 && unicodeBoundary.Length == 1024, "Password boundary fixture is wrong.");
            PackageService.ValidatePassword(asciiBoundary);
            PackageService.ValidatePassword(unicodeBoundary);
            foreach (string oversized in new[] { asciiBoundary + "x", unicodeBoundary + "x" })
            {
                bool rejected = false;
                try { PackageService.ValidatePassword(oversized); }
                catch (PackageException) { rejected = true; }
                Assert(rejected, "A 1025-unit password passed validation.");
            }
            return Task.CompletedTask;
        });

        string[] passwords = Enumerable.Range(0, 16).Select(i => "Independent-slot-" + i + "-synthetic-only!").ToArray();
        passwords[1] = asciiBoundary;
        passwords[7] = "2468";
        passwords[15] = unicodeBoundary;
        byte[] expected = Encoding.UTF8.GetBytes("Independent slot decoder: synthetic data, no stored passwords. 中文 🔑");
        PasswordSlotFixture? fixture = null;
        await Run("Independent V1 decoder opens slots 2 and 16 with boundary-length passwords", async () =>
        {
            string source = Path.Combine(_root, "independent-slots.txt");
            string package = Path.Combine(_root, "independent-slots.2pw");
            await File.WriteAllBytesAsync(source, expected);
            await PackageService.CreateAsync(new(source, package, passwords, PackageCompression.None));
            fixture = ReadPasswordSlotFixture(await File.ReadAllBytesAsync(package));
            Assert(BinaryPrimitives.ReadInt32LittleEndian(fixture.Header.AsSpan(40)) == 16,
                "Independent fixture does not declare sixteen slots.");
            foreach (int slot in new[] { 1, 15 })
            {
                byte[] wrappingKey = PasswordSlotDerive(fixture.Header, slot, passwords[slot]);
                byte[]? contentKey = null;
                try
                {
                    contentKey = TryPasswordSlotUnwrap(fixture.Header, slot, wrappingKey);
                    Assert(contentKey is not null, "Independent decoder rejected the exact password for slot " + (slot + 1));
                    Assert(DecodePasswordSlotArchive(fixture, contentKey!).SequenceEqual(expected),
                        "Independent decoder did not restore the exact file from slot " + (slot + 1));
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(wrappingKey);
                    if (contentKey is not null) CryptographicOperations.ZeroMemory(contentKey);
                }
            }
        });
        if (fixture is null) return;

        await Run("A known slot wrapping key and shared content key do not unwrap other password slots", () =>
        {
            byte[] wrappingKey = PasswordSlotDerive(fixture.Header, 0, passwords[0]);
            byte[]? contentKey = null;
            try
            {
                contentKey = TryPasswordSlotUnwrap(fixture.Header, 0, wrappingKey);
                Assert(contentKey is not null, "Known password fixture failed to unlock.");
                foreach (int slot in new[] { 1, 15 })
                {
                    Assert(!fixture.Header.AsSpan(48, 16).SequenceEqual(fixture.Header.AsSpan(48 + slot * 76, 16)),
                        "Independent password slots reused the same salt.");
                    AssertPasswordSlotRejects(fixture.Header, slot, wrappingKey, "Another slot accepted the first slot's wrapping key.");
                    AssertPasswordSlotRejects(fixture.Header, slot, contentKey!, "Another slot accepted the content key as a wrapping key.");
                    byte[] derivedWithTargetSalt = PasswordSlotDerive(fixture.Header, slot, passwords[0]);
                    try
                    {
                        AssertPasswordSlotRejects(fixture.Header, slot, derivedWithTargetSalt,
                            "The known password unexpectedly opened another independent slot.");
                    }
                    finally { CryptographicOperations.ZeroMemory(derivedWithTargetSalt); }
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(wrappingKey);
                if (contentKey is not null) CryptographicOperations.ZeroMemory(contentKey);
            }
            return Task.CompletedTask;
        });

        await Run("Known-content-key comparison and password-only tag verification agree on fixed candidates", () =>
        {
            byte[] knownWrappingKey = PasswordSlotDerive(fixture.Header, 0, passwords[0]);
            byte[]? knownContentKey = null;
            try
            {
                knownContentKey = TryPasswordSlotUnwrap(fixture.Header, 0, knownWrappingKey);
                Assert(knownContentKey is not null, "Known password fixture failed to unlock.");
                const int target = 7;
                // Deliberately bounded synthetic examples, not a dictionary or an external-package tool.
                foreach (string candidate in new[] { "wrong-test-password", passwords[0], passwords[target] })
                {
                    byte[] candidateKey = PasswordSlotDerive(fixture.Header, target, candidate);
                    byte[]? independentlyUnwrapped = null;
                    try
                    {
                        independentlyUnwrapped = TryPasswordSlotUnwrap(fixture.Header, target, candidateKey);
                        bool tagMatches = independentlyUnwrapped is not null;
                        bool knownPlaintextMatches = PasswordSlotMatchesKnownContentKey(fixture.Header, target, candidateKey, knownContentKey!);
                        Assert(tagMatches == knownPlaintextMatches, "Known content key changed which password candidate is accepted.");
                        Assert(tagMatches == string.Equals(candidate, passwords[target], StringComparison.Ordinal),
                            "Independent candidate validation accepted an incorrect password or rejected the correct one.");
                        if (independentlyUnwrapped is not null)
                            Assert(CryptographicOperations.FixedTimeEquals(independentlyUnwrapped, knownContentKey!),
                                "Different password slots did not wrap the same content key.");
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(candidateKey);
                        if (independentlyUnwrapped is not null) CryptographicOperations.ZeroMemory(independentlyUnwrapped);
                    }
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(knownWrappingKey);
                if (knownContentKey is not null) CryptographicOperations.ZeroMemory(knownContentKey);
            }
            return Task.CompletedTask;
        });
    }

    // Decode the published V1 wire format using only public primitives, without core internals.
    // Explicit offsets keep this independent of production slot selection and AAD construction.
    private static PasswordSlotFixture ReadPasswordSlotFixture(byte[] bytes)
    {
        var footer = bytes.AsSpan(bytes.Length - 192, 64);
        Assert(footer[..8].SequenceEqual("2PWTAIL1"u8) &&
            SHA256.HashData(footer[..32]).AsSpan().SequenceEqual(footer[32..]), "Independent V1 footer validation failed.");
        int start = checked((int)BinaryPrimitives.ReadInt64LittleEndian(footer[8..]));
        int end = checked(start + (int)BinaryPrimitives.ReadInt64LittleEndian(footer[16..]));
        Assert(BinaryPrimitives.ReadInt64LittleEndian(footer[24..]) == 0 && end + 192 == bytes.Length,
            "Independent fixture unexpectedly contains recovery data or extra bytes.");
        var replica = bytes.AsSpan(start, 2048);
        int headerLength = BinaryPrimitives.ReadInt32LittleEndian(replica[8..]);
        byte[] header = replica.Slice(48, headerLength).ToArray();
        Assert(replica[..8].SequenceEqual("2PWHDR01"u8) &&
            SHA256.HashData(header).AsSpan().SequenceEqual(replica.Slice(16, 32)), "Independent V1 header validation failed.");
        Assert(header.AsSpan(0, 8).SequenceEqual("2PWPKG01"u8) &&
            BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(8)) == 1 && header[16] == 0,
            "Independent fixture is not an uncompressed V1 package.");
        int count = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(40));
        Assert(count is >= 1 and <= 16 && header.Length == 48 + count * 76, "Independent slot table length is invalid.");
        return new(bytes, header, start + 6144, end);
    }

    private static byte[] PasswordSlotDerive(byte[] header, int slot, string password)
    {
        byte[] encoded = [0, .. new UTF8Encoding(false, true).GetBytes(password)];
        try
        {
            using var kdf = new Argon2id(encoded)
            {
                Salt = header.AsSpan(48 + slot * 76, 16).ToArray(),
                MemorySize = 65536, Iterations = 3, DegreeOfParallelism = 4
            };
            return kdf.GetBytes(32);
        }
        finally { CryptographicOperations.ZeroMemory(encoded); }
    }

    private static byte[] PasswordSlotAad(byte[] header, int slot)
    {
        byte[] aad = new byte[52];
        header.AsSpan(0, 48).CopyTo(aad);
        BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(48), slot);
        return aad;
    }

    private static byte[]? TryPasswordSlotUnwrap(byte[] header, int slot, byte[] wrappingKey)
    {
        int at = 48 + slot * 76;
        byte[] contentKey = new byte[32];
        try
        {
            using var aes = new AesGcm(wrappingKey, 16);
            aes.Decrypt(header.AsSpan(at + 16, 12), header.AsSpan(at + 28, 32), header.AsSpan(at + 60, 16),
                contentKey, PasswordSlotAad(header, slot));
            return contentKey;
        }
        catch (AuthenticationTagMismatchException)
        {
            CryptographicOperations.ZeroMemory(contentKey);
            return null;
        }
    }

    private static void AssertPasswordSlotRejects(byte[] header, int slot, byte[] key, string message)
    {
        byte[]? decoded = TryPasswordSlotUnwrap(header, slot, key);
        try { Assert(decoded is null, message); }
        finally { if (decoded is not null) CryptographicOperations.ZeroMemory(decoded); }
    }

    private static bool PasswordSlotMatchesKnownContentKey(byte[] header, int slot, byte[] wrappingKey, byte[] knownContentKey)
    {
        int at = 48 + slot * 76;
        byte[] cipher = new byte[32], tag = new byte[16];
        using var aes = new AesGcm(wrappingKey, 16);
        aes.Encrypt(header.AsSpan(at + 16, 12), knownContentKey, cipher, tag, PasswordSlotAad(header, slot));
        return CryptographicOperations.FixedTimeEquals(cipher, header.AsSpan(at + 28, 32)) &&
            CryptographicOperations.FixedTimeEquals(tag, header.AsSpan(at + 60, 16));
    }

    private static byte[] DecodePasswordSlotArchive(PasswordSlotFixture fixture, byte[] contentKey)
    {
        using var plaintext = new MemoryStream();
        using var aes = new AesGcm(contentKey, 16);
        byte[] hash = SHA256.HashData(fixture.Header);
        ulong index = 0;
        bool terminal = false;
        for (int at = fixture.PayloadStart; at < fixture.PayloadEnd;)
        {
            byte[] frame = fixture.Bytes.AsSpan(at, 12).ToArray();
            int rawLength = BinaryPrimitives.ReadInt32LittleEndian(frame);
            int encodedLength = BinaryPrimitives.ReadInt32LittleEndian(frame.AsSpan(4));
            Assert(rawLength is >= 0 and <= 1048576 && encodedLength == rawLength && frame.AsSpan(8).IndexOfAnyExcept((byte)0) < 0,
                "Independent fixture frame is not bounded raw data.");
            byte[] nonce = new byte[12], aad = new byte[52], decoded = new byte[encodedLength];
            fixture.Header.AsSpan(36, 4).CopyTo(nonce);
            BinaryPrimitives.WriteUInt64BigEndian(nonce.AsSpan(4), index);
            hash.CopyTo(aad, 0);
            BinaryPrimitives.WriteUInt64BigEndian(aad.AsSpan(32), index);
            frame.CopyTo(aad, 40);
            aes.Decrypt(nonce, fixture.Bytes.AsSpan(at + 12, encodedLength),
                fixture.Bytes.AsSpan(at + 12 + encodedLength, 16), decoded, aad);
            at += 28 + encodedLength;
            if (rawLength == 0)
            {
                Assert(at == fixture.PayloadEnd, "Independent terminal frame did not end the payload.");
                terminal = true;
                break;
            }
            plaintext.Write(decoded);
            CryptographicOperations.ZeroMemory(decoded);
            index++;
        }
        Assert(terminal, "Independent decoder did not authenticate a terminal frame.");
        plaintext.Position = 0;
        using var reader = new TarReader(plaintext, leaveOpen: true);
        var entry = reader.GetNextEntry(copyData: false);
        Assert(entry is PaxTarEntry { EntryType: TarEntryType.RegularFile, Name: "independent-slots.txt" },
            "Independent archive has an unexpected file.");
        using var content = new MemoryStream();
        entry!.DataStream!.CopyTo(content);
        Assert(reader.GetNextEntry(copyData: false) is null, "Independent archive has additional entries.");
        return content.ToArray();
    }
}
