using System.Security.Cryptography;
using System.Text;

namespace TwoPassword.Core;

/// <summary>
/// A minimum Internet/Restricted zone captured from the selected package and its dataset.
/// This context survives recovery copies; archive metadata cannot lower the original restriction.
/// </summary>
internal readonly record struct ExtractionProvenance(int RestrictedZone)
{
    internal ExtractionProvenance Include(string path)
    {
        if (!OperatingSystem.IsWindows()) return this;
        string full = SafePaths.Full(path);
        if ((WindowsFileSystemCapabilities.Query(full) & WindowsFileSystemCapabilities.NamedStreams) == 0)
            return this;
        byte[]? bytes = null;
        try
        {
            FileStream stream;
            try { stream = new FileStream(SafePaths.Extended(full) + ":Zone.Identifier", FileMode.Open, FileAccess.Read, FileShare.Read); }
            catch (FileNotFoundException) { return this; }
            using (stream)
            {
                if (stream.Length is < 0 or > 65536)
                    throw new IOException(Text.Get("Zone.Identifier 超过 64 KiB，已停止以避免遗漏：{0}", full));
                bytes = new byte[(int)stream.Length];
                stream.ReadExactly(bytes);
                if (stream.ReadByte() != -1) throw new IOException(Text.Get("Zone.Identifier 在检查期间发生变化。"));
            }
            int zone = ParseZone(bytes);
            return zone is 3 or 4 ? new(Math.Max(RestrictedZone, zone)) : this;
        }
        finally { if (bytes is not null) CryptographicOperations.ZeroMemory(bytes); }
    }

    internal byte[]? ForEntry(byte[]? original)
    {
        // Local round trips retain their original ADS bytes, including non-zone metadata.
        if (RestrictedZone == 0) return original;
        int archivedZone = original is null ? 0 : ParseZone(original);
        int effective = archivedZone == 4 || RestrictedZone == 4 ? 4 : 3;
        // Propagate the restriction without disclosing the container's source/referrer URLs.
        return Encoding.ASCII.GetBytes("[ZoneTransfer]\r\nZoneId=" + effective + "\r\n");
    }

    private static int ParseZone(ReadOnlySpan<byte> bytes)
    {
        string text;
        try
        {
            if (bytes.StartsWith(new byte[] { 0xff, 0xfe }))
                text = new UnicodeEncoding(false, true, true).GetString(bytes[2..]);
            else if (bytes.StartsWith(new byte[] { 0xfe, 0xff }))
                text = new UnicodeEncoding(true, true, true).GetString(bytes[2..]);
            else
            {
                if (bytes.StartsWith(new byte[] { 0xef, 0xbb, 0xbf })) bytes = bytes[3..];
                // ZoneTransfer/ZoneId are ASCII. Legacy ANSI or UTF-8 URL bytes must not
                // alter those tokens or require guessing the user's system code page.
                text = Encoding.Latin1.GetString(bytes);
            }
        }
        catch (DecoderFallbackException error) { throw InvalidZone(error); }
        if (text.Any(c => (c < ' ' && c is not '\r' and not '\n' and not '\t') || c == '\x7f')) throw InvalidZone();
        bool inZone = false, seenSection = false;
        int? zone = null;
        using var reader = new StringReader(text);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            line = line.Trim(' ', '\t');
            if (line.Length == 0 || line[0] == ';') continue;
            if (line[0] == '[')
            {
                inZone = line.Equals("[ZoneTransfer]", StringComparison.OrdinalIgnoreCase);
                // Do not guess how Windows' INI parser handles trailing text, padded
                // section names or repeated sections; accept one unambiguous section.
                if (!inZone || seenSection) throw InvalidZone();
                seenSection = true;
                continue;
            }
            int equals = line.IndexOf('=');
            if (!inZone || equals < 0 || !line[..equals].Trim(' ', '\t').Equals("ZoneId", StringComparison.OrdinalIgnoreCase)) continue;
            string value = line[(equals + 1)..].Trim(' ', '\t');
            if (zone is not null || value.Length != 1 || value[0] is < '0' or > '4') throw InvalidZone();
            zone = value[0] - '0';
        }
        return zone ?? throw InvalidZone();
    }

    // An origin-policy error is not payload corruption and must not trigger recovery.
    private static IOException InvalidZone(Exception? inner = null) =>
        new(Text.Get("Zone.Identifier 包含无效或冲突的安全区域。"), inner);
}
