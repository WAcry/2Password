using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using TwoPassword.Core;

namespace TwoPassword.Tests;

internal static partial class Program
{
    private static async Task RunProvenanceTests()
    {
        string work = Path.Combine(_root, "provenance");
        Directory.CreateDirectory(work);
        string source = Path.Combine(work, "source");
        Directory.CreateDirectory(Path.Combine(source, "nested"));
        File.WriteAllText(Path.Combine(source, "a.txt"), "Harmless origin fixture A");
        File.WriteAllText(Path.Combine(source, "nested", "b.txt"), "Harmless origin fixture B");
        string package = Path.Combine(work, "local.2pw");
        await PackageService.CreateAsync(new(source, package, [PasswordA], PackageCompression.None));

        await Run("Internet package provenance reaches every extracted file without source URLs", async () =>
        {
            SetZone(package, 3, "HostUrl=https://example.invalid/private-source\r\n");
            string output = Path.Combine(work, "internet");
            await PackageService.ExtractAsync(new(package, output, PasswordA));
            foreach (string file in Directory.EnumerateFiles(output, "*", SearchOption.AllDirectories)) AssertZone(file, 3);
        });
        await Run("Restricted package provenance reaches every extracted file", async () =>
        {
            SetZone(package, 4);
            string output = Path.Combine(work, "restricted");
            await PackageService.ExtractAsync(new(package, output, PasswordA));
            foreach (string file in Directory.EnumerateFiles(output, "*", SearchOption.AllDirectories)) AssertZone(file, 4);
        });
        await Run("Archive Local Machine zone cannot downgrade Internet origin and Restricted stays stronger", async () =>
        {
            SetZone(Path.Combine(source, "a.txt"), 0);
            SetZone(Path.Combine(source, "nested", "b.txt"), 4);
            string mixed = Path.Combine(work, "mixed.2pw");
            await PackageService.CreateAsync(new(source, mixed, [PasswordA], PackageCompression.None));
            SetZone(mixed, 3);
            string output = Path.Combine(work, "merged");
            await PackageService.ExtractAsync(new(mixed, output, PasswordA));
            AssertZone(Path.Combine(output, "source", "a.txt"), 3);
            AssertZone(Path.Combine(output, "source", "nested", "b.txt"), 4);
        });
        await Run("Container provenance ignores unrelated alternate streams", async () =>
        {
            SetZone(package, 3);
            File.WriteAllText(package + ":unrelated-metadata", "Do not interpret this as provenance.");
            string output = Path.Combine(work, "other-stream");
            await PackageService.ExtractAsync(new(package, output, PasswordA));
            AssertZone(Path.Combine(output, "source", "a.txt"), 3);
        });
        foreach (var format in new[] { "utf8-bom", "utf16-le", "utf16-be", "ansi-url" })
        {
            string captured = format;
            await Run("Container zone parsing supports " + format, async () =>
            {
                const string marker = "[zonetransfer]\r\nzoneid = 3\r\n";
                byte[] bytes = captured switch
                {
                    "utf8-bom" => [.. Encoding.UTF8.GetPreamble(), .. Encoding.UTF8.GetBytes(marker)],
                    "utf16-le" => [.. Encoding.Unicode.GetPreamble(), .. Encoding.Unicode.GetBytes(marker)],
                    "utf16-be" => [.. Encoding.BigEndianUnicode.GetPreamble(), .. Encoding.BigEndianUnicode.GetBytes(marker)],
                    _ => [.. Encoding.ASCII.GetBytes(marker + "HostUrl=https://example.invalid/"), 0x81, 0xff]
                };
                File.WriteAllBytes(package + ":Zone.Identifier", bytes);
                string output = Path.Combine(work, captured);
                await PackageService.ExtractAsync(new(package, output, PasswordA));
                AssertZone(Path.Combine(output, "source", "a.txt"), 3);
            });
        }
        foreach (var invalid in new[]
        {
            "[ZoneTransfer]\r\nZoneId=5\r\n",
            "[ZoneTransfer]\r\nZoneId=3\r\nzoneid=0\r\n",
            "[ZoneTransfer]\r\nZoneId=0\r\n[zonetransfer]\r\nZoneId=3\r\n",
            "[ZoneTransfer]\r\nHostUrl=https://example.invalid/\r\n",
            "[ZoneTransfer]\r\nZoneId=0\0\r\nZoneId=3\r\n",
            "[ZoneTransfer]\r\nZoneId=03\r\n",
            "[ZoneTransfer]\r\nZoneId=0\r\n[ZoneTransfer] trailing\r\nZoneId=3\r\n",
            "[ZoneTransfer]\r\nZoneId=0\r\n[ZoneTransfer ]\r\nZoneId=3\r\n",
            "[ZoneTransfer]\r\nZoneId=0\v\r\nZoneId=3\r\n",
        })
        {
            string captured = invalid;
            await Run("Invalid or ambiguous container origin never publishes plaintext: " + Convert.ToHexString(Encoding.UTF8.GetBytes(invalid)), async () =>
            {
                File.WriteAllText(package + ":Zone.Identifier", captured);
                string output = Path.Combine(work, "invalid-" + Guid.NewGuid().ToString("N"));
                await MustFail(() => PackageService.ExtractAsync(new(package, output, PasswordA)));
                Assert(!Directory.Exists(output), "Invalid origin published plaintext.");
                Assert(!Directory.EnumerateDirectories(work, ".2password-*.extracting").Any(), "Invalid origin left staged plaintext.");
            });
        }
        await Run("Oversized container provenance is rejected before extraction", async () =>
        {
            File.WriteAllBytes(package + ":Zone.Identifier", new byte[65537]);
            string output = Path.Combine(work, "oversized");
            await MustFail(() => PackageService.ExtractAsync(new(package, output, PasswordA)));
            Assert(!Directory.Exists(output), "Oversized origin published output.");
        });
        await Run("Detached launcher origin applies even when the dataset has no origin", async () =>
        {
            var (launcher, _) = await DetachedOriginFixture(work, "launcher-origin", source);
            SetZone(launcher, 3);
            string output = Path.Combine(work, "launcher-output");
            await PackageService.ExtractAsync(new(launcher, output, PasswordA));
            AssertZone(Path.Combine(output, "source", "a.txt"), 3);
        });
        await Run("Detached dataset origin applies even when the launcher has no origin", async () =>
        {
            var (launcher, data) = await DetachedOriginFixture(work, "dataset-origin", source);
            SetZone(data, 3);
            string output = Path.Combine(work, "dataset-output");
            await PackageService.ExtractAsync(new(launcher, output, PasswordA));
            AssertZone(Path.Combine(output, "source", "a.txt"), 3);
        });
        await Run("Detached source restrictions merge without lowering the dataset zone", async () =>
        {
            var (launcher, data) = await DetachedOriginFixture(work, "both-origin", source);
            SetZone(launcher, 3); SetZone(data, 4);
            string output = Path.Combine(work, "both-output");
            await PackageService.ExtractAsync(new(launcher, output, PasswordA));
            AssertZone(Path.Combine(output, "source", "a.txt"), 4);
        });
        await Run("Origin write failure removes staged plaintext without publishing output", async () =>
        {
            SetZone(package, 3);
            bool blocked = false;
            var progress = new InlineProgress<PackageProgress>(p =>
            {
                if (blocked || p.BytesProcessed == 0 || p.CurrentPath != "source/a.txt") return;
                string staging = Directory.EnumerateDirectories(work, ".2password-*.extracting").Single();
                var target = new FileInfo(Path.Combine(staging, "source", "a.txt"));
                var security = target.GetAccessControl();
                security.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User!,
                    FileSystemRights.WriteData | FileSystemRights.AppendData, AccessControlType.Deny));
                target.SetAccessControl(security);
                blocked = true;
            });
            string output = Path.Combine(work, "write-denied");
            await MustFail(() => PackageService.ExtractAsync(new(package, output, PasswordA), progress));
            Assert(blocked, "Fixture did not block the provenance write.");
            Assert(!Directory.Exists(output), "Failed provenance write published output.");
            Assert(!Directory.EnumerateDirectories(work, ".2password-*.extracting").Any(), "Failed provenance write left staged plaintext.");
        });
    }

    private static void SetZone(string path, int zone, string extra = "") =>
        File.WriteAllText(path + ":Zone.Identifier", "[ZoneTransfer]\r\nZoneId=" + zone + "\r\n" + extra);

    private static void AssertZone(string path, int zone) =>
        Assert(File.ReadAllText(path + ":Zone.Identifier") == "[ZoneTransfer]\r\nZoneId=" + zone + "\r\n", "Missing, downgraded, or unexpected provenance at " + path);

    private static async Task<(string Launcher, string Data)> DetachedOriginFixture(string directory, string name, string source)
    {
        string stub = Path.Combine(directory, name + "-stub.exe");
        byte[] stubBytes = new byte[512];
        "MZ"u8.CopyTo(stubBytes);
        File.WriteAllBytes(stub, stubBytes);
        string launcher = Path.Combine(directory, name + ".exe");
        var result = await PackageService.CreateAsync(new(source, launcher, [PasswordA], PackageCompression.None, stub, PackageLayout.Detached));
        return (launcher, result.DataPath!);
    }
}
