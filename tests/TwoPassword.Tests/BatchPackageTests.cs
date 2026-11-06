using TwoPassword.Core;

namespace TwoPassword.Tests;

internal static partial class Program
{
    private static async Task RunBatchPackageTests()
    {
        string work = Path.Combine(_root, "batch");
        string inputs = Path.Combine(work, "inputs");
        string outputs = Path.Combine(work, "outputs");
        Directory.CreateDirectory(inputs);
        Directory.CreateDirectory(outputs);
        string file = Path.Combine(inputs, "资料_日本語_🙂.txt");
        string folder = Path.Combine(inputs, "照片");
        string empty = Path.Combine(inputs, "空文件夹");
        File.WriteAllText(file, "Independent file payload: 中文🙂");
        Directory.CreateDirectory(folder);
        Directory.CreateDirectory(empty);
        File.WriteAllText(Path.Combine(folder, "photo.dat"), "Independent folder payload");
        string stub = Path.Combine(work, "template.exe");
        byte[] stubBytes = new byte[512];
        "MZ"u8.CopyTo(stubBytes);
        await File.WriteAllBytesAsync(stub, stubBytes);

        await Run("Batch mixed selection creates independent embedded packages with exact roots", async () =>
        {
            var plan = BatchPackageService.Plan([file, folder, empty], outputs);
            Assert(plan.Count == 3, "Each selected item needs its own package.");
            Assert(!Directory.EnumerateFileSystemEntries(outputs).Any(), "Planning changed the output directory.");
            for (int i = 0; i < plan.Count; i++)
            {
                var item = plan[i];
                Assert(Path.GetFileName(item.OutputPath) == Path.GetFileName(item.SourcePath) + ".protected.exe",
                    "The full input name was not retained.");
                await PackageService.CreateAsync(new(item.SourcePath, item.OutputPath, [PasswordA, PasswordB],
                    PackageCompression.Zstd, stub, PackageLayout.Embedded));
                var info = await PackageService.InspectAsync(item.OutputPath);
                Assert(!info.IsDetached && info.PasswordSlots == 2, "Batch item did not receive the chosen settings.");
                foreach (string password in new[] { PasswordA, PasswordB })
                {
                    string restored = Path.Combine(work, "embedded-" + i + "-" + (password == PasswordA ? "A" : "B"));
                    await PackageService.ExtractAsync(new(item.OutputPath, restored, password));
                    AssertBatchRoot(item.SourcePath, restored);
                }
            }
        });

        await Run("Batch plan skips executable, sidecar, directory and in-batch name collisions", () =>
        {
            string collisions = Path.Combine(work, "collisions");
            string other = Path.Combine(inputs, "other");
            Directory.CreateDirectory(collisions);
            Directory.CreateDirectory(other);
            string secondFile = Path.Combine(other, Path.GetFileName(file));
            File.WriteAllText(secondFile, "Second item with the same leaf name");
            string baseName = Path.GetFileName(file) + ".protected";
            string existingExe = Path.Combine(collisions, baseName + ".exe");
            string existingData = Path.Combine(collisions, baseName + " (2).2pw");
            string existingDirectory = Path.Combine(collisions, baseName + " (3).exe");
            File.WriteAllText(existingExe, "Executable sentinel");
            File.WriteAllText(existingData, "Sidecar sentinel");
            Directory.CreateDirectory(existingDirectory);
            var plan = BatchPackageService.Plan([file, secondFile], collisions);
            Assert(Path.GetFileName(plan[0].OutputPath) == baseName + " (4).exe" &&
                Path.GetFileName(plan[1].OutputPath) == baseName + " (5).exe", "Collision suffixes were not assigned independently.");
            Assert(File.ReadAllText(existingExe) == "Executable sentinel" && File.ReadAllText(existingData) == "Sidecar sentinel" &&
                Directory.Exists(existingDirectory), "Planning changed an existing destination.");
            Assert(Directory.EnumerateFileSystemEntries(collisions).Count() == 3, "Planning created files.");
            return Task.CompletedTask;
        });

        await Run("Batch input normalization deduplicates paths while preserving selection order", () =>
        {
            var plan = BatchPackageService.Plan([folder + Path.DirectorySeparatorChar, file,
                Path.Combine(inputs, ".", "照片"), file.ToUpperInvariant()], outputs);
            Assert(plan.Count == 2 && plan[0].SourcePath == folder && plan[1].SourcePath == file,
                "Repeated inputs created duplicate packages or changed selection order.");
            return Task.CompletedTask;
        });

        await Run("Batch retains extensions for equal file stems and distinguishes file and folder names", () =>
        {
            string nameInputs = Path.Combine(inputs, "names");
            Directory.CreateDirectory(nameInputs);
            string text = Path.Combine(nameInputs, "same.txt");
            string pdf = Path.Combine(nameInputs, "same.pdf");
            string directory = Path.Combine(nameInputs, "same");
            File.WriteAllText(text, "Text");
            File.WriteAllText(pdf, "PDF");
            Directory.CreateDirectory(directory);
            var plan = BatchPackageService.Plan([text, pdf, directory], outputs);
            Assert(plan.Select(item => Path.GetFileName(item.OutputPath)).SequenceEqual(
                new[] { "same.txt.protected.exe", "same.pdf.protected.exe", "same.protected.exe" }),
                "Extensions or directory names were lost.");
            return Task.CompletedTask;
        });

        await Run("Batch preflight rejects output inside any selected folder before creating files", async () =>
        {
            string nestedOutput = Path.Combine(folder, "nested-output");
            Directory.CreateDirectory(nestedOutput);
            await MustFail(() => Task.FromResult(BatchPackageService.Plan([file, folder], nestedOutput)));
            await MustFail(() => Task.FromResult(BatchPackageService.Plan([file, folder], folder)));
            Assert(!Directory.EnumerateFileSystemEntries(nestedOutput).Any(), "An earlier item was published inside a later source.");
        });

        await Run("Batch preflight rejects missing inputs, empty selection and non-directory output", async () =>
        {
            string invalid = Path.Combine(inputs, "missing-item");
            int before = Directory.EnumerateFileSystemEntries(outputs).Count();
            await MustFail(() => Task.FromResult(BatchPackageService.Plan([file, invalid], outputs)));
            await MustFail(() => Task.FromResult(BatchPackageService.Plan([], outputs)));
            await MustFail(() => Task.FromResult(BatchPackageService.Plan([file], file)));
            await MustFail(() => Task.FromResult(BatchPackageService.Plan([Path.GetPathRoot(inputs)!], outputs)));
            Assert(Directory.EnumerateFileSystemEntries(outputs).Count() == before, "Invalid preflight changed output files.");
        });

        await Run("Batch preflight rejects junction inputs and output ancestors", async () =>
        {
            string sourceLink = Path.Combine(work, "source-junction");
            string outputLink = Path.Combine(work, "output-junction");
            CreateJunction(sourceLink, folder);
            CreateJunction(outputLink, outputs);
            await MustFail(() => Task.FromResult(BatchPackageService.Plan([file, sourceLink], outputs)));
            await MustFail(() => Task.FromResult(BatchPackageService.Plan([file], outputLink)));
        });

        await Run("Batch long Unicode names remain valid and unique after suffix truncation", () =>
        {
            string longInputs = Path.Combine(inputs, "long");
            Directory.CreateDirectory(longInputs);
            string longFile = Path.Combine(longInputs, new string('a', 240) + "🙂-payload.txt");
            File.WriteAllText(longFile, "Long-name sentinel");
            var first = BatchPackageService.Plan([longFile], outputs)[0];
            File.WriteAllText(first.OutputPath, "Existing long-name output");
            var second = BatchPackageService.Plan([longFile], outputs)[0];
            foreach (var item in new[] { first, second })
            {
                string name = Path.GetFileName(item.OutputPath);
                Assert(name.Length <= 255, "Output exceeded the Windows filename limit.");
                _ = new System.Text.UTF8Encoding(false, true).GetBytes(name);
            }
            Assert(first.OutputPath != second.OutputPath && second.OutputPath.EndsWith(" (2).exe", StringComparison.Ordinal),
                "Truncation lost collision handling.");
            return Task.CompletedTask;
        });

        await Run("Batch detached packages have independent data files and restore only their selected item", async () =>
        {
            string detached = Path.Combine(work, "detached");
            Directory.CreateDirectory(detached);
            var plan = BatchPackageService.Plan([file, empty], detached);
            for (int i = 0; i < plan.Count; i++)
            {
                var item = plan[i];
                var result = await PackageService.CreateAsync(new(item.SourcePath, item.OutputPath, [PasswordA],
                    PackageCompression.None, stub, PackageLayout.Detached));
                Assert(result.IsDetached && result.DataPath == Path.ChangeExtension(item.OutputPath, ".2pw"),
                    "Detached package has the wrong companion file.");
                string restored = Path.Combine(work, "detached-restored-" + i);
                await PackageService.ExtractAsync(new(result.DataPath!, restored, PasswordA));
                AssertBatchRoot(item.SourcePath, restored);
            }
            Assert(Directory.EnumerateFiles(detached).Count() == 4, "Detached batch must contain one pair per input.");
        });

        await Run("Batch cancellation keeps completed packages and removes the canceled item's temporary files", async () =>
        {
            string cancelOutput = Path.Combine(work, "cancel-output");
            Directory.CreateDirectory(cancelOutput);
            var plan = BatchPackageService.Plan([file, empty], cancelOutput);
            await PackageService.CreateAsync(new(plan[0].SourcePath, plan[0].OutputPath, [PasswordA], StubPath: stub));
            using var cancellation = new CancellationTokenSource();
            bool temporaryPayloadSeen = false;
            RecoveryWriter cancelRecovery = (payload, _, _, _) =>
            {
                temporaryPayloadSeen = File.Exists(payload);
                cancellation.Cancel();
            };
            await MustCancel(() => PackageService.CreateAsync(new(plan[1].SourcePath, plan[1].OutputPath, [PasswordA],
                StubPath: stub, Layout: PackageLayout.Detached, Recovery: cancelRecovery), cancellationToken: cancellation.Token));
            Assert(temporaryPayloadSeen, "Cancellation did not exercise partial payload cleanup.");
            Assert(Directory.EnumerateFileSystemEntries(cancelOutput).SequenceEqual(new[] { plan[0].OutputPath }),
                "Cancellation removed completed work or left an incomplete item.");
            string restored = Path.Combine(work, "cancel-completed-restored");
            await PackageService.ExtractAsync(new(plan[0].OutputPath, restored, PasswordA));
            AssertBatchRoot(file, restored);
        });

        await Run("Batch item failure keeps completed packages and removes incomplete payload and recovery files", async () =>
        {
            string failedOutput = Path.Combine(work, "failed-output");
            Directory.CreateDirectory(failedOutput);
            var plan = BatchPackageService.Plan([file, empty], failedOutput);
            await PackageService.CreateAsync(new(plan[0].SourcePath, plan[0].OutputPath, [PasswordA], StubPath: stub));
            RecoveryWriter failRecovery = (_, _, output, _) =>
            {
                output.WriteByte(42);
                throw new IOException("Synthetic recovery failure");
            };
            await MustFail(() => PackageService.CreateAsync(new(plan[1].SourcePath, plan[1].OutputPath, [PasswordA],
                StubPath: stub, Layout: PackageLayout.Detached, Recovery: failRecovery)));
            Assert(Directory.EnumerateFileSystemEntries(failedOutput).SequenceEqual(new[] { plan[0].OutputPath }),
                "Failure removed completed work or left incomplete output.");
            string restored = Path.Combine(work, "failed-completed-restored");
            await PackageService.ExtractAsync(new(plan[0].OutputPath, restored, PasswordA));
            AssertBatchRoot(file, restored);
        });

        await Run("Batch execution preserves a destination created after planning", async () =>
        {
            string raceOutput = Path.Combine(work, "race-output");
            Directory.CreateDirectory(raceOutput);
            var item = BatchPackageService.Plan([file], raceOutput)[0];
            string sidecar = Path.ChangeExtension(item.OutputPath, ".2pw");
            File.WriteAllText(sidecar, "Concurrent sidecar sentinel");
            await MustFail(() => PackageService.CreateAsync(new(item.SourcePath, item.OutputPath, [PasswordA],
                StubPath: stub, Layout: PackageLayout.Detached)));
            Assert(!File.Exists(item.OutputPath) && File.ReadAllText(sidecar) == "Concurrent sidecar sentinel",
                "A destination created after planning was overwritten.");
            var next = BatchPackageService.Plan([file], raceOutput)[0];
            Assert(next.OutputPath != item.OutputPath, "A new plan did not account for the new collision.");
        });
    }

    private static void AssertBatchRoot(string source, string restored)
    {
        string root = Path.Combine(restored, Path.GetFileName(source));
        Assert(Directory.EnumerateFileSystemEntries(restored).SequenceEqual(new[] { root }),
            "An independent package contains another selected root.");
        if (Directory.Exists(source)) AssertTreeEqual(source, root);
        else Assert(File.ReadAllBytes(source).SequenceEqual(File.ReadAllBytes(root)), "Independent file bytes changed.");
    }
}
