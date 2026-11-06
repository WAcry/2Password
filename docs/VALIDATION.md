# Validation evidence

[English](VALIDATION.md) · [简体中文](VALIDATION.zh.md)

This document records reproducible verification performed on Windows x64 on 2026-11-06 and the checks included in the release pipeline. All tests use generated synthetic files and test-only passwords. Test code, the independent format parser, and build scripts are kept in the repository. Raw JSON reports are stored locally under `artifacts/`; GitHub Actions also retains the regular reports in the `verification-reports` build artifact.

See [Security design](SECURITY.md) for cryptographic assumptions, filesystem restrictions, and the threat model.

## Security boundary verification (2026-11-06)

The local build completed with **0 warnings and 0 errors**. Core tests passed **253/253**, recovery tests **34/34**, shared localization tests **15/15**, and WPF integration tests **8/8**, with no Core tests skipped. The shared catalogs contain **197 pairs** covering **197 actual source keys**. This WPF run uses a synthetic MZ template and does not register menus. The multiselect, standalone-package, installation, and large-file results below retain their stated verification scope.

- `PasswordIndependenceTests.cs`: independent decoding of password slots 2 and 16 with verification of the decrypted content; rejection of direct reuse of a known wrapping key or content key across slots; agreement between candidate checks with and without a known content key; and the 1024/1025 UTF-16-unit boundary for ASCII and non-BMP passwords.
- `ProvenanceTests.cs`: Internet/Restricted markers on the input package reach every extracted file; archived local-zone claims cannot lower the restriction. Coverage includes separate EXE and dataset origins, UTF-8/UTF-16/ANSI URLs, ambiguous INI syntax, duplicate fields, control characters, size limits, unrelated ADS, and cleanup without publishing plaintext when marker writes fail.
- `Par2MetadataTests.cs`: 64,000 repeated descriptions, repeated checksum tables, and Creator packets retain a bounded selected-packet set and the true end position; separate candidate-count/body-size/recovery-set budgets; conflicts, original packet order, and scan cancellation.
- Recovery integration tests cover normal prechecking, direct and prechecked repair of damaged packages, detached-package provenance, and rejection of invalid origins without entering recovery.

The same synthetic audit package containing **8,699,708 bytes and 64,000 additional FileDesc packets** passed the local application's command-line check with no damaged blocks in approximately **1.05 seconds**, including process startup. This is a single local observation, not a CI timing threshold; regression tests assert deduplication results, budgets, and cancellation semantics.

Reproduce with `dotnet run --project tests/TwoPassword.Tests -c Release`, or use `--par2-only` / `--provenance-only` for the corresponding subset and its prerequisite tests. Additional local logs are `artifacts/security-*-tests.log`, `artifacts/security-build.log`, and `artifacts/security-original-sample-*.json`.

## Additional multiselect encryption verification (2026-11-06)

This change adds independent packaging of each selected item and an Explorer multiselect entry point, while preserving compatibility with the encryption format and single-item creation flow. The full Core regression suite passed **218/218**, recovery tests **32/32**, shared localization tests **15/15**, WPF integration tests using the executable template published for this change **8/8**, and standalone EXE/CLI tests **15/15**. The installation and large-file figures below come from earlier verification; installation and large-file tests were not rerun for this change.

- `BatchPackageTests.cs`: independent restoration of mixed file/folder selections, two passwords, EXE/.2pw pairing, duplicate and long Unicode filenames, output boundaries, conflicts arising after planning, and cleanup after cancellation or failure.
- `ExplorerSelectionBrokerTests.cs` / `GuiLaunchOptionsTests.cs`: preservation of the complete selection and options across an elevation restart, 32 concurrent requests, initialization waits, isolation by user/session/executable copy, malformed messages, and instance shutdown.
- `TwoPassword.Gui.Tests`: a real WPF Dispatcher drives startup with multiple selections, mixed drag and drop, adding/deduplicating/removing items, editing selections whose inputs no longer exist, independent decryption with SHA-256 comparison, detached output, preservation of completed packages after a later item fails or is canceled, and continuation of remaining items without recreating completed ones. The default is a synthetic MZ template; pass `--stub <published EXE>` to check a real template. The tests do not register Explorer menus or change user preferences.
- Actual processes also simulated 8 concurrent `--explorer-encrypt` calls, covering mixed paths, Chinese/space/emoji names, later additions, and deduplication. All 6 checks passed; one process and one window ultimately retained the entire selection. This verifies the receiving path for menu commands; the Explorer context menu itself was not clicked.

The entry point still uses the legacy Windows menu. `MultiSelectModel=Player` has a default limit of 100 items; larger selections can use the application's dialogs or drag and drop. See [Microsoft's selection model documentation](https://learn.microsoft.com/en-us/windows/win32/shell/how-to-employ-the-verb-selection-model).

Reproduce with `pwsh -File scripts/Test-Multiselect.ps1`. Reports are written to `artifacts/test-results.json` and `artifacts/multiselect-results.json`; the cross-process checks for this run are recorded in `artifacts/multiselect-explorer-qa/20261106-smoke-8c741e/results.json`.

## Environment and reproduction

The local large-file verification environment was Windows `10.0.26300`, x64, .NET SDK `10.0.114`, and runtime `.NET 10.0.14`. The release pipeline also performs regular verification in GitHub's hosted `windows-latest` environment.

```powershell
dotnet restore 2Password.slnx --locked-mode
dotnet build 2Password.slnx -c Release --no-restore
dotnet run --project tests/TwoPassword.Tests -c Release --no-build
dotnet run --project tests/TwoPassword.Recovery.Tests -c Release --no-build
dotnet run --project tests/TwoPassword.Localization.Tests -c Release --no-build
dotnet run --project tests/TwoPassword.Gui.Tests -c Release --no-build
pwsh -File scripts/Build-Release.ps1
pwsh -File scripts/Test-Standalone.ps1
pwsh -File scripts/Test-Installer.ps1
```

`Build-Release.ps1` includes all four test projects above by default. `-SkipTests` is only for local repackaging after verification; the release pipeline does not use it. Test programs return a nonzero exit code on failure, which blocks publication in the pipeline.

The Release build for this run had 0 warnings and 0 errors. Regular verification results were:

| Check | Passed | Failed |
| --- | ---: | ---: |
| Independent security and file round trips | 218 | 0 |
| Multiselect WPF interface and independent package restoration | 8 | 0 |
| Actual PAR2 and on-demand recovery | 32 | 0 |
| Shared language resources and cross-language operations | 15 | 0 |
| Actual self-contained EXE / CLI | 15 | 0 |
| Chinese installation, English replacement, and uninstallation (earlier baseline) | 52 | 0 |

Shared localization verification covers 195 resource pairs and 195 actual `Text.Get` keys in source code. The application's own interface has another 163 resource pairs.

## Regular security and restoration verification

The main test project, `tests/TwoPassword.Tests`, contains **218 cases; all passed in this local rerun, with none skipped**. Its main areas of coverage include:

| Area | Actual checks |
| --- | --- |
| Cryptographic primitives | RFC 9106 Argon2id standard vector; published AES-256-GCM vectors and rejection of incorrect tags |
| Independent passwords | Several passwords each restore the same complete file tree; the 16th password slot; empty passwords, single-character passwords, and mixed slots; empty input cannot open packages with only nonempty passwords; incorrect, null, oversized, and invalid-Unicode passwords |
| Independent format checks | Independently written initial V1 container encoder and decoder cross-checked against production code; uniform password encoding distinguishes the empty string, spaces, and U+0000; rejection of unknown schemas |
| Names and contents | Chinese, Japanese, Arabic, emoji, NFC/NFD distinctions, paths longer than 1,000 characters; SHA-256 for every file, empty directories, and empty files |
| Compression | Zstd (Lv.3), Brotli (Lv.6), and no compression; truncation, trailing data, concatenated frames, incorrect lengths, oversized windows, malformed frames, and decompression output bounds |
| Authenticated structure | Tampering with contents, tags, lengths, ordering, and the end marker; truncation, duplicate and extra blocks; damage to unused password slots |
| Metadata redundancy | Survival of each individual header or trailer copy; rejection of valid but conflicting copies |
| Embedded recovery data | Rejection when recovery-data lengths disagree with file length; both the production reader and independent reference reader can skip recovery data after the ciphertext |
| Detached files | Missing or substituted data files, incorrect header identity, absolute paths, traversal, recursive references, and filename restrictions |
| Malicious archives | Traversal, device names, reparse points, case collisions, duplicate entries, malformed metadata, and resource limits |
| Operation integrity | Cancellation, source changes, existing destinations, cleanup after failure, and protection of the final commit |
| PAR2 metadata | 20 cases: default block size, resuming at the next packet after corruption or truncation, mixed recovery sets, conflicting file descriptions, 6 invalid source filenames, length and block-size mismatches, FileID validation, oversized allocations, unknown packet types, duplicate recovery blocks, and cancellation |
| Workspace permissions | 22 cases, including real NTFS permissions and child-directory inheritance, permissive parents, concurrent creation, and maliciously constructed raw ACLs; the capability policy explicitly rejects filesystems without persistent ACLs |
| Administrator retry | 5 cases covering 36 combinations of compression, layout, and recovery percentage, plus paths, the repair entry point, and precheck options for self-extracting EXEs and external packages; passwords are not passed and UAC is not triggered |
| Trailer discovery memory | 4 MiB sample blocks and independent MD5 reference values verify exclusion of empty blocks, padding of the last block with zeros, offsets, truncation, and cancellation; managed allocation during sampling stays below 2 MiB |

Permission tests read back actual NTFS security descriptors and check unexpected principals, null or unprotected DACLs, incorrect owners, callback/object ACEs, and incorrect inheritance or permission scope. FAT/exFAT rejection is checked with simulated capability flags; no actual FAT/exFAT media were mounted.

## Actual PAR2 and on-demand repair

`tests/TwoPassword.Recovery.Tests` invokes the actual embedded `par2cmdline-turbo 1.5.0` process and covers these behaviors:

- Recovery data is generated for filenames containing Chinese, Japanese, and emoji, and stored inside the encrypted package without creating additional files.
- Healthy packages extract directly, with no recovery progress callbacks and no PAR2 scan.
- An incorrect password fails immediately; even when ciphertext is also damaged, an incorrect password does not cause PAR2 to run.
- Oversized and invalid-Unicode passwords are rejected before the precheck. Empty passwords are checked against the actual slots and cannot trigger recovery when there is no empty-password slot.
- PAR2 runs when the user explicitly requests a precheck; an existing restoration destination is always rejected first.
- Damage to packets in the recovery data does not prevent a healthy encrypted package from passing authentication, extraction, or verification.
- Ciphertext bytes are actually flipped: AES-GCM rejection is confirmed first, then a copy is repaired and fully extracted while the original is left unchanged. In-place repair reproduces the original SHA-256.
- A package with an empty-password slot can still use empty input to repair a copy and extract accurately after ciphertext damage, without changing the original.
- An unsupported schema cannot be reported as a valid package or receive a rewritten trailer even with correct PAR2 data. The reconstructed header is validated before the original file is written; rejection leaves its original SHA-256 unchanged.
- Extraction can still complete using recovery data when all three header copies have been zeroed.
- With insufficient redundancy, verification and repair both return exit code 2, leave the damaged file unchanged, and produce no extraction output.
- Verification of a read-only source file does not change its read-only attribute.
- Both a single EXE and the `.2pw` in a two-file package carry recovery data and support extraction and in-place repair after damage.
- A same-named `.2pw` from another package must be rejected for both extraction and writeback even if it uses the same password and its data can be repaired. Cases cover ciphertext damage, damage to all three header copies, a missing trailer, and both precheck modes. Correctly paired data can still be repaired and restored accurately even when all three headers are damaged.
- If all 16 fixed discovery sample blocks are damaged and the trailer is then lost, sufficient recovery data still allows discovery, accurate extraction from a repaired copy, and in-place repair to the original SHA-256. A synthetic package of about 3 MiB checks the three candidate starting offsets; no additional large-file test was added.
- Missing trailers: the last 1,192 bytes are removed from a `.2pw`; the last 4 KiB of an EXE are zeroed, its first header copy is also cleared, and two false `2PWHDR01` markers are placed in its program section. Both cases can be located by scanning and extracted. Repair writes a new trailer, with encrypted data matching the original. A file truncated into its encrypted data reports failure without guessing.
- Cancellation leaves no workspace behind. The complete corresponding PAR2 source is exported offline and checked against its pinned SHA-256; an existing export file is never overwritten.

These tests directly verify the default extraction performance policy: **healthy files receive no additional whole-package PAR2 read, while authentication always runs; extraction is repeated only after damage is detected and repair actually completes.**

## Actual standalone EXEs

`scripts/Test-Standalone.ps1` invokes the published single-file EXE, then the encrypted EXEs it creates. It copies an extraction EXE by itself to another directory and configures the child process with:

- Empty `DOTNET_ROOT` / `DOTNET_ROOT_X64` directories.
- A `PATH` containing only the Windows system directory.
- A separate cache for native runtime components.
- .NET host tracing to check self-contained mode and the bundled `System.Private.CoreLib.dll`.

Actual process checks cover standalone creation and parsing, complete file-tree restoration with each password, an incorrect password producing no destination, overwrite refusal, and uncompressed packages. A password-free Brotli (Lv.6) EXE copied to an isolated directory restores multilingual names and every file byte correctly with either empty standard input or an empty line. For recovery data, both a damaged `.2pw` in a two-file package and a damaged single EXE can be decrypted while their originals remain unchanged; `--repair-recovery` repairs them in place to their original bytes. After the last 4 KiB of an EXE are zeroed, the portable application can verify it, decrypt it, and write a new trailer, after which the repaired EXE can decrypt itself again.

The script also checks English and Chinese CLI help, password errors in both languages in reports, and continued availability of Chinese satellite resources after copying. The second password includes a leading U+FEFF and leading and trailing spaces. CRLF is appended at the end of input to verify that only the input line terminator is removed and the password itself is preserved.

The tests run in isolated processes on the local machine. Actual execution and runtime traces confirm that the EXEs do not depend on an installed .NET runtime.

## English and Chinese resources

`tests/TwoPassword.Localization.Tests` checks matching shared resource keys and format placeholders, default language fallback, explicit language switching, culture inheritance by background workers, password error types and languages, and identical bytes and filenames when creating in English and extracting in Chinese. It also scans Core/Recovery resource references to catch missing user-visible errors.

Application interface resources are additionally covered by UI builds and actual window checks. Switching languages changes only displayed text; it does not transform passwords, user paths, or file contents.

## Actual interface operations

The actual published application was used to select a folder, create a package with two passwords, use Zstd, choose detached layout, generate PAR2 recovery data, and extract with the second password containing Japanese text and leading and trailing spaces. Every file's SHA-256 matched, and empty directories and same-named files in different subdirectories were preserved. When creation or extraction destinations conflicted, existing sentinel files remained unchanged and suggested names with the `(2)` suffix paired correctly.

UI Automation drove actual checks of the English and Chinese interfaces at 125% DPI, once in the light theme and once in the dark theme: routing to encryption, decryption, or repair according to the opened file type; scrolling at the minimum 520×500 window size; maximized-window margins; inline password-row validation for duplicates and mismatched confirmation; incorrect-password messages; and progress and completion pages for encryption, decryption, and repair. Window screenshots are stored in `assets/screenshots/` and contain only empty fields.

Additional interface checks after recovery data was embedded covered the GitHub icon in the title bar; a default recovery setting of 5% with encryption producing only one EXE; opening an EXE with damaged ciphertext on the repair page, checking it, and repairing it; displaying recovery-data size for an EXE with a zeroed trailer and reporting that its trailer is damaged, its encrypted data is intact, and repair is possible; and showing damage on the decryption page for a two-file package with a zeroed `.2pw` trailer, followed by successful decryption after password entry. A one-character password passed interface validation and completed encryption, and the CLI then extracted the package with that password.

Elevation and Explorer menus were also operated directly. When encrypting or decrypting to `C:\Program Files`, a "Retry as administrator" action appeared beside the message. After clicking it and accepting UAC, the new elevated window retained the source and destination, completed encryption and decryption in Program Files, showed "Administrator" in its title, and no longer offered "Run as administrator" in its menu. The elevated window accepted files dragged from a normal-privilege Explorer window. After enabling the context menu, the relevant menu entries for ordinary files, folders, and `.2pw` files were checked in Explorer; disabling the menu removed all its registry entries.

## Installation, upgrades, and uninstallation

WiX builds use `-wx` to treat warnings as errors. `scripts/Test-Installer.ps1` performs actual MSI installation for this project's product identity; it does not invoke `Win32_Product` or scan or repair other software.

Local bilingual installation verification completed **52 checks**. Chinese installation, replacement with the English installer of the same version, and uninstallation all returned exit code `0`. Checks included:

- MSI product identity, per-user installation scope, and standard and custom wizard text in English and Chinese.
- A custom installation directory containing Chinese, Japanese, and spaces.
- Installed SHA-256 values for the application, both README files, and third-party notices.
- Remembering the installation directory when the English version replaces the Chinese version, with only one registered product remaining.
- Start menu shortcuts, HKCU markers, uninstall registration, and removal.
- Preservation during uninstallation of files added by the user inside the installation directory.
- Explorer context menu entries written by the installed application with `--explorer-menu on` point to the installation directory, survive replacement with the English installer, and are removed on uninstallation.
- Sentinel hashes for project source files match before and after testing.

Shortcut verification uses the Windows volume identity and full 128-bit file identity to confirm that the shortcut actually targets the installed program and working directory, with no extra arguments. Original paths, resolved paths, and identities are recorded in the diagnostic report. Actual NTFS 8.3 aliases are correctly recognized as the same object, while a different file or missing target is rejected.

The script refuses to overwrite an existing user installation or existing 2Password Explorer menu entries, so a real installation is not mistaken for a temporary test environment.

## Large files and resource use

Large-file tests run separately to avoid writing tens of GiB on every commit:

```powershell
pwsh -File scripts/Test-LargeFiles.ps1
```

Allow at least approximately 30 GiB of free space. The tests construct sparse source files with nonzero random markers at the 2/4/8 GiB boundaries and at the end, then actually read, encrypt, and extract them. The uncompressed test writes a ciphertext data file larger than 4 GiB.

Actual local measurements from 2026-11-06:

| Test | Source bytes | Output | Creation time | Extraction time | Result |
| --- | ---: | --- | ---: | ---: | --- |
| No compression + automatic layout | 4,423,942,144 | 66,762,374-byte launcher + 4,424,069,228-byte `.2pw` | 5.38 seconds | 7.57 seconds | Source and restored lengths and full SHA-256 match |
| Zstd + automatic layout | 8,589,934,715 | 67,434,976-byte embedded EXE | 6.43 seconds | 21.04 seconds | Length and full SHA-256 match for the PAX file larger than 8 GiB |

The observed peak working set for the entire test process was **413,523,968 bytes (about 394 MiB)**; peak managed memory was 281,612,328 bytes. Timing depends on local storage, caches, sparse files, and highly compressible data. These numbers describe only this dataset on this machine.

The large-file cases call the production Core API and use a snapshot of the published EXE from the time of testing as the template. They do not generate recovery data, and these large packages were not executed directly; see the earlier standalone-EXE section for actual launch verification.

### Windows loader boundary

Loading behavior was also checked with an actual Windows executable and sparse appended data:

| Total EXE bytes | Local result |
| ---: | --- |
| 2,147,483,649 | Started successfully, exit code 0 |
| 4,294,967,295 | Started successfully, exit code 0 |
| 4,294,967,296 | Rejected by Windows as not a valid Win32 application |

Automatic layout therefore decides whether to detach based on the **final EXE size**, rather than simply using the uncompressed source size. Ciphertext above that limit can be stored in a `.2pw` file using 64-bit lengths.

## Verification scope

The following have not been tested and are outside the design goals: recovery from every possible distribution of damage, preservation of all NTFS metadata, defense against malicious processes running as the same user, consistent VSS snapshots, and transactional commits of multiple files during power loss. See the security document for boundaries involving administrator privileges, malicious kernels, crash dumps, and system backups.

Dependency versions, NuGet content hashes, and digests for the PAR2 binary and source are pinned in the repository. NuGet vulnerability checks reported no packages with known vulnerabilities. Release files have SHA-256 checksums and no Authenticode signature.
