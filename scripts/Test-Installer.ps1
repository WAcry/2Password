#Requires -Version 7.0
[CmdletBinding()]
param(
    [string]$Msi,
    [string]$UpgradeMsi
)

# Exercise only this product. Never enumerate Win32_Product (which can repair
# unrelated products), and refuse to replace any existing installation.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = Split-Path -Parent $PSScriptRoot
$expectedUpgrade = '{34DC4355-F21B-4BEA-9EE8-3318C906D5B8}'
$reportPath = Join-Path $repo 'artifacts/installer-results.json'
$checks = [System.Collections.Generic.List[object]]::new()
$started = [DateTime]::UtcNow
$installExit = $null
$uninstallExit = $null
$upgradeExit = $null
$attemptedInstall = $false
$productCode = $null
$failure = $null
$workspace = $null
$mutex = $null
$ownsMutex = $false
$packageName = $null
$productVersion = $null
$expectedHashes = @{}
$sourceSentinels = @{}
$packages = [System.Collections.Generic.List[object]]::new()
$attemptedProducts = [System.Collections.Generic.List[string]]::new()
$shortcutDiagnostics = $null

function Assert-Check([string]$Name, [bool]$Condition, [string]$Detail = '') {
    $checks.Add([pscustomobject]@{ Name = $Name; Passed = $Condition; Detail = $Detail })
    if (-not $Condition) { throw "Installer check failed: $Name. $Detail" }
    Write-Host "PASS $Name"
}

function Invoke-Msi([string[]]$Arguments) {
    $info = [System.Diagnostics.ProcessStartInfo]::new()
    $info.FileName = Join-Path $env:SystemRoot 'System32/msiexec.exe'
    $info.UseShellExecute = $false
    # msiexec has its own property parser: it requires PROPERTY="value",
    # whereas ProcessStartInfo.ArgumentList emits "PROPERTY=value with spaces".
    # This is a direct process call (no shell). Windows paths cannot contain ".
    $tokens = foreach ($argument in $Arguments) {
        if ($argument.Contains('"') -or $argument.Contains([char]0)) {
            throw 'An MSI argument contains a prohibited quote or NUL.'
        }
        if ($argument -match '^/[A-Za-z*]+$') {
            $argument
        } elseif ($argument -match '^([A-Z][A-Z0-9_]*)=(.*)$') {
            $Matches[1] + '="' + $Matches[2] + '"'
        } else { '"' + $argument + '"' }
    }
    $info.Arguments = $tokens -join ' '
    $process = [System.Diagnostics.Process]::Start($info)
    try {
        $process.WaitForExit()
        return $process.ExitCode
    } finally { $process.Dispose() }
}

function Same-Path([string]$First, [string]$Second) {
    return Same-PathIdentity (Get-PathIdentity $First) (Get-PathIdentity $Second)
}

function Get-PathIdentity([string]$Path) {
    try {
        $identity = [TwoPassword.InstallerSmoke.NativeMsi]::ResolveExistingPath($Path)
        return [pscustomobject]@{
            InputPath = $Path
            FinalPath = $identity.FinalPath
            VolumeSerial = $identity.VolumeSerial
            FileId = $identity.FileId
            Error = $null
        }
    } catch {
        return [pscustomobject]@{
            InputPath = $Path
            FinalPath = $null
            VolumeSerial = $null
            FileId = $null
            Error = $_.Exception.Message
        }
    }
}

function Same-PathIdentity($First, $Second) {
    # An 8.3 name, junction, or drive alias may identify the same object.
    # Compare native identities, not hashes or display strings. An unresolved
    # path or a different existing file/directory always fails this check.
    return (
        $null -eq $First.Error -and $null -eq $Second.Error -and
        -not [string]::IsNullOrEmpty($First.FileId) -and
        $First.VolumeSerial -ceq $Second.VolumeSerial -and
        $First.FileId -ceq $Second.FileId
    )
}

function Read-Package([string]$Path) {
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $native = [TwoPassword.InstallerSmoke.NativeMsi]
    $code = $native::GetProperty($resolved, 'ProductCode')
    $language = $native::GetProperty($resolved, 'ProductLanguage')
    $culture = if ($language -eq '2052') { 'zh-CN' } else { 'en-US' }
    Assert-Check "MSI belongs to 2Password ($culture)" (
        $native::GetProperty($resolved, 'UpgradeCode') -eq $expectedUpgrade -and
        $native::GetProperty($resolved, 'ProductName') -eq '2Password' -and
        $native::GetProperty($resolved, 'Manufacturer') -eq 'David Ziyuan Zhang' -and
        $code -match '^\{[0-9A-Fa-f-]{36}\}$'
    )
    Assert-Check "Supported MSI language ($culture)" ($language -in '2052','1033')
    Assert-Check "Per-user package without elevation requirement ($culture)" (
        $native::GetProperty($resolved, 'ALLUSERS') -eq '' -and
        ($native::SummaryFlags($resolved) -band 8) -ne 0
    )
    $launchText = $native::QueryScalar($resolved, 'SELECT `Description` FROM `LaunchCondition` WHERE `Condition`=''Installed OR VersionNT64''')
    $shortcutText = $native::QueryScalar($resolved, 'SELECT `Description` FROM `Shortcut` WHERE `Shortcut`=''StartMenuShortcut''')
    $nextText = $native::QueryScalar($resolved, 'SELECT `Text` FROM `Control` WHERE `Dialog_`=''WelcomeDlg'' AND `Control`=''Next''')
    if ($culture -eq 'zh-CN') {
        $localized = $launchText -eq '2Password 需要 64 位 Windows。' -and
            $shortcutText -eq '多密码加密与独立解包' -and $nextText -match '下一步'
    } else {
        $localized = $launchText -eq '2Password requires 64-bit Windows.' -and
            $shortcutText -eq 'Multi-password encryption and standalone extraction' -and $nextText -match 'Next'
    }
    Assert-Check "Custom messages and standard wizard are localized ($culture)" $localized
    $upgradeAttributes = $native::QueryScalar($resolved, 'SELECT `Attributes` FROM `Upgrade` WHERE `ActionProperty`=''WIX_UPGRADE_DETECTED''')
    $upgradeLanguage = $native::QueryScalar($resolved, 'SELECT `Language` FROM `Upgrade` WHERE `ActionProperty`=''WIX_UPGRADE_DETECTED''')
    Assert-Check "Same-version language switch replaces the previous product ($culture)" (
        $upgradeLanguage -eq '' -and ([int]$upgradeAttributes -band 512) -ne 0
    )
    $removeSequence = [int]$native::QueryScalar($resolved, 'SELECT `Sequence` FROM `InstallExecuteSequence` WHERE `Action`=''RemoveExistingProducts''')
    $initializeSequence = [int]$native::QueryScalar($resolved, 'SELECT `Sequence` FROM `InstallExecuteSequence` WHERE `Action`=''InstallInitialize''')
    $finalizeSequence = [int]$native::QueryScalar($resolved, 'SELECT `Sequence` FROM `InstallExecuteSequence` WHERE `Action`=''InstallFinalize''')
    Assert-Check "Upgrade removal participates in rollback ($culture)" (
        $removeSequence -gt $initializeSequence -and $removeSequence -lt $finalizeSequence
    )
    return [pscustomobject]@{
        Path = $resolved
        Name = (Split-Path -Leaf $resolved)
        ProductCode = $code
        Version = $native::GetProperty($resolved, 'ProductVersion')
        Culture = $culture
    }
}

try {
    if (-not $IsWindows -or -not [Environment]::Is64BitProcess) {
        throw 'Run this test in 64-bit PowerShell 7 on Windows.'
    }
    if (-not ('TwoPassword.InstallerSmoke.NativeMsi' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
namespace TwoPassword.InstallerSmoke {
    public sealed class PathIdentity {
        public string FinalPath { get; set; }
        public string VolumeSerial { get; set; }
        public string FileId { get; set; }
    }
    public static class NativeMsi {
        [StructLayout(LayoutKind.Sequential)]
        struct FileIdInfo {
            public ulong VolumeSerial;
            public ulong FileIdLow;
            public ulong FileIdHigh;
        }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security,
            uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder path, uint size, uint flags);
        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int informationClass,
            out FileIdInfo information, uint size);
        [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        static extern uint MsiOpenDatabaseW(string path, IntPtr mode, out uint database);
        [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        static extern uint MsiDatabaseOpenViewW(uint database, string sql, out uint view);
        [DllImport("msi.dll", ExactSpelling = true)]
        static extern uint MsiViewExecute(uint view, uint record);
        [DllImport("msi.dll", ExactSpelling = true)]
        static extern uint MsiViewFetch(uint view, out uint record);
        [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        static extern uint MsiRecordGetStringW(uint record, uint field, StringBuilder value, ref uint size);
        [DllImport("msi.dll", ExactSpelling = true)]
        static extern uint MsiCloseHandle(uint handle);
        [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        static extern uint MsiEnumRelatedProductsW(string upgrade, uint reserved, uint index, StringBuilder product);
        [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        public static extern int MsiQueryProductStateW(string product);
        [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        static extern uint MsiGetSummaryInformationW(uint database, string path, uint updateCount, out uint summary);
        [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        static extern uint MsiSummaryInfoGetPropertyW(uint summary, uint property, out uint dataType,
            out int integerValue, out long fileTime, StringBuilder value, ref uint size);

        static void Check(uint result, string operation) {
            if (result != 0) throw new Win32Exception((int)result, operation);
        }
        public static PathIdentity ResolveExistingPath(string path) {
            if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
                throw new ArgumentException("Expected an absolute, nonempty existing path.");
            string full = Path.GetFullPath(path);
            string extended = full.StartsWith(@"\\?\", StringComparison.Ordinal) ? full :
                full.StartsWith(@"\\", StringComparison.Ordinal) ? @"\\?\UNC\" + full.Substring(2) : @"\\?\" + full;
            // FILE_READ_ATTRIBUTES, sharing read/write/delete, OPEN_EXISTING.
            // BACKUP_SEMANTICS permits directory handles without changing ACLs.
            using var handle = CreateFileW(extended, 0x80, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero);
            if (handle.IsInvalid)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Open path for shortcut verification: " + path);
            var final = new StringBuilder(512);
            uint length = GetFinalPathNameByHandleW(handle, final, (uint)final.Capacity, 0);
            if (length == 0)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Resolve final path: " + path);
            if (length >= final.Capacity) {
                if (length > 32768) throw new IOException("Resolved path exceeds Windows path limits.");
                final.Capacity = checked((int)length + 1);
                length = GetFinalPathNameByHandleW(handle, final, (uint)final.Capacity, 0);
                if (length == 0 || length >= final.Capacity)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Resolve bounded final path: " + path);
            }
            // FileIdInfo (18) supplies the full 128-bit ID, including on ReFS.
            if (!GetFileInformationByHandleEx(handle, 18, out FileIdInfo identity, (uint)Marshal.SizeOf<FileIdInfo>()))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Read filesystem object identity: " + path);
            if (identity.FileIdLow == 0 && identity.FileIdHigh == 0)
                throw new IOException("The filesystem returned no usable object identity.");
            return new PathIdentity {
                FinalPath = final.ToString(),
                VolumeSerial = identity.VolumeSerial.ToString("X16"),
                FileId = identity.FileIdHigh.ToString("X16") + identity.FileIdLow.ToString("X16")
            };
        }
        public static string GetProperty(string path, string property) {
            if (!System.Text.RegularExpressions.Regex.IsMatch(property, "^[A-Za-z][A-Za-z0-9_]*$"))
                throw new ArgumentException("Invalid property name.");
            return QueryScalar(path, "SELECT \u0060Value\u0060 FROM \u0060Property\u0060 WHERE \u0060Property\u0060='" + property + "'");
        }
        public static string QueryScalar(string path, string sql) {
            uint database = 0, view = 0, record = 0;
            try {
                Check(MsiOpenDatabaseW(path, IntPtr.Zero, out database), "Open MSI read-only");
                Check(MsiDatabaseOpenViewW(database, sql, out view), "Read MSI database");
                Check(MsiViewExecute(view, 0), "Execute MSI query");
                uint fetched = MsiViewFetch(view, out record);
                if (fetched == 259) return "";
                Check(fetched, "Fetch MSI property");
                var value = new StringBuilder(4096);
                uint size = 4096;
                Check(MsiRecordGetStringW(record, 1, value, ref size), "Read bounded MSI property");
                return value.ToString();
            } finally {
                if (record != 0) MsiCloseHandle(record);
                if (view != 0) MsiCloseHandle(view);
                if (database != 0) MsiCloseHandle(database);
            }
        }
        public static string[] RelatedProducts(string upgrade) {
            var products = new System.Collections.Generic.List<string>();
            for (uint index = 0; index < 100; index++) {
                var product = new StringBuilder(39);
                uint result = MsiEnumRelatedProductsW(upgrade, 0, index, product);
                if (result == 259) return products.ToArray();
                Check(result, "Enumerate only 2Password related products");
                products.Add(product.ToString());
            }
            throw new InvalidOperationException("Unexpected number of related products.");
        }
        public static int SummaryFlags(string path) {
            uint summary = 0;
            try {
                Check(MsiGetSummaryInformationW(0, path, 0, out summary), "Read MSI summary");
                uint size = 0, type;
                int value;
                long time;
                Check(MsiSummaryInfoGetPropertyW(summary, 15, out type, out value, out time, null, ref size), "Read MSI privilege flags");
                if (type != 3) throw new InvalidOperationException("Unexpected MSI summary flags type.");
                return value;
            } finally { if (summary != 0) MsiCloseHandle(summary); }
        }
    }
}
'@
    }
    $mutex = [Threading.Mutex]::new($false, 'Local\2Password.InstallerSmoke')
    try { $ownsMutex = $mutex.WaitOne(0) }
    catch [Threading.AbandonedMutexException] { $ownsMutex = $true }
    if (-not $ownsMutex) { throw 'Another 2Password installer smoke test is running.' }

    if (-not $Msi) {
        $candidate = Get-ChildItem -LiteralPath (Join-Path $repo 'artifacts/release') -Filter '2Password-*-win-x64-zh-CN.msi' -File |
            Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
        if (-not $candidate) { throw 'Build an MSI first or supply -Msi.' }
        $Msi = $candidate.FullName
        if (-not $UpgradeMsi) {
            $UpgradeMsi = $Msi -replace '-zh-CN\.msi$', '-en-US.msi'
            if (-not (Test-Path -LiteralPath $UpgradeMsi -PathType Leaf)) {
                throw 'Build both Chinese and English MSIs, or use -Msi for a single-package test.'
            }
        }
    }
    $primary = Read-Package $Msi
    $packages.Add($primary)
    $Msi = $primary.Path
    $packageName = $primary.Name
    $productCode = $primary.ProductCode
    $productVersion = $primary.Version
    $native = [TwoPassword.InstallerSmoke.NativeMsi]
    if ($UpgradeMsi) {
        $secondary = Read-Package $UpgradeMsi
        $packages.Add($secondary)
        Assert-Check 'Language switch uses distinct products at the same version' (
            $secondary.ProductCode -ne $productCode -and $secondary.Version -eq $productVersion -and
            $secondary.Culture -ne $primary.Culture -and
            $native::MsiQueryProductStateW($secondary.ProductCode) -eq -1
        )
    }
    $related = @($native::RelatedProducts($expectedUpgrade))
    $priorState = $native::MsiQueryProductStateW($productCode)
    Assert-Check 'No existing related product will be upgraded or removed' (
        $related.Count -eq 0 -and $priorState -eq -1
    ) 'Only this UpgradeCode and ProductCode were queried.'
    $menuDirectory = Join-Path ([Environment]::GetFolderPath('Programs')) '2Password'
    $registryPath = 'HKCU:\Software\2Password'
    Assert-Check 'No existing application shortcut or registry settings will be overwritten' (
        -not (Test-Path -LiteralPath $menuDirectory) -and -not (Test-Path -LiteralPath $registryPath)
    )

    $expectedFiles = [ordered]@{
        '2Password.exe' = (Join-Path $repo 'artifacts/publish/win-x64/2Password.exe')
        'README.md' = (Join-Path $repo 'README.md')
        'README.en.md' = (Join-Path $repo 'README.en.md')
        'THIRD-PARTY-NOTICES.txt' = (Join-Path $repo 'THIRD-PARTY-NOTICES.txt')
    }
    foreach ($entry in $expectedFiles.GetEnumerator()) {
        $expectedHashes[$entry.Key] = (Get-FileHash -LiteralPath $entry.Value -Algorithm SHA256).Hash
    }
    foreach ($sentinel in @('installer/Package.wxs','installer/Strings.zh-CN.wxl','installer/Strings.en-US.wxl','scripts/Test-Installer.ps1')) {
        $sourceSentinels[$sentinel] = (Get-FileHash -LiteralPath (Join-Path $repo $sentinel) -Algorithm SHA256).Hash
    }
    $workspace = Join-Path $repo ('artifacts/install-smoke/' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $workspace | Out-Null
    # Exercise Unicode and spaces in INSTALLFOLDER without touching the default app directory.
    $installDirectory = Join-Path $workspace '应用 install'
    $installLog = Join-Path $workspace 'install.log'
    $uninstallLog = Join-Path $workspace 'uninstall.log'
    $attemptedInstall = $true
    $attemptedProducts.Add($productCode)
    $installExit = Invoke-Msi @('/i', $Msi, '/qn', '/norestart', '/l*v', $installLog,
        "INSTALLFOLDER=$installDirectory", 'REBOOT=ReallySuppress')
    Assert-Check 'Silent installation succeeds' ($installExit -in 0,3010) "Exit code $installExit"
    Assert-Check 'Product is registered for current user' ($native::MsiQueryProductStateW($productCode) -eq 5)
    foreach ($entry in $expectedFiles.GetEnumerator()) {
        $installedFile = Join-Path $installDirectory $entry.Key
        Assert-Check "Installed $($entry.Key) matches SHA-256" (
            (Test-Path -LiteralPath $installedFile -PathType Leaf) -and
            (Get-FileHash -LiteralPath $installedFile -Algorithm SHA256).Hash -eq $expectedHashes[$entry.Key]
        )
    }
    $shortcutPath = Join-Path $menuDirectory '2Password.lnk'
    Assert-Check 'Current-user Start Menu shortcut exists' (Test-Path -LiteralPath $shortcutPath -PathType Leaf)
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $null
    try {
        $shortcut = $shell.CreateShortcut($shortcutPath)
        $actualTarget = [string]$shortcut.TargetPath
        $actualWorkingDirectory = [string]$shortcut.WorkingDirectory
        $actualArguments = [string]$shortcut.Arguments
        $targetIdentity = Get-PathIdentity $actualTarget
        $expectedTargetIdentity = Get-PathIdentity (Join-Path $installDirectory '2Password.exe')
        $workingIdentity = Get-PathIdentity $actualWorkingDirectory
        $expectedWorkingIdentity = Get-PathIdentity $installDirectory
        $targetMatches = Same-PathIdentity $targetIdentity $expectedTargetIdentity
        $workingDirectoryMatches = Same-PathIdentity $workingIdentity $expectedWorkingIdentity
        $argumentsMatch = $actualArguments -ceq ''
        $shortcutDiagnostics = [ordered]@{
            ShortcutPath = $shortcutPath
            ActualTarget = $targetIdentity
            ExpectedTarget = $expectedTargetIdentity
            ActualWorkingDirectory = $workingIdentity
            ExpectedWorkingDirectory = $expectedWorkingIdentity
            ActualArguments = $actualArguments
            ExpectedArguments = ''
            TargetMatches = $targetMatches
            WorkingDirectoryMatches = $workingDirectoryMatches
            ArgumentsMatch = $argumentsMatch
        }
        $shortcutDetail = $shortcutDiagnostics | ConvertTo-Json -Depth 5 -Compress
        Write-Host "Shortcut diagnostics: $shortcutDetail"
        Assert-Check 'Shortcut targets the installed executable' (
            $targetMatches -and $workingDirectoryMatches -and $argumentsMatch
        ) $shortcutDetail
    } finally {
        if ($null -ne $shortcut) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shortcut) }
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)
    }
    $keys = Get-ItemProperty -LiteralPath $registryPath
    Assert-Check 'Application component keys are under HKCU' (
        $keys.Installed -eq 1 -and $keys.Documentation -eq 1 -and $keys.StartMenu -eq 1 -and
        (Same-Path $keys.InstallLocation $installDirectory)
    )
    $preservedFile = Join-Path $installDirectory 'user-data-must-survive.test.txt'
    [IO.File]::WriteAllText($preservedFile, 'Synthetic unowned user data. Preserve on uninstall.', [Text.UTF8Encoding]::new($false))
    $preservedHash = (Get-FileHash -LiteralPath $preservedFile -Algorithm SHA256).Hash
    if ($UpgradeMsi) {
        $attemptedProducts.Add($secondary.ProductCode)
        $upgradeExit = Invoke-Msi @('/i', $secondary.Path, '/qn', '/norestart', '/l*v',
            (Join-Path $workspace 'upgrade.log'), 'REBOOT=ReallySuppress')
        Assert-Check 'Silent language switch succeeds without a directory override' ($upgradeExit -in 0,3010) "Exit code $upgradeExit"
        Assert-Check 'Language switch removes the previous product registration' ($native::MsiQueryProductStateW($productCode) -eq -1)
        Assert-Check 'Replacement product is registered for current user' ($native::MsiQueryProductStateW($secondary.ProductCode) -eq 5)
        $afterUpgrade = @($native::RelatedProducts($expectedUpgrade))
        Assert-Check 'Exactly one related product remains after language switch' (
            $afterUpgrade.Count -eq 1 -and $afterUpgrade[0] -eq $secondary.ProductCode
        )
        foreach ($entry in $expectedFiles.GetEnumerator()) {
            Assert-Check "Language switch preserves installed $($entry.Key) bytes and directory" (
                (Get-FileHash -LiteralPath (Join-Path $installDirectory $entry.Key) -Algorithm SHA256).Hash -eq $expectedHashes[$entry.Key]
            )
        }
        $afterKeys = Get-ItemProperty -LiteralPath $registryPath
        Assert-Check 'Language switch remembers the Unicode install directory' (Same-Path $afterKeys.InstallLocation $installDirectory)
        Assert-Check 'Language switch preserves unowned user data' (
            (Get-FileHash -LiteralPath $preservedFile -Algorithm SHA256).Hash -eq $preservedHash
        )
    }
} catch {
    $failure = $_
} finally {
    # The flag is set only after product identity, collision, and related-product
    # checks pass. Never uninstall a product that existed before this test.
    if ($attemptedInstall) {
        try {
            for ($index = $attemptedProducts.Count - 1; $index -ge 0; $index--) {
                $ownedCode = $attemptedProducts[$index]
                $state = [TwoPassword.InstallerSmoke.NativeMsi]::MsiQueryProductStateW($ownedCode)
                if ($state -ne -1) {
                    $uninstallExit = Invoke-Msi @('/x', $ownedCode, '/qn', '/norestart', '/l*v', $uninstallLog, 'REBOOT=ReallySuppress')
                    Assert-Check 'Silent uninstallation succeeds' ($uninstallExit -in 0,3010) "Exit code $uninstallExit"
                }
                Assert-Check "Product registration is removed ($ownedCode)" (
                    [TwoPassword.InstallerSmoke.NativeMsi]::MsiQueryProductStateW($ownedCode) -eq -1
                )
            }
            foreach ($name in @('2Password.exe','README.md','README.en.md','THIRD-PARTY-NOTICES.txt')) {
                Assert-Check "Uninstall removes $name" (-not (Test-Path -LiteralPath (Join-Path $installDirectory $name)))
            }
            Assert-Check 'Start Menu shortcut and product folder are removed' (-not (Test-Path -LiteralPath $menuDirectory))
            $remainingKeys = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
            $ownedValuesRemain = $false
            if ($remainingKeys) {
                foreach ($name in @('Installed','Documentation','StartMenu','InstallLocation')) {
                    if ($remainingKeys.PSObject.Properties.Name -contains $name) { $ownedValuesRemain = $true }
                }
            }
            Assert-Check 'Owned HKCU component values are removed' (-not $ownedValuesRemain)
            if (Test-Path variable:preservedHash) {
                Assert-Check 'Uninstall preserves unowned user data' (
                    (Test-Path -LiteralPath $preservedFile -PathType Leaf) -and
                    (Get-FileHash -LiteralPath $preservedFile -Algorithm SHA256).Hash -eq $preservedHash
                )
                # Keep the tiny synthetic survivor and installer logs as evidence.
            }
        } catch {
            if ($null -eq $failure) { $failure = $_ }
            else { Write-Warning "Cleanup check also failed: $($_.Exception.Message)" }
        }
    }
    try {
        foreach ($entry in $sourceSentinels.GetEnumerator()) {
            $path = Join-Path $repo $entry.Key
            Assert-Check "Source sentinel remains unchanged: $($entry.Key)" (
                (Test-Path -LiteralPath $path -PathType Leaf) -and
                (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -eq $entry.Value
            )
        }
    } catch {
        if ($null -eq $failure) { $failure = $_ }
        else { Write-Warning "Source sentinel check also failed: $($_.Exception.Message)" }
    }
    $reportDirectory = Split-Path -Parent $reportPath
    New-Item -ItemType Directory -Force -Path $reportDirectory | Out-Null
    $report = [ordered]@{
        StartedUtc = $started.ToString('O')
        FinishedUtc = [DateTime]::UtcNow.ToString('O')
        Msi = $packageName
        ProductVersion = $productVersion
        ProductCode = $productCode
        Packages = @($packages | Select-Object Name,ProductCode,Version,Culture)
        Workspace = $(if ($workspace) { [IO.Path]::GetRelativePath($repo, $workspace) } else { $null })
        InstallExitCode = $installExit
        UpgradeExitCode = $upgradeExit
        UninstallExitCode = $uninstallExit
        FileSha256 = $expectedHashes
        SourceSentinelSha256 = $sourceSentinels
        ShortcutDiagnostics = $shortcutDiagnostics
        Passed = ($null -eq $failure)
        Checks = @($checks.ToArray())
        Error = $(if ($failure) { $failure.Exception.Message } else { $null })
    }
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $reportPath -Encoding utf8NoBOM
    if ($ownsMutex) { $mutex.ReleaseMutex() }
    if ($null -ne $mutex) { $mutex.Dispose() }
}
if ($failure) { throw $failure }
Write-Host "Installer smoke passed: $($checks.Count) checks. Report: $reportPath"
