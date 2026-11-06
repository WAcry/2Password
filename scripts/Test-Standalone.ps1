[CmdletBinding()]
param([string]$Executable)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = Split-Path -Parent $PSScriptRoot
if (-not $Executable) { $Executable = Join-Path $repo 'artifacts/publish/win-x64/2Password.exe' }
$Executable = [IO.Path]::GetFullPath($Executable)
if (-not (Test-Path -LiteralPath $Executable)) { throw 'Publish the self-contained application first.' }
$work = Join-Path $repo ('artifacts/standalone/' + [Guid]::NewGuid().ToString('N'))
$portableDir = Join-Path $work 'portable'
$isolatedDir = Join-Path $work '另一台电脑 isolated'
$emptyRuntime = Join-Path $work 'empty-runtime'
New-Item -ItemType Directory -Force -Path $portableDir,$isolatedDir,$emptyRuntime | Out-Null
$portable = Join-Path $portableDir '2Password.exe'
Copy-Item -LiteralPath $Executable -Destination $portable
$checks = [Collections.Generic.List[object]]::new()

function Invoke-PackageCommand {
    param([string]$Exe,[string[]]$Arguments,[string]$InputText='', [int]$ExpectedExit=0)
    $start = [Diagnostics.ProcessStartInfo]::new($Exe)
    $start.WorkingDirectory = Split-Path -Parent $Exe
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardInputEncoding = [Text.UTF8Encoding]::new($false)
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    # An isolated runtime root and PATH verify that the published binary carries its runtime.
    $start.Environment['DOTNET_ROOT'] = $emptyRuntime
    $start.Environment['DOTNET_ROOT_X64'] = $emptyRuntime
    $start.Environment['DOTNET_MULTILEVEL_LOOKUP'] = '0'
    $start.Environment['PATH'] = Join-Path $env:windir 'System32'
    $start.Environment['DOTNET_BUNDLE_EXTRACT_BASE_DIR'] = Join-Path $work 'runtime-cache'
    $start.Environment['DOTNET_HOST_TRACE'] = '1'
    $tracePath = Join-Path $work ('host-' + [Guid]::NewGuid().ToString('N') + '.log')
    $start.Environment['DOTNET_HOST_TRACEFILE'] = $tracePath
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    $clock = [Diagnostics.Stopwatch]::StartNew()
    [void]$process.Start()
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $process.StandardInput.Write($InputText)
    $process.StandardInput.Close()
    $peak = 0L
    $bundledRuntimeVerified = $false
    while (-not $process.WaitForExit(100)) {
        try {
            $process.Refresh()
            $peak = [Math]::Max($peak,$process.WorkingSet64)
        } catch { }
        if ($clock.Elapsed.TotalSeconds -gt 120) { $process.Kill($true); throw 'Standalone command timed out.' }
    }
    $clock.Stop()
    $out = $stdout.GetAwaiter().GetResult()
    $err = $stderr.GetAwaiter().GetResult()
    $code = $process.ExitCode
    $process.Dispose()
    if ([IO.File]::Exists($tracePath)) {
        $traceText = [IO.File]::ReadAllText($tracePath)
        $bundledRuntimeVerified = $traceText.Contains('Executing as a self-contained app') -and $traceText.Contains('System.Private.CoreLib.dll found in bundle')
    }
    if ($code -ne $ExpectedExit) { throw "Command exited $code; expected $ExpectedExit. $out $err" }
    [pscustomobject]@{ ExitCode=$code; Seconds=[Math]::Round($clock.Elapsed.TotalSeconds,3); PeakWorkingSetMiB=[Math]::Round($peak/1MB,1); BundledRuntimeVerified=$bundledRuntimeVerified; Output=$out }
}

function Assert-Tree {
    param([string]$Source,[string]$Restored)
    $expected = @(Get-ChildItem -LiteralPath $Source -File -Recurse -Force)
    $actual = @(Get-ChildItem -LiteralPath $Restored -File -Recurse -Force)
    if ($expected.Count -ne $actual.Count) { throw 'File counts differ.' }
    foreach ($file in $expected) {
        $relative = [IO.Path]::GetRelativePath($Source,$file.FullName)
        $target = Join-Path $Restored $relative
        if (-not [IO.File]::Exists($target)) { throw "Missing restored file: $relative" }
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash -ne (Get-FileHash -Algorithm SHA256 -LiteralPath $target).Hash) { throw "File content mismatch: $relative" }
    }
    $expectedDirs = @(Get-ChildItem -LiteralPath $Source -Directory -Recurse -Force)
    $actualDirs = @(Get-ChildItem -LiteralPath $Restored -Directory -Recurse -Force)
    if ($expectedDirs.Count -ne $actualDirs.Count) { throw 'Directory counts differ.' }
}

try {
    $englishHelp = Invoke-PackageCommand $portable @('--help','--language','en')
    $chineseHelp = Invoke-PackageCommand $portable @('--help','--language','zh-CN')
    if ($englishHelp.Output -notmatch '--verify-first' -or $englishHelp.Output -notmatch 'password' -or $chineseHelp.Output -notmatch '密码') { throw 'Bilingual CLI help is incomplete.' }
    $checks.Add([pscustomobject]@{Name='English and Chinese standalone CLI help and recovery flags';Passed=$true})
    $source = Join-Path $work '资料_日本語_📦'
    [void][IO.Directory]::CreateDirectory((Join-Path $source '空目录 empty'))
    $utf8 = [Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText((Join-Path $source '中文 日本語 مرحبا résumé.txt'),("中文 / 日本語 / English / العربية / 🗝️`r`n" * 5000),$utf8)
    [IO.File]::WriteAllText((Join-Path $source 'é.txt'),'NFD file name: preserved exactly',$utf8)
    [IO.File]::WriteAllText((Join-Path $source 'é.txt'),'NFC file name: different file',$utf8)
    [IO.File]::WriteAllBytes((Join-Path $source 'empty.bin'),[byte[]]@())
    $random = [byte[]]::new(3MB)
    [Security.Cryptography.RandomNumberGenerator]::Fill($random)
    [IO.File]::WriteAllBytes((Join-Path $source 'random.bin'),$random)
    $passwords = @('Test-only-桜-2026-!independent',([char]0xFEFF + ' Test-only-🔑-العربية-SECOND  '))
    $passwordJson = ConvertTo-Json -InputObject $passwords -Compress
    $package = Join-Path $work '独立加密包.exe'
    $createReport = Join-Path $work 'create.json'
    $measurement = Invoke-PackageCommand $portable @('--create',$source,'--output',$package,'--passwords-stdin','--compression','zstd','--recovery-percent','0','--language','en','--report',$createReport) $passwordJson
    if (-not (Get-Content -Raw -LiteralPath $createReport | ConvertFrom-Json).success) { throw 'Create report is not successful.' }
    if (-not $measurement.BundledRuntimeVerified) { throw 'The bundled .NET runtime was not verified by the host trace.' }
    $checks.Add([pscustomobject]@{Name='published portable creates encrypted self-extractor';Passed=$true;Measurement=$measurement})

    $standalone = Join-Path $isolatedDir '只有此文件_日本語.exe'
    Copy-Item -LiteralPath $package -Destination $standalone
    if (@(Get-ChildItem -LiteralPath $isolatedDir -File).Count -ne 1) { throw 'Standalone folder is not isolated.' }
    $inspectReport = Join-Path $work 'inspect.json'
    [void](Invoke-PackageCommand $standalone @('--inspect-self','--report',$inspectReport))
    $inspection = Get-Content -Raw -LiteralPath $inspectReport | ConvertFrom-Json
    if (-not $inspection.success -or $inspection.result.PasswordSlots -ne 2) { throw 'Embedded package inspection failed.' }
    $checks.Add([pscustomobject]@{Name='single copied EXE starts with isolated runtime root';Passed=$true;PackageBytes=(Get-Item -LiteralPath $standalone).Length})

    for ($i=0;$i -lt $passwords.Count;$i++) {
        $destination = Join-Path $work ("restored-$i")
        $report = Join-Path $work ("extract-$i.json")
        $language = if ($i -eq 0) { 'zh-CN' } else { 'en' }
        $measurement = Invoke-PackageCommand $standalone @('--extract-self','--output',$destination,'--password-stdin','--language',$language,'--report',$report) ($passwords[$i] + "`r`n")
        Assert-Tree $source (Join-Path $destination ([IO.Path]::GetFileName($source)))
        $checks.Add([pscustomobject]@{Name="independent password $($i+1) restores every file by SHA256";Passed=$true;Measurement=$measurement})
    }
    $wrongDestination = Join-Path $work 'wrong-password-output'
    $wrongReport = Join-Path $work 'wrong-password.json'
    [void](Invoke-PackageCommand $standalone @('--extract-self','--output',$wrongDestination,'--password-stdin','--language','en','--report',$wrongReport) 'this-is-the-wrong-password' 1)
    if (Test-Path -LiteralPath $wrongDestination) { throw 'Wrong password produced a destination.' }
    $englishError = Get-Content -Raw -LiteralPath $wrongReport | ConvertFrom-Json
    if ($englishError.error -notmatch 'password' -or $englishError.errorType -ne 'PasswordNotRecognizedException') { throw 'Expected localized English password error.' }
    $checks.Add([pscustomobject]@{Name='standalone wrong password leaves no destination';Passed=$true})
    $chineseWrong = Join-Path $work 'wrong-password-zh.json'
    [void](Invoke-PackageCommand $standalone @('--extract-self','--output',$wrongDestination,'--password-stdin','--language','zh-CN','--report',$chineseWrong) 'this-is-the-wrong-password' 1)
    if ((Get-Content -Raw -LiteralPath $chineseWrong | ConvertFrom-Json).error -notmatch '密码') { throw 'Chinese satellite resource was not available inside the copied single EXE.' }
    $checks.Add([pscustomobject]@{Name='copied single EXE contains both localized password errors';Passed=$true})
    $existing = Join-Path $work 'restored-0'
    $existingReport = Join-Path $work 'existing-destination.json'
    [void](Invoke-PackageCommand $standalone @('--extract-self','--output',$existing,'--password-stdin','--report',$existingReport) $passwords[0] 2)
    Assert-Tree $source (Join-Path $existing ([IO.Path]::GetFileName($source)))
    $checks.Add([pscustomobject]@{Name='standalone refuses overwrite and preserves existing destination';Passed=$true})

    $plainPackage = Join-Path $work 'no-compression.exe'
    [void](Invoke-PackageCommand $portable @('--create',(Join-Path $source 'random.bin'),'--output',$plainPackage,'--passwords-stdin','--compression','none','--recovery-percent','0','--report',(Join-Path $work 'create-none.json')) $passwordJson)
    $plainDestination = Join-Path $work 'uncompressed-restored'
    [void](Invoke-PackageCommand $plainPackage @('--extract-self','--output',$plainDestination,'--password-stdin','--report',(Join-Path $work 'extract-none.json')) $passwords[1])
    if ((Get-FileHash -LiteralPath (Join-Path $source 'random.bin')).Hash -ne (Get-FileHash -LiteralPath (Join-Path $plainDestination 'random.bin')).Hash) { throw 'Uncompressed round-trip hash differs.' }
    $checks.Add([pscustomobject]@{Name='uncompressed single-file self-extractor round-trip';Passed=$true})

    $detached = Join-Path $work '双文件包.exe'
    $detachedReport = Join-Path $work 'detached-create.json'
    [void](Invoke-PackageCommand $portable @('--create',$source,'--output',$detached,'--passwords-stdin','--compression','zstd','--layout','detached','--recovery-percent','10','--report',$detachedReport) $passwordJson)
    $detachedResult = Get-Content -Raw -LiteralPath $detachedReport | ConvertFrom-Json
    if (-not $detachedResult.result.IsDetached -or -not (Test-Path -LiteralPath $detachedResult.result.DataPath)) { throw 'Detached data file is missing.' }
    $dataHash = (Get-FileHash -LiteralPath $detachedResult.result.DataPath).Hash
    Move-Item -LiteralPath $detachedResult.result.DataPath -Destination ($detachedResult.result.DataPath + '.lost')
    $detachedOutput = Join-Path $work 'detached-repaired-output'
    [void](Invoke-PackageCommand $detached @('--extract-self','--output',$detachedOutput,'--password-stdin','--report',(Join-Path $work 'detached-extract.json')) $passwords[0])
    Assert-Tree $source (Join-Path $detachedOutput ([IO.Path]::GetFileName($source)))
    if ((Get-FileHash -LiteralPath $detachedResult.result.DataPath).Hash -ne $dataHash) { throw 'PAR2 reconstructed detached ciphertext differs.' }
    $checks.Add([pscustomobject]@{Name='standalone restores missing data sidecar with PAR2 before decrypting';Passed=$true})

    $repairable = Join-Path $work '自修复独立包.exe'
    [void](Invoke-PackageCommand $portable @('--create',(Join-Path $source 'random.bin'),'--output',$repairable,'--passwords-stdin','--compression','zstd','--layout','embedded','--recovery-percent','10','--report',(Join-Path $work 'embedded-recovery-create.json')) $passwordJson)
    $beforeRepair = (Get-FileHash -LiteralPath $repairable).Hash
    $damage = [IO.File]::Open($repairable,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    $position = $damage.Length - 8192
    $damage.Position = $position
    $byte = $damage.ReadByte()
    $damage.Position = $position
    $damage.WriteByte([byte]($byte -bxor 64))
    $damage.Dispose()
    $repairOutput = Join-Path $work 'self-repair-output'
    [void](Invoke-PackageCommand $repairable @('--extract-self','--output',$repairOutput,'--password-stdin','--report',(Join-Path $work 'embedded-recovery-extract.json')) $passwords[0])
    if ((Get-FileHash -LiteralPath $repairable).Hash -ne $beforeRepair) { throw 'Embedded self-repair did not restore original ciphertext.' }
    if ((Get-FileHash -LiteralPath (Join-Path $repairOutput 'random.bin')).Hash -ne (Get-FileHash -LiteralPath (Join-Path $source 'random.bin')).Hash) { throw 'Self-repaired plaintext differs.' }
    $checks.Add([pscustomobject]@{Name='running embedded EXE repairs its damaged payload before decrypting';Passed=$true})
    $final = [pscustomobject]@{Success=$true;Checks=$checks;Os=[Runtime.InteropServices.RuntimeInformation]::OSDescription;Scope='Isolated process and copied EXE on current Windows host; not a fresh Windows VM.'}
    $final | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Join-Path $repo 'artifacts/standalone-results.json') -Encoding utf8NoBOM
    $checks | Select-Object Name,Passed | Format-Table -AutoSize
} catch {
    [pscustomobject]@{Success=$false;Error=$_.Exception.Message;Checks=$checks} | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Join-Path $repo 'artifacts/standalone-results.json') -Encoding utf8NoBOM
    throw
}
