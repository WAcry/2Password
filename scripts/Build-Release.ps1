[CmdletBinding()]
param(
    [ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version = '1.0.0',
    [switch]$SkipTests
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = Split-Path -Parent $PSScriptRoot
$previousRollForward = [Environment]::GetEnvironmentVariable('DOTNET_ROLL_FORWARD', 'Process')
Push-Location $repo
try {
    $publish = Join-Path $repo 'artifacts/publish/win-x64'
    $release = Join-Path $repo 'artifacts/release'
    $toolDir = Join-Path $repo '.tools/wix'
    New-Item -ItemType Directory -Force -Path $publish,$release | Out-Null
    dotnet restore 2Password.slnx --locked-mode
    if ($LASTEXITCODE -ne 0) { throw 'Dependency restore failed.' }
    dotnet build 2Password.slnx -c Release --no-restore
    if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
    if (-not $SkipTests) {
        dotnet run --project tests/TwoPassword.Tests -c Release --no-build
        if ($LASTEXITCODE -ne 0) { throw 'Security and round-trip checks failed.' }
        dotnet run --project tests/TwoPassword.Recovery.Tests -c Release --no-build
        if ($LASTEXITCODE -ne 0) { throw 'PAR2 verification and real repair checks failed.' }
        dotnet run --project tests/TwoPassword.Localization.Tests -c Release --no-build
        if ($LASTEXITCODE -ne 0) { throw 'Localization and cross-language compatibility checks failed.' }
    }
    dotnet publish src/TwoPassword.App -c Release -r win-x64 --self-contained true -o $publish -p:Version=$Version -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true -p:DebugType=none -p:DebugSymbols=false
    if ($LASTEXITCODE -ne 0) { throw 'Self-contained publishing failed.' }
    $exe = Join-Path $publish '2Password.exe'
    if (-not (Test-Path -LiteralPath $exe)) { throw 'Published executable is missing.' }
    Copy-Item -LiteralPath $exe -Destination (Join-Path $release "2Password-$Version-win-x64.exe") -Force
    Copy-Item -LiteralPath (Join-Path $repo 'vendor/par2/par2cmdline-turbo-1.5.0.tar.xz') -Destination $release -Force
    $portable = Join-Path $release "2Password-$Version-win-x64-portable.zip"
    Compress-Archive -LiteralPath $exe,(Join-Path $repo 'README.md'),(Join-Path $repo 'README.en.md'),(Join-Path $repo 'THIRD-PARTY-NOTICES.txt') -DestinationPath $portable -Force
    $wix = Join-Path $toolDir 'wix.exe'
    # Run the pinned WiX 4 tool on the maintained SDK runtime; no global setting changes.
    $env:DOTNET_ROLL_FORWARD = 'LatestMajor'
    if (-not (Test-Path -LiteralPath $wix)) {
        dotnet tool install wix --tool-path $toolDir --version 4.0.6
        if ($LASTEXITCODE -ne 0) { throw 'Installing the local WiX tool failed.' }
    }
    & $wix extension add WixToolset.UI.wixext/4.0.6
    if ($LASTEXITCODE -ne 0) { throw 'Installing the WiX UI extension failed.' }
    $assets = @((Join-Path $release "2Password-$Version-win-x64.exe"), $portable, (Join-Path $release 'par2cmdline-turbo-1.5.0.tar.xz'))
    foreach ($culture in @('zh-CN', 'en-US')) {
        $msi = Join-Path $release "2Password-$Version-win-x64-$culture.msi"
        & $wix build installer/Package.wxs -wx -arch x64 -culture $culture -loc "installer/Strings.$culture.wxl" -ext WixToolset.UI.wixext -d "AppVersion=$Version" -d "PublishDir=$publish" -d "RepoRoot=$repo" -pdbtype none -out $msi
        if ($LASTEXITCODE -ne 0) { throw "MSI build failed ($culture)." }
        $assets += $msi
    }
    $hashLines = $assets | Sort-Object | ForEach-Object {
        $file = Get-Item -LiteralPath $_
        "{0}  {1}" -f (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant(), $file.Name
    }
    $hashLines | Set-Content -LiteralPath (Join-Path $release 'SHA256SUMS.txt') -Encoding utf8NoBOM
    Get-ChildItem -LiteralPath $release -File | Select-Object Name,Length
} finally {
    [Environment]::SetEnvironmentVariable('DOTNET_ROLL_FORWARD', $previousRollForward, 'Process')
    Pop-Location
}
