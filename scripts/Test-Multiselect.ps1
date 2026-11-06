[CmdletBinding()]
param([string]$Stub, [switch]$Screenshots)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = Split-Path -Parent $PSScriptRoot
Push-Location $repo
try {
    $arguments = @('run', '--project', 'tests/TwoPassword.Gui.Tests', '-c', 'Release', '--')
    if ($Stub) { $arguments += @('--stub', [IO.Path]::GetFullPath($Stub)) }
    if ($Screenshots) { $arguments += '--screenshots' }
    & dotnet @arguments
    if ($LASTEXITCODE -ne 0) { throw 'Multiselect GUI integration checks failed.' }
} finally {
    Pop-Location
}
