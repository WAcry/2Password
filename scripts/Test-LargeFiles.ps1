[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$repository = Split-Path -Parent $PSScriptRoot
Push-Location $repository
try {
    # Explicit opt-in test: creates sparse source fixtures and real large encrypted/restored files.
    # Requires approximately 30 GiB free disk space. Fixtures are kept under ignored artifacts/large-work.
    dotnet run --project tests/TwoPassword.Large.Tests/TwoPassword.Large.Tests.csproj -c Release
    if ($LASTEXITCODE -ne 0) { throw 'Large-file integration failed. See artifacts/large-results.json.' }
}
finally { Pop-Location }
