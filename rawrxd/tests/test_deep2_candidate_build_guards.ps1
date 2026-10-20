[CmdletBinding()]
param(
    [string]$BuildScript = (Join-Path $PSScriptRoot '..\scripts\build_deep2_candidate.ps1'),
    [string]$CampaignScript = (Join-Path $PSScriptRoot '..\scripts\deep2_tps_mutation_campaign.ps1'),
    [string]$ReportPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$builder = (Resolve-Path -LiteralPath $BuildScript).Path
$campaign = (Resolve-Path -LiteralPath $CampaignScript).Path
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('rawrxd_candidate_guards_' + [guid]::NewGuid().ToString('N'))
$workspace = Join-Path $fixture 'workspace'
$source = Join-Path $workspace 'rawrxd'
New-Item -ItemType Directory -Path $source -Force | Out-Null
[IO.File]::WriteAllText((Join-Path $source 'CMakeLists.txt'), "cmake_minimum_required(VERSION 3.20)`nproject(Fixture NONE)`n")
$results = [Collections.Generic.List[object]]::new()
try {
    foreach ($case in @(
        @{ name = 'outside_build_rejected'; directory = (Join-Path $fixture 'outside'); message = 'BuildDirectory must be inside' },
        @{ name = 'in_source_build_rejected'; directory = $source; message = 'outside its source directory' },
        @{ name = 'foreign_cache_rejected'; directory = (Join-Path $workspace 'foreign'); message = 'different source checkout' },
        @{ name = 'invalid_cache_rejected'; directory = (Join-Path $workspace 'invalid'); message = 'different source checkout' }
    )) {
        $entry = [ordered]@{ name = $case.name; pass = $false }
        $cachePath = Join-Path $case.directory 'CMakeCache.txt'
        if ($case.name -eq 'foreign_cache_rejected') {
            New-Item -ItemType Directory -Path $case.directory -Force | Out-Null
            [IO.File]::WriteAllText($cachePath, 'CMAKE_HOME_DIRECTORY:INTERNAL=' + (Join-Path $fixture 'different_source'))
        } elseif ($case.name -eq 'invalid_cache_rejected') {
            New-Item -ItemType Directory -Path $case.directory -Force | Out-Null
            [IO.File]::WriteAllText($cachePath, 'unrecognized cache data')
        }
        $cacheHash = if (Test-Path -LiteralPath $cachePath) { (Get-FileHash -LiteralPath $cachePath).Hash } else { $null }
        $output = @(& pwsh -NoProfile -File $builder -CandidateRoot $workspace -BuildDirectory $case.directory 2>&1)
        $entry.process_exit = $LASTEXITCODE
        $cacheUnchanged = if ($cacheHash) { (Get-FileHash -LiteralPath $cachePath).Hash -ceq $cacheHash } else { -not (Test-Path -LiteralPath $cachePath) }
        $entry.pass = $entry.process_exit -ne 0 -and ($output -join "`n").Contains($case.message) -and $cacheUnchanged
        [void]$results.Add([pscustomobject]$entry)
        Write-Output ("CASE={0} PASS={1}" -f $entry.name, $entry.pass)
    }
    $manifestDirectory = Join-Path $fixture 'manifest'
    $output = @(& pwsh -NoProfile -File $campaign -Exe (Join-Path $fixture 'not_built_yet.exe') -Model (Join-Path $fixture 'not_loaded.gguf') -OutputDir $manifestDirectory 2>&1)
    $manifestExit = $LASTEXITCODE
    $manifestPath = Join-Path $manifestDirectory 'campaign_manifest.json'
    $manifestOnly = $manifestExit -eq 0 -and ($output -join "`n").Contains('BENCHMARKS=PAUSED') -and (Test-Path -LiteralPath $manifestPath) -and @(Get-ChildItem -LiteralPath $manifestDirectory -Directory).Count -eq 0
    [void]$results.Add([pscustomobject]@{ name = 'manifest_without_built_executable'; pass = $manifestOnly; process_exit = $manifestExit })
    Write-Output "CASE=manifest_without_built_executable PASS=$manifestOnly"
    $passed = @($results | Where-Object { -not $_.pass }).Count -eq 0
    $report = [ordered]@{ schema = 'RAWRXD_CANDIDATE_BUILD_GUARDS_001'; passed = $passed; test_count = $results.Count; benchmarks_launched = 0; results = @($results) }
    if ($ReportPath) {
        $destination = [IO.Path]::GetFullPath($ReportPath)
        New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
        [IO.File]::WriteAllText($destination, ($report | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
    }
    Write-Output "BUILD_GUARDS_PASS=$passed"
    if (-not $passed) { exit 1 }
} finally {
    $fullFixture = [IO.Path]::GetFullPath($fixture)
    $tempPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (-not $fullFixture.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($fullFixture) -notlike 'rawrxd_candidate_guards_*') { throw 'Refusing cleanup outside the owned fixture.' }
    Remove-Item -LiteralPath $fullFixture -Recurse -Force
}
