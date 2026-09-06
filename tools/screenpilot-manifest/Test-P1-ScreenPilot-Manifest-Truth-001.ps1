#Requires -Version 5.1
<#
.SYNOPSIS
  P1_SCREENPILOT_MANIFEST_TRUTH_001 - certify manifest scanner truth invariants.
.EXAMPLE
  .\Test-P1-ScreenPilot-Manifest-Truth-001.ps1 -RepoRoot 'F:\~dev\rawrxd'
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [Parameter()]
    [string]$UiPath = (Join-Path (Split-Path $RepoRoot -Parent) 'BigDaddyG-Universal-Manifest-Generator.html')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Failures = @()
$script:Passes = @()

function Assert-Predicate {
    param(
        [string]$Name,
        [bool]$Condition,
        [string]$Detail = ''
    )
    if ($Condition) {
        $script:Passes += $Name
        Write-Host "  [PASS] $Name"
    } else {
        $script:Failures += $Name
        if ($Detail) {
            Write-Host "  [FAIL] $Name - $Detail"
        } else {
            Write-Host "  [FAIL] $Name"
        }
    }
}

function Get-CMakeOptionCount {
    param([string]$CmakeFile)
    if (-not (Test-Path -LiteralPath $CmakeFile)) { return 0 }
    $text = [IO.File]::ReadAllText($CmakeFile)
    return ([regex]::Matches($text, '(?m)^option\s*\(\s*([A-Z0-9_]+)\s+"')).Count
}

function Get-EnvVarCountFromSources {
    param([string]$Root)
    $patterns = @(
        'getenv\s*\(\s*"([A-Z0-9_]+)"',
        'readEnvFlag\s*\(\s*"([A-Z0-9_]+)"',
        'std::getenv\s*\(\s*"([A-Z0-9_]+)"'
    )
    $found = @{}
    foreach ($ext in @('*.cpp', '*.h', '*.hpp', '*.c', '*.asm')) {
        Get-ChildItem -LiteralPath $Root -Recurse -File -Filter $ext -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch '\\(build-|\.git|node_modules|Full Source|history|reconstructed)\\' } |
            ForEach-Object {
                $content = [IO.File]::ReadAllText($_.FullName)
                foreach ($pat in $patterns) {
                    foreach ($m in [regex]::Matches($content, $pat)) {
                        $name = $m.Groups[1].Value
                        if ($name -match '^RAWR') { $found[$name] = $true }
                    }
                }
            }
    }
    return $found.Count
}

function Invoke-ManifestGeneration {
    param([string]$OutPath)
    & (Join-Path $PSScriptRoot 'Generate-ScreenPilotManifest.ps1') -RepoRoot $RepoRoot -OutPath $OutPath | Out-Null
    return (Get-Content -LiteralPath $OutPath -Raw | ConvertFrom-Json)
}

Write-Host '================================================================'
Write-Host '  P1_SCREENPILOT_MANIFEST_TRUTH_001'
Write-Host '================================================================'
Write-Host ''

$tmp1 = Join-Path $env:TEMP ("screenpilot-manifest-truth-{0}-a.json" -f [guid]::NewGuid().ToString('N'))
$tmp2 = Join-Path $env:TEMP ("screenpilot-manifest-truth-{0}-b.json" -f [guid]::NewGuid().ToString('N'))

try {
    Write-Host '-- Generate manifest (run A) --'
    $manifestA = Invoke-ManifestGeneration -OutPath $tmp1

    Write-Host '-- Generate manifest (run B) --'
    $manifestB = Invoke-ManifestGeneration -OutPath $tmp2

    $rawrxdA = ($manifestA.projects | Where-Object { $_.name -eq 'rawrxd' } | Select-Object -First 1)
    $cmakePath = Join-Path $RepoRoot 'CMakeLists.txt'
    $srcRoot = Join-Path $RepoRoot 'src'

    Write-Host '-- Predicates --'

    Assert-Predicate 'CMAKE_OPTION_COUNT_MATCHES_SCAN' `
        ($rawrxdA.cmakeOptions.Count -eq (Get-CMakeOptionCount -CmakeFile $cmakePath)) `
        ("manifest=$($rawrxdA.cmakeOptions.Count) scan=$(Get-CMakeOptionCount -CmakeFile $cmakePath)")

    Assert-Predicate 'ENV_REGISTRY_MATCHES_SCAN' `
        ($rawrxdA.envVars.Count -eq (Get-EnvVarCountFromSources -Root $srcRoot)) `
        ("manifest=$($rawrxdA.envVars.Count) scan=$(Get-EnvVarCountFromSources -Root $srcRoot)")

    $uiText = [IO.File]::ReadAllText($UiPath)
    $hardcodedCountPatterns = @(
        "statCmake\)\.textContent\s*=\s*[`"']\d+[`"']",
        "statEnv\)\.textContent\s*=\s*[`"']\d+[`"']",
        'cmakeCount\s*=\s*\d+',
        'envCount\s*=\s*\d+'
    )
    $hardcodedHit = $false
    foreach ($pat in $hardcodedCountPatterns) {
        if ($uiText -match $pat) { $hardcodedHit = $true; break }
    }
    Assert-Predicate 'NO_HARDCODED_COUNTS_IN_UI' (-not $hardcodedHit)

    $k2 = $manifestA.certification.K2_001
    Assert-Predicate 'BUILD_PASS_NOT_RUNTIME_PASS' `
        ($k2.status -ne 'RUNTIME_PASS' -and $k2.status -ne 'FULL_RUNTIME_PASS') `
        ("status=$($k2.status)")

    Assert-Predicate 'OPEN_GATE_REMAINS_OPEN' `
        ($manifestA.certification.STATIC_DEP_001.status -eq 'OPEN' -and
         $manifestA.certification.EGRESS_001.status -eq 'OPEN')

    Assert-Predicate 'MISSING_GATE_NOT_PROMOTED' `
        ($manifestA.certification.HOSTED_GATEWAY.status -ne 'SMOKE_PASS' -and
         $manifestA.certification.HEXMAG_IDE_INTEGRATION.status -eq 'NOT_CLOSED')

    $profile = $manifestA.deploymentProfiles.k2_runtime_validation
    Assert-Predicate 'PROFILE_FIELDS_SOURCE_BACKED' `
        ($null -ne $profile.exe -and $profile.requiredTelemetry.Count -ge 8)

    Assert-Predicate 'MANIFEST_SHA_REPRODUCIBLE' `
        ($manifestA.provenance.cmakeSha256 -eq $manifestB.provenance.cmakeSha256 -and
         $manifestA.provenance.sourceInventorySha256 -eq $manifestB.provenance.sourceInventorySha256 -and
         $manifestA.provenance.evidenceInventorySha256 -eq $manifestB.provenance.evidenceInventorySha256 -and
         $rawrxdA.cmakeOptions.Count -eq (($manifestB.projects | Where-Object { $_.name -eq 'rawrxd' }).cmakeOptions.Count))

    Assert-Predicate 'UI_LOADS_GENERATED_MANIFEST' `
        ($uiText -match 'DEFAULT_MANIFEST_URL' -and
         $uiText -match 'applyManifest' -and
         $uiText -match 'cmakeOptions')

    $prov = $manifestA.provenance
    Assert-Predicate 'PROVENANCE_BLOCK_PRESENT' `
        ($prov.manifestVersion -eq 1 -and
         $prov.repoRoot -and
         $prov.generatorSha256 -and
         $prov.cmakeSha256 -and
         $prov.manifestSha256)

    Write-Host ''
    Write-Host '================================================================'
    Write-Host '  P1_SCREENPILOT_MANIFEST_TRUTH_001 Telemetry'
    Write-Host '================================================================'
    Write-Host ("  CMAKE_OPTIONS       = $($rawrxdA.cmakeOptions.Count)")
    Write-Host ("  ENV_VARS            = $($rawrxdA.envVars.Count)")
    $shaShort = if ($prov.manifestSha256.Length -ge 8) { $prov.manifestSha256.Substring(0, 8) + '...' } else { $prov.manifestSha256 }
    Write-Host ("  MANIFEST_SHA        = $shaShort")
    $repoShort = if ($prov.gitCommit.Length -ge 10) { $prov.gitCommit.Substring(0, 10) + '...' } else { $prov.gitCommit }
    Write-Host ("  REPO_SHA            = $repoShort")
    Write-Host ("  DIRTY               = $(if ($prov.gitDirty) { 'YES' } else { 'NO' })")
    Write-Host ("  GENERATED           = $($prov.generatedUtc)")
    Write-Host ("  PASS_COUNT          = $($script:Passes.Count)")
    Write-Host ("  FAIL_COUNT          = $($script:Failures.Count)")
    Write-Host '================================================================'

    if ($script:Failures.Count -gt 0) {
        Write-Host ''
        Write-Host 'P1_SCREENPILOT_MANIFEST_TRUTH_001 FAILED'
        exit 1
    }

    Write-Host ''
    Write-Host 'P1_SCREENPILOT_MANIFEST_TRUTH_001 PASSED'
    exit 0
}
finally {
    foreach ($p in @($tmp1, $tmp2)) {
        if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }
    }
}
