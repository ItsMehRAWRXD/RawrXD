param(
    [Parameter(Mandatory = $true)]
    [string]$MutationScript,
    [Parameter(Mandatory = $true)]
    [string[]]$Variants,
    [Parameter(Mandatory = $true)]
    [string[]]$Files,
    [Parameter(Mandatory = $true)]
    [string]$BuildCommand,
    [string[]]$BuildArguments = @(),
    [string]$ValidationCommand,
    [string[]]$ValidationArguments = @(),
    [Parameter(Mandatory = $true)]
    [string]$BenchmarkScript,
    [string[]]$BenchmarkArguments = @(),
    [Parameter(Mandatory = $true)]
    [double]$BaselineMedianTps,
    [double]$MinRelativeGain = 0.01,
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string]$ReportDirectory = '.rawrxd/tps_mutation_sweep',
    [string]$SummaryPath = '.rawrxd/tps_mutation_sweep.json'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $RepoRoot).Path)
$gate = Join-Path $root 'rawrxd/scripts/deep2_tps_mutation_gate.ps1'
$mutation = if ([System.IO.Path]::IsPathRooted($MutationScript)) { $MutationScript } else { Join-Path $root $MutationScript }
$reportDir = if ([System.IO.Path]::IsPathRooted($ReportDirectory)) { $ReportDirectory } else { Join-Path $root $ReportDirectory }
$summaryFile = if ([System.IO.Path]::IsPathRooted($SummaryPath)) { $SummaryPath } else { Join-Path $root $SummaryPath }
if (-not (Test-Path -LiteralPath $gate -PathType Leaf)) { throw "Mutation gate not found: $gate" }
if (-not (Test-Path -LiteralPath $mutation -PathType Leaf)) { throw "Mutation script not found: $mutation" }
if ($Variants.Count -eq 0) { throw 'At least one mutation variant is required.' }
New-Item -ItemType Directory -Path $reportDir -Force | Out-Null

$previousVariant = [Environment]::GetEnvironmentVariable('RAWRXD_MUTATION_VARIANT', 'Process')
$attempts = @()
$accepted = $false
try {
    for ($index = 0; $index -lt $Variants.Count; $index++) {
        $variant = $Variants[$index]
        [Environment]::SetEnvironmentVariable('RAWRXD_MUTATION_VARIANT', $variant, 'Process')
        $reportPath = Join-Path $reportDir ('attempt_{0:D2}.json' -f ($index + 1))
        Write-Output "MUTATION_VARIANT=$variant"
        & $gate `
            -RepoRoot $root `
            -MutationScript $mutation `
            -Files $Files `
            -BuildCommand $BuildCommand `
            -BuildArguments $BuildArguments `
            -ValidationCommand $ValidationCommand `
            -ValidationArguments $ValidationArguments `
            -BenchmarkScript $BenchmarkScript `
            -BenchmarkArguments $BenchmarkArguments `
            -BaselineMedianTps $BaselineMedianTps `
            -MinRelativeGain $MinRelativeGain `
            -ReportPath $reportPath
        $gateExit = if ($null -eq $LASTEXITCODE) { 0 } else { $LASTEXITCODE }
        if (-not (Test-Path -LiteralPath $reportPath -PathType Leaf)) {
            throw "Mutation gate did not produce a report for variant $variant."
        }
        $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
        $medianTps = if ($report.candidate.PSObject.Properties['medianTps']) { $report.candidate.medianTps } else { $null }
        $requiredMedianTps = if ($report.candidate.PSObject.Properties['requiredMedianTps']) { $report.candidate.requiredMedianTps } else { $null }
        $runTps = if ($report.candidate.PSObject.Properties['runTps']) { @($report.candidate.runTps) } else { @() }
        $failure = if ($report.PSObject.Properties['failure']) { $report.failure } else { $null }
        $attempt = [ordered]@{
            variant = $variant
            exitCode = $gateExit
            verdict = $report.verdict
            medianTps = $medianTps
            requiredMedianTps = $requiredMedianTps
            runTps = $runTps
            failure = $failure
            restoreVerified = $report.restoration.verified
            report = $reportPath
        }
        $attempts += [pscustomobject]$attempt
        if ($report.verdict -eq 'ACCEPTED') {
            $accepted = $true
            break
        }
    }
}
finally {
    [Environment]::SetEnvironmentVariable('RAWRXD_MUTATION_VARIANT', $previousVariant, 'Process')
    $summary = [ordered]@{
        schema = 'RAWRXD_DEEP2_TPS_MUTATION_SWEEP_001'
        generatedUtc = [DateTime]::UtcNow.ToString('o')
        repoRoot = $root
        baselineMedianTps = $BaselineMedianTps
        minRelativeGain = $MinRelativeGain
        accepted = $accepted
        attempts = $attempts
    }
    Set-Content -LiteralPath $summaryFile -Value ($summary | ConvertTo-Json -Depth 12) -Encoding UTF8
    Write-Output "SWEEP_SUMMARY=$summaryFile"
    Write-Output "SWEEP_VERDICT=$(if($accepted){'ACCEPTED'}else{'REJECTED'})"
}

if (-not $accepted) { exit 2 }
