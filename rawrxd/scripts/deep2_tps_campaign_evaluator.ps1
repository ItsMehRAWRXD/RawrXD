[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CampaignDir,
    [double]$BaselineMedianTps = 31.392,
    [double]$CheckpointTps = 40.0,
    [double]$MinRelativeGain = 0.05,
    [int]$RequiredRuns = 3,
    [string]$EvidenceLedger = '',
    [string]$CheckpointRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PropertyValue($Object, [string]$Name, $Default = $null) {
    if ($null -eq $Object) { return $Default }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $Default }
    return $property.Value
}

function Get-Median([double[]]$Values) {
    $ordered = @($Values | Sort-Object)
    if ($ordered.Count -eq 0) { return $null }
    $middle = [int][Math]::Floor($ordered.Count / 2)
    if (($ordered.Count % 2) -eq 1) { return [double]$ordered[$middle] }
    return ([double]$ordered[$middle - 1] + [double]$ordered[$middle]) / 2.0
}

function Resolve-PathIfPresent([string]$Path, [string]$BasePath) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $candidate = if ([System.IO.Path]::IsPathRooted($Path)) {
        $Path
    } else {
        Join-Path $BasePath $Path
    }
    $full = [System.IO.Path]::GetFullPath($candidate)
    if (Test-Path -LiteralPath $full -PathType Leaf) { return $full }
    return $null
}

function Read-EvidenceText($Report, [string]$ReportPath, [string]$CandidateDir) {
    $paths = [System.Collections.Generic.List[string]]::new()
    foreach ($result in @($Report.results)) {
        foreach ($propertyName in @('stdout', 'stderr', 'flight_log')) {
            $path = Resolve-PathIfPresent (Get-PropertyValue $result $propertyName) $CandidateDir
            if ($null -ne $path) { $paths.Add($path) }
        }
    }
    $chunks = [System.Collections.Generic.List[string]]::new()
    foreach ($path in $paths) {
        $chunks.Add((Get-Content -LiteralPath $path -Raw -ErrorAction SilentlyContinue))
    }
    if ($chunks.Count -eq 0) { return '' }
    return $chunks -join [Environment]::NewLine
}

function Get-ParityGate([string]$EvidenceText) {
    if ([string]::IsNullOrWhiteSpace($EvidenceText)) { return 'MISSING' }
    $failure = [regex]::IsMatch(
        $EvidenceText,
        '(?im)(?:mismatch(?:ed|es)?|absolute[_ ]?diff|oracle[_ ]?diff)\s*[=:]?\s*[1-9][0-9]*')
    if ($failure) { return 'FAIL' }
    $pass = [regex]::IsMatch(
        $EvidenceText,
        '(?im)(?:\[?PARITY\]?|ORACLE|SHA-?256|HASH).*(?:PASS(?:ED)?|IDENTICAL|MATCH(?:ED)?)')
    if ($pass) { return 'PASS' }
    return 'MISSING'
}

function Get-BenchmarkReport([string]$GateReportPath, $GateReport) {
    $candidateDir = Split-Path -Parent $GateReportPath
    $candidatePath = Get-PropertyValue (Get-PropertyValue $GateReport 'candidate') 'benchmarkReport'
    $resolved = Resolve-PathIfPresent $candidatePath $candidateDir
    if ($null -ne $resolved) { return $resolved }
    $trialRoot = Get-PropertyValue $GateReport 'trialRoot'
    if (-not [string]::IsNullOrWhiteSpace($trialRoot)) {
        $resolved = Resolve-PathIfPresent (Join-Path $trialRoot 'benchmark\flight_recorder_report.json') $candidateDir
        if ($null -ne $resolved) { return $resolved }
    }
    $fallback = @(Get-ChildItem -LiteralPath $candidateDir -Filter 'flight_recorder_report.json' -File -Recurse -ErrorAction SilentlyContinue)
    if ($fallback.Count -gt 0) { return $fallback[0].FullName }
    return $null
}

function Test-Restoration($GateReport) {
    $restoration = Get-PropertyValue $GateReport 'restoration'
    if ($null -eq $restoration) { return 'MISSING' }
    $attempted = [bool](Get-PropertyValue $restoration 'attempted' $false)
    if (-not $attempted) { return 'NOT_APPLICABLE' }
    return if ([bool](Get-PropertyValue $restoration 'verified' $false)) { 'PASS' } else { 'FAIL' }
}

function Write-Checkpoint($Evaluation, $GateReportPath, $BenchmarkReportPath, [string]$Destination) {
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    Copy-Item -LiteralPath $GateReportPath -Destination (Join-Path $Destination 'gate_report.json') -Force
    if ($null -ne $BenchmarkReportPath) {
        Copy-Item -LiteralPath $BenchmarkReportPath -Destination (Join-Path $Destination 'flight_recorder_report.json') -Force
    }
    $gate = Get-Content -LiteralPath $GateReportPath -Raw | ConvertFrom-Json
    $repoRoot = Get-PropertyValue $gate 'repoRoot'
    $sourceRoot = Join-Path $Destination 'source'
    foreach ($relative in @(Get-PropertyValue $gate 'files' @())) {
        if ([string]::IsNullOrWhiteSpace($repoRoot)) { continue }
        $source = [System.IO.Path]::GetFullPath((Join-Path $repoRoot ($relative -replace '/', '\')))
        $rootPrefix = ([System.IO.Path]::GetFullPath($repoRoot)).TrimEnd('\') + '\'
        if (-not $source.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { continue }
        $destinationPath = Join-Path $sourceRoot ($relative -replace '/', '\')
        New-Item -ItemType Directory -Path (Split-Path -Parent $destinationPath) -Force | Out-Null
        Copy-Item -LiteralPath $source -Destination $destinationPath -Force
    }
    $Evaluation | ConvertTo-Json -Depth 14 | Set-Content -LiteralPath (Join-Path $Destination 'checkpoint.json') -Encoding UTF8
}

$campaignPath = [System.IO.Path]::GetFullPath($CampaignDir)
if (-not (Test-Path -LiteralPath $campaignPath -PathType Container)) { throw "Campaign directory not found: $campaignPath" }
if ($BaselineMedianTps -le 0) { throw 'BaselineMedianTps must be positive.' }
if ($CheckpointTps -le 0) { throw 'CheckpointTps must be positive.' }
if ($RequiredRuns -lt 1) { throw 'RequiredRuns must be positive.' }
if ([string]::IsNullOrWhiteSpace($EvidenceLedger)) { $EvidenceLedger = Join-Path $campaignPath 'evidence_ledger.jsonl' }
if ([string]::IsNullOrWhiteSpace($CheckpointRoot)) { $CheckpointRoot = Join-Path $campaignPath 'checkpoints' }
$EvidenceLedger = [System.IO.Path]::GetFullPath($EvidenceLedger)
$CheckpointRoot = [System.IO.Path]::GetFullPath($CheckpointRoot)
New-Item -ItemType Directory -Path (Split-Path -Parent $EvidenceLedger),$CheckpointRoot -Force | Out-Null

$gatePaths = @(Get-ChildItem -LiteralPath $campaignPath -Filter 'gate_report.json' -File -Recurse -ErrorAction SilentlyContinue | Sort-Object FullName)
$evaluations = [System.Collections.Generic.List[object]]::new()
foreach ($gatePathItem in $gatePaths) {
    $gatePath = $gatePathItem.FullName
    $gate = Get-Content -LiteralPath $gatePath -Raw | ConvertFrom-Json
    $benchmarkPath = Get-BenchmarkReport $gatePath $gate
    $candidateDir = Split-Path -Parent $gatePath
    $benchmark = if ($null -ne $benchmarkPath) { Get-Content -LiteralPath $benchmarkPath -Raw | ConvertFrom-Json } else { $null }
    $evidenceText = if ($null -ne $benchmark) { Read-EvidenceText $benchmark $benchmarkPath $candidateDir } else { '' }
    $results = if ($null -ne $benchmark) { @($benchmark.results) } else { @() }
    $validRuns = @($results | Where-Object { $_.pass -and $null -ne $_.decode_tps })
    $tps = @($validRuns | ForEach-Object { [double]$_.decode_tps })
    $median = Get-Median $tps
    $validation = Get-PropertyValue (Get-PropertyValue $gate 'commands') 'validation'
    $g1 = $null -ne $validation -and [int](Get-PropertyValue $validation 'exitCode' -1) -eq 0
    $parity = Get-ParityGate $evidenceText
    $g2 = $parity -eq 'PASS'
    $g3 = $null -ne $benchmark -and $benchmark.verdict -eq 'PASS' -and
        $validRuns.Count -eq $results.Count -and $results.Count -eq $RequiredRuns -and
        (@($results | Where-Object { [int](Get-PropertyValue $_ 'host_forward_layers' -1) -ne 0 }).Count -eq 0) -and
        (@($results | Where-Object { [int](Get-PropertyValue $_ 'nan' -1) -ne 0 -or [int](Get-PropertyValue $_ 'inf' -1) -ne 0 }).Count -eq 0) -and
        (@($results | Where-Object { [int](Get-PropertyValue $_ 'fence_failures' -1) -ne 0 }).Count -eq 0)
    $g4 = $validRuns.Count -eq $RequiredRuns
    $g5 = $null -ne $median -and $median -ge $CheckpointTps
    $g6 = $null -ne $median -and $median -gt ($BaselineMedianTps * (1.0 + $MinRelativeGain))
    $restoration = Test-Restoration $gate
    $g7 = $restoration -eq 'PASS'
    $evaluation = [ordered]@{
        schema = 'RAWRXD_DEEP2_TPS_CAMPAIGN_EVALUATION_001'
        candidate = Split-Path -Leaf $candidateDir
        gate_report = $gatePath
        benchmark_report = $benchmarkPath
        median_tps = $median
        run_tps = @($tps)
        route = [ordered]@{
            primary_only = Get-PropertyValue $benchmark 'primary_only'
            dense_exec = Get-PropertyValue $benchmark 'dense_exec'
            q4_tile = Get-PropertyValue $benchmark 'q4_tile'
            q6_hot = Get-PropertyValue $benchmark 'q6_hot'
            q6_single_row = Get-PropertyValue $benchmark 'q6_single_row'
            gpu0_weight = Get-PropertyValue $benchmark 'gpu0_weight'
            gpu1_weight = Get-PropertyValue $benchmark 'gpu1_weight'
        }
        parity = $parity
        restoration = $restoration
        gates = [ordered]@{ G1_SPIRV = $g1; G2_PARITY = $g2; G3_STABILITY = $g3; G4_RUNS = $g4; G5_CHECKPOINT_TPS = $g5; G6_BASELINE_GAIN = $g6; G7_RESTORE = $g7 }
        checkpointed = $false
        promotion_eligible = $g1 -and $g2 -and $g3 -and $g4 -and $g5 -and $g6 -and $g7
        generated_utc = [DateTime]::UtcNow.ToString('o')
    }
    if ($g1 -and $g2 -and $g3 -and $g4 -and $g5) {
        $checkpointName = ('{0}_{1}tps' -f ($evaluation.candidate -replace '[^A-Za-z0-9_.-]', '_'), ([math]::Round($median, 3)))
        $checkpointPath = Join-Path $CheckpointRoot $checkpointName
        Write-Checkpoint $evaluation $gatePath $benchmarkPath $checkpointPath
        $evaluation.checkpointed = $true
        $evaluation.checkpoint = $checkpointPath
        $evaluation | ConvertTo-Json -Depth 14 | Set-Content -LiteralPath (Join-Path $checkpointPath 'checkpoint.json') -Encoding UTF8
    }
    $evaluations.Add([pscustomobject]$evaluation)
    ($evaluation | ConvertTo-Json -Depth 14 -Compress) | Add-Content -LiteralPath $EvidenceLedger -Encoding UTF8
}

$summaryPath = Join-Path $campaignPath 'campaign_evaluation.json'
[ordered]@{
    schema = 'RAWRXD_DEEP2_TPS_CAMPAIGN_EVALUATION_SUMMARY_001'
    campaign = $campaignPath
    baseline_median_tps = $BaselineMedianTps
    checkpoint_tps = $CheckpointTps
    min_relative_gain = $MinRelativeGain
    required_runs = $RequiredRuns
    candidate_count = $evaluations.Count
    checkpoint_count = @($evaluations | Where-Object { $_.checkpointed }).Count
    promotion_count = @($evaluations | Where-Object { $_.promotion_eligible }).Count
    evaluations = @($evaluations)
    ledger = $EvidenceLedger
    generated_utc = [DateTime]::UtcNow.ToString('o')
} | ConvertTo-Json -Depth 14 | Set-Content -LiteralPath $summaryPath -Encoding UTF8
Write-Output ("CANDIDATES={0} CHECKPOINTS={1} PROMOTION_ELIGIBLE={2}" -f $evaluations.Count, (@($evaluations | Where-Object { $_.checkpointed }).Count), (@($evaluations | Where-Object { $_.promotion_eligible }).Count))
Write-Output "SUMMARY=$summaryPath"
Write-Output "LEDGER=$EvidenceLedger"
