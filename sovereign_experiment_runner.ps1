# ==============================================================================
# Sovereign Experiment Matrix Runner
# Data-driven experiment orchestrator for worker-performance science loops.
# ==============================================================================
param(
    [string]$MatrixPath = "d:\rawrxd-ci-bootstrap\sovereign_experiment_matrix.sample.json",
    [string]$PipelineScript = "d:\rawrxd-ci-bootstrap\sovereign_run_full_cycle.ps1",
    [string]$RunsRoot = "d:\rawrxd-ci-bootstrap\runs",
    [string]$OutputCsvPath = "d:\rawrxd-ci-bootstrap\sovereign_experiment_leaderboard.csv",
    [string]$OutputJsonPath = "d:\rawrxd-ci-bootstrap\sovereign_experiment_leaderboard.json",
    [string]$DetailCsvPath = "d:\rawrxd-ci-bootstrap\sovereign_experiment_repeats.csv",
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

function To-IntOrDefault([object]$v, [int]$d) {
    if ($null -eq $v -or $v -eq "") { return $d }
    return [int]$v
}

function To-BoolOrDefault([object]$v, [bool]$d) {
    if ($null -eq $v) { return $d }
    return [bool]$v
}

function Get-LatestRunDir([string]$root) {
    $dirs = Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
    if ($null -eq $dirs -or $dirs.Count -eq 0) { return $null }
    return $dirs[0].FullName
}

function Read-JsonFile([string]$path) {
    if (-not (Test-Path $path)) { throw "Missing file: $path" }
    return Get-Content -Path $path -Raw | ConvertFrom-Json
}

function Get-DominantBin([object[]]$bins) {
    if ($null -eq $bins -or $bins.Count -eq 0) { return $null }
    return $bins | Sort-Object {[int]$_.SampleCount} -Descending | Select-Object -First 1
}

function Get-Median([double[]]$values) {
    if ($null -eq $values -or $values.Count -eq 0) { return [double]0 }
    $sorted = $values | Sort-Object
    $n = $sorted.Count
    if (($n % 2) -eq 1) {
        return [double]$sorted[[int]($n / 2)]
    }
    $a = [double]$sorted[[int](($n / 2) - 1)]
    $b = [double]$sorted[[int]($n / 2)]
    return (($a + $b) / 2.0)
}

function Get-PowerShellExe {
    $winPs = Join-Path $PSHOME "powershell.exe"
    if (Test-Path $winPs) { return $winPs }

    $pwshCmd = Get-Command pwsh -ErrorAction SilentlyContinue
    if ($pwshCmd) { return $pwshCmd.Source }

    $psCmd = Get-Command powershell -ErrorAction SilentlyContinue
    if ($psCmd) { return $psCmd.Source }

    throw "No PowerShell executable found"
}

if (-not (Test-Path $PipelineScript)) {
    throw "Pipeline script not found: $PipelineScript"
}

$cfg = Read-JsonFile $MatrixPath
$entries = @()
if ($null -ne $cfg.matrix) {
    $entries += @($cfg.matrix)
}
if ($null -ne $cfg.experiments) {
    $entries += @($cfg.experiments)
}
if ($entries.Count -eq 0) { throw "Matrix is empty in $MatrixPath" }

$g = $cfg.global_overrides
$globalRequest = To-IntOrDefault $g.request_count 1000
$globalCancel = To-IntOrDefault $g.cancel_percent 15
$globalSeed = To-IntOrDefault $g.seed 42
$globalRepeat = To-IntOrDefault $g.repeat_count 1
$globalCooldown = To-IntOrDefault $g.cooldown_sec 3
$globalSaturation = To-IntOrDefault $g.saturation_threshold 48
$globalBurnIn = To-IntOrDefault $g.burn_in_samples 100
$globalSidecarMs = To-IntOrDefault $g.sidecar_interval_ms 25
$globalIncludeSlot = To-BoolOrDefault $g.include_slot_metadata $true

$psExe = Get-PowerShellExe
$results = New-Object System.Collections.Generic.List[object]
$detailRows = New-Object System.Collections.Generic.List[object]

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "Sovereign Experiment Matrix Runner" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "Matrix: $MatrixPath"
Write-Host "DryRun: $DryRun"

$idx = 0
foreach ($exp in $entries) {
    $idx++
    $name = if ([string]::IsNullOrWhiteSpace($exp.name)) { "exp_$idx" } else { [string]$exp.name }

    $ov = if ($null -ne $exp.overrides) { $exp.overrides } else { $exp }

    $req = To-IntOrDefault $ov.request_count $globalRequest
    $cancel = To-IntOrDefault $ov.cancel_percent $globalCancel
    $seed = To-IntOrDefault $ov.seed $globalSeed
    $repeatCount = [Math]::Max(1, (To-IntOrDefault $ov.repeat_count $globalRepeat))
    $cooldown = To-IntOrDefault $ov.cooldown_sec $globalCooldown
    $sat = To-IntOrDefault $ov.saturation_threshold $globalSaturation
    $burnIn = To-IntOrDefault $ov.burn_in_samples $globalBurnIn
    $sidecarMs = To-IntOrDefault $ov.sidecar_interval_ms $globalSidecarMs
    $includeSlot = if ($null -ne $ov.include_slot_metadata) { [bool]$ov.include_slot_metadata } else { $globalIncludeSlot }
    $streamerRequested = if ($null -ne $ov.streamer) { [int]$ov.streamer } else { $null }
    $streamer = if ($null -ne $streamerRequested) { $streamerRequested } else { -1 }

    Write-Host "[$idx/$($entries.Count)] $name :: request=$req cancel=$cancel seed=$seed repeats=$repeatCount burnin=$burnIn"
    if ($null -ne $streamerRequested) {
        Write-Host "  Streamer override requested: $streamerRequested" -ForegroundColor Yellow
    }

    if ($DryRun) {
        $results.Add([PSCustomObject]@{
            Experiment = $name
            RequestCount = $req
            CancelPercent = $cancel
            Seed = $seed
            RepeatCount = $repeatCount
            BurnInSamples = $burnIn
            GatePassed = $false
            GateAvgMs = 0
            GateP95Ms = 0
            DominantBin = ""
            DominantBinStdDevMs = 0
            DominantBinAvgLatencyMs = 0
            BackpressureEvents = 0
            MaxFillOverall = 0
            RunDir = ""
            StreamerRequested = if ($null -ne $streamerRequested) { $streamerRequested } else { -1 }
            Status = "DRY_RUN"
        })
        continue
    }

    $repeatStats = New-Object System.Collections.Generic.List[object]

    for ($rep = 1; $rep -le $repeatCount; $rep++) {
        $before = Get-LatestRunDir $RunsRoot

        $invokeParams = @(
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", $PipelineScript,
            "-RequestCount", $req,
            "-CancelPercent", $cancel,
            "-Seed", $seed,
            "-Streamer", $streamer,
            "-BurnInSamples", $burnIn,
            "-SaturationThreshold", $sat,
            "-SidecarIntervalMs", $sidecarMs,
            "-RunsRoot", $RunsRoot
        )
        if ($includeSlot) { $invokeParams += "-IncludeSlotMetadata" }

        & $psExe @invokeParams
        $pipelineExit = $LASTEXITCODE

        $after = Get-LatestRunDir $RunsRoot
        if ([string]::IsNullOrWhiteSpace($after) -or $after -eq $before) {
            throw "Unable to resolve new run directory for experiment $name repeat $rep"
        }

        $corrPath = Join-Path $after "correlation_report.json"
        if (-not (Test-Path $corrPath)) {
            throw "Missing correlation report for $name repeat $rep at $corrPath"
        }

        $corr = Read-JsonFile $corrPath
        $dominant = Get-DominantBin $corr.PerBin

        $gatePassed = $false
        $gateAvg = 0.0
        $gateP95 = 0.0
        if ($null -ne $corr.GateSummary) {
            if ($null -ne $corr.GateSummary.GatePassed) { $gatePassed = [bool]$corr.GateSummary.GatePassed }
            if (-not [string]::IsNullOrWhiteSpace([string]$corr.GateSummary.AvgInferenceMs)) { $gateAvg = [double]$corr.GateSummary.AvgInferenceMs }
            if (-not [string]::IsNullOrWhiteSpace([string]$corr.GateSummary.P95InferenceMs)) { $gateP95 = [double]$corr.GateSummary.P95InferenceMs }
        }

        $repRow = [PSCustomObject]@{
            Experiment = $name
            Repeat = $rep
            RequestCount = $req
            CancelPercent = $cancel
            Seed = $seed
            BurnInSamples = $burnIn
            GatePassed = $gatePassed
            GateAvgMs = $gateAvg
            GateP95Ms = $gateP95
            DominantBin = if ($dominant) { [string]$dominant.FillBin } else { "" }
            DominantBinStdDevMs = if ($dominant) { [double]$dominant.StdDevLatencyMs } else { 0 }
            DominantBinAvgLatencyMs = if ($dominant) { [double]$dominant.AvgLatencyMs } else { 0 }
            BackpressureEvents = if ($corr.Overall) { [int]$corr.Overall.TotalBackpressureEvents } else { 0 }
            MaxFillOverall = if ($corr.Overall) { [int]$corr.Overall.MaxFillOverall } else { 0 }
            StreamerRequested = if ($null -ne $streamerRequested) { $streamerRequested } else { -1 }
            RunDir = $after
            Status = if ($pipelineExit -eq 0) { "OK" } else { "PIPELINE_EXIT_$pipelineExit" }
        }

        $repeatStats.Add($repRow)
        $detailRows.Add($repRow)

        if ($cooldown -gt 0 -and ($rep -lt $repeatCount -or $idx -lt $entries.Count)) {
            Write-Host "Cooldown ${cooldown}s"
            Start-Sleep -Seconds $cooldown
        }
    }

    $allPassed = (@($repeatStats | Where-Object { -not $_.GatePassed }).Count -eq 0)
    $allOk = (@($repeatStats | Where-Object { $_.Status -ne "OK" }).Count -eq 0)
    $medianGateP95 = [Math]::Round((Get-Median (@($repeatStats | ForEach-Object { [double]$_.GateP95Ms }))), 4)
    $medianGateAvg = [Math]::Round((Get-Median (@($repeatStats | ForEach-Object { [double]$_.GateAvgMs }))), 4)
    $medianStd = [Math]::Round((Get-Median (@($repeatStats | ForEach-Object { [double]$_.DominantBinStdDevMs }))), 4)
    $medianDomAvg = [Math]::Round((Get-Median (@($repeatStats | ForEach-Object { [double]$_.DominantBinAvgLatencyMs }))), 4)
    $maxFill = @($repeatStats | Measure-Object MaxFillOverall -Maximum)[0].Maximum
    $bpMax = @($repeatStats | Measure-Object BackpressureEvents -Maximum)[0].Maximum
    $domBin = (Get-DominantBin @($repeatStats | Group-Object DominantBin | ForEach-Object {
        [PSCustomObject]@{ FillBin = $_.Name; SampleCount = $_.Count }
    })).FillBin

    $results.Add([PSCustomObject]@{
        Experiment = $name
        RequestCount = $req
        CancelPercent = $cancel
        Seed = $seed
        RepeatCount = $repeatCount
        BurnInSamples = $burnIn
        GatePassed = $allPassed
        GateAvgMs = $medianGateAvg
        GateP95Ms = $medianGateP95
        DominantBin = if ($domBin) { [string]$domBin } else { "" }
        DominantBinStdDevMs = $medianStd
        DominantBinAvgLatencyMs = $medianDomAvg
        BackpressureEvents = [int]$bpMax
        MaxFillOverall = [int]$maxFill
        StreamerRequested = if ($null -ne $streamerRequested) { $streamerRequested } else { -1 }
        RunDir = ($repeatStats[-1].RunDir)
        Status = if ($allOk) { if ($allPassed) { "OK" } else { "GATE_FAIL" } } else { "PIPELINE_ISSUES" }
    })
}

$ranked = $results | Sort-Object @{Expression={$_.GatePassed};Descending=$true}, @{Expression={$_.GateP95Ms};Descending=$false}, @{Expression={$_.DominantBinStdDevMs};Descending=$false}, @{Expression={$_.BackpressureEvents};Descending=$false}

$ranked | Export-Csv -Path $OutputCsvPath -NoTypeInformation
if ($detailRows.Count -gt 0) {
    $detailRows | Export-Csv -Path $DetailCsvPath -NoTypeInformation
}

$out = [PSCustomObject]@{
    GeneratedUtc = [DateTime]::UtcNow.ToString("o")
    MatrixPath = $MatrixPath
    DryRun = [bool]$DryRun
    Results = $ranked
}
$out | ConvertTo-Json -Depth 6 | Set-Content -Path $OutputJsonPath -Encoding UTF8

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "EXPERIMENT LEADERBOARD" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
$ranked | Format-Table Experiment,RequestCount,CancelPercent,Seed,GatePassed,GateP95Ms,DominantBinStdDevMs,BackpressureEvents,MaxFillOverall,Status -AutoSize
Write-Host ""
Write-Host "CSV: $OutputCsvPath"
if ($detailRows.Count -gt 0) {
    Write-Host "Detail CSV: $DetailCsvPath"
}
Write-Host "JSON: $OutputJsonPath"
