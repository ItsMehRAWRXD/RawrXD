#!/usr/bin/env pwsh
param(
    [string]$LoopScriptPath = "D:\rawrxd\scripts\loop_attach_capture.ps1",
    [string]$BenchDir = "D:\rawrxd\bench\vulkan_validation_tax",
    [int]$MaxAttempts = 50,
    [int]$Iterations = 100000,
    [int]$AttachDelaySec = 5,
    [switch]$WideNet,
    [switch]$DisableAmdOverlay,
    [switch]$SetCompatLayer,
    [switch]$FailFastOnForbiddenModules,
    [switch]$MoveArtifacts,
    [switch]$KeepCleanLogs
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $LoopScriptPath)) {
    throw "Loop script not found: $LoopScriptPath"
}
if (-not (Test-Path $BenchDir)) {
    throw "Bench directory not found: $BenchDir"
}

$startUtc = (Get-Date).ToUniversalTime()
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"

$injectors = @("RadeonSoftware", "amddvr64", "obs64", "obs")
Write-Host "[PreFlight] Purging known injector processes..." -ForegroundColor Cyan
foreach ($name in $injectors) {
    Stop-Process -Name $name -Force -ErrorAction SilentlyContinue
}

Write-Host "[Run] Starting loop harness..." -ForegroundColor Cyan
& $LoopScriptPath `
    -MaxAttempts $MaxAttempts `
    -Iterations $Iterations `
    -AttachDelaySec $AttachDelaySec `
    -WideNet:$WideNet `
    -DisableAmdOverlay:$DisableAmdOverlay `
    -SetCompatLayer:$SetCompatLayer `
    -FailFastOnForbiddenModules:$FailFastOnForbiddenModules `
    -KeepCleanLogs:$KeepCleanLogs
$loopExit = $LASTEXITCODE

$summaryPath = Join-Path $BenchDir "summary_report.json"
$loopSummaryPath = Join-Path $BenchDir "capture_loop_summary.log"

$status = "Unknown"
$verdict = "Unknown"
$attempt = -1
if (Test-Path $summaryPath) {
    try {
        $reportRaw = Get-Content -Path $summaryPath -Raw
        if ($reportRaw.Trim()) {
            $report = $reportRaw | ConvertFrom-Json
            if ($report.PSObject.Properties.Name -contains "Status") {
                $status = [string]$report.Status
            }
            if ($report.PSObject.Properties.Name -contains "Verdict") {
                $verdict = [string]$report.Verdict
            }
            if ($report.PSObject.Properties.Name -contains "Attempt") {
                $attempt = [int]$report.Attempt
            }
        }
    } catch {
        $status = "UnreadableSummary"
    }
}

$bucket = "clean"
if ($status -eq "Contaminated") {
    $bucket = "contaminated"
} elseif ($verdict -ne "Unknown" -and $verdict -ne "CleanExitOrNoSignal") {
    $bucket = "contaminated"
}

$runRoot = Join-Path $BenchDir "runs"
$runDir = Join-Path (Join-Path $runRoot $bucket) $stamp
New-Item -ItemType Directory -Path $runDir -Force | Out-Null

$patterns = @("summary_report*.json", "capture_attempt_*.log", "capture_loop_summary.log")
$seedFiles = Get-ChildItem -Path $BenchDir -File | Where-Object {
    $name = $_.Name
    $isMatch = $false
    foreach ($p in $patterns) {
        if ($name -like $p) { $isMatch = $true; break }
    }
    $isMatch -and $_.LastWriteTimeUtc -ge $startUtc.AddSeconds(-2)
}

$files = New-Object System.Collections.Generic.List[System.IO.FileInfo]
foreach ($sf in @($seedFiles)) {
    $files.Add($sf)
}

if (Test-Path $summaryPath) {
    $f = Get-Item $summaryPath
    if ($f.FullName -notin $files.FullName) { $files.Add($f) }
}
if (Test-Path $loopSummaryPath) {
    $f = Get-Item $loopSummaryPath
    if ($f.FullName -notin $files.FullName) { $files.Add($f) }
}

foreach ($f in ($files | Select-Object -Unique)) {
    $dest = Join-Path $runDir $f.Name
    if ($MoveArtifacts) {
        Move-Item -Path $f.FullName -Destination $dest -Force
    } else {
        Copy-Item -Path $f.FullName -Destination $dest -Force
    }
}

$meta = [ordered]@{
    TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
    Bucket = $bucket
    LoopExitCode = $loopExit
    Status = $status
    Verdict = $verdict
    Attempt = $attempt
    RunDir = $runDir
    MoveArtifacts = [bool]$MoveArtifacts
}
$metaPath = Join-Path $runDir "run_meta.json"
$meta | ConvertTo-Json -Depth 4 | Set-Content -Path $metaPath -Encoding UTF8

$latestAllPath = Join-Path $runRoot "latest.json"
$latestBucketPath = Join-Path $runRoot ("latest_{0}.json" -f $bucket)
$latestPayload = [ordered]@{
    TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
    Bucket = $bucket
    Status = $status
    Verdict = $verdict
    Attempt = $attempt
    RunDir = $runDir
    MetaPath = $metaPath
    SummaryPath = (Join-Path $runDir "summary_report.json")
}
$latestPayload | ConvertTo-Json -Depth 4 | Set-Content -Path $latestAllPath -Encoding UTF8
$latestPayload | ConvertTo-Json -Depth 4 | Set-Content -Path $latestBucketPath -Encoding UTF8

Write-Host "[PostFlight] Routed artifacts to: $runDir" -ForegroundColor Green
Write-Host "[PostFlight] Bucket=$bucket Status=$status Verdict=$verdict" -ForegroundColor Green
Write-Host "[PostFlight] Latest pointers updated: $latestAllPath, $latestBucketPath" -ForegroundColor Green
