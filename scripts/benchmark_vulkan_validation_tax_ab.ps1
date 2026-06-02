#!/usr/bin/env pwsh
param(
    [int]$Iterations = 10000,
    [int]$Repeats = 5,
    [string]$ExePath = "D:\rawrxd\build_win32ide\tests\RawrXD-VulkanValidationTax.exe",
    [string]$OutDir = "D:\rawrxd\bench\vulkan_validation_tax",
    [switch]$RunFullMode
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $ExePath)) {
    throw "Benchmark executable not found: $ExePath"
}

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$sessionDir = Join-Path $OutDir $stamp
New-Item -ItemType Directory -Path $sessionDir -Force | Out-Null

function Invoke-Phase {
    param(
        [string]$Mode,
        [int]$Iterations,
        [int]$RunIndex,
        [string]$SessionDir,
        [string]$ExePath
    )

    $stdoutPath = Join-Path $SessionDir ("{0}_run{1}_stdout.txt" -f $Mode, $RunIndex)
    $stderrPath = Join-Path $SessionDir ("{0}_run{1}_stderr.txt" -f $Mode, $RunIndex)

    $argList = @("--iterations", $Iterations.ToString(), "--mode=$Mode")

    $proc = Start-Process -FilePath $ExePath -ArgumentList $argList -NoNewWindow -Wait -PassThru -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath

    $stdoutText = Get-Content -Path $stdoutPath -Raw -ErrorAction SilentlyContinue

    if ($proc.ExitCode -ne 0) {
        throw "Mode '$Mode' run $RunIndex failed with exit code $($proc.ExitCode). See $stdoutPath and $stderrPath"
    }

    $metricLine = ($stdoutText -split "`r?`n" | Where-Object { $_ -match '^.+:\s+total=([0-9.]+)\s+ms\s+per-iter=([0-9.]+)\s+us\s+active-imports=([-0-9]+)$' } | Select-Object -Last 1)
    if (-not $metricLine) {
        throw "Could not parse metrics for mode '$Mode' run $RunIndex. See $stdoutPath"
    }

    $m = [regex]::Match($metricLine, '^(.+):\s+total=([0-9.]+)\s+ms\s+per-iter=([0-9.]+)\s+us\s+active-imports=([-0-9]+)$')

    [PSCustomObject]@{
        mode = $Mode
        run = $RunIndex
        label = $m.Groups[1].Value.Trim()
        total_ms = [double]$m.Groups[2].Value
        per_iter_us = [double]$m.Groups[3].Value
        active_imports = [int64]$m.Groups[4].Value
        stdout = $stdoutPath
        stderr = $stderrPath
    }
}

$results = [System.Collections.Generic.List[object]]::new()

for ($i = 1; $i -le $Repeats; $i++) {
    Write-Host ("[A/B] run {0}/{1}: guards-on" -f $i, $Repeats) -ForegroundColor Cyan
    $results.Add((Invoke-Phase -Mode "guards-on" -Iterations $Iterations -RunIndex $i -SessionDir $sessionDir -ExePath $ExePath))

    Write-Host ("[A/B] run {0}/{1}: guards-off" -f $i, $Repeats) -ForegroundColor Cyan
    $results.Add((Invoke-Phase -Mode "guards-off" -Iterations $Iterations -RunIndex $i -SessionDir $sessionDir -ExePath $ExePath))
}

if ($RunFullMode) {
    Write-Host "[A/B] optional full mode pass" -ForegroundColor Yellow
    $results.Add((Invoke-Phase -Mode "full" -Iterations $Iterations -RunIndex 1 -SessionDir $sessionDir -ExePath $ExePath))
}

$on = @($results | Where-Object { $_.mode -eq "guards-on" })
$off = @($results | Where-Object { $_.mode -eq "guards-off" })

if ($on.Count -eq 0 -or $off.Count -eq 0) {
    throw "Missing guards-on or guards-off results."
}

$onAvg = ($on | Measure-Object -Property per_iter_us -Average).Average
$offAvg = ($off | Measure-Object -Property per_iter_us -Average).Average
$onP95 = ($on | Sort-Object per_iter_us | Select-Object -Last ([Math]::Max([int][Math]::Ceiling($on.Count * 0.05), 1)) | Measure-Object -Property per_iter_us -Maximum).Maximum
$offP95 = ($off | Sort-Object per_iter_us | Select-Object -Last ([Math]::Max([int][Math]::Ceiling($off.Count * 0.05), 1)) | Measure-Object -Property per_iter_us -Maximum).Maximum
$deltaUs = $onAvg - $offAvg
$deltaPct = if ($offAvg -gt 0) { ($deltaUs / $offAvg) * 100.0 } else { 0.0 }

$summary = [PSCustomObject]@{
    timestamp = (Get-Date).ToString("o")
    iterations = $Iterations
    repeats = $Repeats
    exe_path = $ExePath
    session_dir = $sessionDir
    guards_on_avg_us = [Math]::Round($onAvg, 6)
    guards_off_avg_us = [Math]::Round($offAvg, 6)
    guards_on_p95_us = [Math]::Round($onP95, 6)
    guards_off_p95_us = [Math]::Round($offP95, 6)
    validation_tax_us = [Math]::Round($deltaUs, 6)
    validation_tax_pct = [Math]::Round($deltaPct, 6)
    runs = $results
}

$jsonPath = Join-Path $sessionDir "summary.json"
$csvPath = Join-Path $sessionDir "runs.csv"
$summary | ConvertTo-Json -Depth 6 | Set-Content -Path $jsonPath -Encoding UTF8
$results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

Write-Host "===============================================================" -ForegroundColor Green
Write-Host ("guards-on avg : {0:N3} us" -f $onAvg) -ForegroundColor Green
Write-Host ("guards-off avg: {0:N3} us" -f $offAvg) -ForegroundColor Green
Write-Host ("validation tax: {0:N3} us ({1:N2}%)" -f $deltaUs, $deltaPct) -ForegroundColor Green
Write-Host ("summary json  : {0}" -f $jsonPath) -ForegroundColor Green
Write-Host ("runs csv      : {0}" -f $csvPath) -ForegroundColor Green
Write-Host "===============================================================" -ForegroundColor Green
