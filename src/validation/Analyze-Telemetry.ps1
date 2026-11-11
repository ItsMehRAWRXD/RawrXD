#=============================================================================
# VAL-025 Telemetry Analyzer
# Calculates P50, P95, P99 percentiles from captured telemetry logs
#=============================================================================

param(
    [string]$LogFile = "D:\RawrXD\logs\telemetry_capture.txt",
    [string]$CsvFile = "",  # Optional: read from CSV instead of log
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  VAL-025 Telemetry Analyzer                                       ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Determine input source
$inputFile = if ($CsvFile -ne "") { $CsvFile } else { $LogFile }

if (!(Test-Path $inputFile)) {
    Write-Error "Input file not found: $inputFile"
    exit 1
}

Write-Host "Analyzing: $inputFile" -ForegroundColor Gray
Write-Host ""

$latencies = @()

if ($CsvFile -ne "") {
    # Parse CSV format
    $data = Import-Csv $CsvFile
    foreach ($row in $data) {
        if ($row.LastAgeMs -and $row.LastAgeMs -match '^\d+$') {
            $latencies += [int]$row.LastAgeMs
        }
    }
} else {
    # Parse log format with regex
    # Expected: [DebugTelemetry] ... LastAge: 15ms ...
    $pattern = 'LastAge:\s*(\d+)ms'
    
    Get-Content $LogFile | ForEach-Object {
        if ($_ -match $pattern) {
            $latencies += [int]$matches[1]
        }
    }
}

if ($latencies.Count -eq 0) {
    Write-Error "No telemetry data found in $inputFile"
    exit 1
}

# Sort for percentile calculation
$latencies = $latencies | Sort-Object

function Get-Percentile {
    param($data, $p)
    $index = [Math]::Floor(($p / 100) * ($data.Count - 1))
    return $data[$index]
}

# Calculate statistics
$stats = [PSCustomObject]@{
    Count       = $latencies.Count
    P50         = Get-Percentile $latencies 50
    P95         = Get-Percentile $latencies 95
    P99         = Get-Percentile $latencies 99
    Max         = $latencies[-1]
    Min         = $latencies[0]
    Mean        = [Math]::Round(($latencies | Measure-Object -Average).Average, 2)
    P50_Status  = if ((Get-Percentile $latencies 50) -lt 20) { "✅ PASS" } else { "❌ FAIL" }
    P95_Status  = if ((Get-Percentile $latencies 95) -lt 100) { "✅ PASS" } else { "❌ FAIL" }
    P99_Status  = if ((Get-Percentile $latencies 99) -lt 250) { "✅ PASS" } else { "❌ FAIL" }
    Max_Status  = if ($latencies[-1] -lt 500) { "✅ PASS" } else { "❌ FAIL" }
}

# Display results
Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  VAL-025 LATENCY ANALYSIS                                         ║" -ForegroundColor Green
Write-Host "╠══════════════════════════════════════════════════════════════════╣" -ForegroundColor Green
Write-Host ("║  Samples:   {0,10}                                            ║" -f $stats.Count) -ForegroundColor White
Write-Host ("╠══════════════════════════════════════════════════════════════════╣") -ForegroundColor Green
Write-Host ("║  P50:       {0,10}ms   (Threshold: < 20ms)   {1}" -f $stats.P50, $stats.P50_Status) -ForegroundColor $(if($stats.P50 -lt 20){"Green"}else{"Red"})
Write-Host ("║  P95:       {0,10}ms   (Threshold: < 100ms)  {1}" -f $stats.P95, $stats.P95_Status) -ForegroundColor $(if($stats.P95 -lt 100){"Green"}else{"Red"})
Write-Host ("║  P99:       {0,10}ms   (Threshold: < 250ms)  {1}" -f $stats.P99, $stats.P99_Status) -ForegroundColor $(if($stats.P99 -lt 250){"Green"}else{"Red"})
Write-Host ("║  Max:       {0,10}ms   (Threshold: < 500ms)  {1}" -f $stats.Max, $stats.Max_Status) -ForegroundColor $(if($stats.Max -lt 500){"Green"}else{"Red"})
Write-Host ("╠══════════════════════════════════════════════════════════════════╣") -ForegroundColor Green
Write-Host ("║  Min:       {0,10}ms                                             ║" -f $stats.Min) -ForegroundColor Gray
Write-Host ("║  Mean:      {0,10}ms                                             ║" -f $stats.Mean) -ForegroundColor Gray
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Green

# Overall certification
$certified = ($stats.P50 -lt 20) -and ($stats.P95 -lt 100) -and ($stats.P99 -lt 250) -and ($stats.Max -lt 500)

Write-Host ""
if ($certified) {
    Write-Host "✅ VAL-025 CERTIFICATION: PASSED" -ForegroundColor Green -BackgroundColor Black
} else {
    Write-Host "❌ VAL-025 CERTIFICATION: FAILED" -ForegroundColor Red -BackgroundColor Black
}

if ($Verbose) {
    Write-Host ""
    Write-Host "Distribution:" -ForegroundColor Cyan
    $buckets = @(
        @{ Name = "0-10ms";   Min = 0;   Max = 10 },
        @{ Name = "10-20ms";  Min = 10;  Max = 20 },
        @{ Name = "20-50ms";  Min = 20;  Max = 50 },
        @{ Name = "50-100ms"; Min = 50;  Max = 100 },
        @{ Name = "100-250ms";Min = 100; Max = 250 },
        @{ Name = "250ms+";   Min = 250; Max = [int]::MaxValue }
    )
    
    foreach ($bucket in $buckets) {
        $count = ($latencies | Where-Object { $_ -ge $bucket.Min -and $_ -lt $bucket.Max }).Count
        $pct = [Math]::Round(($count / $latencies.Count) * 100, 1)
        $bar = "█" * [Math]::Floor($pct / 2)
        Write-Host ("  {0,-12} {1,5} ({2,5}%) {3}" -f $bucket.Name, $count, $pct, $bar) -ForegroundColor Gray
    }
}

Write-Host ""
