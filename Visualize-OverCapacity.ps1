# =============================================================================
# Visualize-OverCapacity.ps1 - Plot RawRamXD Over-Capacity Results
# =============================================================================

param(
    [string]$LatencyFile = "overcapacity_latency.csv",
    [string]$ResidencyFile = "overcapacity_residency.csv",
    [string]$OutputDir = "."
)

$ErrorActionPreference = "Stop"

function Write-Header {
    param([string]$Title)
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

Write-Header "RawRamXD Over-Capacity Visualization"

# Check if files exist
if (-not (Test-Path $LatencyFile)) {
    Write-Host "[!] Latency file not found: $LatencyFile" -ForegroundColor Red
    Write-Host "    Run RawRamXD_OverCapacity_Benchmark.exe first" -ForegroundColor Yellow
    exit 1
}

if (-not (Test-Path $ResidencyFile)) {
    Write-Host "[!] Residency file not found: $ResidencyFile" -ForegroundColor Red
    exit 1
}

Write-Host "[+] Loading data..." -ForegroundColor Green

# Import data
$latencyData = Import-Csv $LatencyFile
$residencyData = Import-Csv $ResidencyFile

Write-Host "    Latency samples: $($latencyData.Count)" -ForegroundColor Gray
Write-Host "    Residency samples: $($residencyData.Count)" -ForegroundColor Gray

# Calculate statistics by model size
Write-Host "`n[+] Analyzing by model size..." -ForegroundColor Green

$modelGroups = $latencyData | Group-Object -Property model_size_gb

foreach ($group in $modelGroups) {
    $size = $group.Name
    $samples = $group.Group
    
    $avgLatency = ($samples | Measure-Object -Property latency_ms -Average).Average
    $avgTPS = ($samples | Measure-Object -Property tps -Average).Average
    $avgPressure = ($samples | Measure-Object -Property vram_pressure -Average).Average
    $maxLatency = ($samples | Measure-Object -Property latency_ms -Maximum).Maximum
    $minTPS = ($samples | Measure-Object -Property tps -Minimum).Minimum
    
    Write-Host "`n  Model: ${size}GB" -ForegroundColor Yellow
    Write-Host "    Avg Latency: $([math]::Round($avgLatency, 2)) ms" -ForegroundColor White
    Write-Host "    Avg TPS: $([math]::Round($avgTPS, 2))" -ForegroundColor White
    Write-Host "    Avg VRAM Pressure: $([math]::Round($avgPressure * 100, 1))%" -ForegroundColor White
    Write-Host "    Max Latency: $([math]::Round($maxLatency, 2)) ms" -ForegroundColor White
    Write-Host "    Min TPS: $([math]::Round($minTPS, 2))" -ForegroundColor White
}

# Generate ASCII plots
Write-Host "`n[+] Generating ASCII plots..." -ForegroundColor Green

# Latency vs VRAM Pressure
Write-Host "`nLatency vs VRAM Pressure:" -ForegroundColor Cyan
Write-Host "(X-axis: VRAM Pressure %, Y-axis: Latency ms)" -ForegroundColor Gray

$pressureBuckets = @{}
foreach ($sample in $latencyData) {
    $pressure = [math]::Floor([float]$sample.vram_pressure * 10) / 10
    if (-not $pressureBuckets.ContainsKey($pressure)) {
        $pressureBuckets[$pressure] = @()
    }
    $pressureBuckets[$pressure] += [float]$sample.latency_ms
}

$sortedPressures = $pressureBuckets.Keys | Sort-Object
foreach ($p in $sortedPressures) {
    $avg = ($pressureBuckets[$p] | Measure-Object -Average).Average
    $barLength = [math]::Min(50, $avg / 2)
    $bar = "█" * $barLength
    Write-Host ([string]::Format("  {0,4:P0} | {1,-50} {2,6:F1} ms", $p, $bar, $avg)) -ForegroundColor White
}

# TPS vs Model Size
Write-Host "`nTPS vs Model Size:" -ForegroundColor Cyan
Write-Host "(X-axis: Model Size GB, Y-axis: TPS)" -ForegroundColor Gray

$sizeBuckets = @{}
foreach ($sample in $latencyData) {
    $size = [int]$sample.model_size_gb
    if (-not $sizeBuckets.ContainsKey($size)) {
        $sizeBuckets[$size] = @()
    }
    $sizeBuckets[$size] += [float]$sample.tps
}

$sortedSizes = $sizeBuckets.Keys | Sort-Object
foreach ($s in $sortedSizes) {
    $avg = ($sizeBuckets[$s] | Measure-Object -Average).Average
    $barLength = [math]::Min(50, $avg / 2)
    $bar = "█" * $barLength
    Write-Host ([string]::Format("  {0,4}GB | {1,-50} {2,6:F1}", $s, $bar, $avg)) -ForegroundColor White
}

# Residency distribution
Write-Host "`n[+] Residency Distribution:" -ForegroundColor Green

$lastSample = $residencyData | Select-Object -Last 1
if ($lastSample) {
    Write-Host "  VRAM:  $($lastSample.vram_gb) GB" -ForegroundColor White
    Write-Host "  RAM:   $($lastSample.ram_gb) GB" -ForegroundColor White
    Write-Host "  NVMe:  $($lastSample.nvme_gb) GB" -ForegroundColor White
}

# Migration statistics
Write-Host "`n[+] Migration Statistics:" -ForegroundColor Green

$totalMigrations = ($residencyData | Measure-Object -Property migrations_completed -Maximum).Maximum
$avgMigrationTime = ($residencyData | Measure-Object -Property avg_migration_ms -Average).Average

Write-Host "  Total Migrations: $totalMigrations" -ForegroundColor White
Write-Host "  Avg Migration Time: $([math]::Round($avgMigrationTime, 2)) ms" -ForegroundColor White

# Key findings
Write-Host "`n[+] Key Findings:" -ForegroundColor Cyan

$baseline = $latencyData | Where-Object { $_.model_size_gb -eq 12 } | Measure-Object -Property latency_ms -Average
$target = $latencyData | Where-Object { $_.model_size_gb -eq 20 } | Measure-Object -Property latency_ms -Average
$extreme = $latencyData | Where-Object { $_.model_size_gb -eq 48 } | Measure-Object -Property latency_ms -Average

if ($baseline.Average -gt 0) {
    $degradation20 = (($target.Average - $baseline.Average) / $baseline.Average) * 100
    $degradation48 = (($extreme.Average - $baseline.Average) / $baseline.Average) * 100
    
    Write-Host "  Baseline (12GB) Latency: $([math]::Round($baseline.Average, 2)) ms" -ForegroundColor Green
    Write-Host "  Target (20GB) Latency: $([math]::Round($target.Average, 2)) ms (+$([math]::Round($degradation20, 1))%)" -ForegroundColor Yellow
    Write-Host "  Extreme (48GB) Latency: $([math]::Round($extreme.Average, 2)) ms (+$([math]::Round($degradation48, 1))%)" -ForegroundColor Red
    
    if ($degradation20 -lt 50) {
        Write-Host "`n  ✓ PASS: 20GB over-capacity shows graceful degradation (<50% latency increase)" -ForegroundColor Green
    } else {
        Write-Host "`n  ✗ FAIL: 20GB over-capacity shows excessive degradation" -ForegroundColor Red
    }
    
    if ($degradation48 -lt 200) {
        Write-Host "  ✓ PASS: 48GB extreme shows controlled degradation (<3x latency)" -ForegroundColor Green
    } else {
        Write-Host "  ✗ FAIL: 48GB extreme shows uncontrolled degradation" -ForegroundColor Red
    }
}

Write-Host "`n[+] Analysis complete" -ForegroundColor Green
Write-Host "`nTo generate detailed plots, import the CSV files into:" -ForegroundColor Cyan
Write-Host "  - Excel: Insert → Charts → Scatter Plot" -ForegroundColor White
Write-Host "  - Python: matplotlib, seaborn" -ForegroundColor White
Write-Host "  - R: ggplot2" -ForegroundColor White
Write-Host "`nSuggested visualizations:" -ForegroundColor Cyan
Write-Host "  1. Latency vs Time (colored by model size)" -ForegroundColor White
Write-Host "  2. TPS vs VRAM Pressure (scatter)" -ForegroundColor White
Write-Host "  3. Tier usage over time (stacked area)" -ForegroundColor White
Write-Host "  4. Migration rate vs Pressure" -ForegroundColor White