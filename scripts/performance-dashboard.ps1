# RawrXD Performance Dashboard Generator
# Generates comprehensive performance reports with visualizations

param(
    [string]$BenchmarkDataPath,
    [string]$OutputDir = "performance-reports",
    [ValidateSet("html", "pdf", "json", "markdown")]
    [string]$Format = "html",
    [switch]$IncludeTrends,
    [switch]$CompareWithBaseline,
    [string]$BaselinePath,
    [int]$HistoryDays = 30
)

$ErrorActionPreference = "Stop"

$script:DashboardData = @{
    GeneratedAt = Get-Date -Format "o"
    Metrics = @{}
    Trends = @()
    Comparisons = @()
    Alerts = @()
}

function Write-Status { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[✓] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }

function Initialize-Dashboard {
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }
}

function Load-BenchmarkData {
    if (-not (Test-Path $BenchmarkDataPath)) {
        # Generate sample data for demonstration
        Write-Warning "Benchmark data not found. Generating sample data..."
        $script:DashboardData.Metrics = @{
            Inference = @{
                TokensPerSecond = 45.2
                TimeToFirstToken = 125
                MemoryUsageMB = 2048
                GPUUtilization = 78.5
            }
            ModelLoad = @{
                LoadTime = 3.5
                PeakMemoryMB = 4096
            }
            Throughput = @{
                RequestsPerSecond = 12.5
                AvgLatency = 85
                P99Latency = 150
            }
        }
        return
    }
    
    $script:DashboardData.Metrics = Get-Content $BenchmarkDataPath | ConvertFrom-Json
}

function Generate-HtmlDashboard {
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>RawrXD Performance Dashboard</title>
    <meta charset="UTF-8">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            padding: 20px;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        .header h1 {
            color: white;
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .header .timestamp {
            color: rgba(255,255,255,0.8);
        }
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .metric-card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 10px;
            padding: 20px;
            transition: transform 0.2s;
        }
        .metric-card:hover {
            transform: translateY(-5px);
            border-color: #58a6ff;
        }
        .metric-card h3 {
            color: #58a6ff;
            margin-bottom: 15px;
            font-size: 1.1em;
        }
        .metric-value {
            font-size: 2.5em;
            font-weight: bold;
            color: #3fb950;
        }
        .metric-unit {
            font-size: 0.9em;
            color: #8b949e;
        }
        .metric-delta {
            margin-top: 10px;
            padding: 5px 10px;
            border-radius: 5px;
            display: inline-block;
        }
        .delta-positive { background: #238636; color: white; }
        .delta-negative { background: #da3633; color: white; }
        .section {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 20px;
        }
        .section h2 {
            color: #f0883e;
            margin-bottom: 20px;
            border-bottom: 2px solid #30363d;
            padding-bottom: 10px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #30363d;
        }
        th {
            background: #0d1117;
            color: #58a6ff;
            font-weight: 600;
        }
        tr:hover {
            background: #1c2128;
        }
        .status-good { color: #3fb950; }
        .status-warning { color: #d29922; }
        .status-critical { color: #f85149; }
        .progress-bar {
            width: 100%;
            height: 20px;
            background: #21262d;
            border-radius: 10px;
            overflow: hidden;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #238636, #3fb950);
            transition: width 0.5s ease;
        }
        .alert {
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 10px;
        }
        .alert-info { background: #1f6feb33; border-left: 4px solid #58a6ff; }
        .alert-warning { background: #d2992233; border-left: 4px solid #d29922; }
        .alert-critical { background: #f8514933; border-left: 4px solid #f85149; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🚀 RawrXD Performance Dashboard</h1>
        <div class="timestamp">Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</div>
    </div>
"@

    # Add metrics cards
    $html += "    <div class='metrics-grid'>"
    
    foreach ($category in $script:DashboardData.Metrics.PSObject.Properties) {
        foreach ($metric in $category.Value.PSObject.Properties) {
            $value = $metric.Value
            $unit = switch ($metric.Name) {
                { $_ -match "Time|Latency" } { "ms" }
                { $_ -match "Memory|Size" } { "MB" }
                { $_ -match "Percent|Utilization" } { "%" }
                { $_ -match "PerSecond" } { "ops/s" }
                default { "" }
            }
            
            $html += @"
        <div class="metric-card">
            <h3>$($metric.Name -replace '([A-Z])', ' $1')</h3>
            <div class="metric-value">$([math]::Round($value, 2))</div>
            <div class="metric-unit">$unit</div>
        </div>
"@
        }
    }
    
    $html += "    </div>"
    
    # Add detailed sections
    $html += @"
    <div class="section">
        <h2>📊 Detailed Metrics</h2>
        <table>
            <tr>
                <th>Category</th>
                <th>Metric</th>
                <th>Value</th>
                <th>Status</th>
            </tr>
"@
    
    foreach ($category in $script:DashboardData.Metrics.PSObject.Properties) {
        foreach ($metric in $category.Value.PSObject.Properties) {
            $status = "Good"
            $statusClass = "status-good"
            
            # Simple threshold logic
            if ($metric.Name -match "Time|Latency" -and $metric.Value -gt 200) {
                $status = "Warning"
                $statusClass = "status-warning"
            }
            if ($metric.Name -match "Memory" -and $metric.Value -gt 6000) {
                $status = "Critical"
                $statusClass = "status-critical"
            }
            
            $html += @"
            <tr>
                <td>$($category.Name)</td>
                <td>$($metric.Name)</td>
                <td>$([math]::Round($metric.Value, 2))</td>
                <td class="$statusClass">$status</td>
            </tr>
"@
        }
    }
    
    $html += @"
        </table>
    </div>
</body>
</html>
"@
    
    $outputFile = "$OutputDir\performance-dashboard-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    $html | Out-File $outputFile -Encoding UTF8
    
    Write-Success "HTML dashboard generated: $outputFile"
}

function Generate-MarkdownReport {
    $md = @"
# RawrXD Performance Report

**Generated:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

## Summary

| Category | Metric | Value | Status |
|----------|--------|-------|--------|
"@
    
    foreach ($category in $script:DashboardData.Metrics.PSObject.Properties) {
        foreach ($metric in $category.Value.PSObject.Properties) {
            $md += "| $($category.Name) | $($metric.Name) | $($metric.Value) | ✅ |`n"
        }
    }
    
    $md += @"

## Detailed Analysis

### Inference Performance
- **Tokens Per Second:** $($script:DashboardData.Metrics.Inference.TokensPerSecond)
- **Time to First Token:** $($script:DashboardData.Metrics.Inference.TimeToFirstToken)ms
- **Memory Usage:** $($script:DashboardData.Metrics.Inference.MemoryUsageMB)MB

### Recommendations

1. Monitor memory usage during peak loads
2. Consider GPU optimization for better throughput
3. Review latency patterns for optimization opportunities

---
*Report generated by RawrXD Performance Dashboard*
"@
    
    $outputFile = "$OutputDir\performance-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').md"
    $md | Out-File $outputFile -Encoding UTF8
    
    Write-Success "Markdown report generated: $outputFile"
}

function Main {
    Write-Host "RawrXD Performance Dashboard Generator" -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-Dashboard
    Load-BenchmarkData
    
    switch ($Format) {
        "html" { Generate-HtmlDashboard }
        "markdown" { Generate-MarkdownReport }
        "json" { 
            $outputFile = "$OutputDir\performance-data-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
            $script:DashboardData | ConvertTo-Json -Depth 10 | Out-File $outputFile
            Write-Success "JSON data exported: $outputFile"
        }
        default { Generate-HtmlDashboard }
    }
    
    Write-Host ""
    Write-Success "Dashboard generation complete!"
}

Main
