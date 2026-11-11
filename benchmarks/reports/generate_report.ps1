# Benchmark Report Generator
# Creates HTML and Markdown reports from benchmark results

param(
    [Parameter(Mandatory=$true)]
    [string]$ResultsPath,
    
    [string]$OutputPath = "benchmarks/reports",
    [string]$Title = "RawrXD Performance Benchmark Report",
    [switch]$IncludeCharts
)

function Import-BenchmarkResults {
    param([string]$Path)
    
    if (-not (Test-Path $Path)) {
        throw "Results file not found: $Path"
    }
    
    $results = Get-Content $Path | ConvertFrom-Json
    return $results
}

function New-HTMLReport {
    param([PSCustomObject]$Results)
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>$Title</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #007acc; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th { background: #007acc; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f5f5f5; }
        .metric { display: inline-block; margin: 10px 20px 10px 0; padding: 15px; background: #f9f9f9; border-left: 4px solid #007acc; }
        .metric-value { font-size: 24px; font-weight: bold; color: #007acc; }
        .metric-label { font-size: 12px; color: #666; }
        .pass { color: #28a745; }
        .fail { color: #dc3545; }
        .warning { color: #ffc107; }
        .chart { margin: 20px 0; padding: 20px; background: #f9f9f9; border: 1px solid #ddd; }
    </style>
</head>
<body>
    <div class="container">
        <h1>$Title</h1>
        <p><strong>Generated:</strong> $($Results.timestamp)</p>
        <p><strong>Test Type:</strong> $($Results.test_type)</p>
        
        <h2>System Information</h2>
        <div class="metric">
            <div class="metric-value">$($Results.system_info.cpu_cores)</div>
            <div class="metric-label">CPU Cores</div>
        </div>
        <div class="metric">
            <div class="metric-value">$($Results.system_info.memory_gb) GB</div>
            <div class="metric-label">Memory</div>
        </div>
        <div class="metric">
            <div class="metric-value">$($Results.system_info.powershell_version)</div>
            <div class="metric-label">PowerShell</div>
        </div>
        
        <h2>Performance Summary</h2>
        <table>
            <thead>
                <tr>
                    <th>Scenario</th>
                    <th>Concurrency</th>
                    <th>TPS</th>
                    <th>Success Rate</th>
                    <th>Latency (p50)</th>
                    <th>Latency (p95)</th>
                    <th>Latency (p99)</th>
                </tr>
            </thead>
            <tbody>
"@
    
    foreach ($scenario in $Results.scenarios) {
        $successClass = if ($scenario.success_rate -ge 99) { "pass" } elseif ($scenario.success_rate -ge 95) { "warning" } else { "fail" }
        
        $html += @"
                <tr>
                    <td>$($scenario.scenario)</td>
                    <td>$($scenario.concurrency)</td>
                    <td>$($scenario.tps)</td>
                    <td class="$successClass">$([math]::Round($scenario.success_rate, 2))%</td>
                    <td>$($scenario.latency_ms.p50) ms</td>
                    <td>$($scenario.latency_ms.p95) ms</td>
                    <td>$($scenario.latency_ms.p99) ms</td>
                </tr>
"@
    }
    
    $html += @"
            </tbody>
        </table>
        
        <h2>Detailed Results</h2>
        <pre>$($Results | ConvertTo-Json -Depth 5)</pre>
        
        <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 12px;">
            <p>RawrXD Performance Benchmark Report</p>
        </footer>
    </div>
</body>
</html>
"@
    
    return $html
}

function New-MarkdownReport {
    param([PSCustomObject]$Results)
    
    $md = @"
# $Title

**Generated:** $($Results.timestamp)  
**Test Type:** $($Results.test_type)  
**Duration:** $($Results.duration_seconds) seconds

## System Information

| Property | Value |
|----------|-------|
| CPU | $($Results.system_info.cpu) |
| Cores | $($Results.system_info.cpu_cores) |
| Memory | $($Results.system_info.memory_gb) GB |
| OS | $($Results.system_info.os) |
| PowerShell | $($Results.system_info.powershell_version) |

## Performance Summary

| Scenario | Concurrency | TPS | Success Rate | Latency (p50) | Latency (p95) | Latency (p99) |
|----------|-------------|-----|--------------|---------------|---------------|---------------|
"@
    
    foreach ($scenario in $Results.scenarios) {
        $md += "| $($scenario.scenario) | $($scenario.concurrency) | $($scenario.tps) | $([math]::Round($scenario.success_rate, 2))% | $($scenario.latency_ms.p50)ms | $($scenario.latency_ms.p95)ms | $($scenario.latency_ms.p99)ms |`n"
    }
    
    $md += @"

## Key Findings

"@
    
    # Find best TPS
    $bestTps = $Results.scenarios | Sort-Object tps -Descending | Select-Object -First 1
    if ($bestTps) {
        $md += "- **Best TPS:** $($bestTps.tps) at $($bestTps.concurrency) concurrent users`n"
    }
    
    # Find best latency
    $bestLatency = $Results.scenarios | Sort-Object { $_.latency_ms.p95 } | Select-Object -First 1
    if ($bestLatency) {
        $md += "- **Best Latency (p95):** $($bestLatency.latency_ms.p95)ms at $($bestLatency.concurrency) concurrent users`n"
    }
    
    # Find breaking point
    $breakingPoint = $Results.scenarios | Where-Object { $_.success_rate -lt 95 } | Select-Object -First 1
    if ($breakingPoint) {
        $md += "- **Breaking Point:** $($breakingPoint.concurrency) concurrent users (Success rate: $([math]::Round($breakingPoint.success_rate, 2))%)`n"
    }
    
    $md += @"

## Recommendations

"@
    
    # Generate recommendations based on results
    $avgSuccessRate = ($Results.scenarios | Measure-Object success_rate -Average).Average
    if ($avgSuccessRate -lt 99) {
        $md += "- Review error handling for failed requests`n"
    }
    
    $avgP95Latency = ($Results.scenarios.latency_ms.p95 | Measure-Object -Average).Average
    if ($avgP95Latency -gt 1000) {
        $md += "- Consider optimization for high-latency operations`n"
    }
    
    $md += @"

## Raw Data

See JSON export for complete results.

---
*Generated by RawrXD Benchmark Framework*
"@
    
    return $md
}

# Main execution
function Invoke-ReportGenerator {
    Write-Host "Benchmark Report Generator" -ForegroundColor Cyan
    Write-Host "=========================" -ForegroundColor Cyan
    Write-Host ""
    
    # Import results
    Write-Host "Importing results from: $ResultsPath" -ForegroundColor Gray
    $results = Import-BenchmarkResults -Path $ResultsPath
    
    # Create output directory
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    
    # Generate HTML report
    Write-Host "Generating HTML report..." -ForegroundColor Gray
    $html = New-HTMLReport -Results $results
    $htmlPath = "$OutputPath/benchmark-report-$timestamp.html"
    $html | Out-File $htmlPath -Encoding UTF8
    Write-Host "  Saved: $htmlPath" -ForegroundColor Green
    
    # Generate Markdown report
    Write-Host "Generating Markdown report..." -ForegroundColor Gray
    $md = New-MarkdownReport -Results $results
    $mdPath = "$OutputPath/benchmark-report-$timestamp.md"
    $md | Out-File $mdPath -Encoding UTF8
    Write-Host "  Saved: $mdPath" -ForegroundColor Green
    
    Write-Host "`nReport generation complete!" -ForegroundColor Green
    Write-Host "Open HTML report: Start-Process $htmlPath" -ForegroundColor Gray
}

# Run report generator
Invoke-ReportGenerator
