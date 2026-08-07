# RawrXD Validation Results Comparator
# Compares validation results across runs to track improvements

param(
    [Parameter(Mandatory=$true)]
    [string]$BaselinePath,
    
    [Parameter(Mandatory=$true)]
    [string]$CurrentPath,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath,
    
    [Parameter(Mandatory=$false)]
    [switch]$GenerateHTML
)

$ErrorActionPreference = "Stop"

function Write-ComparisonHeader($title) {
    Write-Host ""
    Write-Host $title -ForegroundColor Cyan
    Write-Host ("-" * $title.Length) -ForegroundColor Cyan
}

function Compare-Metrics($baseline, $current, $name, $unit, $higherIsBetter = $true) {
    $diff = $current - $baseline
    $percentChange = if ($baseline -ne 0) { ($diff / $baseline) * 100 } else { 0 }
    
    $improved = if ($higherIsBetter) { $diff -gt 0 } else { $diff -lt 0 }
    $significant = [Math]::Abs($percentChange) -gt 5  # 5% threshold
    
    $result = @{
        Name = $name
        Unit = $unit
        Baseline = $baseline
        Current = $current
        Difference = $diff
        PercentChange = $percentChange
        Improved = $improved
        Significant = $significant
    }
    
    # Console output
    $color = if ($improved) { "Green" } else { "Red" }
    $arrow = if ($improved) { "↑" } else { "↓" }
    
    Write-Host "  $name`: " -NoNewline
    Write-Host "$([math]::Round($baseline, 2)) → $([math]::Round($current, 2)) $unit " -NoNewline
    Write-Host "$arrow $([math]::Round([Math]::Abs($percentChange), 1))%" -ForegroundColor $color
    
    return $result
}

function Export-ComparisonReport($comparison, $outputPath) {
    $report = @{
        comparison_timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        baseline_file = $BaselinePath
        current_file = $CurrentPath
        
        summary = @{
            metrics_compared = $comparison.Count
            improvements = ($comparison | Where-Object { $_.Improved }).Count
            regressions = ($comparison | Where-Object { -not $_.Improved }).Count
            significant_changes = ($comparison | Where-Object { $_.Significant }).Count
        }
        
        metrics = $comparison
    }
    
    $report | ConvertTo-Json -Depth 5 | Out-File $outputPath
    Write-Host "Comparison report exported to: $outputPath" -ForegroundColor Green
}

function Export-HTMLReport($comparison, $outputPath) {
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>RawrXD Validation Comparison</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f6f8fa; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #fff; padding: 30px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        h1 { margin: 0; color: #24292e; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .metric-card { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .metric-name { font-size: 14px; color: #586069; margin-bottom: 8px; }
        .metric-values { font-size: 24px; font-weight: 600; color: #24292e; }
        .metric-change { font-size: 14px; margin-top: 8px; }
        .improved { color: #28a745; }
        .regressed { color: #dc3545; }
        .neutral { color: #6c757d; }
        table { width: 100%; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        th { background: #f6f8fa; padding: 12px; text-align: left; font-weight: 600; color: #24292e; }
        td { padding: 12px; border-bottom: 1px solid #e1e4e8; }
        tr:last-child td { border-bottom: none; }
        .significant { background: #fff3cd; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>RawrXD Validation Results Comparison</h1>
            <p>Baseline: $(Split-Path $BaselinePath -Leaf) <br>Current: $(Split-Path $CurrentPath -Leaf)</p>
            <p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        </div>
        
        <div class="summary">
            <div class="metric-card">
                <div class="metric-name">Metrics Compared</div>
                <div class="metric-values">$($comparison.Count)</div>
            </div>
            <div class="metric-card">
                <div class="metric-name">Improvements</div>
                <div class="metric-values improved">$($comparison | Where-Object { $_.Improved }).Count</div>
            </div>
            <div class="metric-card">
                <div class="metric-name">Regressions</div>
                <div class="metric-values regressed">$($comparison | Where-Object { -not $_.Improved }).Count</div>
            </div>
            <div class="metric-card">
                <div class="metric-name">Significant Changes</div>
                <div class="metric-values">$($comparison | Where-Object { $_.Significant }).Count</div>
            </div>
        </div>
        
        <table>
            <thead>
                <tr>
                    <th>Metric</th>
                    <th>Baseline</th>
                    <th>Current</th>
                    <th>Change</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
"@

    foreach ($metric in $comparison) {
        $cssClass = if ($metric.Significant) { "significant" } else { "" }
        $statusClass = if ($metric.Improved) { "improved" } else { "regressed" }
        $statusText = if ($metric.Improved) { "✓ Improved" } else { "✗ Regressed" }
        $arrow = if ($metric.Improved) { "↑" } else { "↓" }
        
        $html += @"
                <tr class="$cssClass">
                    <td>$($metric.Name)</td>
                    <td>$([math]::Round($metric.Baseline, 2)) $($metric.Unit)</td>
                    <td>$([math]::Round($metric.Current, 2)) $($metric.Unit)</td>
                    <td>$arrow $([math]::Round([Math]::Abs($metric.PercentChange), 1))%</td>
                    <td class="$statusClass">$statusText</td>
                </tr>
"@
    }
    
    $html += @"
            </tbody>
        </table>
    </div>
</body>
</html>
"@
    
    $html | Out-File $outputPath
    Write-Host "HTML report exported to: $outputPath" -ForegroundColor Green
}

# ============================================================================
# Main Execution
# ============================================================================

Write-Host "RawrXD Validation Results Comparator" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

# Load validation reports
Write-Host "Loading validation reports..." -ForegroundColor Gray

if (-not (Test-Path $BaselinePath)) {
    throw "Baseline report not found: $BaselinePath"
}

if (-not (Test-Path $CurrentPath)) {
    throw "Current report not found: $CurrentPath"
}

$baseline = Get-Content $BaselinePath | ConvertFrom-Json
$current = Get-Content $CurrentPath | ConvertFrom-Json

Write-Host "  Baseline: $BaselinePath" -ForegroundColor Gray
Write-Host "  Current: $CurrentPath" -ForegroundColor Gray
Write-Host ""

# Compare metrics
$comparison = @()

Write-ComparisonHeader "Performance Metrics Comparison"

if ($baseline.inference -and $current.inference) {
    $comparison += Compare-Metrics `
        $baseline.inference.avg_tps `
        $current.inference.avg_tps `
        "Average TPS" "TPS" $true
    
    $comparison += Compare-Metrics `
        $baseline.inference.avg_latency_ms `
        $current.inference.avg_latency_ms `
        "Average Latency" "ms" $false
    
    $comparison += Compare-Metrics `
        $baseline.inference.avg_ttft_ms `
        $current.inference.avg_ttft_ms `
        "Average TTFT" "ms" $false
    
    $comparison += Compare-Metrics `
        $baseline.inference.success_rate `
        $current.inference.success_rate `
        "Success Rate" "%" $true
}

Write-ComparisonHeader "Hardware Configuration Comparison"

if ($baseline.hardware -and $current.hardware) {
    $hwBaseline = if ($baseline.hardware.multi_gpu_ready) { 2 } else { 1 }
    $hwCurrent = if ($current.hardware.multi_gpu_ready) { 2 } else { 1 }
    
    $comparison += Compare-Metrics `
        $hwBaseline `
        $hwCurrent `
        "GPU Count" "GPUs" $true
}

Write-ComparisonHeader "Certification Status Comparison"

if ($baseline.certification -and $current.certification) {
    $baselinePassed = ($baseline.certification.psobject.properties | Where-Object { $_.Value -eq $true }).Count
    $currentPassed = ($current.certification.psobject.properties | Where-Object { $_.Value -eq $true }).Count
    
    $comparison += Compare-Metrics `
        $baselinePassed `
        $currentPassed `
        "Certification Criteria Passed" "criteria" $true
}

# Summary
Write-ComparisonHeader "Summary"

$improvements = ($comparison | Where-Object { $_.Improved }).Count
$regressions = ($comparison | Where-Object { -not $_.Improved }).Count
$significant = ($comparison | Where-Object { $_.Significant }).Count

Write-Host "  Total metrics compared: $($comparison.Count)"
Write-Host "  Improvements: $improvements" -ForegroundColor Green
Write-Host "  Regressions: $regressions" -ForegroundColor $(if ($regressions -gt 0) { "Red" } else { "Green" })
Write-Host "  Significant changes (>5%): $significant" -ForegroundColor $(if ($significant -gt 0) { "Yellow" } else { "Gray" })

# Export reports
if ($OutputPath) {
    Export-ComparisonReport $comparison $OutputPath
}

if ($GenerateHTML) {
    $htmlPath = if ($OutputPath) { 
        [System.IO.Path]::ChangeExtension($OutputPath, ".html")
    } else {
        "comparison_report.html"
    }
    Export-HTMLReport $comparison $htmlPath
}

Write-Host ""
Write-Host "Comparison complete!" -ForegroundColor Green
