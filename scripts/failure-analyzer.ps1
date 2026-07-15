# RawrXD Failure Analyzer
# Analyzes inference failures and suggests corrections

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Analyze", "Report", "Trend", "Export")]
    [string]$Action = "Analyze",
    
    [string]$LogFile = "logs/rawrxd.log",
    [string]$OutputPath = "failure-reports",
    [string]$StartTime = "",
    [string]$EndTime = "",
    [switch]$AutoCorrect,
    [switch]$GenerateReport
)

$ErrorActionPreference = "Stop"

$FailurePatterns = @{
    Refusal = @("I cannot", "I'm sorry, but I can't", "I apologize, but", "I am not able to")
    Hallucination = @("I remember", "In my experience", "As a human", "I feel emotions")
    FormatViolation = @("```", "JSON:", "Output:", "Response:")
    InfiniteLoop = @("repeat", "again", "loop", "iterative")
    Timeout = @("timeout", "took too long", "exceeded", "deadline")
    SafetyViolation = @("unsafe", "harmful", "dangerous", "malicious")
    LowConfidence = @("I'm not sure", "I think", "maybe", "possibly")
    GarbageOutput = @("asdf", "qwerty", "random", "nonsense")
}

$script:Results = @{
    Timestamp = Get-Date -Format "o"
    Failures = @()
    Summary = @{}
}

function Write-Status { param([string]$Message); Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message); Write-Host "[✓] $Message" -ForegroundColor Green }
function Write-Error { param([string]$Message); Write-Host "[✗] $Message" -ForegroundColor Red }
function Write-Warning { param([string]$Message); Write-Host "[!] $Message" -ForegroundColor Yellow }

function Initialize-Analyzer {
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    Write-Status "Failure Analyzer initialized"
}

function Invoke-FailureAnalysis {
    Write-Status "Analyzing failures in: $LogFile"
    
    if (-not (Test-Path $LogFile)) {
        Write-Error "Log file not found: $LogFile"
        return
    }
    
    $content = Get-Content $LogFile -Raw
    $lines = Get-Content $LogFile
    
    $failures = @()
    $lineNum = 0
    
    foreach ($line in $lines) {
        $lineNum++
        
        foreach ($type in $FailurePatterns.Keys) {
            foreach ($pattern in $FailurePatterns[$type]) {
                if ($line -match $pattern) {
                    $failure = @{
                        Line = $lineNum
                        Type = $type
                        Pattern = $pattern
                        Content = $line.Substring(0, [Math]::Min(100, $line.Length))
                        Timestamp = Extract-Timestamp $line
                        SuggestedAction = Get-SuggestedAction $type
                    }
                    $failures += $failure
                    break
                }
            }
        }
    }
    
    $script:Results.Failures = $failures
    
    # Generate summary
    $summary = @{}
    foreach ($type in $FailurePatterns.Keys) {
        $count = ($failures | Where-Object { $_.Type -eq $type }).Count
        if ($count -gt 0) {
            $summary[$type] = $count
        }
    }
    $script:Results.Summary = $summary
    
    Show-AnalysisResults
}

function Extract-Timestamp {
    param([string]$Line)
    if ($Line -match '(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})') {
        return $matches[1]
    }
    return "Unknown"
}

function Get-SuggestedAction {
    param([string]$FailureType)
    
    switch ($FailureType) {
        "Refusal" { return "Apply token bias or retry with different prompt" }
        "Hallucination" { return "Inject context constraints or factual grounding" }
        "FormatViolation" { return "Apply output format template or schema validation" }
        "InfiniteLoop" { return "Set iteration limits or timeout guards" }
        "Timeout" { return "Optimize model configuration or reduce context" }
        "SafetyViolation" { return "Apply safety filters or content moderation" }
        "LowConfidence" { return "Increase temperature or request clarification" }
        "GarbageOutput" { return "Restart model or clear KV cache" }
        default { return "Manual review required" }
    }
}

function Show-AnalysisResults {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Failure Analysis Results" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "Total Failures Detected: $($script:Results.Failures.Count)" -ForegroundColor White
    Write-Host ""
    
    if ($script:Results.Summary.Count -gt 0) {
        Write-Host "Failure Breakdown:" -ForegroundColor White
        foreach ($type in $script:Results.Summary.Keys | Sort-Object { $script:Results.Summary[$_] } -Descending) {
            $count = $script:Results.Summary[$type]
            Write-Host "  $type`: $count" -ForegroundColor Yellow
        }
        Write-Host ""
    }
    
    if ($script:Results.Failures.Count -gt 0) {
        Write-Host "Recent Failures:" -ForegroundColor White
        $script:Results.Failures | Select-Object -Last 10 | ForEach-Object {
            Write-Host "  [$($_.Type)] Line $($_.Line): $($_.Content)..." -ForegroundColor Gray
            Write-Host "    Suggested: $($_.SuggestedAction)" -ForegroundColor DarkGray
        }
    }
    
    Write-Host ""
}

function Export-FailureReport {
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $reportFile = "$OutputPath\failure-report-$timestamp.json"
    
    $script:Results | ConvertTo-Json -Depth 10 | Out-File $reportFile
    Write-Success "Report exported to: $reportFile"
    
    # Generate HTML report
    $htmlFile = "$OutputPath\failure-report-$timestamp.html"
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>RawrXD Failure Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { background: white; padding: 20px; border-radius: 8px; }
        h1 { color: #333; }
        .metric { display: inline-block; margin: 10px 20px 10px 0; padding: 10px; background: #f0f0f0; border-radius: 4px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #ddd; }
        th { background: #4CAF50; color: white; }
        .refusal { color: #f57c00; }
        .hallucination { color: #d32f2f; }
        .format { color: #1976d2; }
    </style>
</head>
<body>
    <div class="container">
        <h1>RawrXD Failure Analysis Report</h1>
        <p>Generated: $($script:Results.Timestamp)</p>
        <div class="metric"><strong>Total Failures:</strong> $($script:Results.Failures.Count)</div>
        <table>
            <tr><th>Type</th><th>Line</th><th>Content</th><th>Suggested Action</th></tr>
"@
    foreach ($failure in $script:Results.Failures) {
        $class = $failure.Type.ToLower()
        $html += "<tr class='$class'><td>$($failure.Type)</td><td>$($failure.Line)</td><td>$($failure.Content)</td><td>$($failure.SuggestedAction)</td></tr>"
    }
    
    $html += @"
        </table>
    </div>
</body>
</html>
"@
    
    $html | Out-File $htmlFile
    Write-Success "HTML report exported to: $htmlFile"
}

function Show-FailureTrends {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Failure Trends" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    if ($script:Results.Failures.Count -eq 0) {
        Write-Host "No failure data available" -ForegroundColor Gray
        return
    }
    
    # Group by hour
    $hourly = @{}
    foreach ($failure in $script:Results.Failures) {
        $hour = [DateTime]$failure.Timestamp
        $hourKey = $hour.ToString("yyyy-MM-dd HH:00")
        if (-not $hourly.ContainsKey($hourKey)) {
            $hourly[$hourKey] = 0
        }
        $hourly[$hourKey]++
    }
    
    Write-Host "Failures by Hour:" -ForegroundColor White
    foreach ($hour in $hourly.Keys | Sort-Object) {
        $count = $hourly[$hour]
        $bar = "█" * $count
        Write-Host "  $hour : $bar ($count)" -ForegroundColor Gray
    }
    
    Write-Host ""
}

# Main execution
function Main {
    Write-Host "RawrXD Failure Analyzer" -ForegroundColor Cyan
    Write-Host "=======================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-Analyzer
    
    switch ($Action) {
        "Analyze" { Invoke-FailureAnalysis }
        "Report" { Invoke-FailureAnalysis; Export-FailureReport }
        "Trend" { Invoke-FailureAnalysis; Show-FailureTrends }
        "Export" { Invoke-FailureAnalysis; Export-FailureReport }
    }
    
    Write-Host ""
}

Main
