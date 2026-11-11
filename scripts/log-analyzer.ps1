# RawrXD Log Analyzer
# Analyzes log files for errors, patterns, and performance metrics

param(
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "logs",
    
    [ValidateSet("Errors", "Performance", "Security", "All")]
    [string]$AnalysisType = "All",
    
    [string]$OutputPath = "logs\analysis",
    [string]$StartTime = "",
    [string]$EndTime = "",
    [switch]$RealTime,
    [int]$TailLines = 100,
    [switch]$ExportJson
)

$ErrorActionPreference = "Stop"

# Log patterns
$Patterns = @{
    Error = @(
        "ERROR",
        "FATAL",
        "CRITICAL",
        "Exception",
        "Stack trace",
        "Assertion failed"
    )
    Warning = @(
        "WARNING",
        "WARN",
        "Deprecated",
        "Obsolete"
    )
    Performance = @(
        "tokens/sec",
        "latency",
        "memory usage",
        "GPU utilization",
        "CPU usage"
    )
    Security = @(
        "unauthorized",
        "authentication failed",
        "invalid token",
        "rate limit",
        "suspicious"
    )
}

function Write-Status {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[✓] $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "[✗] $Message" -ForegroundColor Red
}

function Initialize-Analyzer {
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    $script:Results = @{
        Timestamp = Get-Date -Format "o"
        LogPath = $LogPath
        AnalysisType = $AnalysisType
        FilesAnalyzed = 0
        TotalLines = 0
        Errors = @()
        Warnings = @()
        PerformanceMetrics = @{}
        SecurityEvents = @()
        Summary = @{}
    }
}

function Get-LogFiles {
    $files = @()
    
    if (Test-Path $LogPath) {
        if ((Get-Item $LogPath) -is [System.IO.DirectoryInfo]) {
            $files = Get-ChildItem -Path $LogPath -Filter "*.log" -Recurse
            $files += Get-ChildItem -Path $LogPath -Filter "*.txt" -Recurse
        } else {
            $files = Get-Item $LogPath
        }
    }
    
    return $files
}

function Invoke-LogAnalysis {
    param([System.IO.FileInfo]$File)
    
    Write-Status "Analyzing: $($File.Name)"
    
    $lines = Get-Content $File.FullName
    $lineNumber = 0
    
    foreach ($line in $lines) {
        $lineNumber++
        $script:Results.TotalLines++
        
        # Check for errors
        if ($AnalysisType -eq "All" -or $AnalysisType -eq "Errors") {
            foreach ($pattern in $Patterns.Error) {
                if ($line -match $pattern) {
                    $script:Results.Errors += @{
                        File = $File.Name
                        Line = $lineNumber
                        Message = $line
                        Pattern = $pattern
                        Timestamp = Extract-Timestamp $line
                    }
                }
            }
        }
        
        # Check for warnings
        if ($AnalysisType -eq "All" -or $AnalysisType -eq "Errors") {
            foreach ($pattern in $Patterns.Warning) {
                if ($line -match $pattern) {
                    $script:Results.Warnings += @{
                        File = $File.Name
                        Line = $lineNumber
                        Message = $line
                        Pattern = $pattern
                    }
                }
            }
        }
        
        # Extract performance metrics
        if ($AnalysisType -eq "All" -or $AnalysisType -eq "Performance") {
            Extract-PerformanceMetrics $line $File.Name
        }
        
        # Check for security events
        if ($AnalysisType -eq "All" -or $AnalysisType -eq "Security") {
            foreach ($pattern in $Patterns.Security) {
                if ($line -match $pattern) {
                    $script:Results.SecurityEvents += @{
                        File = $File.Name
                        Line = $lineNumber
                        Message = $line
                        Pattern = $pattern
                        Severity = "High"
                    }
                }
            }
        }
    }
    
    $script:Results.FilesAnalyzed++
}

function Extract-Timestamp {
    param([string]$Line)
    
    # Common timestamp patterns
    $patterns = @(
        '(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})',
        '(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})',
        '(\[\d{2}:\d{2}:\d{2}\])'
    )
    
    foreach ($pattern in $patterns) {
        if ($Line -match $pattern) {
            return $matches[1]
        }
    }
    
    return $null
}

function Extract-PerformanceMetrics {
    param(
        [string]$Line,
        [string]$FileName
    )
    
    # Tokens per second
    if ($Line -match 'tokens/sec[:\s]+([\d.]+)') {
        $tps = [float]$matches[1]
        if (-not $script:Results.PerformanceMetrics.ContainsKey("TokensPerSecond")) {
            $script:Results.PerformanceMetrics["TokensPerSecond"] = @()
        }
        $script:Results.PerformanceMetrics["TokensPerSecond"] += $tps
    }
    
    # Latency
    if ($Line -match 'latency[:\s]+([\d.]+)\s*ms') {
        $latency = [float]$matches[1]
        if (-not $script:Results.PerformanceMetrics.ContainsKey("Latency")) {
            $script:Results.PerformanceMetrics["Latency"] = @()
        }
        $script:Results.PerformanceMetrics["Latency"] += $latency
    }
    
    # Memory usage
    if ($Line -match 'memory[:\s]+([\d.]+)\s*(MB|GB)') {
        $memory = [float]$matches[1]
        $unit = $matches[2]
        if ($unit -eq "GB") { $memory *= 1024 }
        if (-not $script:Results.PerformanceMetrics.ContainsKey("MemoryMB")) {
            $script:Results.PerformanceMetrics["MemoryMB"] = @()
        }
        $script:Results.PerformanceMetrics["MemoryMB"] += $memory
    }
    
    # GPU utilization
    if ($Line -match 'GPU utilization[:\s]+([\d.]+)%') {
        $gpu = [float]$matches[1]
        if (-not $script:Results.PerformanceMetrics.ContainsKey("GPUUtilization")) {
            $script:Results.PerformanceMetrics["GPUUtilization"] = @()
        }
        $script:Results.PerformanceMetrics["GPUUtilization"] += $gpu
    }
}

function Show-AnalysisResults {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Log Analysis Results" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "Files Analyzed: $($script:Results.FilesAnalyzed)" -ForegroundColor White
    Write-Host "Total Lines: $($script:Results.TotalLines)" -ForegroundColor White
    Write-Host ""
    
    # Errors
    if ($script:Results.Errors.Count -gt 0) {
        Write-Host "Errors Found: $($script:Results.Errors.Count)" -ForegroundColor Red
        $script:Results.Errors | Select-Object -First 10 | ForEach-Object {
            Write-Host "  [$($_.File):$($_.Line)] $($_.Message.Substring(0, [Math]::Min(80, $_.Message.Length)))..." -ForegroundColor Red
        }
        if ($script:Results.Errors.Count -gt 10) {
            Write-Host "  ... and $($script:Results.Errors.Count - 10) more" -ForegroundColor Gray
        }
        Write-Host ""
    }
    
    # Warnings
    if ($script:Results.Warnings.Count -gt 0) {
        Write-Host "Warnings Found: $($script:Results.Warnings.Count)" -ForegroundColor Yellow
        $script:Results.Warnings | Select-Object -First 5 | ForEach-Object {
            Write-Host "  [$($_.File):$($_.Line)] $($_.Message.Substring(0, [Math]::Min(80, $_.Message.Length)))..." -ForegroundColor Yellow
        }
        if ($script:Results.Warnings.Count -gt 5) {
            Write-Host "  ... and $($script:Results.Warnings.Count - 5) more" -ForegroundColor Gray
        }
        Write-Host ""
    }
    
    # Performance metrics
    if ($script:Results.PerformanceMetrics.Count -gt 0) {
        Write-Host "Performance Metrics:" -ForegroundColor Green
        foreach ($metric in $script:Results.PerformanceMetrics.Keys) {
            $values = $script:Results.PerformanceMetrics[$metric]
            $avg = ($values | Measure-Object -Average).Average
            $min = ($values | Measure-Object -Minimum).Minimum
            $max = ($values | Measure-Object -Maximum).Maximum
            Write-Host "  $metric`: Avg=$([math]::Round($avg, 2)), Min=$([math]::Round($min, 2)), Max=$([math]::Round($max, 2))" -ForegroundColor Green
        }
        Write-Host ""
    }
    
    # Security events
    if ($script:Results.SecurityEvents.Count -gt 0) {
        Write-Host "Security Events: $($script:Results.SecurityEvents.Count)" -ForegroundColor Magenta
        $script:Results.SecurityEvents | ForEach-Object {
            Write-Host "  [$($_.File):$($_.Line)] $($_.Pattern): $($_.Message.Substring(0, [Math]::Min(60, $_.Message.Length)))..." -ForegroundColor Magenta
        }
        Write-Host ""
    }
    
    if ($script:Results.Errors.Count -eq 0 -and 
        $script:Results.Warnings.Count -eq 0 -and 
        $script:Results.SecurityEvents.Count -eq 0) {
        Write-Success "No issues found!"
    }
}

function Export-Results {
    if (-not $ExportJson) {
        return
    }
    
    $outputFile = "$OutputPath\analysis-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    $script:Results | ConvertTo-Json -Depth 10 | Out-File $outputFile
    Write-Success "Results exported to: $outputFile"
    
    # Generate HTML report
    $htmlFile = "$OutputPath\analysis-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>RawrXD Log Analysis</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; }
        .metric { display: inline-block; margin: 10px 20px 10px 0; padding: 10px; background: #f0f0f0; border-radius: 4px; }
        .error { color: #d32f2f; }
        .warning { color: #f57c00; }
        .success { color: #388e3c; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #ddd; }
        th { background: #4CAF50; color: white; }
        tr:hover { background: #f5f5f5; }
    </style>
</head>
<body>
    <div class="container">
        <h1>RawrXD Log Analysis Report</h1>
        <p>Generated: $($script:Results.Timestamp)</p>
        <div class="metric">
            <strong>Files Analyzed:</strong> $($script:Results.FilesAnalyzed)
        </div>
        <div class="metric">
            <strong>Total Lines:</strong> $($script:Results.TotalLines)
        </div>
        <div class="metric">
            <strong>Errors:</strong> <span class="error">$($script:Results.Errors.Count)</span>
        </div>
        <div class="metric">
            <strong>Warnings:</strong> <span class="warning">$($script:Results.Warnings.Count)</span>
        </div>
"@
    
    if ($script:Results.Errors.Count -gt 0) {
        $html += @"
        <h2>Errors</h2>
        <table>
            <tr><th>File</th><th>Line</th><th>Message</th></tr>
"@
        foreach ($error in $script:Results.Errors) {
            $html += "<tr><td>$($error.File)</td><td>$($error.Line)</td><td>$([System.Web.HttpUtility]::HtmlEncode($error.Message))</td></tr>"
        }
        $html += "</table>"
    }
    
    $html += @"
    </div>
</body>
</html>
"@
    
    $html | Out-File $htmlFile
    Write-Success "HTML report saved to: $htmlFile"
}

function Watch-Logs {
    if (-not $RealTime) {
        return
    }
    
    Write-Status "Starting real-time log monitoring..."
    Write-Status "Press Ctrl+C to stop"
    
    $files = Get-LogFiles
    $lastPositions = @{}
    
    foreach ($file in $files) {
        $lastPositions[$file.FullName] = $file.Length
    }
    
    while ($true) {
        Start-Sleep -Milliseconds 500
        
        foreach ($file in $files) {
            $currentLength = (Get-Item $file.FullName).Length
            $lastPosition = $lastPositions[$file.FullName]
            
            if ($currentLength -gt $lastPosition) {
                $stream = [System.IO.StreamReader]::new($file.FullName)
                $stream.BaseStream.Seek($lastPosition, [System.IO.SeekOrigin]::Begin) | Out-Null
                
                while ($null -ne ($line = $stream.ReadLine())) {
                    # Check for errors in real-time
                    foreach ($pattern in $Patterns.Error) {
                        if ($line -match $pattern) {
                            Write-Host "[ERROR] [$($file.Name)] $line" -ForegroundColor Red
                        }
                    }
                }
                
                $stream.Close()
                $lastPositions[$file.FullName] = $currentLength
            }
        }
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Log Analyzer" -ForegroundColor Cyan
    Write-Host "====================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-Analyzer
    
    if ($RealTime) {
        Watch-Logs
    } else {
        $files = Get-LogFiles
        
        if ($files.Count -eq 0) {
            Write-Error "No log files found in: $LogPath"
            exit 1
        }
        
        Write-Status "Found $($files.Count) log file(s)"
        
        foreach ($file in $files) {
            Invoke-LogAnalysis -File $file
        }
        
        Show-AnalysisResults
        Export-Results
    }
}

Main
