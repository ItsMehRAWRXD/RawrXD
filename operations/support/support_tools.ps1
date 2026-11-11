# RawrXD Support Tools
# Phase J Batch 4/5: Diagnostic and Support Utilities
# Provides diagnostic tools for troubleshooting

param(
    [Parameter()]
    [ValidateSet("Diagnostics", "CollectLogs", "Analyze", "Repair", "Report", "ShowStatus")]
    [string]$Action = "Diagnostics",
    
    [Parameter()]
    [string]$OutputPath = "$PSScriptRoot\diagnostics",
    
    [Parameter()]
    [string]$LogPath = "$PSScriptRoot\..\..\logs",
    
    [Parameter()]
    [switch]$IncludeSensitive
)

# Ensure output directory exists
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

function Write-SupportLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    $logFile = Join-Path $OutputPath "support_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logEntry
    
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "SUCCESS" { "Green" }
        "SUPPORT" { "Cyan" }
        default { "White" }
    }
    Write-Host $logEntry -ForegroundColor $color
}

function Get-SystemDiagnostics {
    Write-SupportLog "Collecting system diagnostics..." "SUPPORT"
    
    $diagnostics = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        System = @{}
        Services = @{}
        Processes = @{}
        Configuration = @{}
        Logs = @{}
    }
    
    # System information
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
        $memory = Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum
        
        $diagnostics.System = @{
            OS = $os.Caption
            Version = $os.Version
            Architecture = $os.OSArchitecture
            CPU = $cpu.Name
            CPULogicalProcessors = $cpu.NumberOfLogicalProcessors
            TotalMemoryGB = [math]::Round($memory.Sum / 1GB, 2)
            Uptime = (Get-Date) - $os.LastBootUpTime
        }
    }
    catch {
        $diagnostics.System.Error = $_.Exception.Message
    }
    
    # Service status
    $services = @("RawrXD_Runtime", "RawrXD_Telemetry", "RawrXD_Monitor")
    foreach ($service in $services) {
        try {
            $svc = Get-Service $service -ErrorAction SilentlyContinue
            if ($svc) {
                $diagnostics.Services[$service] = @{
                    Status = $svc.Status.ToString()
                    StartType = $svc.StartType.ToString()
                }
            }
            else {
                $diagnostics.Services[$service] = @{ Status = "NotInstalled" }
            }
        }
        catch {
            $diagnostics.Services[$service] = @{ Status = "Error"; Error = $_.Exception.Message }
        }
    }
    
    # Process information
    $processes = @("rawrxd", "powershell")
    foreach ($proc in $processes) {
        $procs = Get-Process -Name $proc -ErrorAction SilentlyContinue
        if ($procs) {
            $diagnostics.Processes[$proc] = $procs | ForEach-Object {
                @{
                    Id = $_.Id
                    CPU = $_.CPU
                    MemoryMB = [math]::Round($_.WorkingSet64 / 1MB, 2)
                    StartTime = $_.StartTime
                }
            }
        }
    }
    
    # Configuration files
    $configFiles = @(
        "$PSScriptRoot\..\..\config\*.json",
        "$PSScriptRoot\..\..\governance\*\*.json",
        "$PSScriptRoot\..\..\analytics\*\*.json"
    )
    
    foreach ($pattern in $configFiles) {
        $files = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue
        foreach ($file in $files) {
            try {
                $content = Get-Content $file.FullName -Raw | ConvertFrom-Json
                $diagnostics.Configuration[$file.Name] = "Valid JSON"
            }
            catch {
                $diagnostics.Configuration[$file.Name] = "Invalid JSON: $($_.Exception.Message)"
            }
        }
    }
    
    # Recent log errors
    $logFiles = Get-ChildItem -Path $LogPath -Filter "*.log" -ErrorAction SilentlyContinue | Select-Object -First 10
    foreach ($logFile in $logFiles) {
        $errors = Get-Content $logFile.FullName -Tail 100 | Where-Object { $_ -match "ERROR|CRITICAL" }
        if ($errors) {
            $diagnostics.Logs[$logFile.Name] = $errors.Count
        }
    }
    
    return $diagnostics
}

function Invoke-LogCollection {
    Write-SupportLog "Collecting logs..." "SUPPORT"
    
    $collection = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Files = @()
    }
    
    $outputDir = Join-Path $OutputPath "log_collection_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    
    # Collect log files
    $logFiles = Get-ChildItem -Path $LogPath -Recurse -Filter "*.log" -ErrorAction SilentlyContinue
    foreach ($logFile in $logFiles) {
        $dest = Join-Path $outputDir $logFile.Name
        Copy-Item -Path $logFile.FullName -Destination $dest -Force
        $collection.Files += @{
            Source = $logFile.FullName
            Destination = $dest
            Size = $logFile.Length
        }
    }
    
    # Create manifest
    $collection | ConvertTo-Json -Depth 10 | Out-File (Join-Path $outputDir "manifest.json") -Encoding UTF8
    
    Write-SupportLog "Logs collected to: $outputDir" "SUCCESS"
    return $collection
}

function Invoke-LogAnalysis {
    Write-SupportLog "Analyzing logs..." "SUPPORT"
    
    $analysis = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Summary = @{
            TotalErrors = 0
            TotalWarnings = 0
            TotalLines = 0
        }
        ErrorPatterns = @{}
        RecentIssues = @()
    }
    
    $logFiles = Get-ChildItem -Path $LogPath -Recurse -Filter "*.log" -ErrorAction SilentlyContinue
    
    foreach ($logFile in $logFiles) {
        $lines = Get-Content $logFile.FullName -ErrorAction SilentlyContinue
        foreach ($line in $lines) {
            $analysis.Summary.TotalLines++
            
            if ($line -match "ERROR") {
                $analysis.Summary.TotalErrors++
                
                # Extract error pattern
                if ($line -match "ERROR\s*:\s*(.+?)(?:\s+at|\s*$)") {
                    $pattern = $matches[1].Trim()
                    if (-not $analysis.ErrorPatterns.ContainsKey($pattern)) {
                        $analysis.ErrorPatterns[$pattern] = 0
                    }
                    $analysis.ErrorPatterns[$pattern]++
                }
            }
            elseif ($line -match "WARN") {
                $analysis.Summary.TotalWarnings++
            }
        }
    }
    
    # Get top error patterns
    $analysis.TopErrors = $analysis.ErrorPatterns.GetEnumerator() | 
        Sort-Object -Property Value -Descending | 
        Select-Object -First 10 | 
        ForEach-Object { @{ Pattern = $_.Key; Count = $_.Value } }
    
    return $analysis
}

function Invoke-Repair {
    Write-SupportLog "Attempting repairs..." "SUPPORT"
    
    $repairs = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Attempted = @()
        Successful = @()
        Failed = @()
    }
    
    # Repair 1: Restart stopped services
    $services = @("RawrXD_Runtime", "RawrXD_Telemetry")
    foreach ($service in $services) {
        $repairs.Attempted += "Restart service: $service"
        try {
            $svc = Get-Service $service -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -ne "Running") {
                Start-Service $service -ErrorAction Stop
                $repairs.Successful += "Started service: $service"
                Write-SupportLog "Started service: $service" "SUCCESS"
            }
        }
        catch {
            $repairs.Failed += "Failed to start service: $service - $($_.Exception.Message)"
            Write-SupportLog "Failed to start service: $service" "ERROR"
        }
    }
    
    # Repair 2: Clear temp files
    $repairs.Attempted += "Clear temporary files"
    try {
        $tempFiles = Get-ChildItem -Path $env:TEMP -Filter "rawrxd_*" -ErrorAction SilentlyContinue
        foreach ($file in $tempFiles) {
            Remove-Item -Path $file.FullName -Recurse -Force -ErrorAction SilentlyContinue
        }
        $repairs.Successful += "Cleared temporary files"
    }
    catch {
        $repairs.Failed += "Failed to clear temp files: $($_.Exception.Message)"
    }
    
    return $repairs
}

function New-SupportReport {
    Write-SupportLog "Generating support report..." "SUPPORT"
    
    $report = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Diagnostics = Get-SystemDiagnostics
        LogAnalysis = Invoke-LogAnalysis
        Recommendations = @()
    }
    
    # Generate recommendations
    if ($report.Diagnostics.Services["RawrXD_Runtime"].Status -ne "Running") {
        $report.Recommendations += "RawrXD Runtime service is not running. Try: .\operations\support\support_tools.ps1 -Action Repair"
    }
    
    if ($report.LogAnalysis.Summary.TotalErrors -gt 100) {
        $report.Recommendations += "High error count detected. Review logs in: $LogPath"
    }
    
    if ($report.Diagnostics.System.TotalMemoryGB -lt 8) {
        $report.Recommendations += "System has less than 8GB RAM. Performance may be degraded."
    }
    
    # Save report
    $reportFile = Join-Path $OutputPath "support_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $report | ConvertTo-Json -Depth 10 | Out-File $reportFile -Encoding UTF8
    
    Write-SupportLog "Support report generated: $reportFile" "SUCCESS"
    return $report
}

function Show-SupportStatus {
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║           RawrXD Support Tools Status                       ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    
    # Check services
    Write-Host "║ Service Status:" -ForegroundColor Cyan
    $services = @("RawrXD_Runtime", "RawrXD_Telemetry", "RawrXD_Monitor")
    foreach ($service in $services) {
        try {
            $svc = Get-Service $service -ErrorAction SilentlyContinue
            if ($svc) {
                $color = if ($svc.Status -eq "Running") { "Green" } else { "Red" }
                Write-Host "║   $service`: $($svc.Status)" -ForegroundColor $color
            }
            else {
                Write-Host "║   $service`: Not Installed" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host "║   $service`: Error" -ForegroundColor Red
        }
    }
    
    # Check recent reports
    $reports = Get-ChildItem -Path $OutputPath -Filter "support_report_*.json" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 5
    if ($reports.Count -gt 0) {
        Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
        Write-Host "║ Recent Support Reports:" -ForegroundColor Cyan
        foreach ($report in $reports) {
            Write-Host "║   $($report.Name)" -ForegroundColor Gray
        }
    }
    
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
}

# Main execution
switch ($Action) {
    "Diagnostics" {
        $result = Get-SystemDiagnostics
        $result | ConvertTo-Json -Depth 10
    }
    "CollectLogs" {
        $result = Invoke-LogCollection
        $result | ConvertTo-Json
    }
    "Analyze" {
        $result = Invoke-LogAnalysis
        $result | ConvertTo-Json -Depth 10
    }
    "Repair" {
        $result = Invoke-Repair
        $result | ConvertTo-Json
    }
    "Report" {
        $result = New-SupportReport
        $result | ConvertTo-Json -Depth 10
    }
    "ShowStatus" {
        Show-SupportStatus
    }
}
