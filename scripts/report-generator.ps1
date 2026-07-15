# RawrXD Report Generator
# Generates comprehensive reports in multiple formats

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("System", "Performance", "Security", "Usage", "Compliance", "Custom", "All")]
    [string]$ReportType = "System",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("HTML", "PDF", "CSV", "JSON", "Markdown", "XML")]
    [string]$Format = "HTML",
    
    [string]$OutputPath = "reports",
    [string]$Title = "RawrXD Report",
    [DateTime]$StartDate = (Get-Date).AddDays(-30),
    [DateTime]$EndDate = (Get-Date),
    [string[]]$IncludeSections = @(),
    [string]$LogoPath = "",
    [switch]$IncludeCharts,
    [switch]$EmailReport,
    [string]$EmailTo = "",
    [switch]$OpenAfter
)

$ErrorActionPreference = "Stop"

$script:ReportId = "report-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$script:ReportData = @{}

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

function Initialize-Report {
    Write-Status "Initializing report generator..."
    Write-Status "Report Type: $ReportType"
    Write-Status "Format: $Format"
    Write-Status "Report ID: $script:ReportId"
    
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
}

function Get-SystemReportData {
    Write-Status "Collecting system data..."
    
    $data = @{
        Timestamp = Get-Date -Format "o"
        SystemInfo = @{}
        Hardware = @{}
        Software = @{}
        Services = @()
    }
    
    # System information
    $os = Get-CimInstance Win32_OperatingSystem
    $data.SystemInfo = @{
        OS = $os.Caption
        Version = $os.Version
        Architecture = $os.OSArchitecture
        LastBoot = $os.LastBootUpTime
        Uptime = (Get-Date) - $os.LastBootUpTime
    }
    
    # Hardware information
    $cpu = Get-CimInstance Win32_Processor
    $memory = Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum
    $data.Hardware = @{
        CPU = $cpu.Name
        Cores = $cpu.NumberOfCores
        LogicalProcessors = $cpu.NumberOfLogicalProcessors
        TotalMemoryGB = [math]::Round($memory.Sum / 1GB, 2)
    }
    
    # Disk information
    $disks = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
    $data.Hardware.Disks = @()
    foreach ($disk in $disks) {
        $data.Hardware.Disks += @{
            Drive = $disk.DeviceID
            SizeGB = [math]::Round($disk.Size / 1GB, 2)
            FreeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
            UsedPercent = [math]::Round((($disk.Size - $disk.FreeSpace) / $disk.Size) * 100, 1)
        }
    }
    
    # RawrXD specific
    if (Test-Path "config.json") {
        $data.Software.Config = Get-Content "config.json" | ConvertFrom-Json
    }
    
    if (Test-Path "logs") {
        $logFiles = Get-ChildItem "logs" -Filter "*.log" | 
            Where-Object { $_.LastWriteTime -ge $StartDate -and $_.LastWriteTime -le $EndDate }
        $data.Software.LogFiles = $logFiles.Count
    }
    
    return $data
}

function Get-PerformanceReportData {
    Write-Status "Collecting performance data..."
    
    $data = @{
        Timestamp = Get-Date -Format "o"
        Metrics = @{}
        Benchmarks = @()
        Trends = @()
    }
    
    # Current metrics
    $cpu = Get-Counter "\Processor(_Total)\% Processor Time" -SampleInterval 1 -MaxSamples 3
    $memory = Get-Counter "\Memory\Available MBytes"
    $disk = Get-Counter "\PhysicalDisk(_Total)\Disk Read Bytes/sec"
    
    $data.Metrics = @{
        CPUAvg = ($cpu.CounterSamples | Measure-Object CookedValue -Average).Average
        MemoryAvailableMB = $memory.CounterSamples[0].CookedValue
        DiskReadBytesSec = $disk.CounterSamples[0].CookedValue
    }
    
    # Load benchmark results if available
    if (Test-Path "benchmarks\results") {
        $resultFiles = Get-ChildItem "benchmarks\results" -Filter "*.json" |
            Where-Object { $_.LastWriteTime -ge $StartDate -and $_.LastWriteTime -le $EndDate }
        
        foreach ($file in $resultFiles) {
            $result = Get-Content $file.FullName | ConvertFrom-Json
            $data.Benchmarks += $result
        }
    }
    
    return $data
}

function Get-SecurityReportData {
    Write-Status "Collecting security data..."
    
    $data = @{
        Timestamp = Get-Date -Format "o"
        AuditResults = @()
        Vulnerabilities = @()
        ComplianceStatus = @{}
    }
    
    # Load audit results
    if (Test-Path "security\audit-results.json") {
        $data.AuditResults = Get-Content "security\audit-results.json" | ConvertFrom-Json
    }
    
    # Check for security events in logs
    if (Test-Path "logs") {
        $securityEvents = @()
        $logFiles = Get-ChildItem "logs" -Filter "*.log" | 
            Where-Object { $_.LastWriteTime -ge $StartDate -and $_.LastWriteTime -le $EndDate }
        
        foreach ($logFile in $logFiles) {
            $content = Get-Content $logFile.FullName -ErrorAction SilentlyContinue
            $securityLines = $content | Select-String -Pattern "(security|vulnerability|breach|unauthorized)" -ErrorAction SilentlyContinue
            foreach ($line in $securityLines) {
                $securityEvents += $line.Line
            }
        }
        
        $data.SecurityEvents = $securityEvents.Count
    }
    
    return $data
}

function Get-UsageReportData {
    Write-Status "Collecting usage data..."
    
    $data = @{
        Timestamp = Get-Date -Format "o"
        Period = @{
            Start = $StartDate
            End = $EndDate
        }
        Requests = @{
            Total = 0
            ByEndpoint = @{}
            ByStatus = @{}
        }
        Models = @{}
        Users = @()
    }
    
    # Parse access logs
    if (Test-Path "logs\access.log") {
        $accessLog = Get-Content "logs\access.log" -ErrorAction SilentlyContinue
        $data.Requests.Total = $accessLog.Count
        
        # Count by status code
        foreach ($line in $accessLog) {
            if ($line -match '" (\d{3}) ') {
                $status = $matches[1]
                if (-not $data.Requests.ByStatus[$status]) {
                    $data.Requests.ByStatus[$status] = 0
                }
                $data.Requests.ByStatus[$status]++
            }
        }
    }
    
    # Model usage
    if (Test-Path "models") {
        $models = Get-ChildItem "models" -Filter "*.gguf" -ErrorAction SilentlyContinue
        foreach ($model in $models) {
            $data.Models[$model.Name] = @{
                SizeGB = [math]::Round($model.Length / 1GB, 2)
                LastAccessed = $model.LastAccessTime
            }
        }
    }
    
    return $data
}

function Export-HTMLReport {
    param([hashtable]$Data, [string]$FilePath)
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>$Title</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #0066cc; padding-bottom: 10px; }
        h2 { color: #0066cc; margin-top: 30px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #0066cc; color: white; }
        tr:hover { background: #f5f5f5; }
        .metric { display: inline-block; padding: 15px; margin: 10px; background: #f0f0f0; border-radius: 5px; }
        .metric-value { font-size: 24px; font-weight: bold; color: #0066cc; }
        .metric-label { font-size: 12px; color: #666; }
        .status-good { color: green; }
        .status-warning { color: orange; }
        .status-error { color: red; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>$Title</h1>
        <p><strong>Generated:</strong> $($Data.Timestamp)</p>
        <p><strong>Report ID:</strong> $script:ReportId</p>
        <p><strong>Period:</strong> $($StartDate.ToString("yyyy-MM-dd")) to $($EndDate.ToString("yyyy-MM-dd"))</p>
"@
    
    # Add report-specific content
    if ($ReportType -eq "System" -or $ReportType -eq "All") {
        $html += "<h2>System Information</h2>"
        $html += "<div class='metrics'>"
        $html += "<div class='metric'><div class='metric-value'>$($Data.Hardware.CPU)</div><div class='metric-label'>CPU</div></div>"
        $html += "<div class='metric'><div class='metric-value'>$($Data.Hardware.TotalMemoryGB) GB</div><div class='metric-label'>Memory</div></div>"
        $html += "</div>"
        
        $html += "<h3>Disk Usage</h3>"
        $html += "<table><tr><th>Drive</th><th>Size (GB)</th><th>Free (GB)</th><th>Used %</th></tr>"
        foreach ($disk in $Data.Hardware.Disks) {
            $class = if ($disk.UsedPercent -gt 90) { "status-error" } elseif ($disk.UsedPercent -gt 70) { "status-warning" } else { "status-good" }
            $html += "<tr><td>$($disk.Drive)</td><td>$($disk.SizeGB)</td><td>$($disk.FreeGB)</td><td class='$class'>$($disk.UsedPercent)%</td></tr>"
        }
        $html += "</table>"
    }
    
    $html += @"
        <div class="footer">
            <p>RawrXD Vision & Generation System v3.2.0</p>
            <p>This report was automatically generated by the RawrXD Report Generator.</p>
        </div>
    </div>
</body>
</html>
"@
    
    $html | Out-File -FilePath $FilePath -Encoding UTF8
}

function Export-CSVReport {
    param([hashtable]$Data, [string]$FilePath)
    
    $csvData = @()
    
    if ($ReportType -eq "System" -or $ReportType -eq "All") {
        foreach ($disk in $Data.Hardware.Disks) {
            $csvData += [PSCustomObject]@{
                Category = "Disk"
                Drive = $disk.Drive
                SizeGB = $disk.SizeGB
                FreeGB = $disk.FreeGB
                UsedPercent = $disk.UsedPercent
            }
        }
    }
    
    $csvData | Export-Csv -Path $FilePath -NoTypeInformation
}

function Export-JSONReport {
    param([hashtable]$Data, [string]$FilePath)
    
    $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $FilePath -Encoding UTF8
}

function Export-MarkdownReport {
    param([hashtable]$Data, [string]$FilePath)
    
    $md = @"
# $Title

**Generated:** $($Data.Timestamp)  
**Report ID:** $script:ReportId  
**Period:** $($StartDate.ToString("yyyy-MM-dd")) to $($EndDate.ToString("yyyy-MM-dd"))

---

"@
    
    if ($ReportType -eq "System" -or $ReportType -eq "All") {
        $md += "## System Information

"
        $md += "| Property | Value |
"
        $md += "|----------|-------|
"
        $md += "| OS | $($Data.SystemInfo.OS) |
"
        $md += "| CPU | $($Data.Hardware.CPU) |
"
        $md += "| Memory | $($Data.Hardware.TotalMemoryGB) GB |
"
        $md += "| Architecture | $($Data.SystemInfo.Architecture) |

"
        
        $md += "### Disk Usage

"
        $md += "| Drive | Size (GB) | Free (GB) | Used % |
"
        $md += "|-------|-----------|-----------|--------|
"
        foreach ($disk in $Data.Hardware.Disks) {
            $md += "| $($disk.Drive) | $($disk.SizeGB) | $($disk.FreeGB) | $($disk.UsedPercent)% |
"
        }
    }
    
    $md += @"

---

*Generated by RawrXD Report Generator v3.2.0*
"@
    
    $md | Out-File -FilePath $FilePath -Encoding UTF8
}

# Main execution
function Main {
    Write-Host "RawrXD Report Generator" -ForegroundColor Cyan
    Write-Host "======================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-Report
    
    # Collect data based on report type
    $script:ReportData = switch ($ReportType) {
        "System" { Get-SystemReportData }
        "Performance" { Get-PerformanceReportData }
        "Security" { Get-SecurityReportData }
        "Usage" { Get-UsageReportData }
        "All" { 
            @{
                System = Get-SystemReportData
                Performance = Get-PerformanceReportData
                Security = Get-SecurityReportData
                Usage = Get-UsageReportData
            }
        }
        default { Get-SystemReportData }
    }
    
    # Generate output filename
    $extension = switch ($Format) {
        "HTML" { "html" }
        "PDF" { "pdf" }
        "CSV" { "csv" }
        "JSON" { "json" }
        "Markdown" { "md" }
        "XML" { "xml" }
    }
    
    $outputFile = "$OutputPath\$ReportType-report-$script:ReportId.$extension"
    
    # Export report
    Write-Status "Generating $Format report..."
    switch ($Format) {
        "HTML" { Export-HTMLReport -Data $script:ReportData -FilePath $outputFile }
        "CSV" { Export-CSVReport -Data $script:ReportData -FilePath $outputFile }
        "JSON" { Export-JSONReport -Data $script:ReportData -FilePath $outputFile }
        "Markdown" { Export-MarkdownReport -Data $script:ReportData -FilePath $outputFile }
    }
    
    Write-Success "Report generated: $outputFile"
    
    # Open report if requested
    if ($OpenAfter) {
        Start-Process $outputFile
    }
    
    Write-Host ""
}

Main
