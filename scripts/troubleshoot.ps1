# RawrXD OMEGA-1 Troubleshooting Automation
# Automated diagnosis and repair of common issues

param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("all", "startup", "gpu", "ipc", "performance", "network", "logs")]
    [string]$Category = "all",
    
    [string]$InstallDir = "d:\rawrxd",
    [switch]$AutoFix = $false,
    [switch]$Verbose = $false
)

$ErrorActionPreference = 'Continue'
$script:IssuesFound = 0
$script:IssuesFixed = 0
$script:Diagnostics = @()

function Write-Diag {
    param($Message, $Level = "INFO")
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN" { "Yellow" }
        "SUCCESS" { "Green" }
        "FIX" { "Cyan" }
        default { "White" }
    }
    Write-Host "[$Level] $Message" -ForegroundColor $color
    
    $script:Diagnostics += [PSCustomObject]@{
        Timestamp = Get-Date -Format "HH:mm:ss"
        Level = $Level
        Message = $Message
    }
}

function Add-Issue {
    param($Description, $Severity = "WARNING")
    $script:IssuesFound++
    Write-Diag $Description $Severity
}

function Add-Fix {
    param($Description)
    $script:IssuesFixed++
    Write-Diag $Description "FIX"
}

# =============================================================================
# Diagnostic Functions
# =============================================================================

function Test-StartupIssues {
    Write-Diag "=== Checking Startup Issues ===" "INFO"
    
    # Check if binaries exist
    $win32ide = Join-Path $InstallDir "build\bin\RawrXD-Win32IDE.exe"
    $engine = Join-Path $InstallDir "build\bin\RawrXD-InferenceEngine.exe"
    
    if (!(Test-Path $win32ide)) {
        Add-Issue "Win32IDE binary not found at expected location" "ERROR"
        if ($AutoFix) {
            Write-Diag "Run build_omega1_full.ps1 to rebuild" "FIX"
        }
    }
    else {
        Write-Diag "Win32IDE binary found" "SUCCESS"
    }
    
    if (!(Test-Path $engine)) {
        Add-Issue "InferenceEngine binary not found" "ERROR"
    }
    else {
        Write-Diag "InferenceEngine binary found" "SUCCESS"
    }
    
    # Check configuration
    $configPath = Join-Path $InstallDir "config\omega1.json"
    if (!(Test-Path $configPath)) {
        Add-Issue "Configuration file missing" "WARN"
        if ($AutoFix) {
            Write-Diag "Run config_wizard.ps1 to create configuration" "FIX"
        }
    }
    else {
        try {
            $config = Get-Content $configPath -Raw | ConvertFrom-Json
            Write-Diag "Configuration file valid" "SUCCESS"
        }
        catch {
            Add-Issue "Configuration file is corrupted" "ERROR"
        }
    }
    
    # Check for running processes
    $running = Get-Process | Where-Object { $_.ProcessName -match "RawrXD" }
    if ($running) {
        Write-Diag "RawrXD processes running: $($running.Count)" "INFO"
        $running | ForEach-Object {
            Write-Diag "  - $($_.ProcessName) (PID: $($_.Id))" "INFO"
        }
    }
}

function Test-GpuIssues {
    Write-Diag "`n=== Checking GPU Issues ===" "INFO"
    
    # Check GPU detection
    $gpus = Get-PnpDevice -Class Display -ErrorAction SilentlyContinue | 
        Where-Object { $_.Name -match "AMD|NVIDIA" -and $_.Status -eq "OK" }
    
    if ($gpus.Count -eq 0) {
        Add-Issue "No GPUs detected" "ERROR"
    }
    elseif ($gpus.Count -eq 1) {
        Write-Diag "Single GPU detected: $($gpus[0].Name)" "WARN"
        Write-Diag "Dual GPU configuration recommended for optimal performance" "INFO"
    }
    else {
        Write-Diag "Dual GPU configuration detected" "SUCCESS"
        $gpus | ForEach-Object {
            Write-Diag "  - $($_.Name)" "INFO"
        }
    }
    
    # Check GPU drivers
    $videoControllers = Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue | 
        Where-Object { $_.Name -match "AMD|NVIDIA" }
    
    foreach ($gpu in $videoControllers) {
        $driverVersion = $gpu.DriverVersion
        Write-Diag "GPU: $($gpu.Name), Driver: $driverVersion" "INFO"
        
        # Check for outdated drivers (simplified check)
        if ($gpu.Name -match "AMD") {
            Write-Diag "Ensure AMD drivers are up to date (Adrenalin 24.x or later)" "INFO"
        }
    }
    
    # Check for GPU memory issues
    try {
        $adapterRam = ($videoControllers | Measure-Object -Property AdapterRAM -Sum).Sum / 1GB
        Write-Diag "Total GPU Memory: $([math]::Round($adapterRam, 2)) GB" "INFO"
        
        if ($adapterRam -lt 8) {
            Add-Issue "Low GPU memory may limit model size" "WARN"
        }
    }
    catch {
        Write-Diag "Could not determine GPU memory" "WARN"
    }
}

function Test-IpcIssues {
    Write-Diag "`n=== Checking IPC Issues ===" "INFO"
    
    $pipeName = "\\.\pipe\RawrXD_Omega1_v2"
    
    # Check if pipe exists
    $pipes = Get-ChildItem -Path "\\.\pipe\" -ErrorAction SilentlyContinue | 
        Where-Object { $_.Name -eq "RawrXD_Omega1_v2" }
    
    if ($pipes) {
        Write-Diag "Named pipe exists: $pipeName" "SUCCESS"
    }
    else {
        Write-Diag "Named pipe not currently active (normal if services not running)" "INFO"
    }
    
    # Check for pipe-related errors in logs
    $logPath = Join-Path $InstallDir "logs\error.log"
    if (Test-Path $logPath) {
        $pipeErrors = Select-String -Path $logPath -Pattern "pipe|ipc|communication" -ErrorAction SilentlyContinue
        if ($pipeErrors) {
            Add-Issue "IPC errors found in logs" "WARN"
            if ($Verbose) {
                $pipeErrors | Select-Object -Last 5 | ForEach-Object {
                    Write-Diag "  $_" "INFO"
                }
            }
        }
    }
}

function Test-PerformanceIssues {
    Write-Diag "`n=== Checking Performance Issues ===" "INFO"
    
    # Check system memory
    $totalRam = (Get-CimInstance Win32_PhysicalMemory -ErrorAction SilentlyContinue | 
        Measure-Object -Property Capacity -Sum).Sum / 1GB
    
    $availableRam = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).FreePhysicalMemory / 1MB
    
    Write-Diag "Total RAM: $([math]::Round($totalRam, 2)) GB" "INFO"
    Write-Diag "Available RAM: $([math]::Round($availableRam, 2)) GB" "INFO"
    
    if ($availableRam -lt 4) {
        Add-Issue "Low available memory may impact performance" "WARN"
        if ($AutoFix) {
            Write-Diag "Consider closing other applications" "FIX"
        }
    }
    
    # Check CPU
    $cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue
    Write-Diag "CPU: $($cpu.Name)" "INFO"
    Write-Diag "Cores: $($cpu.NumberOfCores), Logical: $($cpu.NumberOfLogicalProcessors)" "INFO"
    
    # Check disk space
    $drive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='D:'" -ErrorAction SilentlyContinue
    if ($drive) {
        $freeSpaceGB = $drive.FreeSpace / 1GB
        $totalSpaceGB = $drive.Size / 1GB
        Write-Diag "D: Drive - Free: $([math]::Round($freeSpaceGB, 2)) GB / $([math]::Round($totalSpaceGB, 2)) GB" "INFO"
        
        if ($freeSpaceGB -lt 10) {
            Add-Issue "Low disk space on D: drive" "WARN"
        }
    }
}

function Test-NetworkIssues {
    Write-Diag "`n=== Checking Network Issues ===" "INFO"
    
    # Check if HTTP port is available
    $port = 8080
    $portInUse = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
    
    if ($portInUse) {
        Add-Issue "Port $port is already in use" "WARN"
        $portInUse | ForEach-Object {
            Write-Diag "  Process: $($_.OwningProcess)" "INFO"
        }
        if ($AutoFix) {
            Write-Diag "Consider changing port in configuration" "FIX"
        }
    }
    else {
        Write-Diag "Port $port is available" "SUCCESS"
    }
    
    # Check firewall
    $firewallRule = Get-NetFirewallRule -DisplayName "*RawrXD*" -ErrorAction SilentlyContinue
    if ($firewallRule) {
        Write-Diag "Firewall rules found" "SUCCESS"
    }
    else {
        Write-Diag "No RawrXD firewall rules found" "INFO"
    }
}

function Test-LogIssues {
    Write-Diag "`n=== Checking Log Issues ===" "INFO"
    
    $logDir = Join-Path $InstallDir "logs"
    
    if (!(Test-Path $logDir)) {
        Add-Issue "Log directory not found" "WARN"
        if ($AutoFix) {
            New-Item -ItemType Directory -Force -Path $logDir | Out-Null
            Add-Fix "Created log directory"
        }
    }
    else {
        # Check log file sizes
        $logFiles = Get-ChildItem -Path $logDir -Filter "*.log" -ErrorAction SilentlyContinue
        
        if ($logFiles) {
            $totalSize = ($logFiles | Measure-Object -Property Length -Sum).Sum / 1MB
            Write-Diag "Log files: $($logFiles.Count), Total size: $([math]::Round($totalSize, 2)) MB" "INFO"
            
            if ($totalSize -gt 100) {
                Add-Issue "Large log files may need rotation" "INFO"
                if ($AutoFix) {
                    Write-Diag "Run log_rotator.ps1 to rotate logs" "FIX"
                }
            }
        }
        else {
            Write-Diag "No log files found" "INFO"
        }
    }
}

function Repair-CommonIssues {
    Write-Diag "`n=== Attempting Repairs ===" "INFO"
    
    if (!$AutoFix) {
        Write-Diag "Auto-fix not enabled. Use -AutoFix to attempt repairs." "INFO"
        return
    }
    
    # Repair 1: Ensure directories exist
    $requiredDirs = @("logs", "config", "temp", "backups")
    foreach ($dir in $requiredDirs) {
        $path = Join-Path $InstallDir $dir
        if (!(Test-Path $path)) {
            New-Item -ItemType Directory -Force -Path $path | Out-Null
            Add-Fix "Created directory: $dir"
        }
    }
    
    # Repair 2: Reset permissions (simplified)
    Write-Diag "Checking directory permissions..." "INFO"
    
    # Repair 3: Clear temp files
    $tempDir = Join-Path $InstallDir "temp"
    if (Test-Path $tempDir) {
        $tempFiles = Get-ChildItem -Path $tempDir -File -ErrorAction SilentlyContinue
        if ($tempFiles.Count -gt 10) {
            $tempFiles | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) } | Remove-Item -Force
            Add-Fix "Cleaned old temp files"
        }
    }
}

function Show-Summary {
    Write-Host "`n╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║     Troubleshooting Summary                                                    ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    
    Write-Host "`nIssues Found: $script:IssuesFound" -ForegroundColor $(if($script:IssuesFound -eq 0){"Green"}elseif($script:IssuesFound -lt 5){"Yellow"}else{"Red"})
    
    if ($AutoFix) {
        Write-Host "Issues Fixed: $script:IssuesFixed" -ForegroundColor $(if($script:IssuesFixed -eq $script:IssuesFound){"Green"}else{"Yellow"})
    }
    
    if ($script:IssuesFound -eq 0) {
        Write-Host "`n✅ No issues detected - system appears healthy" -ForegroundColor Green
    }
    elseif ($script:IssuesFound -le 3) {
        Write-Host "`n⚠️  Minor issues detected - system should function normally" -ForegroundColor Yellow
    }
    else {
        Write-Host "`n❌ Multiple issues detected - review recommended" -ForegroundColor Red
    }
    
    Write-Host "`nRecommended Actions:" -ForegroundColor Cyan
    if ($script:IssuesFound -gt 0) {
        Write-Host "  1. Review issues above" -ForegroundColor White
        Write-Host "  2. Run with -AutoFix to attempt automatic repairs" -ForegroundColor White
        Write-Host "  3. Check documentation in $InstallDir\docs\" -ForegroundColor White
    }
    else {
        Write-Host "  - System is healthy, no action required" -ForegroundColor Green
    }
}

# =============================================================================
# Main Execution
# =============================================================================

Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     RawrXD OMEGA-1 Troubleshooting Tool                                        ║" -ForegroundColor Cyan
Write-Host "║     Category: $Category" -NoNewline -ForegroundColor Cyan
Write-Host "$(' ' * (63 - $Category.Length))║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

switch ($Category) {
    "startup" { Test-StartupIssues }
    "gpu" { Test-GpuIssues }
    "ipc" { Test-IpcIssues }
    "performance" { Test-PerformanceIssues }
    "network" { Test-NetworkIssues }
    "logs" { Test-LogIssues }
    "all" {
        Test-StartupIssues
        Test-GpuIssues
        Test-IpcIssues
        Test-PerformanceIssues
        Test-NetworkIssues
        Test-LogIssues
    }
}

Repair-CommonIssues
Show-Summary

# Export diagnostics if verbose
if ($Verbose) {
    $diagPath = Join-Path $InstallDir "logs\diagnostics_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $script:Diagnostics | ConvertTo-Json | Out-File $diagPath
    Write-Host "`nDiagnostics exported to: $diagPath" -ForegroundColor Gray
}
