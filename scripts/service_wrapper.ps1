# RawrXD OMEGA-1 Service Wrapper
# Manages InferenceEngine as a Windows service

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("install", "uninstall", "start", "stop", "restart", "status", "logs")]
    [string]$Action = "status",
    
    [string]$ServiceName = "RawrXDInferenceEngine",
    [string]$InstallDir = "$env:LOCALAPPDATA\RawrXD\OMEGA1",
    [string]$ModelPath = "",
    [switch]$AutoStart = $true
)

$ErrorActionPreference = 'Stop'

function Write-Header {
    param($Text)
    Write-Host "`n═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
}

function Write-Status {
    param($Text, $Status)
    $color = switch ($Status) {
        "OK" { "Green" }
        "WARN" { "Yellow" }
        "FAIL" { "Red" }
        "INFO" { "White" }
        default { "Gray" }
    }
    Write-Host "  [$Status] $Text" -ForegroundColor $color
}

function Test-AdminRights {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Install-Service {
    Write-Header "Installing Windows Service"
    
    if (!(Test-AdminRights)) {
        Write-Status "Administrator rights required for service installation" "FAIL"
        Write-Host "  Please run as Administrator" -ForegroundColor Yellow
        return
    }
    
    $exePath = Join-Path $InstallDir "bin\RawrXD-InferenceEngine.exe"
    
    if (!(Test-Path $exePath)) {
        Write-Status "InferenceEngine not found: $exePath" "FAIL"
        return
    }
    
    # Check if service already exists
    $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existingService) {
        Write-Status "Service already exists: $ServiceName" "WARN"
        Write-Host "  Use -Action uninstall first to remove" -ForegroundColor Yellow
        return
    }
    
    # Create service arguments
    $serviceArgs = "--service --daemon"
    if ($ModelPath) {
        $serviceArgs += " --model `"$ModelPath`""
    }
    
    # Install service using sc.exe
    $binPath = "`"$exePath`" $serviceArgs"
    
    try {
        $result = sc.exe create $ServiceName binPath= $binPath start= $(if($AutoStart){"auto"}else{"demand"}) DisplayName= "RawrXD OMEGA-1 Inference Engine"
        
        if ($LASTEXITCODE -eq 0) {
            Write-Status "Service installed successfully" "OK"
            
            # Configure service description
            sc.exe description $ServiceName "RawrXD OMEGA-1 Local LLM Inference Engine Service" | Out-Null
            
            # Set recovery options
            sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null
            Write-Status "Service recovery configured" "OK"
            
            Write-Host "`n  Service configuration:" -ForegroundColor Gray
            Write-Host "    Name: $ServiceName" -ForegroundColor Gray
            Write-Host "    Path: $exePath" -ForegroundColor Gray
            Write-Host "    Startup: $(if($AutoStart){"Automatic"}else{"Manual"})" -ForegroundColor Gray
            
        } else {
            Write-Status "Failed to install service (exit code: $LASTEXITCODE)" "FAIL"
        }
    } catch {
        Write-Status "Failed to install service: $_" "FAIL"
    }
}

function Uninstall-Service {
    Write-Header "Uninstalling Windows Service"
    
    if (!(Test-AdminRights)) {
        Write-Status "Administrator rights required" "FAIL"
        return
    }
    
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    
    if (!$service) {
        Write-Status "Service not found: $ServiceName" "WARN"
        return
    }
    
    # Stop service if running
    if ($service.Status -eq "Running") {
        Write-Status "Stopping service..." "INFO"
        Stop-Service -Name $ServiceName -Force
        Start-Sleep -Seconds 2
    }
    
    try {
        $result = sc.exe delete $ServiceName
        if ($LASTEXITCODE -eq 0) {
            Write-Status "Service uninstalled successfully" "OK"
        } else {
            Write-Status "Failed to uninstall service (exit code: $LASTEXITCODE)" "FAIL"
        }
    } catch {
        Write-Status "Failed to uninstall service: $_" "FAIL"
    }
}

function Start-ServiceWrapper {
    Write-Header "Starting Service"
    
    if (!(Test-AdminRights)) {
        Write-Status "Administrator rights recommended" "WARN"
    }
    
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    
    if (!$service) {
        Write-Status "Service not found: $ServiceName" "FAIL"
        Write-Host "  Use -Action install first" -ForegroundColor Yellow
        return
    }
    
    if ($service.Status -eq "Running") {
        Write-Status "Service is already running" "OK"
        return
    }
    
    try {
        Start-Service -Name $ServiceName
        Start-Sleep -Seconds 2
        
        $service.Refresh()
        if ($service.Status -eq "Running") {
            Write-Status "Service started successfully" "OK"
        } else {
            Write-Status "Service failed to start (status: $($service.Status))" "FAIL"
        }
    } catch {
        Write-Status "Failed to start service: $_" "FAIL"
    }
}

function Stop-ServiceWrapper {
    Write-Header "Stopping Service"
    
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    
    if (!$service) {
        Write-Status "Service not found: $ServiceName" "WARN"
        return
    }
    
    if ($service.Status -eq "Stopped") {
        Write-Status "Service is already stopped" "OK"
        return
    }
    
    try {
        Stop-Service -Name $ServiceName -Force
        Start-Sleep -Seconds 2
        
        $service.Refresh()
        if ($service.Status -eq "Stopped") {
            Write-Status "Service stopped successfully" "OK"
        } else {
            Write-Status "Service failed to stop (status: $($service.Status))" "WARN"
        }
    } catch {
        Write-Status "Failed to stop service: $_" "FAIL"
    }
}

function Restart-ServiceWrapper {
    Write-Header "Restarting Service"
    
    Stop-ServiceWrapper
    Start-Sleep -Seconds 2
    Start-ServiceWrapper
}

function Get-ServiceStatus {
    Write-Header "Service Status"
    
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    
    if (!$service) {
        Write-Status "Service not installed: $ServiceName" "WARN"
        return
    }
    
    Write-Status "Service Name: $($service.Name)" "INFO"
    Write-Status "Display Name: $($service.DisplayName)" "INFO"
    Write-Status "Status: $($service.Status)" $(if($service.Status -eq "Running"){"OK"}else{"WARN"})
    Write-Status "Startup Type: $($service.StartType)" "INFO"
    
    # Get process info if running
    if ($service.Status -eq "Running") {
        try {
            $process = Get-Process -Name "RawrXD-InferenceEngine" -ErrorAction SilentlyContinue
            if ($process) {
                Write-Status "Process ID: $($process.Id)" "INFO"
                Write-Status "Memory: $([math]::Round($process.WorkingSet64 / 1MB, 2)) MB" "INFO"
                Write-Status "CPU Time: $($process.TotalProcessorTime)" "INFO"
                Write-Status "Started: $($process.StartTime)" "INFO"
            }
        } catch {
            # Process info not available
        }
    }
    
    # Check for named pipes
    try {
        $pipes = [System.IO.Directory]::GetFiles("\\.\pipe\") | Where-Object { $_ -match "RawrXD" }
        Write-Status "Named Pipes: $($pipes.Count)" $(if($pipes.Count -gt 0){"OK"}else{"WARN"})
        foreach ($pipe in $pipes) {
            Write-Host "    - $(Split-Path $pipe -Leaf)" -ForegroundColor Gray
        }
    } catch {
        Write-Status "Cannot enumerate named pipes" "WARN"
    }
}

function Show-ServiceLogs {
    Write-Header "Service Logs"
    
    $logPaths = @(
        "$env:SYSTEMROOT\System32\LogFiles\$ServiceName.log",
        "$InstallDir\logs\service.log",
        "$InstallDir\logs\inference.log"
    )
    
    $foundLogs = $false
    
    foreach ($logPath in $logPaths) {
        if (Test-Path $logPath) {
            $foundLogs = $true
            Write-Status "Log file: $logPath" "INFO"
            
            # Show last 20 lines
            try {
                $lines = Get-Content $logPath -Tail 20
                Write-Host "`n  Last 20 lines:" -ForegroundColor Gray
                $lines | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
            } catch {
                Write-Status "Cannot read log file" "WARN"
            }
            
            Write-Host ""
        }
    }
    
    if (!$foundLogs) {
        Write-Status "No log files found" "WARN"
        Write-Host "  Checked locations:" -ForegroundColor Gray
        $logPaths | ForEach-Object { Write-Host "    - $_" -ForegroundColor Gray }
    }
    
    # Also check Windows Event Log
    Write-Host "`n  Windows Event Log entries:" -ForegroundColor Gray
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='System'; ID=7034,7036} -MaxEvents 10 -ErrorAction SilentlyContinue | 
            Where-Object { $_.Message -match $ServiceName }
        
        if ($events) {
            $events | ForEach-Object {
                Write-Host "    [$($_.TimeCreated)] $($_.LevelDisplayName): $($_.Message.Substring(0, [Math]::Min(80, $_.Message.Length)))..." -ForegroundColor Gray
            }
        } else {
            Write-Host "    No recent events found" -ForegroundColor Gray
        }
    } catch {
        Write-Host "    Cannot access event log" -ForegroundColor Gray
    }
}

# =============================================================================
# Main Execution
# =============================================================================
Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     RawrXD OMEGA-1 Service Wrapper                                             ║" -ForegroundColor Cyan
Write-Host "║     Action: $Action" -NoNewline -ForegroundColor Cyan
Write-Host "$(' ' * (63 - $Action.Length))║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

if ($Action -in @("install", "uninstall") -and !(Test-AdminRights)) {
    Write-Host "`n  ⚠️  Administrator rights required for this action" -ForegroundColor Yellow
    Write-Host "  Right-click PowerShell and select 'Run as Administrator'`n" -ForegroundColor Yellow
}

switch ($Action) {
    "install" { Install-Service }
    "uninstall" { Uninstall-Service }
    "start" { Start-ServiceWrapper }
    "stop" { Stop-ServiceWrapper }
    "restart" { Restart-ServiceWrapper }
    "status" { Get-ServiceStatus }
    "logs" { Show-ServiceLogs }
}

Write-Host "`nService wrapper complete!`n" -ForegroundColor Cyan
