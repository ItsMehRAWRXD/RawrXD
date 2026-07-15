# RawrXD Service Manager
# Manages RawrXD as a Windows service

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Install", "Uninstall", "Start", "Stop", "Restart", "Status", "Configure")]
    [string]$Action = "Status",
    
    [string]$ServiceName = "RawrXD",
    [string]$DisplayName = "RawrXD Vision & Generation System",
    [string]$BinaryPath = "",
    [string]$ServiceAccount = "LocalSystem",
    [string]$Description = "High-performance AI inference runtime",
    [switch]$AutoStart,
    [switch]$DelayedStart
)

$ErrorActionPreference = "Stop"

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

function Write-Warning {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Initialize-ServiceManager {
    Write-Status "Service Manager initialized"
    Write-Status "Service Name: $ServiceName"
    Write-Status "Action: $Action"
    
    # Check if running as administrator
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Warning "Some operations require Administrator privileges"
    }
}

function Get-ServiceStatus {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    return $service
}

function Install-Service {
    Write-Status "Installing service: $ServiceName"
    
    # Check if service already exists
    $existingService = Get-ServiceStatus
    if ($existingService) {
        Write-Warning "Service '$ServiceName' already exists"
        return
    }
    
    # Determine binary path
    if (-not $BinaryPath) {
        $BinaryPath = "$PSScriptRoot\..\bin\rawrxd.exe"
    }
    
    if (-not (Test-Path $BinaryPath)) {
        Write-Error "Binary not found: $BinaryPath"
        return
    }
    
    $binaryPathResolved = Resolve-Path $BinaryPath
    $serviceCommand = "`"$binaryPathResolved`" --service"
    
    try {
        # Create service using sc.exe
        $startType = if ($AutoStart) { "auto" } else { "demand" }
        if ($DelayedStart) { $startType = "delayed-auto" }
        
        $result = sc.exe create $ServiceName binPath= $serviceCommand start= $startType DisplayName= "$DisplayName" obj= $ServiceAccount
        
        if ($LASTEXITCODE -eq 0) {
            # Set description
            sc.exe description $ServiceName "$Description" | Out-Null
            
            Write-Success "Service '$ServiceName' installed successfully"
            Write-Status "Binary: $binaryPathResolved"
            Write-Status "Start Type: $startType"
            Write-Status "Account: $ServiceAccount"
        } else {
            Write-Error "Failed to install service. Exit code: $LASTEXITCODE"
        }
    }
    catch {
        Write-Error "Failed to install service: $_"
    }
}

function Uninstall-Service {
    Write-Status "Uninstalling service: $ServiceName"
    
    $service = Get-ServiceStatus
    if (-not $service) {
        Write-Warning "Service '$ServiceName' not found"
        return
    }
    
    # Stop service first
    if ($service.Status -eq "Running") {
        Write-Status "Stopping service..."
        Stop-Service -Name $ServiceName -Force
        Start-Sleep -Seconds 2
    }
    
    try {
        $result = sc.exe delete $ServiceName
        
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Service '$ServiceName' uninstalled successfully"
        } else {
            Write-Error "Failed to uninstall service. Exit code: $LASTEXITCODE"
        }
    }
    catch {
        Write-Error "Failed to uninstall service: $_"
    }
}

function Start-RawrXDService {
    Write-Status "Starting service: $ServiceName"
    
    $service = Get-ServiceStatus
    if (-not $service) {
        Write-Error "Service '$ServiceName' not found"
        return
    }
    
    if ($service.Status -eq "Running") {
        Write-Warning "Service is already running"
        return
    }
    
    try {
        Start-Service -Name $ServiceName
        
        # Wait for service to start
        $timeout = 30
        $timer = [Diagnostics.Stopwatch]::StartNew()
        
        while ($service.Status -ne "Running" -and $timer.Elapsed.TotalSeconds -lt $timeout) {
            Start-Sleep -Seconds 1
            $service.Refresh()
        }
        
        if ($service.Status -eq "Running") {
            Write-Success "Service '$ServiceName' started successfully"
        } else {
            Write-Error "Service failed to start within $timeout seconds"
        }
    }
    catch {
        Write-Error "Failed to start service: $_"
    }
}

function Stop-RawrXDService {
    Write-Status "Stopping service: $ServiceName"
    
    $service = Get-ServiceStatus
    if (-not $service) {
        Write-Error "Service '$ServiceName' not found"
        return
    }
    
    if ($service.Status -eq "Stopped") {
        Write-Warning "Service is already stopped"
        return
    }
    
    try {
        Stop-Service -Name $ServiceName -Force
        
        # Wait for service to stop
        $timeout = 30
        $timer = [Diagnostics.Stopwatch]::StartNew()
        
        while ($service.Status -ne "Stopped" -and $timer.Elapsed.TotalSeconds -lt $timeout) {
            Start-Sleep -Seconds 1
            $service.Refresh()
        }
        
        if ($service.Status -eq "Stopped") {
            Write-Success "Service '$ServiceName' stopped successfully"
        } else {
            Write-Error "Service failed to stop within $timeout seconds"
        }
    }
    catch {
        Write-Error "Failed to stop service: $_"
    }
}

function Restart-RawrXDService {
    Write-Status "Restarting service: $ServiceName"
    
    Stop-RawrXDService
    Start-Sleep -Seconds 2
    Start-RawrXDService
}

function Show-ServiceStatus {
    Write-Host ""
    Write-Host "Service Status" -ForegroundColor Cyan
    Write-Host "==============" -ForegroundColor Cyan
    
    $service = Get-ServiceStatus
    
    if (-not $service) {
        Write-Warning "Service '$ServiceName' not found"
        return
    }
    
    $statusColor = switch ($service.Status) {
        "Running" { "Green" }
        "Stopped" { "Red" }
        "Paused" { "Yellow" }
        default { "White" }
    }
    
    Write-Host "Service Name: $($service.Name)"
    Write-Host "Display Name: $($service.DisplayName)"
    Write-Host "Status: " -NoNewline
    Write-Host $service.Status -ForegroundColor $statusColor
    Write-Host "Start Type: $($service.StartType)"
    
    # Get additional service info
    try {
        $serviceInfo = Get-WmiObject -Class Win32_Service -Filter "Name='$ServiceName'"
        Write-Host "Process ID: $($serviceInfo.ProcessId)"
        Write-Host "Service Account: $($serviceInfo.StartName)"
        Write-Host "Description: $($serviceInfo.Description)"
        
        if ($service.Status -eq "Running" -and $serviceInfo.ProcessId -gt 0) {
            $process = Get-Process -Id $serviceInfo.ProcessId -ErrorAction SilentlyContinue
            if ($process) {
                Write-Host "Memory Usage: $([math]::Round($process.WorkingSet64 / 1MB, 2)) MB"
                Write-Host "CPU Time: $($process.TotalProcessorTime)"
            }
        }
    }
    catch {
        Write-Warning "Could not retrieve additional service information"
    }
}

function Configure-Service {
    Write-Status "Configuring service: $ServiceName"
    
    $service = Get-ServiceStatus
    if (-not $service) {
        Write-Error "Service '$ServiceName' not found"
        return
    }
    
    try {
        # Set startup type
        if ($AutoStart) {
            Set-Service -Name $ServiceName -StartupType Automatic
            Write-Success "Service startup type set to Automatic"
        } elseif ($DelayedStart) {
            sc.exe config $ServiceName start= delayed-auto | Out-Null
            Write-Success "Service startup type set to Delayed Automatic"
        }
        
        # Set description
        if ($Description) {
            sc.exe description $ServiceName "$Description" | Out-Null
            Write-Success "Service description updated"
        }
    }
    catch {
        Write-Error "Failed to configure service: $_"
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Service Manager" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-ServiceManager
    
    switch ($Action) {
        "Install" { Install-Service }
        "Uninstall" { Uninstall-Service }
        "Start" { Start-RawrXDService }
        "Stop" { Stop-RawrXDService }
        "Restart" { Restart-RawrXDService }
        "Status" { Show-ServiceStatus }
        "Configure" { Configure-Service }
    }
    
    Write-Host ""
}

Main
