# safe_mode.ps1
# Phase H.4 Batch 3/5: Emergency Recovery Mode

param(
    [switch]$Enter,
    [switch]$Exit,
    [switch]$Diagnostics,
    [string]$InstallDir = "${env:ProgramFiles}\RawrXD"
)

$ErrorActionPreference = "Stop"

$SafeModeConfig = @{
    ConfigPath = Join-Path $env:ProgramData "RawrXD\safe_mode.yaml"
    BackupConfig = Join-Path $env:ProgramData "RawrXD\config_backup.yaml"
    MinimalFeatures = @("core", "logging")
    DisabledFeatures = @("autonomous", "hotpatch", "telemetry", "swarm")
}

function Write-Log($Message, $Level = "INFO") {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARNING" { "Yellow" }
        "SUCCESS" { "Green" }
        default { "Cyan" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Enter-SafeMode {
    Write-Log "ENTERING SAFE MODE" "WARNING"
    Write-Log "This will disable advanced features and start minimal services"
    
    # Stop current service
    Write-Log "Stopping RawrXD service..."
    Stop-Service -Name "RawrXD" -ErrorAction SilentlyContinue
    
    # Backup current config
    $configPath = Join-Path $InstallDir "config\rawrxd.yaml"
    if (Test-Path $configPath) {
        Write-Log "Backing up current configuration..."
        Copy-Item -Path $configPath -Destination $SafeModeConfig.BackupConfig -Force
    }
    
    # Create safe mode config
    Write-Log "Creating safe mode configuration..."
    $safeConfig = @"
# RawrXD Safe Mode Configuration
# Generated: $(Get-Date -Format "o")
# WARNING: Minimal configuration for emergency recovery

version: "1.0.0"

safe_mode: true

server:
  host: "127.0.0.1"
  port: 8080
  max_connections: 10

inference:
  default_model: "default"
  max_tokens: 1024
  temperature: 0.5
  gpu_enabled: false
  batch_size: 1

logging:
  level: "debug"
  file: "$env:ProgramData\RawrXD\logs\safe_mode.log"
  console: true

features:
  autonomous: false
  hotpatch: false
  telemetry: false
  swarm: false
  chaos: false
  monitoring: false

recovery:
  auto_restart: false
  max_restarts: 0
  health_check_interval: 30

security:
  strict_mode: true
  validate_inputs: true
  sandbox_enabled: true
"@
    
    $safeConfig | Out-File -FilePath $configPath -Encoding UTF8
    
    # Create safe mode marker
    $markerPath = Join-Path $env:ProgramData "RawrXD\.safe_mode"
    "Safe mode enabled at $(Get-Date -Format "o")" | Out-File $markerPath
    
    # Start service with safe config
    Write-Log "Starting RawrXD in safe mode..."
    Start-Service -Name "RawrXD" -ErrorAction SilentlyContinue
    
    Start-Sleep -Seconds 3
    
    # Verify service started
    $service = Get-Service -Name "RawrXD" -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq "Running") {
        Write-Log "Safe mode enabled successfully" "SUCCESS"
        Write-Log ""
        Write-Log "RawrXD is running in SAFE MODE with minimal features"
        Write-Log "Advanced features disabled: $($SafeModeConfig.DisabledFeatures -join ', ')"
        Write-Log ""
        Write-Log "To exit safe mode, run: safe_mode.ps1 -Exit"
    }
    else {
        Write-Log "Failed to start service in safe mode" "ERROR"
    }
}

function Exit-SafeMode {
    Write-Log "EXITING SAFE MODE"
    
    # Check if in safe mode
    $markerPath = Join-Path $env:ProgramData "RawrXD\.safe_mode"
    if (-not (Test-Path $markerPath)) {
        Write-Log "Not currently in safe mode" "WARNING"
        return
    }
    
    # Stop service
    Write-Log "Stopping RawrXD service..."
    Stop-Service -Name "RawrXD" -ErrorAction SilentlyContinue
    
    # Restore original config
    if (Test-Path $SafeModeConfig.BackupConfig) {
        Write-Log "Restoring original configuration..."
        $configPath = Join-Path $InstallDir "config\rawrxd.yaml"
        Copy-Item -Path $SafeModeConfig.BackupConfig -Destination $configPath -Force
        Remove-Item -Path $SafeModeConfig.BackupConfig -Force
    }
    
    # Remove safe mode marker
    Remove-Item -Path $markerPath -Force -ErrorAction SilentlyContinue
    
    # Start service
    Write-Log "Starting RawrXD with normal configuration..."
    Start-Service -Name "RawrXD" -ErrorAction SilentlyContinue
    
    Start-Sleep -Seconds 3
    
    $service = Get-Service -Name "RawrXD" -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq "Running") {
        Write-Log "Safe mode exited successfully" "SUCCESS"
        Write-Log "RawrXD is running with full features enabled"
    }
    else {
        Write-Log "Failed to start service normally" "ERROR"
        Write-Log "You may need to re-enter safe mode and troubleshoot" "WARNING"
    }
}

function Invoke-Diagnostics {
    Write-Log "Running emergency diagnostics..."
    
    $results = @{
        Timestamp = Get-Date -Format "o"
        Tests = @()
        Passed = 0
        Failed = 0
    }
    
    # Test 1: Service status
    Write-Log "Test 1: Service Status"
    $service = Get-Service -Name "RawrXD" -ErrorAction SilentlyContinue
    if ($service) {
        Write-Log "  Status: $($service.Status)"
        Write-Log "  StartType: $($service.StartType)"
        $results.Tests += @{ Name = "Service Status"; Result = "PASS"; Details = $service.Status }
        $results.Passed++
    }
    else {
        Write-Log "  Service not found" "ERROR"
        $results.Tests += @{ Name = "Service Status"; Result = "FAIL"; Details = "Service not found" }
        $results.Failed++
    }
    
    # Test 2: Binary exists
    Write-Log "Test 2: Binary Integrity"
    $exePath = Join-Path $InstallDir "RawrXD.exe"
    if (Test-Path $exePath) {
        $version = (Get-Item $exePath).VersionInfo.ProductVersion
        Write-Log "  Version: $version"
        $results.Tests += @{ Name = "Binary Integrity"; Result = "PASS"; Details = "v$version" }
        $results.Passed++
    }
    else {
        Write-Log "  Binary not found" "ERROR"
        $results.Tests += @{ Name = "Binary Integrity"; Result = "FAIL"; Details = "Binary missing" }
        $results.Failed++
    }
    
    # Test 3: Configuration
    Write-Log "Test 3: Configuration"
    $configPath = Join-Path $InstallDir "config\rawrxd.yaml"
    if (Test-Path $configPath) {
        Write-Log "  Config file exists"
        $results.Tests += @{ Name = "Configuration"; Result = "PASS" }
        $results.Passed++
    }
    else {
        Write-Log "  Config file missing" "ERROR"
        $results.Tests += @{ Name = "Configuration"; Result = "FAIL" }
        $results.Failed++
    }
    
    # Test 4: Disk space
    Write-Log "Test 4: Disk Space"
    $drive = Get-PSDrive -Name C
    $freePercent = ($drive.Free / $drive.Used) * 100
    if ($freePercent -gt 10) {
        Write-Log "  Free space: $([math]::Round($drive.Free / 1GB, 2)) GB"
        $results.Tests += @{ Name = "Disk Space"; Result = "PASS" }
        $results.Passed++
    }
    else {
        Write-Log "  Low disk space: $([math]::Round($freePercent, 1))%" "WARNING"
        $results.Tests += @{ Name = "Disk Space"; Result = "WARN"; Details = "Low space" }
    }
    
    # Test 5: Network
    Write-Log "Test 5: Network Connectivity"
    try {
        $test = Test-Connection -ComputerName "rawrxd.ai" -Count 1 -ErrorAction Stop
        Write-Log "  Network: OK"
        $results.Tests += @{ Name = "Network"; Result = "PASS" }
        $results.Passed++
    }
    catch {
        Write-Log "  Network: Unavailable" "WARNING"
        $results.Tests += @{ Name = "Network"; Result = "WARN"; Details = "No connectivity" }
    }
    
    # Summary
    Write-Log ""
    Write-Log "Diagnostics Complete: $($results.Passed) passed, $($results.Failed) failed"
    
    # Save report
    $reportPath = Join-Path $env:ProgramData "RawrXD\diagnostics_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $results | ConvertTo-Json | Out-File $reportPath
    Write-Log "Report saved: $reportPath"
    
    if ($results.Failed -gt 0) {
        Write-Log ""
        Write-Log "RECOMMENDATION: Enter safe mode to troubleshoot" "WARNING"
        Write-Log "Run: safe_mode.ps1 -Enter"
    }
}

# Main execution
Write-Log "RawrXD Emergency Recovery Mode"
Write-Log ""

if ($Enter) {
    Enter-SafeMode
}
elseif ($Exit) {
    Exit-SafeMode
}
elseif ($Diagnostics) {
    Invoke-Diagnostics
}
else {
    Write-Log "Usage:"
    Write-Log "  safe_mode.ps1 -Enter      # Enter safe mode"
    Write-Log "  safe_mode.ps1 -Exit       # Exit safe mode"
    Write-Log "  safe_mode.ps1 -Diagnostics # Run diagnostics"
}
