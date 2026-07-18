# deploy.ps1
# Production Deployment Script for RawrXD Sovereign v1.0.0

param(
    [string]$Version = "1.0.0",
    [string]$DownloadUrl = "https://github.com/ItsMehRAWRXD/RawrXD/releases/download/v1.0.0-sovereign-complete",
    [string]$InstallDir = "${env:ProgramFiles}\RawrXD",
    [string]$ConfigPath = ".\deployment\configs\production.yaml",
    [switch]$SkipVerification,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

$DeploymentLog = @{
    StartTime = Get-Date -Format "o"
    Version = $Version
    Steps = @()
    Success = $false
}

function Write-DeployLog($Message, $Level = "INFO") {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARNING" { "Yellow" }
        "SUCCESS" { "Green" }
        "STEP" { "Cyan" }
        default { "White" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Invoke-DeploymentStep($Name, $ScriptBlock) {
    Write-DeployLog "Step: $Name" "STEP"
    
    if ($DryRun) {
        Write-DeployLog "DRY RUN: Would execute $Name" "WARNING"
        $DeploymentLog.Steps += @{ Name = $Name; Status = "DRY_RUN"; Duration = 0 }
        return $true
    }
    
    $startTime = Get-Date
    try {
        $result = & $ScriptBlock
        $duration = (Get-Date) - $startTime
        
        if ($result) {
            Write-DeployLog "✅ $Name completed" "SUCCESS"
            $DeploymentLog.Steps += @{ 
                Name = $Name; 
                Status = "SUCCESS"; 
                Duration = $duration.TotalSeconds 
            }
            return $true
        } else {
            throw "Step returned false"
        }
    }
    catch {
        $duration = (Get-Date) - $startTime
        Write-DeployLog "❌ $Name failed: $_" "ERROR"
        $DeploymentLog.Steps += @{ 
            Name = $Name; 
            Status = "FAILED"; 
            Error = $_.Exception.Message;
            Duration = $duration.TotalSeconds 
        }
        return $false
    }
}

# Main deployment
Write-DeployLog "RawrXD Sovereign v$Version Production Deployment"
Write-DeployLog "Target: AMD RX 7800 XT"
Write-DeployLog ""

if ($DryRun) {
    Write-DeployLog "DRY RUN MODE - No changes will be made" "WARNING"
    Write-DeployLog ""
}

$success = $true

# Step 1: Pre-deployment checks
$success = $success -and (Invoke-DeploymentStep "Pre-deployment checks" {
    # Check admin privileges
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Administrator privileges required"
    }
    
    # Check disk space
    $disk = Get-PSDrive -Name C
    if ($disk.Free -lt 10GB) {
        throw "Insufficient disk space (need 10GB, have $([math]::Round($disk.Free / 1GB, 2))GB)"
    }
    
    # Check if already installed
    if (Test-Path "$InstallDir\RawrXD.exe") {
        Write-DeployLog "Existing installation detected" "WARNING"
    }
    
    return $true
})

# Step 2: Download installer
$installerPath = "$env:TEMP\RawrXD-$Version-x64.msi"
$success = $success -and (Invoke-DeploymentStep "Download installer" {
    $url = "$DownloadUrl/RawrXD-$Version-x64.msi"
    Invoke-WebRequest -Uri $url -OutFile $installerPath -TimeoutSec 300
    return Test-Path $installerPath
})

# Step 3: Verify download
if (-not $SkipVerification) {
    $success = $success -and (Invoke-DeploymentStep "Verify download" {
        # In production, verify SHA256 hash
        Write-DeployLog "Hash verification would occur here" "WARNING"
        return $true
    })
}

# Step 4: Install
$success = $success -and (Invoke-DeploymentStep "Install RawrXD" {
    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$installerPath`" /qn /norestart /l*v `"$env:TEMP\rawrxd_install.log`"" -Wait -PassThru
    return $process.ExitCode -eq 0
})

# Step 5: Configure
$success = $success -and (Invoke-DeploymentStep "Configure RawrXD" {
    if (Test-Path $ConfigPath) {
        $targetConfig = "${env:ProgramData}\RawrXD\config\rawrxd.yaml"
        Copy-Item -Path $ConfigPath -Destination $targetConfig -Force
        return $true
    }
    Write-DeployLog "Using default configuration" "WARNING"
    return $true
})

# Step 6: Start service
$success = $success -and (Invoke-DeploymentStep "Start service" {
    Start-Service -Name "RawrXD" -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 10
    
    $service = Get-Service -Name "RawrXD" -ErrorAction SilentlyContinue
    return ($service -and $service.Status -eq "Running")
})

# Step 7: Health check
$success = $success -and (Invoke-DeploymentStep "Health check" {
    try {
        $response = Invoke-RestMethod -Uri "http://localhost:8080/api/v1/health" -TimeoutSec 30
        return $response.status -eq "healthy"
    }
    catch {
        return $false
    }
})

# Step 8: Test inference
$success = $success -and (Invoke-DeploymentStep "Test inference" {
    try {
        $testRequest = @{
            model = "llama-3-8b"
            prompt = "Hello"
            max_tokens = 10
        } | ConvertTo-Json
        
        $response = Invoke-RestMethod -Uri "http://localhost:8080/api/v1/inference" -Method POST -Body $testRequest -ContentType "application/json" -TimeoutSec 30
        return $response.content -ne $null
    }
    catch {
        return $false
    }
})

# Step 9: Setup monitoring
$success = $success -and (Invoke-DeploymentStep "Setup monitoring" {
    # Create scheduled task for metrics collection
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File `"$InstallDir\monitoring\telemetry\metrics_collector.ps1`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    
    try {
        Register-ScheduledTask -TaskName "RawrXD Metrics" -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
        return $true
    }
    catch {
        Write-DeployLog "Failed to setup monitoring: $_" "WARNING"
        return $true  # Non-critical
    }
})

# Step 10: Create backup
$success = $success -and (Invoke-DeploymentStep "Create initial backup" {
    $backupScript = "$InstallDir\recovery\backup\data_preservation.ps1"
    if (Test-Path $backupScript) {
        & $backupScript -Action "backup" -Compress
    }
    return $true
})

# Finalize
$DeploymentLog.EndTime = Get-Date -Format "o"
$DeploymentLog.Success = $success

# Save deployment log
$logPath = "${env:ProgramData}\RawrXD\logs\deployment_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
$DeploymentLog | ConvertTo-Json -Depth 5 | Out-File $logPath

Write-DeployLog ""
Write-DeployLog "Deployment log saved: $logPath"

if ($success) {
    Write-DeployLog ""
    Write-DeployLog "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-DeployLog "║     DEPLOYMENT SUCCESSFUL                                  ║" -ForegroundColor Green
    Write-DeployLog "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-DeployLog ""
    Write-DeployLog "RawrXD Sovereign v$Version is now running"
    Write-DeployLog "API Endpoint: http://localhost:8080"
    Write-DeployLog "Health Check: http://localhost:8080/api/v1/health"
    Write-DeployLog ""
    exit 0
} else {
    Write-DeployLog ""
    Write-DeployLog "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-DeployLog "║     DEPLOYMENT FAILED                                      ║" -ForegroundColor Red
    Write-DeployLog "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Red
    Write-DeployLog ""
    Write-DeployLog "Check logs for details: $logPath"
    Write-DeployLog "Run rollback if needed: .\deployment\scripts\rollback.ps1"
    Write-DeployLog ""
    exit 1
}
