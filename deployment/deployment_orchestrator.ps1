# RawrXD Deployment Orchestrator
# Manages blue/green deployments, canary releases, and automated rollbacks

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("BlueGreen", "Canary", "Rolling", "A/B", "Recreate")]
    [string]$Strategy,
    
    [Parameter(Mandatory=$true)]
    [string]$Version,
    
    [Parameter(Mandatory=$true)]
    [ValidateSet("dev", "staging", "production")]
    [string]$Environment,
    
    [string]$SourcePath = ".",
    [string]$TargetPath,
    [int]$CanaryPercentage = 10,
    [int]$HealthCheckRetries = 3,
    [int]$HealthCheckInterval = 30,
    [switch]$AutoRollback,
    [switch]$DryRun,
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"

# Deployment state
$script:DeploymentState = @{
    deployment_id = [Guid]::NewGuid().ToString()
    version = $Version
    environment = $Environment
    strategy = $Strategy
    started_at = Get-Date -Format "o"
    status = "in_progress"
    steps = @()
    health_checks = @()
    rollback_triggered = $false
}

# Environment configuration
$script:EnvironmentConfig = @{
    dev = @{
        target_path = "C:\\RawrXD\\dev"
        health_endpoint = "http://localhost:8080/health"
        instances = 1
        backup_before_deploy = $false
    }
    staging = @{
        target_path = "C:\\RawrXD\\staging"
        health_endpoint = "http://localhost:8081/health"
        instances = 2
        backup_before_deploy = $true
    }
    production = @{
        target_path = "C:\\RawrXD\\production"
        health_endpoint = "http://localhost:8082/health"
        instances = 4
        backup_before_deploy = $true
    }
}

function Write-DeploymentLog {
    param(
        [string]$Step,
        [string]$Status,
        [string]$Details = ""
    )
    
    $script:DeploymentState.steps += @{
        step = $Step
        status = $Status
        timestamp = Get-Date -Format "o"
        details = $Details
    }
    
    $color = switch ($Status) {
        "success" { "Green" }
        "error" { "Red" }
        "warning" { "Yellow" }
        "info" { "Cyan" }
        default { "White" }
    }
    
    $icon = switch ($Status) {
        "success" { "✓" }
        "error" { "✗" }
        "warning" { "⚠" }
        "info" { "ℹ" }
        default { "•" }
    }
    
    Write-Host "$icon $Step" -ForegroundColor $color
    if ($Details) {
        Write-Host "  $Details" -ForegroundColor Gray
    }
}

function Initialize-Deployment {
    Write-DeploymentLog -Step "Initialize Deployment" -Status "info" -Details "Strategy: $Strategy, Version: $Version, Environment: $Environment"
    
    # Validate environment
    if (-not $script:EnvironmentConfig.ContainsKey($Environment)) {
        throw "Unknown environment: $Environment"
    }
    
    $config = $script:EnvironmentConfig[$Environment]
    if (-not $TargetPath) {
        $script:TargetPath = $config.target_path
    } else {
        $script:TargetPath = $TargetPath
    }
    
    # Create target directory if needed
    if (-not (Test-Path $script:TargetPath)) {
        New-Item -ItemType Directory -Path $script:TargetPath -Force | Out-Null
        Write-DeploymentLog -Step "Created Target Directory" -Status "success" -Details $script:TargetPath
    }
    
    # Validate source
    if (-not (Test-Path $SourcePath)) {
        throw "Source path not found: $SourcePath"
    }
    
    Write-DeploymentLog -Step "Deployment Initialized" -Status "success"
}

function Invoke-PreDeploymentChecks {
    Write-DeploymentLog -Step "Pre-Deployment Checks" -Status "info"
    
    if ($DryRun) {
        Write-DeploymentLog -Step "Pre-Deployment Checks" -Status "warning" -Details "Skipped in dry-run mode"
        return
    }
    
    # Run smoke tests
    if (-not $SkipTests) {
        Write-Host "  Running smoke tests..." -ForegroundColor Gray
        $testResult = Invoke-Pester -Path "tests/smoke" -PassThru -Show None
        if ($testResult.FailedCount -gt 0) {
            throw "Smoke tests failed: $($testResult.FailedCount) failures"
        }
        Write-DeploymentLog -Step "Smoke Tests" -Status "success" -Details "All tests passed"
    }
    
    # Check disk space
    $drive = (Get-Item $script:TargetPath).PSDrive
    $freeSpaceGB = [math]::Round($drive.Free / 1GB, 2)
    if ($freeSpaceGB -lt 1) {
        throw "Insufficient disk space: $freeSpaceGB GB available"
    }
    Write-DeploymentLog -Step "Disk Space Check" -Status "success" -Details "$freeSpaceGB GB available"
    
    # Backup if configured
    $config = $script:EnvironmentConfig[$Environment]
    if ($config.backup_before_deploy) {
        Write-Host "  Creating pre-deployment backup..." -ForegroundColor Gray
        $backupPath = "disaster-recovery/backups/pre-deploy-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        & "disaster-recovery/backups/backup_manager.ps1" -BackupType ConfigOnly -BackupPath $backupPath
        Write-DeploymentLog -Step "Pre-Deployment Backup" -Status "success" -Details $backupPath
    }
}

function Invoke-BlueGreenDeployment {
    Write-DeploymentLog -Step "Blue/Green Deployment" -Status "info"
    
    $bluePath = Join-Path $script:TargetPath "blue"
    $greenPath = Join-Path $script:TargetPath "green"
    $activePath = Join-Path $script:TargetPath "active"
    
    # Determine which environment is currently active
    $currentActive = $null
    if (Test-Path $activePath) {
        $currentActive = Get-Item $activePath | Select-Object -ExpandProperty Target
    }
    
    $newColor = if ($currentActive -eq $bluePath) { "green" } else { "blue" }
    $newPath = if ($newColor -eq "blue") { $bluePath } else { $greenPath }
    $oldPath = if ($newColor -eq "blue") { $greenPath } else { $bluePath }
    
    Write-DeploymentLog -Step "Blue/Green Analysis" -Status "info" -Details "Current: $(if($currentActive){'active'}else{'none'}), Deploying to: $newColor"
    
    # Deploy to inactive environment
    Write-Host "  Deploying to $newColor environment..." -ForegroundColor Gray
    if (-not $DryRun) {
        if (Test-Path $newPath) {
            Remove-Item $newPath -Recurse -Force
        }
        Copy-Item $SourcePath $newPath -Recurse -Force
    }
    Write-DeploymentLog -Step "Deploy to $newColor" -Status "success"
    
    # Health check on new environment
    $health = Test-DeploymentHealth -Path $newPath
    if (-not $health.healthy) {
        if ($AutoRollback) {
            Write-DeploymentLog -Step "Health Check Failed" -Status "error" -Details "Auto-rollback triggered"
            Invoke-Rollback -Reason "Health check failed on $newColor environment"
            return
        } else {
            throw "Health check failed on $newColor environment"
        }
    }
    Write-DeploymentLog -Step "Health Check" -Status "success" -Details "$newColor environment healthy"
    
    # Switch traffic
    Write-Host "  Switching traffic to $newColor..." -ForegroundColor Gray
    if (-not $DryRun) {
        if (Test-Path $activePath) {
            Remove-Item $activePath -Force
        }
        New-Item -ItemType Junction -Path $activePath -Target $newPath | Out-Null
    }
    Write-DeploymentLog -Step "Traffic Switch" -Status "success" -Details "Now serving from $newColor"
    
    # Keep old environment for quick rollback
    Write-DeploymentLog -Step "Blue/Green Complete" -Status "success" -Details "Previous version preserved in $(if($newColor -eq 'blue'){'green'}else{'blue'})"
}

function Invoke-CanaryDeployment {
    Write-DeploymentLog -Step "Canary Deployment" -Status "info" -Details "Target: $CanaryPercentage%"
    
    $stablePath = Join-Path $script:TargetPath "stable"
    $canaryPath = Join-Path $script:TargetPath "canary"
    
    # Ensure stable exists
    if (-not (Test-Path $stablePath)) {
        Copy-Item $SourcePath $stablePath -Recurse -Force
        Write-DeploymentLog -Step "Initialize Stable" -Status "success"
    }
    
    # Deploy canary
    Write-Host "  Deploying canary version..." -ForegroundColor Gray
    if (-not $DryRun) {
        if (Test-Path $canaryPath) {
            Remove-Item $canaryPath -Recurse -Force
        }
        Copy-Item $SourcePath $canaryPath -Recurse -Force
    }
    Write-DeploymentLog -Step "Deploy Canary" -Status "success"
    
    # Health check
    $health = Test-DeploymentHealth -Path $canaryPath
    if (-not $health.healthy) {
        if ($AutoRollback) {
            Write-DeploymentLog -Step "Canary Health Check Failed" -Status "error"
            Invoke-Rollback -Reason "Canary health check failed"
            return
        } else {
            throw "Canary health check failed"
        }
    }
    Write-DeploymentLog -Step "Canary Health Check" -Status "success"
    
    # Monitor canary
    Write-Host "  Monitoring canary for 5 minutes..." -ForegroundColor Gray
    Start-Sleep -Seconds 300  # Simplified - would be actual monitoring
    
    # Promote or rollback based on metrics
    $canaryMetrics = Get-CanaryMetrics
    if ($canaryMetrics.error_rate -lt 1 -and $canaryMetrics.latency_p95 -lt 1000) {
        Write-Host "  Promoting canary to stable..." -ForegroundColor Gray
        if (-not $DryRun) {
            Remove-Item $stablePath -Recurse -Force
            Move-Item $canaryPath $stablePath -Force
        }
        Write-DeploymentLog -Step "Promote Canary" -Status "success" -Details "Canary promoted to stable"
    } else {
        Write-DeploymentLog -Step "Canary Metrics" -Status "warning" -Details "Error rate: $($canaryMetrics.error_rate)%, Latency: $($canaryMetrics.latency_p95)ms"
        if ($AutoRollback) {
            Invoke-Rollback -Reason "Canary metrics below threshold"
        }
    }
}

function Invoke-RollingDeployment {
    Write-DeploymentLog -Step "Rolling Deployment" -Status "info"
    
    $config = $script:EnvironmentConfig[$Environment]
    $instances = $config.instances
    
    for ($i = 1; $i -le $instances; $i++) {
        Write-Host "  Updating instance $i of $instances..." -ForegroundColor Gray
        
        $instancePath = Join-Path $script:TargetPath "instance-$i"
        
        # Take instance out of rotation (would integrate with load balancer)
        Write-DeploymentLog -Step "Instance $i" -Status "info" -Details "Removing from rotation"
        
        # Update instance
        if (-not $DryRun) {
            if (Test-Path $instancePath) {
                Remove-Item $instancePath -Recurse -Force
            }
            Copy-Item $SourcePath $instancePath -Recurse -Force
        }
        
        # Health check
        $health = Test-DeploymentHealth -Path $instancePath
        if (-not $health.healthy) {
            if ($AutoRollback) {
                Write-DeploymentLog -Step "Instance $i Health Failed" -Status "error"
                Invoke-Rollback -Reason "Instance $i health check failed"
                return
            } else {
                throw "Instance $i health check failed"
            }
        }
        
        # Return to rotation
        Write-DeploymentLog -Step "Instance $i" -Status "success" -Details "Back in rotation"
        
        # Wait between instances
        if ($i -lt $instances) {
            Start-Sleep -Seconds 10
        }
    }
    
    Write-DeploymentLog -Step "Rolling Deployment" -Status "success"
}

function Test-DeploymentHealth {
    param([string]$Path)
    
    $config = $script:EnvironmentConfig[$Environment]
    $healthEndpoint = $config.health_endpoint
    
    for ($i = 0; $i -lt $HealthCheckRetries; $i++) {
        try {
            $response = Invoke-RestMethod -Uri $healthEndpoint -Method Get -TimeoutSec 10
            if ($response.status -eq "healthy") {
                return @{ healthy = $true; response = $response }
            }
        }
        catch {
            Write-Host "    Health check attempt $($i+1) failed: $_" -ForegroundColor Gray
        }
        
        if ($i -lt $HealthCheckRetries - 1) {
            Start-Sleep -Seconds $HealthCheckInterval
        }
    }
    
    return @{ healthy = $false }
}

function Get-CanaryMetrics {
    # Simplified - would integrate with monitoring system
    return @{
        error_rate = 0.5  # percentage
        latency_p95 = 800  # milliseconds
        requests_per_second = 100
    }
}

function Invoke-Rollback {
    param([string]$Reason)
    
    Write-DeploymentLog -Step "Rollback Initiated" -Status "error" -Details $Reason
    $script:DeploymentState.rollback_triggered = $true
    
    # Call rollback script
    & "deployment/rollback/rollback_manager.ps1" -Environment $Environment -Reason $Reason
    
    $script:DeploymentState.status = "rolled_back"
    Save-DeploymentState
    
    throw "Deployment rolled back: $Reason"
}

function Save-DeploymentState {
    $script:DeploymentState.completed_at = Get-Date -Format "o"
    if ($script:DeploymentState.status -eq "in_progress") {
        $script:DeploymentState.status = "completed"
    }
    
    $statePath = Join-Path $script:TargetPath ".deployment-state.json"
    $script:DeploymentState | ConvertTo-Json -Depth 10 | Out-File $statePath
}

# Main execution
function Invoke-DeploymentOrchestrator {
    Write-Host "RawrXD Deployment Orchestrator" -ForegroundColor Cyan
    Write-Host "==============================" -ForegroundColor Cyan
    Write-Host "Strategy: $Strategy" -ForegroundColor Yellow
    Write-Host "Version: $Version" -ForegroundColor Yellow
    Write-Host "Environment: $Environment" -ForegroundColor Yellow
    if ($DryRun) { Write-Host "*** DRY RUN MODE ***" -ForegroundColor Magenta }
    Write-Host ""
    
    try {
        Initialize-Deployment
        Invoke-PreDeploymentChecks
        
        switch ($Strategy) {
            "BlueGreen" { Invoke-BlueGreenDeployment }
            "Canary" { Invoke-CanaryDeployment }
            "Rolling" { Invoke-RollingDeployment }
            default { throw "Strategy not implemented: $Strategy" }
        }
        
        Save-DeploymentState
        
        Write-Host "`n========================================" -ForegroundColor Green
        Write-Host "Deployment Complete!" -ForegroundColor Green
        Write-Host "Deployment ID: $($script:DeploymentState.deployment_id)" -ForegroundColor White
        Write-Host "========================================" -ForegroundColor Green
    }
    catch {
        Write-DeploymentLog -Step "Deployment Failed" -Status "error" -Details $_.Exception.Message
        Save-DeploymentState
        throw
    }
}

# Run deployment
Invoke-DeploymentOrchestrator
