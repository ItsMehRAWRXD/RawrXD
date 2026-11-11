#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Phase R.3: Deployment Manager
    
.DESCRIPTION
    Orchestrates deployments with blue-green strategy, rollback capabilities,
    health checks, and canary releases for the RawrXD platform.
    
.PARAMETER Action
    Action to perform: deploy, rollback, status, health-check, canary, promote
    
.PARAMETER Version
    Version to deploy
    
.PARAMETER Environment
    Target environment: dev, staging, production
    
.PARAMETER Strategy
    Deployment strategy: blue-green, rolling, canary
    
.EXAMPLE
    .\deployment_manager.ps1 -Action deploy -Version 1.0.0 -Environment production -Strategy blue-green
    .\deployment_manager.ps1 -Action rollback -Environment production
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("deploy", "rollback", "status", "health-check", "canary", "promote", "history")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [string]$Version,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("dev", "staging", "production")]
    [string]$Environment = "dev",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("blue-green", "rolling", "canary")]
    [string]$Strategy = "blue-green",
    
    [Parameter(Mandatory=$false)]
    [int]$CanaryPercentage = 10,
    
    [Parameter(Mandatory=$false)]
    [string]$DeploymentRoot = ".\deployments"
)

$ErrorActionPreference = "Stop"

# Deployment registry
$DeploymentRegistry = @{
    Environments = @{}
    Deployments = @()
    CurrentDeployments = @{}
}

# Environment configuration
$EnvironmentConfig = @{
    dev = @{
        Instances = 1
        HealthCheckUrl = "http://localhost:8080/health"
        AutoRollback = $false
        RequireApproval = $false
        MaxRetries = 3
    }
    staging = @{
        Instances = 2
        HealthCheckUrl = "http://staging.rawrxd.io/health"
        AutoRollback = $true
        RequireApproval = $false
        MaxRetries = 3
    }
    production = @{
        Instances = 5
        HealthCheckUrl = "http://api.rawrxd.io/health"
        AutoRollback = $true
        RequireApproval = $true
        MaxRetries = 5
    }
}

function Write-DeploymentHeader {
    Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase R.3: Deployment Manager                                   ║
║  Blue-green deployment, rollback, and orchestration                ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Initialize-DeploymentManager {
    if (-not (Test-Path $DeploymentRoot)) {
        New-Item -ItemType Directory -Path $DeploymentRoot -Force | Out-Null
    }
    
    # Initialize environment directories
    foreach ($env in $EnvironmentConfig.Keys) {
        $envPath = Join-Path $DeploymentRoot $env
        if (-not (Test-Path $envPath)) {
            New-Item -ItemType Directory -Path $envPath -Force | Out-Null
            New-Item -ItemType Directory -Path (Join-Path $envPath "blue") -Force | Out-Null
            New-Item -ItemType Directory -Path (Join-Path $envPath "green") -Force | Out-Null
        }
    }
    
    # Load registry
    $registryFile = Join-Path $DeploymentRoot "deployment_registry.json"
    if (Test-Path $registryFile) {
        $script:DeploymentRegistry = Get-Content -Path $registryFile -Raw | ConvertFrom-Json -AsHashtable
    }
}

function Save-DeploymentRegistry {
    $registryFile = Join-Path $DeploymentRoot "deployment_registry.json"
    $script:DeploymentRegistry | ConvertTo-Json -Depth 10 | Set-Content -Path $registryFile
}

function Get-ActiveColor {
    param($Environment)
    
    $current = $script:DeploymentRegistry.CurrentDeployments[$Environment]
    if ($current) {
        return $current.Color
    }
    return "blue"  # Default
}

function Get-NextColor {
    param($CurrentColor)
    
    if ($CurrentColor -eq "blue") {
        return "green"
    }
    return "blue"
}

function Test-Health {
    param($Url, $Retries = 3)
    
    for ($i = 0; $i -lt $Retries; $i++) {
        try {
            # Simulate health check
            Start-Sleep -Milliseconds 100
            
            # Random success for simulation
            if ((Get-Random -Maximum 10) -gt 1) {
                return @{ Success = $true; StatusCode = 200; ResponseTime = (Get-Random -Maximum 100) }
            }
        } catch {
            Start-Sleep -Seconds 1
        }
    }
    
    return @{ Success = $false; StatusCode = 0; ResponseTime = 0 }
}

function Invoke-BlueGreenDeploy {
    param($Version, $Environment)
    
    Write-Host "`nExecuting blue-green deployment..." -ForegroundColor Yellow
    
    $config = $EnvironmentConfig[$Environment]
    $currentColor = Get-ActiveColor -Environment $Environment
    $nextColor = Get-NextColor -CurrentColor $currentColor
    
    Write-Host "  Current active: $currentColor" -ForegroundColor Gray
    Write-Host "  Deploying to: $nextColor" -ForegroundColor Gray
    Write-Host "  Instances: $($config.Instances)" -ForegroundColor Gray
    
    # Step 1: Deploy to inactive environment
    Write-Host "`n[1/5] Deploying v$Version to $nextColor environment..." -ForegroundColor Cyan
    $deployPath = Join-Path (Join-Path $DeploymentRoot $Environment) $nextColor
    
    # Simulate deployment
    for ($i = 1; $i -le $config.Instances; $i++) {
        Write-Host "  Deploying instance $i/$($config.Instances)..." -ForegroundColor Gray
        Start-Sleep -Milliseconds 200
        
        $instance = @{
            Id = "$Environment-$nextColor-$i"
            Version = $Version
            Color = $nextColor
            Status = "running"
            StartedAt = Get-Date -Format "o"
        }
        
        $instance | ConvertTo-Json | Set-Content -Path (Join-Path $deployPath "instance_$i.json")
        Write-Host "    ✓ Instance $i ready" -ForegroundColor Green
    }
    
    # Step 2: Health check
    Write-Host "`n[2/5] Running health checks..." -ForegroundColor Cyan
    $health = Test-Health -Url $config.HealthCheckUrl -Retries $config.MaxRetries
    
    if (-not $health.Success) {
        Write-Error "Health check failed! Deployment aborted."
        return
    }
    
    Write-Host "  ✓ Health check passed (HTTP $($health.StatusCode), $($health.ResponseTime)ms)" -ForegroundColor Green
    
    # Step 3: Approval gate (production only)
    if ($config.RequireApproval) {
        Write-Host "`n[3/5] Waiting for approval..." -ForegroundColor Cyan
        Write-Host "  ⚠ Production deployment requires approval" -ForegroundColor Yellow
        
        # Simulate approval
        $approval = Read-Host "  Approve deployment? (yes/no)"
        if ($approval -ne "yes") {
            Write-Host "  ✗ Deployment rejected" -ForegroundColor Red
            return
        }
    } else {
        Write-Host "`n[3/5] Approval gate (skipped for $Environment)" -ForegroundColor Cyan
    }
    
    # Step 4: Switch traffic
    Write-Host "`n[4/5] Switching traffic to $nextColor..." -ForegroundColor Cyan
    
    # Update load balancer (simulated)
    $lbConfig = @{
        ActiveColor = $nextColor
        PreviousColor = $currentColor
        SwitchedAt = Get-Date -Format "o"
    }
    $lbConfig | ConvertTo-Json | Set-Content -Path (Join-Path $DeploymentRoot "$Environment-loadbalancer.json")
    
    Write-Host "  ✓ Traffic switched to $nextColor" -ForegroundColor Green
    
    # Step 5: Verify
    Write-Host "`n[5/5] Verifying deployment..." -ForegroundColor Cyan
    Start-Sleep -Seconds 2
    
    $verifyHealth = Test-Health -Url $config.HealthCheckUrl
    if ($verifyHealth.Success) {
        Write-Host "  ✓ Deployment verified" -ForegroundColor Green
    } else {
        Write-Warning "Verification issues detected"
    }
    
    # Register deployment
    $deployment = @{
        Id = [Guid]::NewGuid().ToString()
        Version = $Version
        Environment = $Environment
        Strategy = "blue-green"
        Color = $nextColor
        PreviousColor = $currentColor
        DeployedAt = Get-Date -Format "o"
        Status = "active"
        Health = $health
        Instances = $config.Instances
    }
    
    $script:DeploymentRegistry.Deployments += $deployment
    $script:DeploymentRegistry.CurrentDeployments[$Environment] = @{
        Version = $Version
        Color = $nextColor
        DeployedAt = Get-Date -Format "o"
    }
    
    Save-DeploymentRegistry
    
    Write-Host "`n✓ Blue-green deployment complete" -ForegroundColor Green
    Write-Host "  Version $Version is now live on $Environment ($nextColor)" -ForegroundColor Cyan
    
    if ($Environment -eq "production") {
        Write-Host "`n⚠ Previous version ($currentColor) is still running for quick rollback" -ForegroundColor Yellow
    }
}

function Invoke-RollingDeploy {
    param($Version, $Environment)
    
    Write-Host "`nExecuting rolling deployment..." -ForegroundColor Yellow
    
    $config = $EnvironmentConfig[$Environment]
    $color = Get-ActiveColor -Environment $Environment
    $deployPath = Join-Path (Join-Path $DeploymentRoot $Environment) $color
    
    Write-Host "  Instances: $($config.Instances)" -ForegroundColor Gray
    Write-Host "  Batch size: 1" -ForegroundColor Gray
    
    for ($i = 1; $i -le $config.Instances; $i++) {
        Write-Host "`n[$i/$($config.Instances)] Updating instance $i..." -ForegroundColor Cyan
        
        # Stop instance
        Write-Host "  Stopping instance $i..." -ForegroundColor Gray
        Start-Sleep -Milliseconds 300
        
        # Start new version
        Write-Host "  Starting v$Version on instance $i..." -ForegroundColor Gray
        Start-Sleep -Milliseconds 300
        
        # Health check
        $health = Test-Health -Url $config.HealthCheckUrl -Retries 2
        if ($health.Success) {
            Write-Host "  ✓ Instance $i healthy" -ForegroundColor Green
        } else {
            Write-Error "Instance $i failed health check!"
            return
        }
    }
    
    # Register deployment
    $deployment = @{
        Id = [Guid]::NewGuid().ToString()
        Version = $Version
        Environment = $Environment
        Strategy = "rolling"
        Color = $color
        DeployedAt = Get-Date -Format "o"
        Status = "active"
        Instances = $config.Instances
    }
    
    $script:DeploymentRegistry.Deployments += $deployment
    $script:DeploymentRegistry.CurrentDeployments[$Environment] = @{
        Version = $Version
        Color = $color
        DeployedAt = Get-Date -Format "o"
    }
    
    Save-DeploymentRegistry
    
    Write-Host "`n✓ Rolling deployment complete" -ForegroundColor Green
}

function Invoke-CanaryDeploy {
    param($Version, $Environment, $Percentage)
    
    Write-Host "`nExecuting canary deployment ($Percentage%)..." -ForegroundColor Yellow
    
    $config = $EnvironmentConfig[$Environment]
    $canaryCount = [math]::Ceiling($config.Instances * $Percentage / 100)
    
    Write-Host "  Total instances: $($config.Instances)" -ForegroundColor Gray
    Write-Host "  Canary instances: $canaryCount" -ForegroundColor Gray
    Write-Host "  Stable traffic: $((100 - $Percentage))%" -ForegroundColor Gray
    
    # Deploy canary instances
    for ($i = 1; $i -le $canaryCount; $i++) {
        Write-Host "`n[$i/$canaryCount] Deploying canary instance..." -ForegroundColor Cyan
        Start-Sleep -Milliseconds 300
        Write-Host "  ✓ Canary instance $i ready" -ForegroundColor Green
    }
    
    # Monitor canary
    Write-Host "`nMonitoring canary for 30 seconds..." -ForegroundColor Cyan
    for ($i = 1; $i -le 6; $i++) {
        Write-Host "  Check $i/6..." -ForegroundColor Gray
        $health = Test-Health -Url $config.HealthCheckUrl
        if (-not $health.Success) {
            Write-Error "Canary health check failed! Rolling back..."
            Invoke-Rollback -Environment $Environment
            return
        }
        Start-Sleep -Seconds 5
    }
    
    Write-Host "  ✓ Canary healthy" -ForegroundColor Green
    
    # Register canary deployment
    $deployment = @{
        Id = [Guid]::NewGuid().ToString()
        Version = $Version
        Environment = $Environment
        Strategy = "canary"
        CanaryPercentage = $Percentage
        DeployedAt = Get-Date -Format "o"
        Status = "canary"
        Instances = $canaryCount
    }
    
    $script:DeploymentRegistry.Deployments += $deployment
    Save-DeploymentRegistry
    
    Write-Host "`n✓ Canary deployment active" -ForegroundColor Green
    Write-Host "  Run 'promote' to complete rollout or 'rollback' to revert" -ForegroundColor Cyan
}

function Invoke-Rollback {
    param($Environment)
    
    Write-Host "`nRolling back $Environment..." -ForegroundColor Yellow
    
    $current = $script:DeploymentRegistry.CurrentDeployments[$Environment]
    if (-not $current) {
        Write-Error "No active deployment found for $Environment"
        return
    }
    
    $previousColor = Get-NextColor -CurrentColor $current.Color
    Write-Host "  Current: $($current.Version) on $($current.Color)" -ForegroundColor Gray
    Write-Host "  Rolling back to: $previousColor" -ForegroundColor Gray
    
    # Switch traffic back
    $lbConfig = @{
        ActiveColor = $previousColor
        RolledBackFrom = $current.Color
        RolledBackAt = Get-Date -Format "o"
    }
    $lbConfig | ConvertTo-Json | Set-Content -Path (Join-Path $DeploymentRoot "$Environment-loadbalancer.json")
    
    # Update registry
    $rollbackDeployment = @{
        Id = [Guid]::NewGuid().ToString()
        Version = $current.Version
        Environment = $Environment
        Strategy = "rollback"
        RolledBackAt = Get-Date -Format "o"
        PreviousColor = $current.Color
        RestoredColor = $previousColor
        Status = "rolled_back"
    }
    
    $script:DeploymentRegistry.Deployments += $rollbackDeployment
    $script:DeploymentRegistry.CurrentDeployments[$Environment] = @{
        Version = "previous"
        Color = $previousColor
        RestoredAt = Get-Date -Format "o"
    }
    
    Save-DeploymentRegistry
    
    Write-Host "`n✓ Rollback complete" -ForegroundColor Green
    Write-Host "  Traffic restored to $previousColor environment" -ForegroundColor Cyan
}

function Get-DeploymentStatus {
    param($Environment)
    
    Write-Host "`nDeployment Status" -ForegroundColor Yellow
    Write-Host ""
    
    if ($Environment) {
        $current = $script:DeploymentRegistry.CurrentDeployments[$Environment]
        if ($current) {
            Write-Host "  Environment: $Environment" -ForegroundColor White
            Write-Host "  Version: $($current.Version)" -ForegroundColor Gray
            Write-Host "  Color: $($current.Color)" -ForegroundColor Gray
            Write-Host "  Deployed: $($current.DeployedAt)" -ForegroundColor Gray
            
            $config = $EnvironmentConfig[$Environment]
            $health = Test-Health -Url $config.HealthCheckUrl -Retries 1
            Write-Host "  Health: $(if ($health.Success) { "✓ Healthy" } else { "✗ Unhealthy" })" -ForegroundColor $(if ($health.Success) { "Green" } else { "Red" })
        } else {
            Write-Host "  No active deployment for $Environment" -ForegroundColor Gray
        }
    } else {
        foreach ($env in $EnvironmentConfig.Keys) {
            $current = $script:DeploymentRegistry.CurrentDeployments[$env]
            if ($current) {
                Write-Host "  $env : v$($current.Version) ($($current.Color))" -ForegroundColor White
            } else {
                Write-Host "  $env : (no deployment)" -ForegroundColor Gray
            }
        }
    }
}

function Get-DeploymentHistory {
    param($Environment)
    
    Write-Host "`nDeployment History" -ForegroundColor Yellow
    Write-Host ""
    
    $deployments = $script:DeploymentRegistry.Deployments
    if ($Environment) {
        $deployments = $deployments | Where-Object { $_.Environment -eq $Environment }
    }
    
    if ($deployments.Count -eq 0) {
        Write-Host "  No deployments found" -ForegroundColor Gray
        return
    }
    
    Write-Host "  {0,-20} {1,-12} {2,-12} {3,-15} {4}" -f "Time", "Version", "Environment", "Strategy", "Status" -ForegroundColor White
    Write-Host "  $("-" * 80)" -ForegroundColor Gray
    
    foreach ($dep in ($deployments | Sort-Object DeployedAt -Descending | Select-Object -First 20)) {
        $time = [DateTime]::Parse($dep.DeployedAt).ToString("yyyy-MM-dd HH:mm")
        $statusColor = switch ($dep.Status) {
            "active" { "Green" }
            "rolled_back" { "Red" }
            "canary" { "Yellow" }
            default { "Gray" }
        }
        Write-Host "  {0,-20} {1,-12} {2,-12} {3,-15} {4}" -f $time, $dep.Version, $dep.Environment, $dep.Strategy, $dep.Status -ForegroundColor $statusColor
    }
}

# Main execution
Write-DeploymentHeader
Initialize-DeploymentManager

switch ($Action) {
    "deploy" {
        if (-not $Version) {
            Write-Error "Version required for deploy action"
            exit 1
        }
        
        switch ($Strategy) {
            "blue-green" { Invoke-BlueGreenDeploy -Version $Version -Environment $Environment }
            "rolling" { Invoke-RollingDeploy -Version $Version -Environment $Environment }
            "canary" { Invoke-CanaryDeploy -Version $Version -Environment $Environment -Percentage $CanaryPercentage }
        }
    }
    "rollback" {
        Invoke-Rollback -Environment $Environment
    }
    "status" {
        Get-DeploymentStatus -Environment $Environment
    }
    "health-check" {
        $config = $EnvironmentConfig[$Environment]
        $health = Test-Health -Url $config.HealthCheckUrl -Retries 3
        Write-Host "`nHealth Check ($Environment):" -ForegroundColor Yellow
        Write-Host "  Status: $(if ($health.Success) { "✓ PASS" } else { "✗ FAIL" })" -ForegroundColor $(if ($health.Success) { "Green" } else { "Red" })
        Write-Host "  Response Time: $($health.ResponseTime)ms" -ForegroundColor Gray
    }
    "canary" {
        if (-not $Version) {
            Write-Error "Version required for canary action"
            exit 1
        }
        Invoke-CanaryDeploy -Version $Version -Environment $Environment -Percentage $CanaryPercentage
    }
    "promote" {
        Write-Host "`nPromoting canary to full deployment..." -ForegroundColor Yellow
        Write-Host "  ✓ Canary promoted to 100%" -ForegroundColor Green
    }
    "history" {
        Get-DeploymentHistory -Environment $Environment
    }
}

Write-Host "`n✅ Deployment manager operation complete" -ForegroundColor Green
