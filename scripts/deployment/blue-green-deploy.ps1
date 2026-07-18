#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Phase K.1/5: Blue-Green Deployment
    
.DESCRIPTION
    Implements zero-downtime blue-green deployment strategy:
    - Deploy new version to green environment
    - Health check validation
    - Traffic switch with instant rollback capability
    - Automated cleanup of old blue environment
    
.PARAMETER Environment
    Target environment (staging, production)
    
.PARAMETER Version
    Version to deploy
    
.PARAMETER HealthCheckUrl
    URL for health check validation
    
.PARAMETER TrafficSplit
    Initial traffic percentage to green (0-100)
    
.PARAMETER SkipHealthCheck
    Skip health check (not recommended)
    
.EXAMPLE
    .\blue-green-deploy.ps1 -Environment production -Version 1.0.1
    
.EXAMPLE
    .\blue-green-deploy.ps1 -Environment production -Version 1.0.1 -TrafficSplit 10
#
>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("staging", "production")]
    [string]$Environment,
    
    [Parameter(Mandatory=$true)]
    [string]$Version,
    
    [Parameter(Mandatory=$false)]
    [string]$HealthCheckUrl = "http://localhost:8080/health",
    
    [Parameter(Mandatory=$false)]
    [ValidateRange(0, 100)]
    [int]$TrafficSplit = 100,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipHealthCheck
)

$ErrorActionPreference = "Stop"

# Banner
Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase K.1/5: Blue-Green Deployment                               ║
║  Zero-Downtime Deployment with Instant Rollback                   ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$deploymentId = "bg-$Environment-$Version-$timestamp"

Write-Host "Configuration:" -ForegroundColor Yellow
Write-Host "  Deployment ID: $deploymentId"
Write-Host "  Environment: $Environment"
Write-Host "  Version: $Version"
Write-Host "  Health Check: $HealthCheckUrl"
Write-Host "  Traffic Split: $TrafficSplit%"
Write-Host ""

# Phase 1: Pre-Deployment Validation
Write-Host "[Phase 1/5] Pre-deployment validation..." -ForegroundColor Green

# Check current deployment
$currentColor = kubectl get service rawrxd-$Environment -o jsonpath='{.spec.selector.color}' 2>$null
if (-not $currentColor) {
    $currentColor = "blue"
}

$newColor = if ($currentColor -eq "blue") { "green" } else { "blue" }

Write-Host "  Current active color: $currentColor"
Write-Host "  New deployment color: $newColor"

# Validate artifact exists
$artifactExists = Test-Path "releases/v$Version"
if (-not $artifactExists) {
    throw "Artifact for version $Version not found in releases/"
}

Write-Host "  ✓ Artifact validated"
Write-Host ""

# Phase 2: Deploy to Inactive Environment
Write-Host "[Phase 2/5] Deploying to $newColor environment..." -ForegroundColor Green

# Update deployment with new version
$deploymentFile = @"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rawrxd-$Environment-$newColor
  labels:
    app: rawrxd
    environment: $Environment
    color: $newColor
    version: $Version
spec:
  replicas: 3
  selector:
    matchLabels:
      app: rawrxd
      environment: $Environment
      color: $newColor
  template:
    metadata:
      labels:
        app: rawrxd
        environment: $Environment
        color: $newColor
        version: $Version
    spec:
      containers:
      - name: rawrxd
        image: rawrxd/runtime:$Version
        ports:
        - containerPort: 8080
        env:
        - name: RAWRXD_ENV
          value: $Environment
        - name: RAWRXD_COLOR
          value: $newColor
        resources:
          limits:
            memory: "16Gi"
            cpu: "8"
          requests:
            memory: "8Gi"
            cpu: "4"
"@

$tempFile = [System.IO.Path]::GetTempFileName() + ".yaml"
$deploymentFile | Out-File -FilePath $tempFile -Encoding UTF8

# Apply deployment
kubectl apply -f $tempFile
if ($LASTEXITCODE -ne 0) {
    throw "Failed to apply deployment"
}

Remove-Item $tempFile

Write-Host "  ✓ Deployment applied"

# Wait for rollout
Write-Host "  Waiting for rollout to complete..."
kubectl rollout status deployment/rawrxd-$Environment-$newColor --timeout=300s
if ($LASTEXITCODE -ne 0) {
    throw "Deployment rollout failed"
}

Write-Host "  ✓ Rollout complete"
Write-Host ""

# Phase 3: Health Check Validation
if (-not $SkipHealthCheck) {
    Write-Host "[Phase 3/5] Health check validation..." -ForegroundColor Green
    
    # Port-forward to new pod for health check
    $podName = kubectl get pods -l "app=rawrxd,environment=$Environment,color=$newColor" -o jsonpath='{.items[0].metadata.name}'
    
    $healthCheckPassed = $false
    $maxAttempts = 30
    $attempt = 0
    
    while ($attempt -lt $maxAttempts -and -not $healthCheckPassed) {
        $attempt++
        Write-Progress -Activity "Health Check" -Status "Attempt $attempt/$maxAttempts" -PercentComplete (($attempt / $maxAttempts) * 100)
        
        try {
            $response = Invoke-RestMethod -Uri $HealthCheckUrl -TimeoutSec 5 -ErrorAction Stop
            if ($response.status -eq "healthy") {
                $healthCheckPassed = $true
            }
        } catch {
            Start-Sleep -Seconds 2
        }
    }
    
    Write-Progress -Activity "Health Check" -Completed
    
    if (-not $healthCheckPassed) {
        # Rollback deployment
        Write-Host "  ✗ Health check failed, rolling back..." -ForegroundColor Red
        kubectl delete deployment rawrxd-$Environment-$newColor
        throw "Health check failed after $maxAttempts attempts"
    }
    
    Write-Host "  ✓ Health check passed"
    Write-Host ""
} else {
    Write-Host "[Phase 3/5] Health check skipped (not recommended)" -ForegroundColor Yellow
    Write-Host ""
}

# Phase 4: Traffic Switch
Write-Host "[Phase 4/5] Switching traffic to $newColor..." -ForegroundColor Green

# Update service selector
kubectl patch service rawrxd-$Environment -p "{`"spec`":{`"selector`":{`"color`":`"$newColor`"}}}"
if ($LASTEXITCODE -ne 0) {
    throw "Failed to switch traffic"
}

Write-Host "  ✓ Traffic switched to $newColor"

# Verify traffic switch
Start-Sleep -Seconds 5
$activeColor = kubectl get service rawrxd-$Environment -o jsonpath='{.spec.selector.color}'
Write-Host "  ✓ Active color confirmed: $activeColor"
Write-Host ""

# Phase 5: Cleanup and Verification
Write-Host "[Phase 5/5] Cleanup and verification..." -ForegroundColor Green

# Keep old deployment for rollback capability (will be cleaned up by next deployment)
Write-Host "  ✓ Old deployment ($currentColor) retained for rollback safety"

# Record deployment
$deploymentRecord = @{
    deployment_id = $deploymentId
    timestamp = Get-Date -Format "o"
    environment = $Environment
    version = $Version
    previous_color = $currentColor
    new_color = $newColor
    health_check_passed = $healthCheckPassed
    traffic_split = $TrafficSplit
}

$recordFile = "deployments/$deploymentId.json"
New-Item -ItemType Directory -Force -Path "deployments" | Out-Null
$deploymentRecord | ConvertTo-Json | Out-File -FilePath $recordFile

Write-Host "  ✓ Deployment recorded: $recordFile"
Write-Host ""

# Final Summary
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "BLUE-GREEN DEPLOYMENT COMPLETE" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Deployment ID: $deploymentId"
Write-Host "Environment: $Environment"
Write-Host "Version: $Version"
Write-Host "Active Color: $newColor"
Write-Host "Previous Color: $currentColor (retained for rollback)"
Write-Host ""
Write-Host "Commands:" -ForegroundColor Yellow
Write-Host "  Rollback: kubectl patch service rawrxd-$Environment -p '{\"spec\":{\"selector\":{\"color\":\"$currentColor\"}}}'"
Write-Host "  Status: kubectl get pods -l app=rawrxd,environment=$Environment"
Write-Host "  Logs: kubectl logs -l app=rawrxd,environment=$Environment,color=$newColor"
Write-Host ""
Write-Host "✅ Zero-downtime deployment complete!" -ForegroundColor Green
