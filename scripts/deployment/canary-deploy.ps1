#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Phase K.2/5: Canary Deployment
    
.DESCRIPTION
    Implements progressive traffic shifting with automated rollback:
    - Start with small traffic percentage (5-10%)
    - Monitor error rates and latency
    - Gradually increase traffic if metrics healthy
    - Automatic rollback on error threshold breach
    
.PARAMETER Environment
    Target environment (staging, production)
    
.PARAMETER Version
    Version to deploy
    
.PARAMETER InitialTraffic
    Initial traffic percentage (default: 5)
    
.PARAMETER StepSize
    Traffic increase step size (default: 10)
    
.PARAMETER ErrorThreshold
    Error rate threshold for rollback (default: 1.0)
    
.PARAMETER LatencyThreshold
    P99 latency threshold in ms (default: 100)
    
.PARAMETER StepDuration
    Duration to hold each traffic step in seconds (default: 300)
    
.PARAMETER PrometheusUrl
    Prometheus URL for metrics (default: http://localhost:9090)
    
.EXAMPLE
    .\canary-deploy.ps1 -Environment production -Version 1.0.1
    
.EXAMPLE
    .\canary-deploy.ps1 -Environment production -Version 1.0.1 -InitialTraffic 10 -StepSize 20
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
    [ValidateRange(1, 100)]
    [int]$InitialTraffic = 5,
    
    [Parameter(Mandatory=$false)]
    [ValidateRange(1, 100)]
    [int]$StepSize = 10,
    
    [Parameter(Mandatory=$false)]
    [double]$ErrorThreshold = 1.0,
    
    [Parameter(Mandatory=$false)]
    [int]$LatencyThreshold = 100,
    
    [Parameter(Mandatory=$false)]
    [int]$StepDuration = 300,
    
    [Parameter(Mandatory=$false)]
    [string]$PrometheusUrl = "http://localhost:9090"
)

$ErrorActionPreference = "Stop"

# Banner
Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase K.2/5: Canary Deployment                                    ║
║  Progressive Traffic Shifting with Automated Rollback             ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$deploymentId = "canary-$Environment-$Version-$timestamp"

Write-Host "Configuration:" -ForegroundColor Yellow
Write-Host "  Deployment ID: $deploymentId"
Write-Host "  Environment: $Environment"
Write-Host "  Version: $Version"
Write-Host "  Initial Traffic: $InitialTraffic%"
Write-Host "  Step Size: $StepSize%"
Write-Host "  Error Threshold: $ErrorThreshold%"
    Write-Host "  Latency Threshold: $LatencyThreshold ms"
    Write-Host "  Step Duration: $StepDuration seconds"
    Write-Host ""

# Phase 1: Deploy Canary
Write-Host "[Phase 1/5] Deploying canary version..." -ForegroundColor Green

# Create canary deployment
$canaryDeployment = @"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rawrxd-$Environment-canary
  labels:
    app: rawrxd
    environment: $Environment
    track: canary
    version: $Version
spec:
  replicas: 1
  selector:
    matchLabels:
      app: rawrxd
      environment: $Environment
      track: canary
  template:
    metadata:
      labels:
        app: rawrxd
        environment: $Environment
        track: canary
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
        - name: RAWRXD_TRACK
          value: canary
        resources:
          limits:
            memory: "16Gi"
            cpu: "8"
          requests:
            memory: "8Gi"
            cpu: "4"
"@

$tempFile = [System.IO.Path]::GetTempFileName() + ".yaml"
$canaryDeployment | Out-File -FilePath $tempFile -Encoding UTF8

kubectl apply -f $tempFile
Remove-Item $tempFile

Write-Host "  ✓ Canary deployment created"

# Wait for canary to be ready
Write-Host "  Waiting for canary to be ready..."
kubectl rollout status deployment/rawrxd-$Environment-canary --timeout=300s
Write-Host "  ✓ Canary ready"
Write-Host ""

# Phase 2: Initial Traffic Split
Write-Host "[Phase 2/5] Setting initial traffic split ($InitialTraffic%)..." -ForegroundColor Green

# Create/update canary service with traffic split
$canaryService = @"
apiVersion: v1
kind: Service
metadata:
  name: rawrxd-$Environment-canary
  annotations:
    traefik.ingress.kubernetes.io/service.sticky.cookie: "true"
spec:
  selector:
    app: rawrxd
    environment: $Environment
    track: canary
  ports:
  - port: 8080
    targetPort: 8080
"@

$tempFile = [System.IO.Path]::GetTempFileName() + ".yaml"
$canaryService | Out-File -FilePath $tempFile -Encoding UTF8
kubectl apply -f $tempFile
Remove-Item $tempFile

# Update ingress with traffic split
$ingressPatch = @"
spec:
  rules:
  - http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: rawrxd-$Environment
            port:
              number: 8080
      - path: /
        pathType: Prefix
        backend:
          service:
            name: rawrxd-$Environment-canary
            port:
              number: 8080
"@

# Apply traffic split via ingress annotation
kubectl annotate ingress rawrxd-$Environment --overwrite "traefik.ingress.kubernetes.io/service.weights=rawrxd-$Environment:$((100-$InitialTraffic)),rawrxd-$Environment-canary:$InitialTraffic"

Write-Host "  ✓ Traffic split configured: Stable $((100-$InitialTraffic))%, Canary $InitialTraffic%"
Write-Host ""

# Phase 3: Progressive Rollout
Write-Host "[Phase 3/5] Progressive rollout..." -ForegroundColor Green

$currentTraffic = $InitialTraffic
$rolloutComplete = $false
$rollbackTriggered = $false

while ($currentTraffic -le 100 -and -not $rolloutComplete -and -not $rollbackTriggered) {
    Write-Host "  Current traffic: $currentTraffic% canary"
    
    # Monitor metrics
    $startTime = Get-Date
    $monitorDuration = $StepDuration
    $stepHealthy = $true
    
    Write-Host "  Monitoring for $monitorDuration seconds..."
    
    while (((Get-Date) - $startTime).TotalSeconds -lt $monitorDuration -and $stepHealthy) {
        $elapsed = [math]::Floor(((Get-Date) - $startTime).TotalSeconds)
        $remaining = $monitorDuration - $elapsed
        
        Write-Progress -Activity "Canary Monitoring" -Status "Traffic: $currentTraffic% | Remaining: $remaining s" -PercentComplete (($elapsed / $monitorDuration) * 100)
        
        # Query Prometheus for metrics
        try {
            # Error rate query
            $errorQuery = "sum(rate(rawrxd_requests_total{track=`"canary`",status=~`"5..`"}[1m])) / sum(rate(rawrxd_requests_total{track=`"canary`"}[1m])) * 100"
            $errorResponse = Invoke-RestMethod -Uri "$PrometheusUrl/api/v1/query?query=$([System.Web.HttpUtility]::UrlEncode($errorQuery))" -TimeoutSec 5
            $errorRate = if ($errorResponse.data.result.Count -gt 0) { [double]$errorResponse.data.result[0].value[1] } else { 0 }
            
            # Latency query
            $latencyQuery = "histogram_quantile(0.99, sum(rate(rawrxd_request_duration_seconds_bucket{track=`"canary`"}[1m])) by (le)) * 1000"
            $latencyResponse = Invoke-RestMethod -Uri "$PrometheusUrl/api/v1/query?query=$([System.Web.HttpUtility]::UrlEncode($latencyQuery))" -TimeoutSec 5
            $p99Latency = if ($latencyResponse.data.result.Count -gt 0) { [double]$latencyResponse.data.result[0].value[1] } else { 0 }
            
            # Check thresholds
            if ($errorRate -gt $ErrorThreshold) {
                Write-Host ""
                Write-Host "  ✗ ERROR THRESHOLD BREACHED: $([math]::Round($errorRate, 2))% > $ErrorThreshold%" -ForegroundColor Red
                $stepHealthy = $false
                $rollbackTriggered = $true
            }
            
            if ($p99Latency -gt $LatencyThreshold) {
                Write-Host ""
                Write-Host "  ✗ LATENCY THRESHOLD BREACHED: $([math]::Round($p99Latency, 2))ms > $LatencyThreshold ms" -ForegroundColor Red
                $stepHealthy = $false
                $rollbackTriggered = $true
            }
        } catch {
            Write-Host "  Warning: Could not query metrics - $_" -ForegroundColor Yellow
        }
        
        Start-Sleep -Seconds 5
    }
    
    Write-Progress -Activity "Canary Monitoring" -Completed
    
    if ($rollbackTriggered) {
        break
    }
    
    if ($stepHealthy) {
        Write-Host "  ✓ Step healthy, metrics within thresholds"
        
        # Increase traffic
        $currentTraffic += $StepSize
        if ($currentTraffic -ge 100) {
            $currentTraffic = 100
            $rolloutComplete = $true
        }
        
        # Update traffic split
        kubectl annotate ingress rawrxd-$Environment --overwrite "traefik.ingress.kubernetes.io/service.weights=rawrxd-$Environment:$((100-$currentTraffic)),rawrxd-$Environment-canary:$currentTraffic"
        Write-Host "  ✓ Traffic increased to $currentTraffic%"
    }
}

Write-Host ""

# Phase 4: Finalize or Rollback
if ($rollbackTriggered) {
    Write-Host "[Phase 4/5] ROLLBACK TRIGGERED" -ForegroundColor Red
    
    # Remove canary from traffic
    kubectl annotate ingress rawrxd-$Environment --overwrite "traefik.ingress.kubernetes.io/service.weights=rawrxd-$Environment:100,rawrxd-$Environment-canary:0"
    
    # Delete canary deployment
    kubectl delete deployment rawrxd-$Environment-canary --grace-period=30
    kubectl delete service rawrxd-$Environment-canary
    
    Write-Host "  ✓ Traffic reverted to stable"
    Write-Host "  ✓ Canary deployment removed"
    Write-Host ""
    
    throw "Canary deployment failed - automatic rollback completed"
} else {
    Write-Host "[Phase 4/5] Promoting canary to stable..." -ForegroundColor Green
    
    # Update stable deployment to canary version
    kubectl set image deployment/rawrxd-$Environment rawrxd=rawrxd/runtime:$Version
    kubectl rollout status deployment/rawrxd-$Environment --timeout=300s
    
    # Remove canary from traffic
    kubectl annotate ingress rawrxd-$Environment --overwrite "traefik.ingress.kubernetes.io/service.weights=rawrxd-$Environment:100,rawrxd-$Environment-canary:0"
    
    # Delete canary resources
    kubectl delete deployment rawrxd-$Environment-canary --grace-period=30
    kubectl delete service rawrxd-$Environment-canary
    
    Write-Host "  ✓ Stable deployment updated to $Version"
    Write-Host "  ✓ Canary resources cleaned up"
    Write-Host ""
}

# Phase 5: Verification
Write-Host "[Phase 5/5] Final verification..." -ForegroundColor Green

# Verify stable deployment
$stablePods = kubectl get pods -l "app=rawrxd,environment=$Environment,track!=canary" -o json | ConvertFrom-Json
$readyPods = ($stablePods.items | Where-Object { 
    $_.status.conditions | Where-Object { $_.type -eq "Ready" -and $_.status -eq "True" }
}).Count

Write-Host "  Ready pods: $readyPods"

# Record deployment
$deploymentRecord = @{
    deployment_id = $deploymentId
    timestamp = Get-Date -Format "o"
    environment = $Environment
    version = $Version
    initial_traffic = $InitialTraffic
    step_size = $StepSize
    final_traffic = $currentTraffic
    rollback_triggered = $rollbackTriggered
    error_threshold = $ErrorThreshold
    latency_threshold = $LatencyThreshold
}

$recordFile = "deployments/$deploymentId.json"
New-Item -ItemType Directory -Force -Path "deployments" | Out-Null
$deploymentRecord | ConvertTo-Json | Out-File -FilePath $recordFile

Write-Host "  ✓ Deployment recorded: $recordFile"
Write-Host ""

# Final Summary
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
if ($rollbackTriggered) {
    Write-Host "CANARY DEPLOYMENT ROLLED BACK" -ForegroundColor Red
} else {
    Write-Host "CANARY DEPLOYMENT COMPLETE" -ForegroundColor Green
}
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Deployment ID: $deploymentId"
Write-Host "Environment: $Environment"
Write-Host "Version: $Version"
Write-Host "Final Traffic: $currentTraffic%"
Write-Host "Rollback Triggered: $rollbackTriggered"
Write-Host ""
Write-Host "✅ Canary deployment process complete!" -ForegroundColor Green
