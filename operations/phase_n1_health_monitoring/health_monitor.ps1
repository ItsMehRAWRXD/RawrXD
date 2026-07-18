#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Phase N.1: Health Monitoring System
    
.DESCRIPTION
    Comprehensive health monitoring for RawrXD SaaS platform.
    Monitors inference engine, tenant resources, and infrastructure.
    
.PARAMETER Action
    Action to perform: check, watch, report, export
    
.PARAMETER Component
    Component to monitor: all, engine, tenants, infrastructure
    
.PARAMETER Interval
    Watch interval in seconds (default: 30)
    
.EXAMPLE
    .\health_monitor.ps1 -Action check -Component all
    .\health_monitor.ps1 -Action watch -Interval 30
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("check", "watch", "report", "export")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("all", "engine", "tenants", "infrastructure")]
    [string]$Component = "all",
    
    [Parameter(Mandatory=$false)]
    [int]$Interval = 30,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\health_data"
)

$ErrorActionPreference = "Stop"

# Health thresholds
$Thresholds = @{
    Engine = @{
        CpuPercent = 80
        MemoryPercent = 85
        GpuPercent = 90
        LatencyMs = 500
        ErrorRate = 0.01
    }
    Tenant = @{
        MaxQuotaUsage = 90
        MaxResponseTime = 2000
    }
    Infrastructure = @{
        DiskPercent = 85
        NetworkLatencyMs = 100
    }
}

# Health status cache
$HealthCache = @{
    LastCheck = $null
    Components = @{}
    History = @()
}

function Write-HealthHeader {
    Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase N.1: Health Monitoring System                               ║
║  Real-time health checks for RawrXD SaaS platform                  ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Initialize-HealthData {
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    $cacheFile = Join-Path $OutputPath "health_cache.json"
    if (Test-Path $cacheFile) {
        $script:HealthCache = Get-Content -Path $cacheFile -Raw | ConvertFrom-Json -AsHashtable
    }
}

function Save-HealthData {
    $cacheFile = Join-Path $OutputPath "health_cache.json"
    $script:HealthCache.LastCheck = Get-Date -Format "o"
    $script:HealthCache | ConvertTo-Json -Depth 10 | Set-Content -Path $cacheFile
}

function Test-EngineHealth {
    Write-Host "`nChecking Inference Engine..." -ForegroundColor Yellow
    
    $health = @{
        Component = "engine"
        Status = "healthy"
        Checks = @{}
        Timestamp = Get-Date -Format "o"
    }
    
    # Check if RawrXD process is running
    $process = Get-Process -Name "RawrXD*" -ErrorAction SilentlyContinue | Select-Object -First 1
    $health.Checks.ProcessRunning = @{
        Pass = ($null -ne $process)
        Value = if ($process) { "Running (PID: $($process.Id))" } else { "Not found" }
    }
    
    # Check CPU usage
    if ($process) {
        Start-Sleep -Milliseconds 500
        $cpu = $process.CPU
        $health.Checks.CpuUsage = @{
            Pass = ($cpu -lt $Thresholds.Engine.CpuPercent)
            Value = [math]::Round($cpu, 2)
            Threshold = $Thresholds.Engine.CpuPercent
        }
        
        # Check memory usage
        $memoryMB = [math]::Round($process.WorkingSet64 / 1MB, 2)
        $health.Checks.MemoryUsage = @{
            Pass = ($memoryMB -lt 8192)  # 8GB threshold
            Value = "$memoryMB MB"
            Threshold = "8192 MB"
        }
    }
    
    # Check API endpoint (if available)
    try {
        $response = Invoke-RestMethod -Uri "http://localhost:8080/health" -TimeoutSec 5 -ErrorAction SilentlyContinue
        $health.Checks.ApiResponse = @{
            Pass = $true
            Value = "OK"
            Latency = 0
        }
    } catch {
        $health.Checks.ApiResponse = @{
            Pass = $false
            Value = "Unavailable"
            Latency = -1
        }
    }
    
    # Determine overall status
    $failedChecks = $health.Checks.Values | Where-Object { -not $_.Pass }
    if ($failedChecks.Count -gt 0) {
        $health.Status = if ($failedChecks.Count -gt 1) { "critical" } else { "degraded" }
    }
    
    # Display results
    foreach ($check in $health.Checks.GetEnumerator()) {
        $symbol = if ($check.Value.Pass) { "✓" } else { "✗" }
        $color = if ($check.Value.Pass) { "Green" } else { "Red" }
        Write-Host "  $symbol $($check.Key): $($check.Value.Value)" -ForegroundColor $color
    }
    
    $statusColor = switch ($health.Status) {
        "healthy" { "Green" }
        "degraded" { "Yellow" }
        "critical" { "Red" }
    }
    Write-Host "  Status: $($health.Status.ToUpper())" -ForegroundColor $statusColor
    
    return $health
}

function Test-TenantHealth {
    Write-Host "`nChecking Tenant Resources..." -ForegroundColor Yellow
    
    $health = @{
        Component = "tenants"
        Status = "healthy"
        Checks = @{}
        Tenants = @()
        Timestamp = Get-Date -Format "o"
    }
    
    # Load tenant registry
    $tenantRegistryPath = "..\saas\phase_m1_tenant_isolation\tenants\tenant_registry.json"
    if (Test-Path $tenantRegistryPath) {
        $tenants = Get-Content -Path $tenantRegistryPath -Raw | ConvertFrom-Json -AsHashtable
        
        foreach ($tenant in $tenants.Tenants.Values) {
            $tenantHealth = @{
                Id = $tenant.Id
                Status = $tenant.Status
                QuotaUsage = @{
                    Tokens = $tenant.Usage.TokensThisMonth
                    Storage = $tenant.Usage.StorageUsedGB
                }
            }
            
            # Check quota usage
            $tokenPercent = ($tenant.Usage.TokensThisMonth / $tenant.Quota.MaxTokensPerMinute) * 100
            $tenantHealth.QuotaUsage.TokenPercent = [math]::Round($tokenPercent, 2)
            
            $health.Tenants += $tenantHealth
        }
        
        $health.Checks.TenantCount = @{
            Pass = $true
            Value = $tenants.Tenants.Count
        }
        
        # Check for tenants near quota
        $nearQuota = $health.Tenants | Where-Object { $_.QuotaUsage.TokenPercent -gt $Thresholds.Tenant.MaxQuotaUsage }
        $health.Checks.QuotaBreaches = @{
            Pass = ($nearQuota.Count -eq 0)
            Value = "$($nearQuota.Count) tenants near quota"
        }
    } else {
        $health.Checks.TenantRegistry = @{
            Pass = $false
            Value = "Not found"
        }
        $health.Status = "degraded"
    }
    
    # Display results
    foreach ($check in $health.Checks.GetEnumerator()) {
        $symbol = if ($check.Value.Pass) { "✓" } else { "✗" }
        $color = if ($check.Value.Pass) { "Green" } else { "Red" }
        Write-Host "  $symbol $($check.Key): $($check.Value.Value)" -ForegroundColor $color
    }
    
    if ($health.Tenants.Count -gt 0) {
        Write-Host "  Active tenants: $($health.Tenants.Count)" -ForegroundColor Gray
    }
    
    return $health
}

function Test-InfrastructureHealth {
    Write-Host "`nChecking Infrastructure..." -ForegroundColor Yellow
    
    $health = @{
        Component = "infrastructure"
        Status = "healthy"
        Checks = @{}
        Timestamp = Get-Date -Format "o"
    }
    
    # Check disk space
    $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"
    $freePercent = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 2)
    $usedPercent = 100 - $freePercent
    
    $health.Checks.DiskSpace = @{
        Pass = ($usedPercent -lt $Thresholds.Infrastructure.DiskPercent)
        Value = "$usedPercent% used"
        Threshold = "$($Thresholds.Infrastructure.DiskPercent)%"
    }
    
    # Check memory
    $memory = Get-CimInstance -ClassName Win32_OperatingSystem
    $memoryUsed = [math]::Round((($memory.TotalVisibleMemorySize - $memory.FreePhysicalMemory) / $memory.TotalVisibleMemorySize) * 100, 2)
    
    $health.Checks.SystemMemory = @{
        Pass = ($memoryUsed -lt 90)
        Value = "$memoryUsed% used"
        Threshold = "90%"
    }
    
    # Check network connectivity
    $pingResult = Test-Connection -ComputerName "8.8.8.8" -Count 1 -ErrorAction SilentlyContinue
    $health.Checks.Network = @{
        Pass = ($null -ne $pingResult)
        Value = if ($pingResult) { "$($pingResult.ResponseTime)ms" } else { "Unreachable" }
        Threshold = "$($Thresholds.Infrastructure.NetworkLatencyMs)ms"
    }
    
    # Determine status
    $failedChecks = $health.Checks.Values | Where-Object { -not $_.Pass }
    if ($failedChecks.Count -gt 0) {
        $health.Status = if ($failedChecks.Count -gt 1) { "critical" } else { "degraded" }
    }
    
    # Display results
    foreach ($check in $health.Checks.GetEnumerator()) {
        $symbol = if ($check.Value.Pass) { "✓" } else { "✗" }
        $color = if ($check.Value.Pass) { "Green" } else { "Red" }
        Write-Host "  $symbol $($check.Key): $($check.Value.Value)" -ForegroundColor $color
    }
    
    return $health
}

function Start-HealthWatch {
    param($Interval)
    
    Write-Host "`nStarting health watch (interval: ${Interval}s, press Ctrl+C to stop)..." -ForegroundColor Cyan
    Write-Host ""
    
    try {
        while ($true) {
            Clear-Host
            Write-HealthHeader
            
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Write-Host "Last update: $timestamp`n" -ForegroundColor Gray
            
            $engineHealth = Test-EngineHealth
            $tenantHealth = Test-TenantHealth
            $infraHealth = Test-InfrastructureHealth
            
            # Update cache
            $script:HealthCache.Components["engine"] = $engineHealth
            $script:HealthCache.Components["tenants"] = $tenantHealth
            $script:HealthCache.Components["infrastructure"] = $infraHealth
            $script:HealthCache.History += @{
                Timestamp = $timestamp
                Engine = $engineHealth.Status
                Tenants = $tenantHealth.Status
                Infrastructure = $infraHealth.Status
            }
            
            # Keep only last 100 entries
            if ($script:HealthCache.History.Count -gt 100) {
                $script:HealthCache.History = $script:HealthCache.History[-100..-1]
            }
            
            Save-HealthData
            
            Write-Host "`n$("─" * 60)" -ForegroundColor Gray
            Write-Host "Next check in $Interval seconds..." -ForegroundColor Gray
            
            Start-Sleep -Seconds $Interval
        }
    } catch {
        Write-Host "`nHealth watch stopped." -ForegroundColor Yellow
    }
}

function Export-HealthReport {
    $report = @{
        GeneratedAt = Get-Date -Format "o"
        Components = $script:HealthCache.Components
        Summary = @{
            TotalChecks = 0
            PassedChecks = 0
            FailedChecks = 0
            OverallStatus = "healthy"
        }
    }
    
    # Calculate summary
    foreach ($component in $script:HealthCache.Components.Values) {
        foreach ($check in $component.Checks.Values) {
            $report.Summary.TotalChecks++
            if ($check.Pass) {
                $report.Summary.PassedChecks++
            } else {
                $report.Summary.FailedChecks++
            }
        }
        
        if ($component.Status -eq "critical") {
            $report.Summary.OverallStatus = "critical"
        } elseif ($component.Status -eq "degraded" -and $report.Summary.OverallStatus -eq "healthy") {
            $report.Summary.OverallStatus = "degraded"
        }
    }
    
    $reportFile = Join-Path $OutputPath "health_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $report | ConvertTo-Json -Depth 10 | Set-Content -Path $reportFile
    
    Write-Host "`nHealth report exported to: $reportFile" -ForegroundColor Green
    Write-Host "Overall status: $($report.Summary.OverallStatus.ToUpper())" -ForegroundColor $(
        if ($report.Summary.OverallStatus -eq "healthy") { "Green" } 
        elseif ($report.Summary.OverallStatus -eq "degraded") { "Yellow" } 
        else { "Red" }
    )
    Write-Host "Checks: $($report.Summary.PassedChecks)/$($report.Summary.TotalChecks) passed" -ForegroundColor Gray
}

# Main execution
Write-HealthHeader
Initialize-HealthData

switch ($Action) {
    "check" {
        if ($Component -eq "all" -or $Component -eq "engine") {
            Test-EngineHealth | Out-Null
        }
        if ($Component -eq "all" -or $Component -eq "tenants") {
            Test-TenantHealth | Out-Null
        }
        if ($Component -eq "all" -or $Component -eq "infrastructure") {
            Test-InfrastructureHealth | Out-Null
        }
        Save-HealthData
    }
    "watch" {
        Start-HealthWatch -Interval $Interval
    }
    "report" {
        if ($script:HealthCache.Components.Count -eq 0) {
            # Run checks first
            Test-EngineHealth | Out-Null
            Test-TenantHealth | Out-Null
            Test-InfrastructureHealth | Out-Null
        }
        Export-HealthReport
    }
    "export" {
        Export-HealthReport
    }
}

Write-Host "`n✅ Health monitoring operation complete" -ForegroundColor Green
