#Requires -Version 7.0
<#
.SYNOPSIS
    Metrics Collector for RawrXD Hotpatch System

.DESCRIPTION
    Collects and exports hotpatch metrics to various backends (Prometheus, InfluxDB, CloudWatch).

.PARAMETER Backend
    Metrics backend: prometheus, influxdb, cloudwatch, file (default: prometheus)

.PARAMETER Interval
    Collection interval in seconds (default: 60)

.PARAMETER OutputPath
    Output path for file backend

.EXAMPLE
    .\metrics_collector.ps1 -Backend prometheus -Interval 30
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("prometheus", "influxdb", "cloudwatch", "file")]
    [string]$Backend = "prometheus",

    [Parameter(Mandatory = $false)]
    [int]$Interval = 60,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$env:RAWRXD_HOME\logs\hotpatch_metrics.json",

    [Parameter(Mandatory = $false)]
    [string]$RegistryPath = "$env:RAWRXD_HOME\security\phase_g1_hotpatch\registry\registry.json"
)

# Metrics data structure
$script:MetricsData = @{
    Timestamp = $null
    Patches = @{
        Total = 0
        Active = 0
        Failed = 0
        RolledBack = 0
        BySystem = @{}
        ByType = @{}
        BySeverity = @{}
    }
    Performance = @{
        AvgApplyTime = 0
        AvgRollbackTime = 0
        SuccessRate = 0
    }
    Health = @{
        Swarm = 1
        Agent = 1
        Tools = 1
    }
}

# Collect metrics from registry
function Collect-Metrics {
    $script:MetricsData.Timestamp = Get-Date -Format "o"

    if (-not (Test-Path $RegistryPath)) {
        Write-Warning "Registry not found at $RegistryPath"
        return
    }

    try {
        $registry = Get-Content $RegistryPath -Raw | ConvertFrom-Json

        # Patch counts
        $script:MetricsData.Patches.Total = $registry.Patches.Count
        $script:MetricsData.Patches.Active = ($registry.Patches | Where-Object { $_.Status -eq 'active' }).Count
        $script:MetricsData.Patches.Failed = ($registry.Patches | Where-Object { $_.Status -eq 'failed' }).Count
        $script:MetricsData.Patches.RolledBack = ($registry.Patches | Where-Object { $_.Status -eq 'rolled-back' }).Count

        # By system
        $script:MetricsData.Patches.BySystem = @{}
        foreach ($patch in $registry.Patches) {
            foreach ($system in $patch.Systems) {
                if (-not $script:MetricsData.Patches.BySystem[$system]) {
                    $script:MetricsData.Patches.BySystem[$system] = 0
                }
                $script:MetricsData.Patches.BySystem[$system]++
            }
        }

        # By type
        $byType = $registry.Patches | Group-Object Type
        $script:MetricsData.Patches.ByType = @{}
        foreach ($group in $byType) {
            $script:MetricsData.Patches.ByType[$group.Name] = $group.Count
        }

        # By severity
        $bySeverity = $registry.Patches | Group-Object Severity
        $script:MetricsData.Patches.BySeverity = @{}
        foreach ($group in $bySeverity) {
            $script:MetricsData.Patches.BySeverity[$group.Name] = $group.Count
        }

        # Calculate success rate
        $applied = ($registry.Patches.History | Where-Object { $_.Action -eq 'applied' }).Count
        $failed = ($registry.Patches.History | Where-Object { $_.Action -eq 'failed' }).Count
        $total = $applied + $failed
        $script:MetricsData.Performance.SuccessRate = if ($total -gt 0) { $applied / $total } else { 1.0 }

        # Calculate average times (from history)
        $applyTimes = @()
        $rollbackTimes = @()
        foreach ($patch in $registry.Patches) {
            $applyEntry = $patch.History | Where-Object { $_.Action -eq 'applied' } | Select-Object -Last 1
            $rollbackEntry = $patch.History | Where-Object { $_.Action -eq 'rollback' } | Select-Object -Last 1

            if ($applyEntry -and $applyEntry.Details -match 'duration: (\d+)') {
                $applyTimes += [int]$matches[1]
            }
            if ($rollbackEntry -and $rollbackEntry.Details -match 'duration: (\d+)') {
                $rollbackTimes += [int]$matches[1]
            }
        }

        $script:MetricsData.Performance.AvgApplyTime = if ($applyTimes.Count -gt 0) { ($applyTimes | Measure-Object -Average).Average } else { 0 }
        $script:MetricsData.Performance.AvgRollbackTime = if ($rollbackTimes.Count -gt 0) { ($rollbackTimes | Measure-Object -Average).Average } else { 0 }

        # System health (placeholder - would query actual health)
        $script:MetricsData.Health.Swarm = 1
        $script:MetricsData.Health.Agent = 1
        $script:MetricsData.Health.Tools = 1

        Write-Verbose "Metrics collected successfully"
    }
    catch {
        Write-Error "Failed to collect metrics: $_"
    }
}

# Export to Prometheus format
function Export-Prometheus {
    $output = @()
    $timestamp = [DateTimeOffset]::Parse($script:MetricsData.Timestamp).ToUnixTimeSeconds()

    # Patch counts
    $output += "# HELP hotpatch_total_patches Total number of patches"
    $output += "# TYPE hotpatch_total_patches gauge"
    $output += "hotpatch_total_patches $($script:MetricsData.Patches.Total)"

    $output += "# HELP hotpatch_active_patches Number of active patches"
    $output += "# TYPE hotpatch_active_patches gauge"
    foreach ($system in $script:MetricsData.Patches.BySystem.Keys) {
        $count = ($script:MetricsData.Patches.BySystem[$system])
        $output += "hotpatch_active_patches{system=`"$system`"} $count"
    }

    $output += "# HELP hotpatch_failed_patches Total failed patches"
    $output += "# TYPE hotpatch_failed_patches counter"
    $output += "hotpatch_failed_patches $($script:MetricsData.Patches.Failed)"

    $output += "# HELP hotpatch_rollback_patches Total rolled back patches"
    $output += "# TYPE hotpatch_rollback_patches counter"
    $output += "hotpatch_rollback_patches $($script:MetricsData.Patches.RolledBack)"

    # Performance metrics
    $output += "# HELP hotpatch_success_rate Patch success rate"
    $output += "# TYPE hotpatch_success_rate gauge"
    $output += "hotpatch_success_rate $($script:MetricsData.Performance.SuccessRate)"

    $output += "# HELP hotpatch_avg_apply_time_seconds Average patch apply time"
    $output += "# TYPE hotpatch_avg_apply_time_seconds gauge"
    $output += "hotpatch_avg_apply_time_seconds $($script:MetricsData.Performance.AvgApplyTime)"

    # Health metrics
    $output += "# HELP hotpatch_system_health System health status"
    $output += "# TYPE hotpatch_system_health gauge"
    foreach ($system in $script:MetricsData.Health.Keys) {
        $output += "hotpatch_system_health{system=`"$system`"} $($script:MetricsData.Health[$system])"
    }

    return $output -join "`n"
}

# Export to InfluxDB line protocol
function Export-InfluxDB {
    $timestamp = [DateTimeOffset]::Parse($script:MetricsData.Timestamp).ToUnixTimeMilliseconds()
    $lines = @()

    # Patch metrics
    $lines += "hotpatch_patches,metric=total value=$($script:MetricsData.Patches.Total) $timestamp"
    $lines += "hotpatch_patches,metric=active value=$($script:MetricsData.Patches.Active) $timestamp"
    $lines += "hotpatch_patches,metric=failed value=$($script:MetricsData.Patches.Failed) $timestamp"
    $lines += "hotpatch_patches,metric=rolled_back value=$($script:MetricsData.Patches.RolledBack) $timestamp"

    # System breakdown
    foreach ($system in $script:MetricsData.Patches.BySystem.Keys) {
        $count = $script:MetricsData.Patches.BySystem[$system]
        $lines += "hotpatch_patches_by_system,system=$system value=$count $timestamp"
    }

    # Performance metrics
    $lines += "hotpatch_performance,metric=success_rate value=$($script:MetricsData.Performance.SuccessRate) $timestamp"
    $lines += "hotpatch_performance,metric=avg_apply_time value=$($script:MetricsData.Performance.AvgApplyTime) $timestamp"
    $lines += "hotpatch_performance,metric=avg_rollback_time value=$($script:MetricsData.Performance.AvgRollbackTime) $timestamp"

    # Health metrics
    foreach ($system in $script:MetricsData.Health.Keys) {
        $health = $script:MetricsData.Health[$system]
        $lines += "hotpatch_health,system=$system value=$health $timestamp"
    }

    return $lines -join "`n"
}

# Export to CloudWatch format
function Export-CloudWatch {
    $metrics = @()

    # Helper to create metric data
    function New-CloudWatchMetric {
        param($Namespace, $MetricName, $Value, $Unit, $Dimensions)

        $metric = @{
            Namespace = $Namespace
            MetricData = @(
                @{
                    MetricName = $MetricName
                    Value = $Value
                    Unit = $Unit
                    Timestamp = $script:MetricsData.Timestamp
                }
            )
        }

        if ($Dimensions) {
            $metric.MetricData[0].Dimensions = $Dimensions
        }

        return $metric
    }

    # Patch counts
    $metrics += New-CloudWatchMetric -Namespace "RawrXD/Hotpatch" -MetricName "TotalPatches" -Value $script:MetricsData.Patches.Total -Unit "Count"
    $metrics += New-CloudWatchMetric -Namespace "RawrXD/Hotpatch" -MetricName "ActivePatches" -Value $script:MetricsData.Patches.Active -Unit "Count"
    $metrics += New-CloudWatchMetric -Namespace "RawrXD/Hotpatch" -MetricName "FailedPatches" -Value $script:MetricsData.Patches.Failed -Unit "Count"

    # System-specific metrics
    foreach ($system in $script:MetricsData.Patches.BySystem.Keys) {
        $metrics += New-CloudWatchMetric -Namespace "RawrXD/Hotpatch" -MetricName "PatchesBySystem" -Value $script:MetricsData.Patches.BySystem[$system] -Unit "Count" -Dimensions @(@{Name = "System"; Value = $system})
    }

    # Performance metrics
    $metrics += New-CloudWatchMetric -Namespace "RawrXD/Hotpatch" -MetricName "SuccessRate" -Value $script:MetricsData.Performance.SuccessRate -Unit "Percent"
    $metrics += New-CloudWatchMetric -Namespace "RawrXD/Hotpatch" -MetricName "AvgApplyTime" -Value $script:MetricsData.Performance.AvgApplyTime -Unit "Seconds"

    return $metrics | ConvertTo-Json -Depth 10
}

# Export to file
function Export-File {
    $script:MetricsData | ConvertTo-Json -Depth 10 | Out-File $OutputPath -Encoding UTF8
    Write-Host "Metrics exported to: $OutputPath" -ForegroundColor Green
}

# Main collection loop
Write-Host "Starting metrics collector..." -ForegroundColor Cyan
Write-Host "Backend: $Backend" -ForegroundColor Gray
Write-Host "Interval: $Interval seconds" -ForegroundColor Gray
Write-Host "Press Ctrl+C to stop..." -ForegroundColor Gray
Write-Host ""

while ($true) {
    try {
        Collect-Metrics

        switch ($Backend) {
            "prometheus" {
                $metrics = Export-Prometheus
                Write-Output $metrics
            }
            "influxdb" {
                $metrics = Export-InfluxDB
                Write-Output $metrics
            }
            "cloudwatch" {
                $metrics = Export-CloudWatch
                Write-Output $metrics
            }
            "file" {
                Export-File
            }
        }

        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Metrics collected" -ForegroundColor Green
    }
    catch {
        Write-Error "Error collecting metrics: $_"
    }

    Start-Sleep -Seconds $Interval
}
