#Requires -Version 7.0
<#
.SYNOPSIS
    Prometheus Metrics Exporter for RawrXD Hotpatch System

.DESCRIPTION
    Exposes hotpatch metrics in Prometheus format for scraping.

.PARAMETER Port
    HTTP port to listen on (default: 9101)

.PARAMETER Endpoint
    Metrics endpoint path (default: /metrics)

.PARAMETER RegistryPath
    Path to patch registry JSON file

.EXAMPLE
    .\hotpatch_metrics_exporter.ps1 -Port 9101

    # Scrape from: http://localhost:9101/metrics
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$Port = 9101,

    [Parameter(Mandatory = $false)]
    [string]$Endpoint = "/metrics",

    [Parameter(Mandatory = $false)]
    [string]$RegistryPath = "$env:RAWRXD_HOME\security\phase_g1_hotpatch\registry\registry.json"
)

# Import required assemblies
Add-Type -AssemblyName System.Net.Http
Add-Type -AssemblyName System.Web

# Metrics storage
$script:Metrics = @{
    Counters = @{}
    Gauges = @{}
    Histograms = @{}
    Summaries = @{}
}

# Initialize metrics
function Initialize-Metrics {
    # Counter: Total patches applied
    $script:Metrics.Counters['hotpatch_applied_total'] = @{
        help = "Total number of patches applied"
        type = "counter"
        labels = @('system', 'type', 'severity')
        values = @{}
    }

    # Counter: Total patches failed
    $script:Metrics.Counters['hotpatch_failed_total'] = @{
        help = "Total number of patches that failed"
        type = "counter"
        labels = @('system', 'type', 'severity')
        values = @{}
    }

    # Counter: Total rollbacks
    $script:Metrics.Counters['hotpatch_rollback_total'] = @{
        help = "Total number of patch rollbacks"
        type = "counter"
        labels = @('system', 'reason')
        values = @{}
    }

    # Gauge: Active patches
    $script:Metrics.Gauges['hotpatch_active_patches'] = @{
        help = "Number of currently active patches"
        type = "gauge"
        labels = @('system')
        values = @{}
    }

    # Gauge: Patch registry size
    $script:Metrics.Gauges['hotpatch_registry_size'] = @{
        help = "Total number of patches in registry"
        type = "gauge"
        value = 0
    }

    # Gauge: System health
    $script:Metrics.Gauges['hotpatch_system_health'] = @{
        help = "System health status (1 = healthy, 0 = unhealthy)"
        type = "gauge"
        labels = @('system')
        values = @{}
    }

    # Histogram: Patch duration
    $script:Metrics.Histograms['hotpatch_duration_seconds'] = @{
        help = "Time spent applying patches"
        type = "histogram"
        labels = @('system', 'type')
        buckets = @(0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0)
        values = @{}
    }

    # Summary: Time to rollback
    $script:Metrics.Summaries['hotpatch_rollback_duration_seconds'] = @{
        help = "Time spent rolling back patches"
        type = "summary"
        labels = @('system')
        quantiles = @(0.5, 0.9, 0.99)
        values = @{}
    }
}

# Update metrics from registry
function Update-MetricsFromRegistry {
    if (-not (Test-Path $RegistryPath)) {
        return
    }

    try {
        $registry = Get-Content $RegistryPath -Raw | ConvertFrom-Json

        # Update active patches gauge
        $activeBySystem = $registry.Patches | Where-Object { $_.Status -eq 'active' } | Group-Object -Property { $_.Systems -join ',' }
        foreach ($group in $activeBySystem) {
            $key = "system=`"$($group.Name)`""
            $script:Metrics.Gauges['hotpatch_active_patches'].values[$key] = $group.Count
        }

        # Update registry size
        $script:Metrics.Gauges['hotpatch_registry_size'].value = $registry.Patches.Count

        # Update counters from history
        foreach ($patch in $registry.Patches) {
            foreach ($entry in $patch.History) {
                switch ($entry.Action) {
                    'applied' {
                        $key = "system=`"$($patch.Systems -join ',')`",type=`"$($patch.Type)`",severity=`"$($patch.Severity)`""
                        if (-not $script:Metrics.Counters['hotpatch_applied_total'].values[$key]) {
                            $script:Metrics.Counters['hotpatch_applied_total'].values[$key] = 0
                        }
                        $script:Metrics.Counters['hotpatch_applied_total'].values[$key]++
                    }
                    'failed' {
                        $key = "system=`"$($patch.Systems -join ',')`",type=`"$($patch.Type)`",severity=`"$($patch.Severity)`""
                        if (-not $script:Metrics.Counters['hotpatch_failed_total'].values[$key]) {
                            $script:Metrics.Counters['hotpatch_failed_total'].values[$key] = 0
                        }
                        $script:Metrics.Counters['hotpatch_failed_total'].values[$key]++
                    }
                    'rollback' {
                        $key = "system=`"$($patch.Systems -join ',')`",reason=`"$($entry.Details)`""
                        if (-not $script:Metrics.Counters['hotpatch_rollback_total'].values[$key]) {
                            $script:Metrics.Counters['hotpatch_rollback_total'].values[$key] = 0
                        }
                        $script:Metrics.Counters['hotpatch_rollback_total'].values[$key]++
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Failed to update metrics from registry: $_"
    }
}

# Format metrics for Prometheus
function Format-PrometheusMetrics {
    $output = @()

    # Add header
    $output += "# RawrXD Hotpatch Metrics"
    $output += "# Generated: $(Get-Date -Format 'o')"
    $output += ""

    # Format counters
    foreach ($counter in $script:Metrics.Counters.GetEnumerator()) {
        $output += "# HELP $($counter.Key) $($counter.Value.help)"
        $output += "# TYPE $($counter.Key) $($counter.Value.type)"

        if ($counter.Value.values.Count -eq 0) {
            $output += "$($counter.Key) 0"
        }
        else {
            foreach ($value in $counter.Value.values.GetEnumerator()) {
                $output += "$($counter.Key){$($value.Key)} $($value.Value)"
            }
        }
        $output += ""
    }

    # Format gauges
    foreach ($gauge in $script:Metrics.Gauges.GetEnumerator()) {
        $output += "# HELP $($gauge.Key) $($gauge.Value.help)"
        $output += "# TYPE $($gauge.Key) $($gauge.Value.type)"

        if ($gauge.Value.values.Count -gt 0) {
            foreach ($value in $gauge.Value.values.GetEnumerator()) {
                $output += "$($gauge.Key){$($value.Key)} $($value.Value)"
            }
        }
        else {
            $output += "$($gauge.Key) $($gauge.Value.value)"
        }
        $output += ""
    }

    # Format histograms
    foreach ($histogram in $script:Metrics.Histograms.GetEnumerator()) {
        $output += "# HELP $($histogram.Key) $($histogram.Value.help)"
        $output += "# TYPE $($histogram.Key) $($histogram.Value.type)"

        foreach ($value in $histogram.Value.values.GetEnumerator()) {
            $labels = $value.Key
            $bucketValues = $value.Value

            foreach ($bucket in $histogram.Value.buckets) {
                $bucketValue = ($bucketValues | Where-Object { $_ -le $bucket }).Count
                $output += "$($histogram.Key)_bucket{$labels,le=`"$bucket`"} $bucketValue"
            }
            $output += "$($histogram.Key)_bucket{$labels,le=`"+Inf`"} $($bucketValues.Count)"
            $output += "$($histogram.Key)_sum{$labels} $($bucketValues | Measure-Object -Sum | Select-Object -ExpandProperty Sum)"
            $output += "$($histogram.Key)_count{$labels} $($bucketValues.Count)"
        }
        $output += ""
    }

    # Format summaries
    foreach ($summary in $script:Metrics.Summaries.GetEnumerator()) {
        $output += "# HELP $($summary.Key) $($summary.Value.help)"
        $output += "# TYPE $($summary.Key) $($summary.Value.type)"

        foreach ($value in $summary.Value.values.GetEnumerator()) {
            $labels = $value.Key
            $values = $value.Value | Sort-Object

            foreach ($quantile in $summary.Value.quantiles) {
                $index = [math]::Floor($values.Count * $quantile)
                $quantileValue = if ($index -lt $values.Count) { $values[$index] } else { 0 }
                $output += "$($summary.Key){$labels,quantile=`"$quantile`"} $quantileValue"
            }
            $output += "$($summary.Key)_sum{$labels} $($values | Measure-Object -Sum | Select-Object -ExpandProperty Sum)"
            $output += "$($summary.Key)_count{$labels} $($values.Count)"
        }
        $output += ""
    }

    return $output -join "`n"
}

# HTTP listener
function Start-MetricsServer {
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://+:$Port/")

    try {
        $listener.Start()
        Write-Host "Hotpatch metrics exporter started on http://localhost:$Port$Endpoint" -ForegroundColor Green
        Write-Host "Press Ctrl+C to stop..." -ForegroundColor Gray

        while ($listener.IsListening) {
            $context = $listener.GetContext()
            $request = $context.Request
            $response = $context.Response

            if ($request.Url.PathAndQuery -eq $Endpoint) {
                # Update metrics before serving
                Update-MetricsFromRegistry

                # Generate and serve metrics
                $metricsText = Format-PrometheusMetrics
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($metricsText)

                $response.ContentType = "text/plain; version=0.0.4"
                $response.ContentLength64 = $buffer.Length
                $response.OutputStream.Write($buffer, 0, $buffer.Length)
            }
            else {
                $response.StatusCode = 404
                $message = "Not Found. Metrics available at $Endpoint"
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($message)
                $response.OutputStream.Write($buffer, 0, $buffer.Length)
            }

            $response.OutputStream.Close()
        }
    }
    finally {
        $listener.Stop()
        Write-Host "Metrics exporter stopped." -ForegroundColor Yellow
    }
}

# Main execution
Initialize-Metrics
Start-MetricsServer
