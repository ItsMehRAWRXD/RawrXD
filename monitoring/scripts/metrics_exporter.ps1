# RawrXD Metrics Exporter for Prometheus
# Version: 1.0.0
# Exposes metrics on http://localhost:8080/metrics

param(
    [int]$Port = 8080,
    [string]$RegistryPath = "security/phase_g1_hotpatch/registry/patch_registry.json",
    [string]$AuditLogPath = "logs/audit"
)

#requires -Version 7.0

$ErrorActionPreference = "Stop"

# Metric storage
$script:Metrics = @{
    counters = @{}
    gauges = @{}
    histograms = @{}
}

# Initialize metrics
function Initialize-Metrics {
    # Patch operation counters
    $script:Metrics.counters['patch_operations_total'] = @{
        help = "Total number of patch operations"
        type = "counter"
        labels = @("system", "operation", "status")
        values = @{}
    }
    
    # Rollback counter
    $script:Metrics.counters['patch_rollback_total'] = @{
        help = "Total number of patch rollbacks"
        type = "counter"
        labels = @("system", "reason")
        values = @{}
    }
    
    # Backup creation
    $script:Metrics.counters['backup_creation_total'] = @{
        help = "Total number of backups created"
        type = "counter"
        labels = @("system", "status")
        values = @{}
    }
    
    # RBAC counters
    $script:Metrics.counters['rbac_access_allowed_total'] = @{
        help = "Total number of RBAC access grants"
        type = "counter"
        labels = @("user", "permission")
        values = @{}
    }
    
    $script:Metrics.counters['rbac_access_denied_total'] = @{
        help = "Total number of RBAC access denials"
        type = "counter"
        labels = @("user", "permission", "reason")
        values = @{}
    }
    
    # Audit log counters
    $script:Metrics.counters['audit_log_entries_total'] = @{
        help = "Total number of audit log entries"
        type = "counter"
        labels = @("event_type", "status")
        values = @{}
    }
    
    $script:Metrics.counters['audit_log_write_failures_total'] = @{
        help = "Total number of audit log write failures"
        type = "counter"
        labels = @()
        values = @{}
    }
    
    # Security counters
    $script:Metrics.counters['unauthorized_patch_attempts_total'] = @{
        help = "Total number of unauthorized patch attempts"
        type = "counter"
        labels = @("user", "system")
        values = @{}
    }
    
    # Gauges
    $script:Metrics.gauges['compliance_score'] = @{
        help = "Current compliance score (0-100)"
        type = "gauge"
        labels = @()
        value = 100
    }
    
    $script:Metrics.gauges['registry_corrupted'] = @{
        help = "Whether registry is corrupted (1=yes, 0=no)"
        type = "gauge"
        labels = @()
        value = 0
    }
    
    $script:Metrics.gauges['patches_applied'] = @{
        help = "Number of patches currently applied"
        type = "gauge"
        labels = @("system")
        values = @{}
    }
    
    $script:Metrics.gauges['patches_rolled_back'] = @{
        help = "Number of patches rolled back"
        type = "gauge"
        labels = @("system")
        values = @{}
    }
    
    # Histograms
    $script:Metrics.histograms['patch_operation_duration_seconds'] = @{
        help = "Patch operation duration in seconds"
        type = "histogram"
        buckets = @(0.1, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300)
        values = @()
    }
    
    $script:Metrics.histograms['backup_creation_duration_seconds'] = @{
        help = "Backup creation duration in seconds"
        type = "histogram"
        buckets = @(0.1, 0.5, 1, 2.5, 5, 10, 30)
        values = @()
    }
}

# Collect metrics from registry
function Update-MetricsFromRegistry {
    if (-not (Test-Path $RegistryPath)) {
        $script:Metrics.gauges['registry_corrupted'].value = 1
        return
    }
    
    try {
        $registry = Get-Content $RegistryPath -Raw | ConvertFrom-Json -ErrorAction Stop
        $script:Metrics.gauges['registry_corrupted'].value = 0
        
        # Count patches by system and status
        $systems = @("swarm", "agent", "tools", "unified")
        foreach ($system in $systems) {
            $applied = ($registry.patches | Where-Object { 
                $_.system_type -eq $system -and $_.status -eq "applied" 
            }).Count
            
            $rolledBack = ($registry.patches | Where-Object { 
                $_.system_type -eq $system -and $_.status -eq "rolled_back" 
            }).Count
            
            $script:Metrics.gauges['patches_applied'].values[$system] = $applied
            $script:Metrics.gauges['patches_rolled_back'].values[$system] = $rolledBack
        }
    }
    catch {
        $script:Metrics.gauges['registry_corrupted'].value = 1
        Write-Warning "Failed to read registry: $_"
    }
}

# Collect metrics from audit logs
function Update-MetricsFromAuditLogs {
    if (-not (Test-Path $AuditLogPath)) {
        return
    }
    
    $currentMonth = Get-Date -Format "yyyyMM"
    $logFile = Join-Path $AuditLogPath "audit_$currentMonth.jsonl"
    
    if (-not (Test-Path $logFile)) {
        return
    }
    
    try {
        # Read last 1000 entries for recent metrics
        $entries = Get-Content $logFile -Tail 1000 | ForEach-Object {
            try { $_ | ConvertFrom-Json -ErrorAction SilentlyContinue } catch { $null }
        } | Where-Object { $_ -ne $null }
        
        # Count by event type
        $eventCounts = $entries | Group-Object -Property event_type
        foreach ($group in $eventCounts) {
            $key = $group.Name
            $count = $group.Count
            $script:Metrics.counters['audit_log_entries_total'].values[$key] = $count
        }
    }
    catch {
        Write-Warning "Failed to read audit logs: $_"
    }
}

# Generate Prometheus format output
function Get-MetricsOutput {
    $output = @()
    $timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    
    # Counters
    foreach ($counter in $script:Metrics.counters.GetEnumerator()) {
        $name = $counter.Key
        $config = $counter.Value
        
        $output += "# HELP $name $($config.help)"
        $output += "# TYPE $name $($config.type)"
        
        if ($config.labels.Count -eq 0) {
            $value = if ($config.values -is [hashtable]) { 
                $config.values["total"] ?? 0 
            } else { 
                $config.values 
            }
            $output += "$name $value"
        } else {
            foreach ($valueEntry in $config.values.GetEnumerator()) {
                $labelStr = $valueEntry.Key
                $value = $valueEntry.Value
                $output += "$name{$labelStr} $value"
            }
        }
    }
    
    # Gauges
    foreach ($gauge in $script:Metrics.gauges.GetEnumerator()) {
        $name = $gauge.Key
        $config = $gauge.Value
        
        $output += "# HELP $name $($config.help)"
        $output += "# TYPE $name $($config.type)"
        
        if ($config.labels.Count -eq 0) {
            $output += "$name $($config.value)"
        } else {
            foreach ($valueEntry in $config.values.GetEnumerator()) {
                $labelStr = $valueEntry.Key
                $value = $valueEntry.Value
                $output += "$name{$labelStr} $value"
            }
        }
    }
    
    # Histograms
    foreach ($histogram in $script:Metrics.histograms.GetEnumerator()) {
        $name = $histogram.Key
        $config = $histogram.Value
        
        $output += "# HELP $name $($config.help)"
        $output += "# TYPE $name $($config.type)"
        
        # Output buckets
        foreach ($bucket in $config.buckets) {
            $count = ($config.values | Where-Object { $_ -le $bucket }).Count
            $output += "${name}_bucket{le=`"$bucket`"} $count"
        }
        
        # +Inf bucket
        $totalCount = $config.values.Count
        $output += "${name}_bucket{le=`"+Inf`"} $totalCount"
        
        # Sum and count
        $sum = ($config.values | Measure-Object -Sum).Sum
        $output += "${name}_sum $sum"
        $output += "${name}_count $totalCount"
    }
    
    return $output -join "`n"
}

# HTTP Listener
function Start-MetricsServer {
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://+:$Port/")
    $listener.Start()
    
    Write-Host "RawrXD Metrics Exporter started on http://localhost:$Port/metrics"
    Write-Host "Press Ctrl+C to stop"
    
    try {
        while ($listener.IsListening) {
            $context = $listener.GetContext()
            $request = $context.Request
            $response = $context.Response
            
            if ($request.Url.PathAndQuery -eq "/metrics") {
                # Update metrics before serving
                Update-MetricsFromRegistry
                Update-MetricsFromAuditLogs
                
                $metricsOutput = Get-MetricsOutput
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($metricsOutput)
                
                $response.ContentType = "text/plain; version=0.0.4"
                $response.ContentLength64 = $buffer.Length
                $response.OutputStream.Write($buffer, 0, $buffer.Length)
            }
            elseif ($request.Url.PathAndQuery -eq "/health") {
                $health = @{ status = "healthy"; timestamp = Get-Date -Format "o" } | ConvertTo-Json
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($health)
                
                $response.ContentType = "application/json"
                $response.ContentLength64 = $buffer.Length
                $response.OutputStream.Write($buffer, 0, $buffer.Length)
            }
            else {
                $response.StatusCode = 404
                $message = "Not found. Try /metrics or /health"
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($message)
                $response.ContentLength64 = $buffer.Length
                $response.OutputStream.Write($buffer, 0, $buffer.Length)
            }
            
            $response.OutputStream.Close()
        }
    }
    finally {
        $listener.Stop()
        $listener.Close()
    }
}

# Main execution
Initialize-Metrics
Start-MetricsServer
