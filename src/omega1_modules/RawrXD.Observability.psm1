#Requires -Version 7.4
#Requires -PSEdition Core
# RawrXD OMEGA-1 Observability Module
# Telemetry, metrics, and health monitoring

$script:OmegaRoot = $env:RAWRXD_OMEGA_ROOT ?? "D:\lazy init ide\auto_generated_methods"
$script:MetricsBuffer = [System.Collections.ArrayList]::new()
$script:MaxBufferSize = 1000

function Invoke-Observability {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Path = $script:OmegaRoot,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$Config = @{}
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    
    try {
        # Collect system metrics
        $process = Get-Process -Id $PID
        $memory = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
        
        $metric = @{
            Timestamp = $timestamp
            ProcessId = $PID
            WorkingSetMB = [Math]::Round($process.WorkingSet64 / 1MB, 2)
            PrivateMemoryMB = [Math]::Round($process.PrivateMemorySize64 / 1MB, 2)
            CpuPercent = $process.TotalProcessorTime.TotalSeconds  # Cumulative
            ThreadCount = $process.Threads.Count
            HandleCount = $process.HandleCount
        }
        
        # Buffer management
        [void]$script:MetricsBuffer.Add($metric)
        if ($script:MetricsBuffer.Count -gt $script:MaxBufferSize) {
            $script:MetricsBuffer.RemoveAt(0)
        }
        
        # Flush to disk periodically
        if ($script:MetricsBuffer.Count % 100 -eq 0) {
            $metricsPath = "$script:OmegaRoot\logs\metrics.jsonl"
            $script:MetricsBuffer | ForEach-Object { $_ | ConvertTo-Json -Compress | Add-Content -Path $metricsPath }
            $script:MetricsBuffer.Clear()
        }
        
        $result = @{
            Status = 'Active'
            Module = 'RawrXD.Observability'
            Timestamp = $timestamp
            ProcessId = $PID
            MemoryMB = [Math]::Round($process.WorkingSet64 / 1MB, 2)
            MetricsBuffered = $script:MetricsBuffer.Count
            SystemMemoryTotalGB = if ($memory) { [Math]::Round($memory.TotalVisibleMemorySize / 1MB, 2) } else { 0 }
        }
        
        Write-Verbose "[Observability] Metrics collected"
        return $result
    }
    catch {
        Write-Error "[Observability] Error: $_"
        throw
    }
}

function Test-ObservabilityHealth {
    [CmdletBinding()]
    param()
    
    return @{
        Module = 'RawrXD.Observability'
        Healthy = $script:MetricsBuffer.Count -lt $script:MaxBufferSize
        Status = 'Operational'
        Timestamp = Get-Date
        BufferUtilization = "$($script:MetricsBuffer.Count) / $script:MaxBufferSize"
    }
}

Export-ModuleMember -Function Invoke-Observability, Test-ObservabilityHealth
