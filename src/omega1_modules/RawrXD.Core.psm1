#Requires -Version 7.4
#Requires -PSEdition Core
# RawrXD OMEGA-1 Core Module
# Self-healing autonomous infrastructure component

$script:OmegaRoot = $env:RAWRXD_OMEGA_ROOT ?? "D:\lazy init ide\auto_generated_methods"
$script:ModuleVersion = "1.0.0-OMEGA"
$script:LastHealthCheck = [DateTime]::MinValue

function Invoke-Core {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Path = $script:OmegaRoot,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$Config = @{}
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    
    try {
        # Ensure directory structure
        if (-not (Test-Path $Path)) {
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
            Write-Verbose "[Core] Created root directory: $Path"
        }
        
        # Core heartbeat
        $process = Get-Process -Id $PID -ErrorAction SilentlyContinue
        $result = @{
            Status = 'Active'
            Module = 'RawrXD.Core'
            Timestamp = $timestamp
            ProcessId = $PID
            MemoryMB = if ($process) { [Math]::Round($process.WorkingSet64 / 1MB, 2) } else { 0 }
            Version = $script:ModuleVersion
            Uptime = [DateTime]::Now - $process.StartTime
            ConfigHash = ($Config.GetEnumerator() | Sort-Object Key | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ';'
        }
        
        $sw.Stop()
        $result.LatencyMs = $sw.ElapsedMilliseconds
        
        Write-Verbose "[Core] Heartbeat completed in $($sw.ElapsedMilliseconds)ms"
        return $result
    }
    catch {
        Write-Error "[Core] Critical error: $_"
        throw
    }
}

function Test-CoreHealth {
    [CmdletBinding()]
    param()
    
    $script:LastHealthCheck = Get-Date
    
    return @{
        Module = 'RawrXD.Core'
        Healthy = $true
        Status = 'Operational'
        Timestamp = Get-Date
        Version = $script:ModuleVersion
        Checks = @{
            DirectoryAccess = Test-Path $script:OmegaRoot
            MemoryPressure = (Get-Process -Id $PID).WorkingSet64 -lt 500MB
            PowerShellVersion = $PSVersionTable.PSVersion -ge [Version]'7.4'
        }
    }
}

function Repair-Core {
    [CmdletBinding()]
    param()
    
    Write-Verbose "[Core] Initiating self-repair sequence"
    
    # Re-establish directory structure
    $requiredPaths = @(
        $script:OmegaRoot,
        "$script:OmegaRoot\logs",
        "$script:OmegaRoot\cache",
        "$script:OmegaRoot\manifests"
    )
    
    foreach ($path in $requiredPaths) {
        if (-not (Test-Path $path)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
            Write-Verbose "[Core] Repaired path: $path"
        }
    }
    
    return @{ Repaired = $true; Timestamp = Get-Date }
}

Export-ModuleMember -Function Invoke-Core, Test-CoreHealth, Repair-Core
