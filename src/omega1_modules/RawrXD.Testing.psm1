#Requires -Version 7.4
#Requires -PSEdition Core
# RawrXD OMEGA-1 Testing Module
# Automated test execution and validation

$script:OmegaRoot = $env:RAWRXD_OMEGA_ROOT ?? "D:\lazy init ide\auto_generated_methods"
$script:TestResults = [System.Collections.ArrayList]::new()

function Invoke-Testing {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Path = $script:OmegaRoot,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$Config = @{}
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    
    try {
        # Run health checks on all modules
        $modules = Get-ChildItem -Path $Path -Filter 'RawrXD.*.psm1' -ErrorAction SilentlyContinue
        $results = @()
        $passed = 0
        $failed = 0
        
        foreach ($mod in $modules) {
            $modName = $mod.BaseName
            $healthFunction = "Test-$($modName.Replace('RawrXD.', ''))Health"
            
            try {
                Import-Module $mod.FullName -Force -ErrorAction SilentlyContinue
                if (Get-Command $healthFunction -ErrorAction SilentlyContinue) {
                    $health = & $healthFunction
                    if ($health.Healthy) { $passed++ } else { $failed++ }
                    $results += @{ Module = $modName; Healthy = $health.Healthy; Status = $health.Status }
                }
            } catch {
                $failed++
                $results += @{ Module = $modName; Healthy = $false; Error = $_.ToString() }
            }
        }
        
        $result = @{
            Status = if ($failed -eq 0) { 'AllPassed' } else { 'SomeFailed' }
            Module = 'RawrXD.Testing'
            Timestamp = $timestamp
            ProcessId = $PID
            MemoryMB = [Math]::Round((Get-Process -Id $PID).WorkingSet64 / 1MB, 2)
            Passed = $passed
            Failed = $failed
            Total = $modules.Count
            Results = $results
        }
        
        Write-Verbose "[Testing] $passed passed, $failed failed"
        return $result
    }
    catch {
        Write-Error "[Testing] Error: $_"
        throw
    }
}

function Test-TestingHealth {
    [CmdletBinding()]
    param()
    
    return @{
        Module = 'RawrXD.Testing'
        Healthy = $true
        Status = 'Operational'
        Timestamp = Get-Date
        TestHistory = $script:TestResults.Count
    }
}

Export-ModuleMember -Function Invoke-Testing, Test-TestingHealth
