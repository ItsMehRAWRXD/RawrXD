# Sovereign_Topology_Affinity.ps1
# Enumerates CPU topology and calculates optimal process affinity masks 
# to enforce L2 cache isolation (forcing IPC telemetry over L3 cache).

$processor = Get-CimInstance -ClassName Win32_Processor
$numCores = $processor.NumberOfCores
$logicalCores = $processor.NumberOfLogicalProcessors

Write-Host "=========================================="
Write-Host " Sovereign Kernel - CPU Topology Profiler "
Write-Host "=========================================="
Write-Host "Physical Cores : $numCores"
Write-Host "Logical Cores  : $logicalCores"

<# 
  Calculate cache-isolated physical cores.
  Assuming typical Hyperthreading (2 threads per core):
  - Physical Core 0 = Logical Thread 0
  - Physical Core 4 = Logical Thread 8
  Placing processes at least 4 physical cores apart avoids 
  L2 cluster (CCX/E-Core) starvation and forces IPC to resolve in L3/RAM.
#>

$engineLogicalID = 0
$engineMask = [math]::pow(2, $engineLogicalID)

# Target a core located in an entirely different cluster (e.g. 4 physical cores away)
$monitorLogicalID = 8
if ($monitorLogicalID -ge $logicalCores) {
    # Fallback to the last available physical core on smaller core-count systems
    $monitorLogicalID = $logicalCores - 2 
}
$monitorMask = [math]::pow(2, $monitorLogicalID)

Write-Host ""
Write-Host "[Optimal Affinity Target Calculations]"
Write-Host "Engine Thread  (Logical $engineLogicalID) : Mask 0x$("{0:X}" -f $engineMask) ($engineMask)"
Write-Host "Monitor Thread (Logical $monitorLogicalID) : Mask 0x$("{0:X}" -f $monitorMask) ($monitorMask)"

Write-Host ""
Write-Host "[Integration Examples]"
Write-Host ">> Bind Current PowerShell Monitor Instance:"
Write-Host "   (Get-Process -Id `$PID).ProcessorAffinity = $monitorMask"
Write-Host ">> Bind Platinum Engine Target:"
Write-Host "   (Get-Process -Name 'Sovereign_Platinum_Engine' -ErrorAction SilentlyContinue).ProcessorAffinity = $engineMask"
Write-Host "=========================================="
