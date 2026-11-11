#Requires -Version 7.2
<#
.SYNOPSIS
    SovereignSwarmOrchestrator.ps1 - Decentralized Controller for Beaconism

.DESCRIPTION
    Replaces centralized dashboard management. Watches local systems silently
    and uses SovereignBeacon to drop hints about structural status.
    Zero open ports. Pure outbound signaling.

.NOTES
    Version: 1.1.0
    Engine: PowerShell 7.2+ Core / Beaconism Transport
#>

[CmdletBinding()]
param (
    [string]$NodeIdentifier = "node-alpha-01",
    [string]$BeaconC2Domain = "recovery.internal.local",
    [string]$UdpCollectorHost = "127.0.0.1",
    [int]$UdpCollectorPort = 9999,
    [switch]$EnableEventLogFallback,
    [switch]$Daemon
)

# Force weight-removal constraints
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

Write-Output "[BEACONISM] Initializing Decentralized Outbound Signaling for $NodeIdentifier..."
Write-Output "[BEACONISM] Target: $UdpCollectorHost`:$UdpCollectorPort | Domain: $BeaconC2Domain"

# Import the beacon engine
$BeaconModulePath = Join-Path $PSScriptRoot "SovereignBeaconGenerator.ps1"
if (Test-Path $BeaconModulePath) {
    . $BeaconModulePath
} else {
    Write-Output "[BEACONISM] WARNING: Beacon module not found at $BeaconModulePath"
    exit 1
}

# Instantiate the Beacon Engine
$BeaconEngine = New-SovereignBeacon `
    -NodeId $NodeIdentifier `
    -PrimaryDomain $BeaconC2Domain `
    -JitterMin 15 `
    -JitterMax 45 `
    -FallbackCollectorIP "8.8.8.8" `
    -EnableEventLogFallback:$EnableEventLogFallback

Write-Output "[BEACONISM] Beacon engine online. Entering infinite telemetry loop..."

# ============================================================================
# Self-governed telemetry loop
# ============================================================================
try {
    while ($true) {
        # 1. Gather structural metrics silently from local guardians
        $CurrentHealth = "GREEN"
        $ProcessCheck = Get-Process -Name "RawrXD_IDE" -ErrorAction SilentlyContinue
        if ($ProcessCheck) {
            $CurrentHealth = "ACTIVE_DEV"
        }

        # Check for SovereignRuntime
        $RuntimeCheck = Get-Process -Name "SovereignRuntime" -ErrorAction SilentlyContinue
        if ($RuntimeCheck) {
            $CurrentHealth = "RUNTIME_ACTIVE"
        }

        # Gather system metrics
        $CpuLoad = 0
        $FreeMemMB = 0
        try {
            $CpuLoad = [math]::Round((Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average)
            $FreeMemMB = [math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1KB)
        } catch { }

        $SystemMetrics = @{
            "node"     = $NodeIdentifier
            "status"   = $CurrentHealth
            "cpu"      = $CpuLoad
            "mem_mb"   = $FreeMemMB
            "epoch"    = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
            "version"  = "1.1.0"
        }

        # 2. Compile metrics into raw hex string and pulse
        Write-Output "[BEACONISM] Telemetry cycle: status=$CurrentHealth cpu=$CpuLoad% mem=$FreeMemMB MB"
        Invoke-SovereignBeaconPulse `
            -Beacon $BeaconEngine `
            -StateData $SystemMetrics `
            -UdpTargetHost $UdpCollectorHost `
            -UdpTargetPort $UdpCollectorPort

        # 3. Enforce randomized sleep pattern to disrupt detection profiles
        $BeaconEngine.Rest()

        # If not in daemon mode, run once and exit
        if (-not $Daemon) {
            Write-Output "[BEACONISM] Single-shot mode complete. Exiting."
            break
        }
    }
} finally {
    $BeaconEngine.Dispose()
    Write-Output "[BEACONISM] Orchestrator shutdown complete."
}
