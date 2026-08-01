#Requires -Version 7.2
<#
.SYNOPSIS
    SovereignPingStream.ps1 - Unidirectional UDP Beacon Engine (Ping-Ping)

.DESCRIPTION
    Strict "ping-ping" behavior: transmits sequential status pulses without
    waiting for or processing acknowledgment. Connectionless UDP datagrams.
    Replaces TCP handshake / HTTP request-response with raw outbound blasting.

.NOTES
    Version: 1.1.0
    Communication Protocol: UDP_UNIDIRECTIONAL_BEACONISM
#>

[CmdletBinding()]
param (
    [string]$TargetCollectorHost = "127.0.0.1",
    [int]$TargetCollectorPort = 9999,
    [string]$NodeId = "node-heretic-01",
    [int]$PulseIntervalMin = 5,
    [int]$PulseIntervalMax = 15,
    [switch]$EnableBinaryPayload
)

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

Write-Output "[PINGPING] Initializing unidirectional pulse channel to ${TargetCollectorHost}:${TargetCollectorPort}..."
Write-Output "[PINGPING] Node: $NodeId | Mode: Fire-and-forget | No acknowledgments"

# ============================================================================
# UDP Client Setup
# ============================================================================
try {
    $UdpClient = [System.Net.Sockets.UdpClient]::new()
    Write-Output "[PINGPING] UDP socket initialized"
} catch {
    Write-Output "[PINGPING] FATAL: Cannot create UDP client: $_"
    exit 1
}

# ============================================================================
# Payload Generators
# ============================================================================
function New-TextPayload {
    param ([string]$NodeId)
    $Timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    return "NODE:$NodeId|TIME:$Timestamp|STATUS:ZERO_WEIGHT_STABLE|PING:PING"
}

function New-BinaryPayload {
    param ([string]$NodeId)
    # Compact binary layout: 4 bytes node ID hash + 8 bytes timestamp + 1 byte status
    $Timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $NodeHash = [System.BitConverter]::GetBytes($NodeId.GetHashCode())
    $TimeBytes = [System.BitConverter]::GetBytes([long]$Timestamp)
    $StatusByte = [byte]0x01  # ZERO_WEIGHT_STABLE

    $Payload = New-Object byte[] 13
    [Array]::Copy($NodeHash, 0, $Payload, 0, 4)
    [Array]::Copy($TimeBytes, 0, $Payload, 4, 8)
    $Payload[12] = $StatusByte

    return $Payload
}

# ============================================================================
# Pulse Transmission
# ============================================================================
function Send-SovereignPulse {
    param (
        [System.Net.Sockets.UdpClient]$Client,
        [string]$Host,
        [int]$Port,
        [byte[]]$Payload
    )

    try {
        [void]$Client.Send($Payload, $Payload.Length, $Host, $Port)
        return $true
    } catch {
        return $false
    }
}

# ============================================================================
# Main Pulse Loop
# ============================================================================
$Rng = [System.Random]::new()
$Sequence = 0

Write-Output "[PINGPING] Entering transmission loop..."
Write-Output "[PINGPING] Press Ctrl+C to terminate"

try {
    while ($true) {
        # Construct payload
        if ($EnableBinaryPayload) {
            $Payload = New-BinaryPayload -NodeId $NodeId
        } else {
            $PayloadString = New-TextPayload -NodeId $NodeId
            $Payload = [System.Text.Encoding]::UTF8.GetBytes($PayloadString)
        }

        # Transmit without waiting for response (ping-ping, not ping-pong)
        $Success = Send-SovereignPulse -Client $UdpClient -Host $TargetCollectorHost -Port $TargetCollectorPort -Payload $Payload

        $Timestamp = Get-Date -Format "HH:mm:ss.fff"
        if ($Success) {
            Write-Output "[PINGPING] #$Sequence | $Timestamp | OUTBOUND | $($Payload.Length) bytes"
        } else {
            Write-Output "[PINGPING] #$Sequence | $Timestamp | FAILED | silent degradation"
        }
        $Sequence++

        # Crypto-grade jitter interval
        $Jitter = $Rng.Next($PulseIntervalMin, $PulseIntervalMax)
        Start-Sleep -Seconds $Jitter
    }
} catch {
    # Ctrl+C or termination
} finally {
    $UdpClient.Close()
    $UdpClient.Dispose()
    Write-Output "[PINGPING] Transmission terminated. Total pulses: $Sequence"
}
