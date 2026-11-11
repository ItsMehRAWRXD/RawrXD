#Requires -Version 7.2
<#
.SYNOPSIS
    SovereignBeaconParser.ps1 - Production Multi-Transport Telemetry Decoding Engine

.DESCRIPTION
    Reads incoming DNS logs, UDP packets, or event logs and decodes hex payloads
    back into real-time metrics. Runs on the collector/gateway server.
    Includes clock drift detection, AES-256-GCM decryption, and multi-transport parsing.

.NOTES
    Version: 2.0.0
    Role: Gateway Server / Collector
    Layers: Layer 8 & Layer 10 Validation Ingestion Points
#>

[CmdletBinding()]
param (
    [int]$ListeningPortAddress = 9999,
    [string]$EncryptionKeyHex = "8f3b20a7c41e9d82b350f1a6d4e8c9b2a1f0e3d5c7b9a2468013579edfca3210",
    [switch]$ParseDnsLogs,
    [switch]$ParseEventLogs,
    [string]$DnsLogPath = "C:\logs\dns_queries.log"
)

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

Write-Output "[BOOT] Production Ingestion Collector online. Processing connectionless streams on port $ListeningPortAddress..."

# ============================================================================
# Clock Drift Detection and Alerting
# ============================================================================
$global:BeaconTimestamps = @{}
$global:DriftThresholdSeconds = 300  # 5 minutes

function Test-SovereignClockDrift {
    param (
        [string]$NodeId,
        [long]$ReportedEpoch
    )

    $Now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $Drift = [math]::Abs($Now - $ReportedEpoch)

    if ($Drift -gt $global:DriftThresholdSeconds) {
        Write-Output "[ALERT] CLOCK DRIFT DETECTED: Node=$NodeId | Drift=${Drift}s | Threshold=$($global:DriftThresholdSeconds)s"
        return $true
    }
    return $false
}

# ============================================================================
# Reconstruct system byte arrays from hex strings safely
# ============================================================================
function Convert-HexStringToByteArray {
    param ([string]$Hex)
    $Hex = $Hex.Replace(" ", "").Replace("-", "")
    $Bytes = New-Object byte[] ($Hex.Length / 2)
    for ($i = 0; $i -lt $Hex.Length; $i += 2) {
        $Bytes[$i / 2] = [Convert]::ToByte($Hex.Substring($i, 2), 16)
    }
    return $Bytes
}

# ============================================================================
# Decode payload entry with AES-256-GCM support
# ============================================================================
function Decode-SovereignPayloadEntry {
    param ([byte[]]$DataBuffer)

    $RawString = [System.Text.Encoding]::UTF8.GetString($DataBuffer)
    
    # Try parsing plaintext JSON fields instantly
    if ($RawString -match "^\{.*\}$") {
        return ConvertFrom-Json -InputObject $RawString
    }

    # Attempt decrypting via validated AES-256-GCM configurations if text data is obscured
    if ($DataBuffer.Length -gt 32 -and (-not [string]::IsNullOrEmpty($EncryptionKeyHex))) {
        try {
            $KeyBytes = Convert-HexStringToByteArray -Hex $EncryptionKeyHex
            
            # Extract standard NIST authentication layout spaces (96-bit nonce, 128-bit tag)
            $NonceBytes = New-Object byte[] 12
            [Array]::Copy($DataBuffer, 0, $NonceBytes, 0, 12)
            
            $TagBytes = New-Object byte[] 16
            [Array]::Copy($DataBuffer, 12, $TagBytes, 0, 16)
            
            $CiphertextLength = $DataBuffer.Length - 28
            $CipherBytes = New-Object byte[] $CiphertextLength
            [Array]::Copy($DataBuffer, 28, $CipherBytes, 0, $CiphertextLength)
            
            $PlainBytes = New-Object byte[] $CiphertextLength
            $AesEngine = [System.Security.Cryptography.AesGcm]::new($KeyBytes)
            $AesEngine.Decrypt($NonceBytes, $CipherBytes, $TagBytes, $PlainBytes)
            $AesEngine.Dispose()
            
            return ConvertFrom-Json -InputObject ([System.Text.Encoding]::UTF8.GetString($PlainBytes))
        }
        catch {
            # Return raw data strings if decryption fails
        }
    }
    return $RawString
}

# ============================================================================
# Legacy hex payload decoder (backward compatibility)
# ============================================================================
function ConvertFrom-SovereignHexPayload {
    param (
        [string]$HexPayload,
        [byte[]]$CryptoKey = $null
    )

    if ($HexPayload.Length % 2 -ne 0) {
        Write-Output "[PARSER] Invalid hex length"
        return $null
    }

    try {
        $Bytes = for ($i = 0; $i -lt $HexPayload.Length; $i += 2) {
            [Convert]::ToByte($HexPayload.Substring($i, 2), 16)
        }

        $Json = [System.Text.Encoding]::UTF8.GetString($Bytes)
        $Parsed = $Json | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($Parsed) {
            return $Parsed
        }
    } catch { }

    # If plaintext fails and crypto key available, try AES-256-GCM decrypt
    if ($CryptoKey -and $Bytes.Length -ge 28) {
        $CryptoModule = Join-Path $PSScriptRoot "SovereignCryptoWrapper.ps1"
        if (Test-Path $CryptoModule) {
            . $CryptoModule
            $Decrypted = Unprotect-SovereignPayload -EncryptedBytes $Bytes -Key $CryptoKey -AssociatedData ([System.Text.Encoding]::UTF8.GetBytes("sovereign-beacon-v1"))
            if ($Decrypted) {
                $Json = [System.Text.Encoding]::UTF8.GetString($Decrypted)
                return $Json | ConvertFrom-Json
            }
        }
    }

    Write-Output "[PARSER] Decode failed: payload may be encrypted without matching key"
    return $null
}

# ============================================================================
# UDP Listener for direct ping-ping packets (Production)
# ============================================================================
function Start-SovereignUdpListener {
    param ([int]$Port)

    $UdpInboundListener = [System.Net.Sockets.UdpClient]::new($Port)
    $NetworkClientEndpoint = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)

    Write-Output "[PARSER] UDP listener active on port $Port"
    Write-Output "[PARSER] Press Ctrl+C to stop"

    try {
        while ($true) {
            $ReceivedBytes = $UdpInboundListener.Receive([ref]$NetworkClientEndpoint)
            if ($ReceivedBytes.Length -eq 0) { continue }

            $DecodedObject = Decode-SovereignPayloadEntry -DataBuffer $ReceivedBytes
            $Timestamp = [DateTime]::Now.ToString("yyyy-MM-dd HH:mm:ss")
            
            Write-Output "[$Timestamp] [INGEST] [FROM: $($NetworkClientEndpoint.Address)] Data: $($DecodedObject | ConvertTo-Json -Compress)"

            # Clock drift check for structured payloads
            if ($DecodedObject.node_id -and $DecodedObject.timestamp) {
                Test-SovereignClockDrift -NodeId $DecodedObject.node_id -ReportedEpoch $DecodedObject.timestamp | Out-Null
            }
        }
    } catch {
        Write-Error "[FATAL] Receiver runtime processing loop dropped: $_"
    } finally {
        $UdpInboundListener.Close()
        Write-Output "[PARSER] Listener stopped"
    }
}

# ============================================================================
# Parse DNS query logs for beacon signatures
# ============================================================================
function Read-SovereignDnsBeacons {
    param ([string]$LogPath)

    if (-not (Test-Path $LogPath)) {
        Write-Output "[PARSER] DNS log not found: $LogPath"
        return
    }

    Write-Output "[PARSER] Scanning DNS logs for beacon signatures..."

    Get-Content $LogPath | ForEach-Object {
        # Look for subdomain patterns: node-id.hexpayload.domain
        if ($_ -match '([a-z0-9-]+)\.([0-9a-fA-F]{20,})\.([a-z0-9.-]+)') {
            $NodeId = $Matches[1]
            $HexPayload = $Matches[2]
            $Domain = $Matches[3]

            Write-Output "[PARSER] DNS Beacon: node=$NodeId domain=$Domain"
            $Decoded = ConvertFrom-SovereignHexPayload -HexPayload $HexPayload
            if ($Decoded) {
                if ($Decoded.node_id -and $Decoded.timestamp) {
                    Test-SovereignClockDrift -NodeId $Decoded.node_id -ReportedEpoch $Decoded.timestamp | Out-Null
                }
                Write-Output "[PARSER] Decoded metrics: $($Decoded | ConvertTo-Json -Compress)"
            }
        }
    }
}

# ============================================================================
# Parse Windows Event Log for beacon signals
# ============================================================================
function Read-SovereignEventLogBeacons {
    Write-Output "[PARSER] Scanning Application event log for SovereignBeacon signals..."

    Get-WinEvent -FilterHashtable @{LogName='Application'; ID=1001} -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'SIG:([0-9a-fA-F]+)' } |
        ForEach-Object {
            $HexPayload = $Matches[1]
            Write-Output "[PARSER] EventLog Beacon: time=$($_.TimeCreated)"
            $Decoded = ConvertFrom-SovereignHexPayload -HexPayload $HexPayload
            if ($Decoded) {
                if ($Decoded.node_id -and $Decoded.timestamp) {
                    Test-SovereignClockDrift -NodeId $Decoded.node_id -ReportedEpoch $Decoded.timestamp | Out-Null
                }
                Write-Output "[PARSER] Decoded: $($Decoded | ConvertTo-Json -Compress)"
            }
        }
}

# ============================================================================
# Main execution
# ============================================================================
if ($ParseDnsLogs) {
    Read-SovereignDnsBeacons -LogPath $DnsLogPath
}

if ($ParseEventLogs) {
    Read-SovereignEventLogBeacons
}

# Default: start UDP listener
if (-not $ParseDnsLogs -and -not $ParseEventLogs) {
    Start-SovereignUdpListener -Port $ListeningPortAddress
}
if (-not $ParseDnsLogs -and -not $ParseEventLogs) {
    Start-SovereignUdpListener -Port $ListenPort
}
