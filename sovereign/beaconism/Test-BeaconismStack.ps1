#Requires -Version 7.2
<#
.SYNOPSIS
    Test-BeaconismStack.ps1 - Validation suite for the full Beaconism infrastructure

.DESCRIPTION
    Tests disk remediation, memory patching, beacon encoding/decoding,
    and UDP ping-ping transmission without requiring actual network targets.

.NOTES
    Version: 1.0.0
#>

[CmdletBinding()]
param (
    [switch]$TestDiskRemediation,
    [switch]$TestMemoryPatch,
    [switch]$TestBeaconEncoding,
    [switch]$TestUdpPingPing,
    [switch]$TestAll
)

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

$ModuleDir = $PSScriptRoot
$PassCount = 0
$FailCount = 0

function Report-Test {
    param ([string]$Name, [bool]$Result)
    if ($Result) {
        Write-Output "[PASS] $Name"
        $script:PassCount++
    } else {
        Write-Output "[FAIL] $Name"
        $script:FailCount++
    }
}

Write-Output "=== Beaconism Stack Validation ==="
Write-Output ""

# ============================================================================
# Test 1: Beacon Encoding/Decoding Roundtrip
# ============================================================================
if ($TestBeaconEncoding -or $TestAll) {
    Write-Output "--- Test: Beacon Encoding/Decoding ---"

    $BeaconModule = Join-Path $ModuleDir "SovereignBeaconGenerator.ps1"
    if (Test-Path $BeaconModule) {
        . $BeaconModule

        $Beacon = New-SovereignBeacon -NodeId "test-node" -PrimaryDomain "test.local" -EnableEncryption:$false
        $TestData = @{
            "status" = "GREEN"
            "cpu" = "42"
            "mem_mb" = "8192"
        }

        $Encoded = $Beacon.EncodeState($TestData)
        Write-Output "Encoded: $Encoded"

        # Decode manually
        $Bytes = for ($i = 0; $i -lt $Encoded.Length; $i += 2) {
            [Convert]::ToByte($Encoded.Substring($i, 2), 16)
        }
        $DecodedJson = [System.Text.Encoding]::UTF8.GetString($Bytes)
        $Decoded = $DecodedJson | ConvertFrom-Json

        $RoundtripOk = ($Decoded.status -eq "GREEN") -and ($Decoded.cpu -eq "42")
        Report-Test "Beacon encode/decode roundtrip" $RoundtripOk
    } else {
        Report-Test "Beacon module exists" $false
    }
    Write-Output ""
}

# ============================================================================
# Test 2: Disk Remediation (create test binary, patch, verify)
# ============================================================================
if ($TestDiskRemediation -or $TestAll) {
    Write-Output "--- Test: Disk Remediation ---"

    $DiskModule = Join-Path $ModuleDir "SovereignDiskRemediator.ps1"
    if (Test-Path $DiskModule) {
        . $DiskModule

        # Create a test binary with HTTP patterns
        $TestBinary = "$env:TEMP\test_beacon_binary.exe"
        $TestBytes = [System.Text.Encoding]::ASCII.GetBytes("https://api.openai.com/v1/completions`0`0`0`0")
        [System.IO.File]::WriteAllBytes($TestBinary, $TestBytes)

        # Run weight removal
        $Result = Remove-SovereignWeightDependencies -BinaryPath $TestBinary -BackupDirectory "$env:TEMP\beacon_backups"
        Report-Test "Disk remediation execution" $Result

        # Verify HTTP patterns are zeroed
        $PatchedBytes = [System.IO.File]::ReadAllBytes($TestBinary)
        $HttpPattern = [System.Text.Encoding]::ASCII.GetBytes("https://")
        $StillHasHttp = $false
        for ($i = 0; $i -le $PatchedBytes.Length - $HttpPattern.Length; $i++) {
            $Match = $true
            for ($j = 0; $j -lt $HttpPattern.Length; $j++) {
                if ($PatchedBytes[$i + $j] -ne $HttpPattern[$j]) { $Match = $false; break }
            }
            if ($Match) { $StillHasHttp = $true; break }
        }
        # If we didn't find it, it's clean
        Report-Test "HTTP patterns zeroed" (-not $StillHasHttp)

        # Cleanup
        Remove-Item $TestBinary -Force -ErrorAction SilentlyContinue
    } else {
        Report-Test "Disk module exists" $false
    }
    Write-Output ""
}

# ============================================================================
# Test 3: UDP Ping-Ping (loopback, no external dependency)
# ============================================================================
if ($TestUdpPingPing -or $TestAll) {
    Write-Output "--- Test: UDP Ping-Ping Transmission ---"

    # Start listener in background
    $ListenerJob = Start-Job -ScriptBlock {
        $UdpClient = [System.Net.Sockets.UdpClient]::new(19999)
        $RemoteEP = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
        $Data = $UdpClient.Receive([ref]$RemoteEP)
        $UdpClient.Close()
        return [System.Text.Encoding]::UTF8.GetString($Data)
    }

    Start-Sleep -Milliseconds 500

    # Send ping-ping
    $Sender = [System.Net.Sockets.UdpClient]::new()
    $Payload = [System.Text.Encoding]::UTF8.GetBytes("NODE:test|STATUS:PINGPING")
    [void]$Sender.Send($Payload, $Payload.Length, "127.0.0.1", 19999)
    $Sender.Close()

    # Wait for receipt
    $ListenerJob | Wait-Job -Timeout 5 | Out-Null
    $Received = $ListenerJob | Receive-Job
    Remove-Job $ListenerJob

    $PingPingOk = ($Received -match "PINGPING")
    Report-Test "UDP ping-ping loopback" $PingPingOk
    Write-Output ""
}

# ============================================================================
# Test 4: Memory Patch API (validate Win32 definitions compile)
# ============================================================================
if ($TestMemoryPatch -or $TestAll) {
    Write-Output "--- Test: Memory Patch API ---"

    $MemoryModule = Join-Path $ModuleDir "SovereignRuntimeMemoryPatch.ps1"
    if (Test-Path $MemoryModule) {
        # Just verify the module loads without errors
        $LoadOk = $true
        try {
            . $MemoryModule
        } catch {
            $LoadOk = $false
        }
        Report-Test "Memory patch module loads" $LoadOk
    } else {
        Report-Test "Memory module exists" $false
    }
    Write-Output ""
}

# ============================================================================
# Summary
# ============================================================================
Write-Output "=== Validation Summary ==="
Write-Output "Passed: $PassCount"
Write-Output "Failed: $FailCount"
Write-Output ""

if ($FailCount -eq 0) {
    Write-Output "ALL TESTS PASSED - Beaconism stack is operational"
} else {
    Write-Output "SOME TESTS FAILED - Review output above"
}
