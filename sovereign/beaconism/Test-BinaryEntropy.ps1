# =======================================================================================
# Sovereign Framework - Production Byte Entropy Analyzer
# File: D:\rawrxd\sovereign\beaconism\Test-BinaryEntropy.ps1
# =======================================================================================

param (
    [string]$TargetBinaryPath = "C:\RawrXD\SovereignRecovery\SovereignSection.obj",
    [double]$HighEntropyThreshold = 6.8
)

$ErrorActionPreference = "Stop"

Write-Output "==============================================================================="
Write-Output "               SOVEREIGN INFRASTRUCTURE BYTE ENTROPY ANALYZER                 "
Write-Output "==============================================================================="
Write-Output "[*] Running Shannon Entropy scan on target footprint: $TargetBinaryPath"

if (-not (Test-Path $TargetBinaryPath)) {
    throw "[ENTROPY_ABORT] Target file asset does not exist. Ensure build steps completed."
}

[byte[]]$FileBytes = [System.IO.File]::ReadAllBytes($TargetBinaryPath)
$TotalByteCount = $FileBytes.Length

if ($TotalByteCount -eq 0) {
    throw "[ENTROPY_ABORT] Target file asset is empty. Byte allocation verification faulted."
}

# 2. Build frequency tracking distribution table across 256 byte possibilities
$ByteFrequencies = New-Object int[] 256
foreach ($Byte in $FileBytes) {
    $ByteFrequencies[$Byte]++
}

# 3. Calculate Shannon Entropy formula: H(X) = -sum(P(xi) * log2(P(xi)))
$EntropyValue = 0.0
for ($i = 0; $i -lt 256; $i++) {
    $Frequency = $ByteFrequencies[$i]
    if ($Frequency -gt 0) {
        $Probability = $Frequency / $TotalByteCount
        $EntropyValue -= $Probability * [math]::Log($Probability, 2)
    }
}

$RoundedEntropy = [math]::Round($EntropyValue, 4)
Write-Output "   [+] Calculated Byte Segment Entropy : $RoundedEntropy (Scale: 0.0 -> 8.0)"

# 4. Assert structural security threshold bounds
Write-Output "-------------------------------------------------------------------------------"
if ($RoundedEntropy -ge $HighEntropyThreshold) {
    Write-Warning "   [!] ALERT: High Entropy signature matched. Packed or encrypted data detected."
    $SecurityStatus = "PACKED_OR_CRYPT_BOUND"
} else {
    Write-Output "   [SUCCESS] Entropy levels within standard executable range (Clean Opcode Layout)."
    $SecurityStatus = "STANDARD_OPCODE_VERIFIED"
}

# 5. Route diagnostic profile out-of-band via connectionless stream
$SovereignPingStream = Join-Path $PSScriptRoot "SovereignPingStream.ps1"
if (Test-Path $SovereignPingStream) {
    . $SovereignPingStream
    $PulseData = "LAYER:SECURITY_AUDIT|STATUS:$SecurityStatus|ENTROPY:$RoundedEntropy|SIZE:$TotalByteCount"
    Start-SovereignPingStream -Payload $PulseData -Destination "127.0.0.1" -Port 9999
}

Write-Output "==============================================================================="
Write-Output " STRUCTURAL POSTURE AUDIT STATE: $SecurityStatus"
Write-Output "==============================================================================="

if ($RoundedEntropy -ge $HighEntropyThreshold -and $HighEntropyThreshold -ne 0) {
    exit 1
} else {
    exit 0
}
