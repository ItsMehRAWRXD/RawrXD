# =======================================================================================
# Sovereign Framework - Production Section Alignment Auditor
# File: D:\rawrxd\sovereign\beaconism\Test-SectionAlignment.ps1
# =======================================================================================

param (
    [string]$ObjectFilePath = "C:\RawrXD\SovereignRecovery\SovereignSection.obj",
    [uint32]$RequiredAlignment = 16
)

$ErrorActionPreference = "Stop"

Write-Output "==============================================================================="
Write-Output "               SOVEREIGN INFRASTRUCTURE SECTION ALIGNMENT AUDITOR              "
Write-Output "==============================================================================="
Write-Output "[*] Auditing file footprint target: $ObjectFilePath"

if (-not (Test-Path $ObjectFilePath)) {
    throw "[AUDIT_ABORT] Target file asset does not exist. Ensure compilation completed."
}

$FileMetrics = Get-Item $ObjectFilePath
$RawBytes = [System.IO.File]::ReadAllBytes($ObjectFilePath)
$Length = $RawBytes.Length

Write-Output "   [+] Base Target File Size : $Length bytes"

# 1. Structural Header Check
$MachineType = [BitConverter]::ToUInt16($RawBytes, 0)
if ($MachineType -eq 0x8664) {
    Write-Output "   [+] Validated Binary Type : COFF x64 (AMD64) Object Structure"
} elseif ($MachineType -eq 0x5A4D) {
    Write-Output "   [+] Validated Binary Type : Portable Executable (PE32/PE32+) Container"
} else {
    Write-Warning "   [!] Unrecognized file signature marker: 0x$($MachineType.ToString('X4'))"
}

# 2. Assert 16-Byte Padding Alignment Constraints
$Remainder = $Length % $RequiredAlignment
$SkewAdjustment = if ($Remainder -eq 0) { 0 } else { $RequiredAlignment - $Remainder }

Write-Output "-------------------------------------------------------------------------------"
Write-Output " Alignment Verification Metrics:"
Write-Output "   [+] Requested Boundary Align Block : $RequiredAlignment bytes"
Write-Output "   [+] Extracted Padding Remainder    : $Remainder bytes"

if ($Remainder -eq 0) {
    Write-Output "   [SUCCESS] Section payload matches execution space alignment constraints."
    $AuditStatus = "ALIGNMENT_SECURE"
} else {
    Write-Warning "   [!] Alignment padding variance found. Payload requires $SkewAdjustment trailing NOP bytes."
    $AuditStatus = "ALIGNMENT_SKEWED"
}

# 3. Stream Alignment Verification Diagnostics Out-Of-Band
$SovereignPingStream = Join-Path $PSScriptRoot "SovereignPingStream.ps1"
if (Test-Path $SovereignPingStream) {
    . $SovereignPingStream
    $PayloadMsg = "LAYER:BUILD_AUDIT|STATUS:$AuditStatus|REMAINDER:$Remainder|SKEW:$SkewAdjustment"
    Start-SovereignPingStream -Payload $PayloadMsg -Destination "127.0.0.1" -Port 9999
}

Write-Output "==============================================================================="
Write-Output " AUDIT COMPLETION STATE: $AuditStatus"
Write-Output "==============================================================================="

if ($AuditStatus -eq "ALIGNMENT_SECURE") {
    exit 0
} else {
    exit 1
}
