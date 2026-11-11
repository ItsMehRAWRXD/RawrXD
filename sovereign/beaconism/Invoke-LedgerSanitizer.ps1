# =======================================================================================
# Sovereign Framework - Production Hash Ledger Sanitizer
# File: D:\rawrxd\sovereign\beaconism\Invoke-LedgerSanitizer.ps1
# =======================================================================================

param (
    [string]$TargetArtifactPath = "C:\RawrXD\SovereignRecovery",
    [string[]]$TransientExtensions = @("*.obj", "*.pdb", "*.tmp", "*.ilk")
)

$ErrorActionPreference = "Stop"

Write-Output "==============================================================================="
Write-Output "               SOVEREIGN AUTOMATED HASH LEDGER SANITIZER                      "
Write-Output "==============================================================================="
Write-Output "[*] Initializing cryptographic tracking sweep: $TargetArtifactPath"

if (-not (Test-Path $TargetArtifactPath)) {
    Write-Warning "[!] Targeted directory path non-existent. Ledger scan bypassed."
    exit 0
}

$ItemsLoggedCount = 0

foreach ($Extension in $TransientExtensions) {
    $TransientFiles = Get-ChildItem -Path $TargetArtifactPath -Filter $Extension -Recurse -ErrorAction SilentlyContinue
    
    foreach ($File in $TransientFiles) {
        try {
            # Compute hash signature before dropping file footprint
            $HashObject = Get-FileHash -Path $File.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue
            $HashString = $HashObject.Hash
            
            Remove-Item -Path $File.FullName -Force
            Write-Output "   [-] Evicted: $($File.Name) [SHA256: $($HashString.Substring(0,16))...]"
            
            # Broadcast the hash out-of-band to confirm sanitation
            $SovereignPingStream = Join-Path $PSScriptRoot "SovereignPingStream.ps1"
            if (Test-Path $SovereignPingStream) {
                . $SovereignPingStream
                $PulseMsg = "LAYER:LEDGER_CLEANUP|FILE:$($File.Name)|HASH:$HashString|STATUS:DELETED"
                Start-SovereignPingStream -Payload $PulseMsg -Destination "127.0.0.1" -Port 9999
            }
            $ItemsLoggedCount++
        }
        catch {
            Write-Warning "   [!] File lock prevented ledger processing on asset: $($File.Name)"
        }
    }
}

Write-Output "-------------------------------------------------------------------------------"
Write-Output " Ledger Metrics Summary:"
Write-Output "   [+] Clean Sweep Completed. Total Footprints Logged and Purged: $ItemsLoggedCount"
Write-Output "==============================================================================="
exit 0
