# =======================================================================================
# Sovereign Framework - Production Workspace Build Sanitizer
# File: D:\rawrxd\sovereign\beaconism\Invoke-WorkspaceSanitizer.ps1
# =======================================================================================

param (
    [string]$TargetArtifactPath = "C:\RawrXD\SovereignRecovery",
    [string[]]$TransientExtensions = @("*.obj", "*.pdb", "*.tmp", "*.ilk")
)

$ErrorActionPreference = "Stop"

Write-Output "==============================================================================="
Write-Output "               SOVEREIGN AUTOMATED WORKSPACE BUILD SANITIZER                  "
Write-Output "==============================================================================="
Write-Output "[*] Initializing garbage sweeping metrics inside target space: $TargetArtifactPath"

if (-not (Test-Path $TargetArtifactPath)) {
    Write-Warning "[!] Targeted directory path non-existent. Sanitation sweep bypassed."
    exit 0
}

$ItemsPurgedCount = 0

foreach ($Extension in $TransientExtensions) {
    $TransientFiles = Get-ChildItem -Path $TargetArtifactPath -Filter $Extension -Recurse -ErrorAction SilentlyContinue
    
    foreach ($File in $TransientFiles) {
        try {
            Remove-Item -Path $File.FullName -Force
            Write-Output "   [-] Safely Evicted Transient Artifact: $($File.Name)"
            $ItemsPurgedCount++
        }
        catch {
            Write-Warning "   [!] Unable to release lock on artifact boundary: $($File.Name)"
        }
    }
}

Write-Output "-------------------------------------------------------------------------------"
Write-Output " Sanitation Metrics Summary:"
Write-Output "   [+] Clean Sweep Completed. Total Footprints Evicted: $ItemsPurgedCount"

# Route out-of-band sanitation status to connectionless analytics collectors
$SovereignPingStream = Join-Path $PSScriptRoot "SovereignPingStream.ps1"
if (Test-Path $SovereignPingStream) {
    . $SovereignPingStream
    $PulseMsg = "LAYER:BUILD_CLEANUP|STATUS:WORKSPACE_SANITIZED|ITEMS_REMOVED:$ItemsPurgedCount"
    Start-SovereignPingStream -Payload $PulseMsg -Destination "127.0.0.1" -Port 9999
}

Write-Output "==============================================================================="
exit 0
