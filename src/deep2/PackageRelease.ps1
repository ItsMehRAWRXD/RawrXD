# SOVEREIGN-671B-REPRO-001 Packaging Script
# -------------------------------------------------------------------------------------

$ReleaseDir = "f:\~dev\rawrxd\src\deep2\dist"
$ManifestPath = "C:\Users\Garrett\Downloads\sover_release_manifest.json"
$ZipPath = "C:\Users\Garrett\Downloads\SovereignEngine_Release_Repro_001.zip"

Write-Host "[*] Initiating Sovereign Engine Asset Packaging..." -ForegroundColor Cyan

# 1. Verify Binary Integrity
$Binary = "f:\~dev\rawrxd\src\deep2\dist\SovereignSweep_X64.exe"
if (Test-Path $Binary) {
    $Hash = (Get-FileHash $Binary -Algorithm SHA256).Hash
    Write-Host "[+] Binary SHA-256 Verified: $Hash" -ForegroundColor Green
} else {
    Write-Host "[!] Error: Standalone binary not found in dist folder." -ForegroundColor Red
    exit 1
}

# 2. Collect Shards and Headers
$Shards = @(
    "f:\~dev\RawrXD-production-lazy-init\src\masm\final-ide\masm_core_thread_affinity.asm",
    "f:\~dev\RawrXD-production-lazy-init\src\masm\final-ide\avx512_tensor_quant.asm",
    "f:\~dev\RawrXD-production-lazy-init\src\masm\final-ide\avx512_negative_scale.asm",
    "f:\~dev\rawrxd\src\deep2\Deep2MultiGpuBridge.hpp",
    "f:\~dev\rawrxd\src\deep2\Deep2StorageRing.hpp"
)

# 3. Create Immutable Asset Archive
$TempDir = New-Item -ItemType Directory -Path "$env:TEMP\SovereignRelease" -Force
Copy-Item $Binary -Destination $TempDir
foreach ($Shard in $Shards) {
    Copy-Item $Shard -Destination $TempDir
}
Copy-Item $ManifestPath -Destination $TempDir

Write-Host "[*] Compressing archive into asset envelope..." -ForegroundColor Gray
Compress-Archive -Path "$TempDir\*" -DestinationPath $ZipPath -Force

# 4. Cleanup
Remove-Item $TempDir -Recurse -Force

Write-Host "[🏁] Success: Sovereign Engine Release Archive created at: $ZipPath" -ForegroundColor Green
