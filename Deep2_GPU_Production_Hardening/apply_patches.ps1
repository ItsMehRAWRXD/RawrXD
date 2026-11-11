# Deep2 GPU Production Hardening — Apply Patches
# Run from F:\rawrxd

param(
    [string]$PatchDir = "F:\rawrxd\Deep2_GPU_Production_Hardening",
    [switch]$DryRun,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

Write-Host "=== Deep2 GPU Production Hardening — Patch Application ===" -ForegroundColor Cyan
Write-Host "Patch directory: $PatchDir"
Write-Host "DryRun: $DryRun"
Write-Host "Force: $Force"
Write-Host ""

# Define patch mappings: [patch_file, target_file]
$patches = @(
    @("src\deep2\vulkan_compute.h", "src\deep2\vulkan_compute.h"),
    @("src\deep2\vulkan_compute.cpp", "src\deep2\vulkan_compute.cpp"),
    @("src\deep2\runtime_graph_executor.cpp.patch", "src\deep2\runtime_graph_executor.cpp"),
    @("src\deep2\Deep2Engine.cpp.patch", "src\deep2\Deep2Engine.cpp"),
    @("src\deep2\quant_dot_dispatch.hpp.patch", "src\deep2\quant_dot_dispatch.hpp"),
    @("src\tools\deep2_strata_bench.cpp.patch", "src\tools\deep2_strata_bench.cpp"),
)

function Apply-Patch {
    param(
        [string]$PatchFile,
        [string]$TargetFile,
        [bool]$DryRun,
        [bool]$Force
    )

    $patchPath = Join-Path $PatchDir $PatchFile
    $targetPath = Join-Path (Get-Location) $TargetFile

    if (-not (Test-Path $patchPath)) {
        Write-Warning "Patch not found: $patchPath"
        return $false
    }

    if (-not (Test-Path $targetPath)) {
        Write-Warning "Target not found: $targetPath"
        return $false
    }

    Write-Host "Applying: $PatchFile -> $TargetFile"

    if ($DryRun) {
        Write-Host "  [DRY RUN] Would apply patch"
        return $true
    }

    # Backup original
    $backupPath = $targetPath + ".bak.$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    Copy-Item $targetPath $backupPath -Force
    Write-Host "  Backed up to: $backupPath"

    # For .patch files, use git apply or manual merge
    if ($PatchFile.EndsWith(".patch")) {
        # Simple patch application - replace the target with patch content
        # In production, use proper git apply
        $patchContent = Get-Content $patchPath -Raw
        Write-Host "  Patch content length: $($patchContent.Length) chars"
        # For now, just report - actual merge would need careful handling
        Write-Host "  [MANUAL MERGE REQUIRED] Patch file: $patchPath"
        Write-Host "  Review and merge changes into: $targetPath"
    } else {
        # Full file replacement (for .h/.cpp files in patch dir)
        Copy-Item $patchPath $targetPath -Force
        Write-Host "  Replaced target file"
    }

    return $true
}

$success = 0
$failed = 0

foreach ($pair in $patches) {
    $patchFile = $pair[0]
    $targetFile = $pair[1]

    try {
        if (Apply-Patch $patchFile $targetFile $DryRun $Force) {
            $success++
        } else {
            $failed++
        }
    } catch {
        Write-Error "Failed to apply $patchFile: $_"
        $failed++
    }
}

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
Write-Host "Applied: $success"
Write-Host "Failed: $failed"

if ($failed -gt 0 -and -not $Force) {
    Write-Warning "Some patches failed. Use -Force to continue anyway."
    exit 1
}

if (-not $DryRun) {
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "  1. Review modified files for merge conflicts"
    Write-Host "  2. Run: .\Deep2_GPU_Production_Hardening\verify_build.ps1"
    Write-Host "  3. Run benchmarks to validate fixes"
}

exit 0