# RawrXD OMEGA-1 Release Package Creator
# Creates a complete release package with all binaries and documentation

param(
    [string]$Version = "1.0.0",
    [string]$SourceDir = "d:\rawrxd",
    [string]$OutputDir = "d:\rawrxd\releases"
)

$ErrorActionPreference = 'Stop'
$StartTime = Get-Date

function Write-Header {
    param($Text)
    Write-Host "`n═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
}

function Write-Status {
    param($Text, $Status)
    $color = switch ($Status) {
        "OK" { "Green" }
        "WARN" { "Yellow" }
        "FAIL" { "Red" }
        default { "White" }
    }
    Write-Host "  [$Status] $Text" -ForegroundColor $color
}

Write-Host "`n╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     RawrXD OMEGA-1 Release Package Creator                                     ║" -ForegroundColor Cyan
Write-Host "║     Version: $Version" -NoNewline -ForegroundColor Cyan
Write-Host "$(' ' * (63 - $Version.Length))║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

# =============================================================================
# Phase 1: Prepare Output Directory
# =============================================================================
Write-Header "Phase 1: Preparing Release Directory"

$releaseName = "RawrXD-OMEGA1-v$Version"
$releaseDir = Join-Path $OutputDir $releaseName

if (Test-Path $releaseDir) {
    Write-Status "Cleaning existing release directory..." "OK"
    Remove-Item -Recurse -Force $releaseDir
}

New-Item -ItemType Directory -Force -Path $releaseDir | Out-Null
New-Item -ItemType Directory -Force -Path "$releaseDir\bin" | Out-Null
New-Item -ItemType Directory -Force -Path "$releaseDir\docs" | Out-Null
New-Item -ItemType Directory -Force -Path "$releaseDir\scripts" | Out-Null
New-Item -ItemType Directory -Force -Path "$releaseDir\config" | Out-Null
New-Item -ItemType Directory -Force -Path "$releaseDir\test_results" | Out-Null

Write-Status "Created release directory: $releaseDir" "OK"

# =============================================================================
# Phase 2: Copy Binaries
# =============================================================================
Write-Header "Phase 2: Copying Binaries"

$binaries = @(
    @{ Source = "$SourceDir\build\bin\RawrXD-Win32IDE.exe"; Target = "bin\RawrXD-Win32IDE.exe"; Required = $true }
    @{ Source = "$SourceDir\build\bin\RawrXD-Win32IDE.pdb"; Target = "bin\RawrXD-Win32IDE.pdb"; Required = $false }
    @{ Source = "$SourceDir\build\bin\RawrXD-InferenceEngine.exe"; Target = "bin\RawrXD-InferenceEngine.exe"; Required = $true }
    @{ Source = "$SourceDir\build\bin\RawrXD_MultiWindow_Kernel.dll"; Target = "bin\RawrXD_MultiWindow_Kernel.dll"; Required = $false }
)

$binariesCopied = 0
$binariesFailed = 0

foreach ($bin in $binaries) {
    $targetPath = Join-Path $releaseDir $bin.Target
    if (Test-Path $bin.Source) {
        Copy-Item $bin.Source $targetPath -Force
        $size = (Get-Item $targetPath).Length / 1MB
        Write-Status "Copied: $($bin.Target) ($([math]::Round($size, 2)) MB)" "OK"
        $binariesCopied++
    } else {
        if ($bin.Required) {
            Write-Status "Missing required: $($bin.Target)" "FAIL"
            $binariesFailed++
        } else {
            Write-Status "Optional not found: $($bin.Target)" "WARN"
        }
    }
}

if ($binariesFailed -gt 0) {
    Write-Status "Failed to copy $binariesFailed required binaries" "FAIL"
    exit 1
}

Write-Status "Copied $binariesCopied binaries successfully" "OK"

# =============================================================================
# Phase 3: Copy Documentation
# =============================================================================
Write-Header "Phase 3: Copying Documentation"

$docs = @(
    @{ Source = "$SourceDir\OMEGA1_BUILD_SUMMARY.md"; Target = "docs\BUILD_SUMMARY.md"; Required = $true }
    @{ Source = "$SourceDir\README.md"; Target = "docs\README.md"; Required = $false }
    @{ Source = "$SourceDir\OMEGA1_INTEGRATION.md"; Target = "docs\OMEGA1_INTEGRATION.md"; Required = $false }
)

$docsCopied = 0
foreach ($doc in $docs) {
    $targetPath = Join-Path $releaseDir $doc.Target
    if (Test-Path $doc.Source) {
        Copy-Item $doc.Source $targetPath -Force
        Write-Status "Copied: $($doc.Target)" "OK"
        $docsCopied++
    } else {
        if ($doc.Required) {
            Write-Status "Missing required: $($doc.Target)" "WARN"
        }
    }
}

Write-Status "Copied $docsCopied documentation files" "OK"

# =============================================================================
# Phase 4: Copy Scripts
# =============================================================================
Write-Header "Phase 4: Copying Scripts"

$scripts = @(
    @{ Source = "$SourceDir\scripts\dual_gpu_live_test.ps1"; Target = "scripts\test_dual_gpu.ps1"; Required = $true }
    @{ Source = "$SourceDir\scripts\ipc_validation_test.ps1"; Target = "scripts\test_ipc.ps1"; Required = $true }
)

$scriptsCopied = 0
foreach ($script in $scripts) {
    $targetPath = Join-Path $releaseDir $script.Target
    if (Test-Path $script.Source) {
        Copy-Item $script.Source $targetPath -Force
        Write-Status "Copied: $($script.Target)" "OK"
        $scriptsCopied++
    } else {
        if ($script.Required) {
            Write-Status "Missing required: $($script.Target)" "WARN"
        }
    }
}

Write-Status "Copied $scriptsCopied scripts" "OK"

# =============================================================================
# Phase 5: Copy Test Results
# =============================================================================
Write-Header "Phase 5: Copying Test Results"

$testResults = Get-ChildItem "$SourceDir\test_results\*.json" -ErrorAction SilentlyContinue | 
    Sort-Object LastWriteTime -Descending | 
    Select-Object -First 5

if ($testResults) {
    foreach ($result in $testResults) {
        $targetPath = Join-Path "$releaseDir\test_results" $result.Name
        Copy-Item $result.FullName $targetPath -Force
        Write-Status "Copied: test_results\$($result.Name)" "OK"
    }
} else {
    Write-Status "No test results found" "WARN"
}

# =============================================================================
# Phase 6: Create README
# =============================================================================
Write-Header "Phase 6: Creating Release README"

$readmeContent = @"
# RawrXD OMEGA-1 v$Version

## Overview

RawrXD OMEGA-1 is a local LLM inference IDE with dual GPU support and ghost text completion.

## System Requirements

- **OS:** Windows 10/11 (x64)
- **CPU:** AMD Ryzen 7 7800X3D or equivalent
- **RAM:** 64GB DDR5
- **GPU:** Dual AMD GPU setup (e.g., Radeon AI PRO R9700 + RX 7800 XT)
- **Storage:** 10GB free space

## Quick Start

1. Run the IDE:
   ```
   bin\RawrXD-Win32IDE.exe
   ```

2. Run the Inference Engine:
   ```
   bin\RawrXD-InferenceEngine.exe --model <path> --prompt "Hello"
   ```

## Dual GPU Configuration

The system automatically distributes inference layers across dual GPUs:
- **Primary GPU (R9700):** 22 layers (70%)
- **Secondary GPU (7800XT):** 10 layers (30%)

## Testing

Run validation tests:
```powershell
# Dual GPU test
powershell -ExecutionPolicy Bypass -File scripts\test_dual_gpu.ps1

# IPC communication test
powershell -ExecutionPolicy Bypass -File scripts\test_ipc.ps1
```

## Documentation

- docs\BUILD_SUMMARY.md - Build details and validation results
- docs\OMEGA1_INTEGRATION.md - Integration guide

## Performance Targets

- Prompt Processing: 557 t/s
- Token Generation: 344 t/s

## Support

For issues and feature requests, refer to the documentation in the docs folder.

---

*Built: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')*
*Version: $Version*
"@

$readmePath = Join-Path $releaseDir "README.txt"
$readmeContent | Out-File $readmePath -Encoding UTF8
Write-Status "Created: README.txt" "OK"

# =============================================================================
# Phase 7: Create Package Info
# =============================================================================
Write-Header "Phase 7: Creating Package Info"

$packageInfo = @{
    Name = "RawrXD-OMEGA1"
    Version = $Version
    BuildDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Binaries = @()
    TestResults = @()
}

# Collect binary info
$binFiles = Get-ChildItem "$releaseDir\bin\*.exe" -ErrorAction SilentlyContinue
foreach ($bin in $binFiles) {
    $packageInfo.Binaries += @{
        Name = $bin.Name
        Size = $bin.Length
        SizeMB = [math]::Round($bin.Length / 1MB, 2)
    }
}

# Collect test result info
$testFiles = Get-ChildItem "$releaseDir\test_results\*.json" -ErrorAction SilentlyContinue
foreach ($test in $testFiles) {
    $packageInfo.TestResults += $test.Name
}

$packageInfoPath = Join-Path $releaseDir "package_info.json"
$packageInfo | ConvertTo-Json -Depth 4 | Out-File $packageInfoPath
Write-Status "Created: package_info.json" "OK"

# =============================================================================
# Phase 8: Calculate Package Size
# =============================================================================
Write-Header "Phase 8: Package Summary"

$packageSize = (Get-ChildItem $releaseDir -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB
$packageSizeGB = $packageSize / 1024

Write-Status "Package location: $releaseDir" "OK"
Write-Status "Package size: $([math]::Round($packageSize, 2)) MB ($([math]::Round($packageSizeGB, 2)) GB)" "OK"

# List contents
Write-Host "`n  Package Contents:" -ForegroundColor Gray
Get-ChildItem $releaseDir -Recurse | Where-Object { !$_.PSIsContainer } | ForEach-Object {
    $relPath = $_.FullName.Replace($releaseDir, "").TrimStart("\")
    $size = [math]::Round($_.Length / 1MB, 2)
    Write-Host "    - $relPath ($size MB)" -ForegroundColor Gray
}

# =============================================================================
# Summary
# =============================================================================
$EndTime = Get-Date
$Duration = $EndTime - $StartTime

Write-Header "Release Package Complete"

Write-Status "Package: $releaseName" "OK"
Write-Status "Location: $releaseDir" "OK"
Write-Status "Duration: $($Duration.ToString('hh\:mm\:ss'))" "OK"

Write-Host "`n╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║     ✅ RawrXD OMEGA-1 Release Package Created Successfully                        ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green

exit 0
